"""Validate and package a bounded, non-PDK reference-replay evidence set."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

from simcairn.pdk_replay import ReplayPreparationError, load_replay_inventory
from simcairn.reference import (
    validate_gf180_bundle,
    validate_sky130_bundle,
    verify_reference,
)

_MAX_JSON_BYTES = 16 * 1024 * 1024
_MAX_TEXT_BYTES = 256 * 1024


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_bounded(path: Path, maximum: int, name: str) -> bytes:
    with path.open("rb") as stream:
        payload = stream.read(maximum + 1)
    if len(payload) > maximum:
        raise ValueError(f"{name} exceeds the {maximum}-byte limit")
    return payload


def _json(path: Path, name: str) -> Any:
    payload = _read_bounded(path, _MAX_JSON_BYTES, name)
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_constant=lambda token: (_ for _ in ()).throw(
                ValueError(f"non-finite JSON number in {name}: {token}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, OverflowError) as error:
        raise ValueError(f"cannot parse {name}: {error}") from error


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _mapping(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name} must be an object")
    return cast(Mapping[str, Any], value)


def _observation(sidecar: Mapping[str, Any], path: tuple[str, ...]) -> Mapping[str, Any]:
    value: object = sidecar
    for part in path:
        value = _mapping(value, "sidecar observation").get(part)
    return _mapping(value, "sidecar observation")


def _metric_rows(bundle: Mapping[str, Any], name: str) -> dict[str, Mapping[str, Any]]:
    points = bundle.get("points")
    if not isinstance(points, list):
        raise ValueError(f"{name} points must be an array")
    result: dict[str, Mapping[str, Any]] = {}
    for point in points:
        record = _mapping(point, f"{name} point")
        identity = json.dumps(
            [record.get("case"), record.get("sample")],
            sort_keys=True,
            separators=(",", ":"),
        )
        if identity in result:
            raise ValueError(f"{name} contains duplicate case/sample identities")
        result[identity] = _mapping(record.get("metrics"), f"{name} metrics")
    return result


def _numeric_drift(
    actual: Mapping[str, Any], reference: Mapping[str, Any]
) -> dict[str, int | float]:
    actual_rows = _metric_rows(actual, "actual bundle")
    reference_rows = _metric_rows(reference, "reference bundle")
    if set(actual_rows) != set(reference_rows):
        raise ValueError("actual and reference case/sample sets differ")
    compared = 0
    exact_changed = 0
    tolerant_changed = 0
    maximum_absolute = 0.0
    maximum_relative = 0.0
    for identity in sorted(reference_rows):
        observed_metrics = actual_rows[identity]
        expected_metrics = reference_rows[identity]
        if set(observed_metrics) != set(expected_metrics):
            raise ValueError("actual and reference metric sets differ")
        for metric in sorted(expected_metrics):
            observed = _mapping(observed_metrics[metric], "actual measurement")
            expected = _mapping(expected_metrics[metric], "reference measurement")
            if observed.get("unit") != expected.get("unit"):
                raise ValueError(f"metric unit differs for {metric}")
            observed_value = observed.get("value")
            expected_value = expected.get("value")
            if (
                isinstance(observed_value, bool)
                or not isinstance(observed_value, int | float)
                or isinstance(expected_value, bool)
                or not isinstance(expected_value, int | float)
            ):
                raise ValueError(f"metric {metric} does not contain numeric values")
            observed_number = float(observed_value)
            expected_number = float(expected_value)
            if not math.isfinite(observed_number) or not math.isfinite(expected_number):
                raise ValueError(f"metric {metric} is not finite")
            compared += 1
            difference = abs(observed_number - expected_number)
            relative = difference / max(abs(observed_number), abs(expected_number), 1e-300)
            maximum_absolute = max(maximum_absolute, difference)
            maximum_relative = max(maximum_relative, relative)
            if observed_value != expected_value:
                exact_changed += 1
            if not math.isclose(observed_number, expected_number, rel_tol=1e-6, abs_tol=1e-18):
                tolerant_changed += 1
    return {
        "compared_values": compared,
        "exact_changed_count": exact_changed,
        "tolerance_changed_count": tolerant_changed,
        "maximum_absolute_difference": maximum_absolute,
        "maximum_relative_difference": maximum_relative,
    }


def _copy_bounded(source: Path, destination: Path, maximum: int, name: str) -> str:
    payload = _read_bounded(source, maximum, name)
    destination.write_bytes(payload)
    return _sha256_bytes(payload)


def build_replay_report(
    case: str,
    *,
    inventory_path: Path,
    actual_path: Path,
    plan_path: Path,
    run_result_path: Path,
    wheel_path: Path,
    environment_path: Path,
    output_path: Path,
    pdk_fetch_path: Path | None = None,
) -> dict[str, Any]:
    """Verify historical/current bindings and create an explicit evidence allowlist."""
    inventory = load_replay_inventory(inventory_path)
    repository_root = inventory_path.resolve().parent.parent
    if case not in inventory.replays:
        raise ValueError(f"unsupported replay case: {case}")
    pin = inventory.replays[case]
    sidecar_path = repository_root / pin.sidecar
    reference_path = repository_root / pin.reference
    sidecar = _mapping(_json(sidecar_path, "reference sidecar"), "reference sidecar")
    reference_payload = _read_bounded(reference_path, _MAX_JSON_BYTES, "reference bundle")
    if _sha256_bytes(reference_payload) != pin.reference_sha256:
        raise ValueError("frozen reference SHA-256 differs from the independent lock")
    reference = _mapping(_json(reference_path, "reference bundle"), "reference bundle")
    artifacts = _mapping(sidecar.get("artifacts"), "sidecar artifacts")
    if artifacts.get(pin.reference) != pin.reference_sha256:
        raise ValueError("reference sidecar does not bind the locked frozen bundle")
    expected = _mapping(sidecar.get("expected"), "sidecar expected values")
    if expected.get("points") != pin.expected_points:
        raise ValueError("reference sidecar point count differs from the independent lock")
    reference_run = _mapping(reference.get("run"), "reference run")
    if sidecar.get("producer_identity") != reference_run.get("producer_identity"):
        raise ValueError("reference sidecar and bundle producer identities differ")
    observation = _observation(sidecar, pin.observation_path)
    if observation.get("aggregate_activity_id") != reference_run.get("aggregate_activity_id"):
        raise ValueError("reference sidecar and bundle aggregate identities differ")
    if observation.get("successful_activities") != pin.expected_activities:
        raise ValueError("reference sidecar activity count differs from the independent lock")

    plan = _mapping(_json(plan_path, "current plan"), "current plan")
    activities = plan.get("activities")
    if not isinstance(activities, list) or len(activities) != pin.expected_activities:
        raise ValueError("current plan does not contain the locked activity count")
    aggregate = _mapping(activities[-1], "current aggregate activity")
    aggregate_id = aggregate.get("id")
    if aggregate.get("kind") != "aggregate" or not isinstance(aggregate_id, str):
        raise ValueError("current plan does not end in an aggregate activity")
    run_result = _mapping(_json(run_result_path, "run result"), "run result")
    if run_result.get("status") != "succeeded" or run_result.get("plan_id") != plan.get("id"):
        raise ValueError("run result is not a successful execution of the captured plan")
    if run_result.get("counts") != {"succeeded": pin.expected_activities}:
        raise ValueError("run result does not contain the locked successful activity count")
    outcomes = run_result.get("outcomes")
    if not isinstance(outcomes, list) or len(outcomes) != pin.expected_activities:
        raise ValueError("run result outcome count differs from the current plan")
    plan_activity_ids = {
        _mapping(activity, "current activity").get("id") for activity in activities
    }
    outcome_ids: set[object] = set()
    for outcome in outcomes:
        outcome_record = _mapping(outcome, "run outcome")
        if outcome_record.get("status") != "succeeded":
            raise ValueError("run result contains a non-successful outcome")
        outcome_ids.add(outcome_record.get("activity_id"))
    if outcome_ids != plan_activity_ids or len(outcome_ids) != len(outcomes):
        raise ValueError("run result outcomes do not bind every current activity exactly once")

    verify_reference(
        actual_path,
        reference_path,
        expected_points=pin.expected_points,
        expected_activity_id=aggregate_id,
    )
    if case == "sky130":
        validate_sky130_bundle(actual_path)
    elif case == "gf180":
        validate_gf180_bundle(actual_path)
    actual = _mapping(_json(actual_path, "actual bundle"), "actual bundle")
    drift = _numeric_drift(actual, reference)
    if drift["tolerance_changed_count"] != 0:
        raise ValueError("current numeric result exceeds the frozen comparison tolerance")

    pdk_fetch: Mapping[str, Any] | None = None
    if case == "rc":
        if pdk_fetch_path is not None:
            raise ValueError("RC replay must not provide PDK fetch evidence")
    else:
        if pdk_fetch_path is None:
            raise ValueError("PDK replay requires fetch evidence")
        pdk_fetch = _mapping(_json(pdk_fetch_path, "PDK fetch evidence"), "PDK fetch evidence")
        if (
            pdk_fetch.get("schema") != "org.simcairn.ciel-replay-evidence"
            or pdk_fetch.get("inventory_sha256") != inventory.sha256
            or pdk_fetch.get("family") != case
            or pdk_fetch.get("revision") != inventory.revision
        ):
            raise ValueError("PDK fetch evidence does not match the locked replay")

    if output_path.exists() or output_path.is_symlink():
        raise ValueError("evidence output already exists")
    staging = output_path.with_name(f".{output_path.name}.tmp-{os.getpid()}")
    if staging.exists() or staging.is_symlink():
        raise ValueError("evidence staging output already exists")
    try:
        staging.mkdir(parents=True)
        file_hashes = {
            "actual-bundle.json": _copy_bounded(
                actual_path, staging / "actual-bundle.json", _MAX_JSON_BYTES, "actual bundle"
            ),
            "plan.json": _copy_bounded(
                plan_path, staging / "plan.json", _MAX_JSON_BYTES, "current plan"
            ),
            "run-result.json": _copy_bounded(
                run_result_path, staging / "run-result.json", _MAX_JSON_BYTES, "run result"
            ),
            "environment.txt": _copy_bounded(
                environment_path,
                staging / "environment.txt",
                _MAX_TEXT_BYTES,
                "environment evidence",
            ),
        }
        if pdk_fetch_path is not None:
            file_hashes["pdk-fetch.json"] = _copy_bounded(
                pdk_fetch_path,
                staging / "pdk-fetch.json",
                _MAX_JSON_BYTES,
                "PDK fetch evidence",
            )
        wheel_sha256 = _sha256(wheel_path)
        wheel_line = f"{wheel_sha256}  {wheel_path.name}\n"
        (staging / "wheel.sha256").write_text(wheel_line, encoding="ascii", newline="\n")
        file_hashes["wheel.sha256"] = _sha256(staging / "wheel.sha256")
        summary: dict[str, Any] = {
            "schema": "org.simcairn.real-reference-replay",
            "version": 1,
            "case": case,
            "inventory_sha256": inventory.sha256,
            "reference": {
                "path": pin.reference,
                "sha256": pin.reference_sha256,
                "producer_identity": reference_run["producer_identity"],
                "aggregate_activity_id": reference_run["aggregate_activity_id"],
            },
            "current": {
                "wheel": wheel_path.name,
                "wheel_bytes": wheel_path.stat().st_size,
                "wheel_sha256": wheel_sha256,
                "plan_id": plan.get("id"),
                "aggregate_activity_id": aggregate_id,
                "producer_identity": _mapping(actual.get("run"), "actual run").get(
                    "producer_identity"
                ),
                "successful_activities": pin.expected_activities,
                "points": pin.expected_points,
            },
            "numeric_drift": drift,
            "files": dict(sorted(file_hashes.items())),
        }
        (staging / "summary.json").write_text(
            json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
            newline="\n",
        )
        staging.rename(output_path)
        return summary
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("case", choices=("rc", "sky130", "gf180"))
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--actual", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--run-result", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--environment", type=Path, required=True)
    parser.add_argument("--pdk-fetch", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        summary = build_replay_report(
            arguments.case,
            inventory_path=arguments.inventory,
            actual_path=arguments.actual,
            plan_path=arguments.plan,
            run_result_path=arguments.run_result,
            wheel_path=arguments.wheel,
            environment_path=arguments.environment,
            output_path=arguments.output,
            pdk_fetch_path=arguments.pdk_fetch,
        )
    except (OSError, ReplayPreparationError, ValueError) as error:
        parser.exit(2, f"report_reference_replay: {error}\n")
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
