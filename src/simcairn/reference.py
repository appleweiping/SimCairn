"""Strict comparison of a fresh ngspice bundle with a numeric reference."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Never

from simcairn.provenance import ProducerIdentity, ProducerIdentityError

_MAX_BUNDLE_BYTES = 8 * 1024 * 1024
_MAX_JSON_DEPTH = 64


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _constant(token: str) -> Never:
    raise ValueError(f"non-finite JSON number {token!r}")


def _check_json_depth(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for character in text:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > _MAX_JSON_DEPTH:
                raise ValueError(f"JSON exceeds the maximum depth of {_MAX_JSON_DEPTH}")
        elif character in "]}":
            depth -= 1


def _load(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as stream:
            payload = stream.read(_MAX_BUNDLE_BYTES + 1)
        if len(payload) > _MAX_BUNDLE_BYTES:
            raise ValueError("measurement bundle exceeds the 8 MiB limit")
        text = payload.decode("utf-8")
        _check_json_depth(text)
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except (OSError, UnicodeError, RecursionError, OverflowError, ValueError) as error:
        raise ValueError(f"cannot read measurement bundle {path}: {error}") from error
    if not isinstance(value, dict) or set(value) != {"schema_version", "run", "points"}:
        raise ValueError(f"{path} is not a measurement bundle")
    if type(value["schema_version"]) is not int or value["schema_version"] != 2:
        raise ValueError(f"{path} has an unsupported schema")
    run = value["run"]
    if (
        not isinstance(run, dict)
        or set(run) != {"producer", "producer_identity", "contract", "aggregate_activity_id"}
        or run.get("producer") != "SimCairn"
        or run.get("contract") != "regressistor.measurement-bundle/2"
        or not isinstance(run.get("aggregate_activity_id"), str)
        or len(run["aggregate_activity_id"]) != 64
        or any(character not in "0123456789abcdef" for character in run["aggregate_activity_id"])
    ):
        raise ValueError(f"{path} has invalid producer provenance")
    try:
        ProducerIdentity.from_value(run["producer_identity"])
    except ProducerIdentityError as error:
        raise ValueError(f"{path} has invalid producer identity: {error}") from error
    return value


def _finite_number(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _points(bundle: dict[str, Any], expected_points: int) -> dict[str, dict[str, Any]]:
    raw = bundle["points"]
    if not isinstance(raw, list) or len(raw) != expected_points:
        raise ValueError(f"reference workflow must contain exactly {expected_points} points")
    result: dict[str, dict[str, Any]] = {}
    for point in raw:
        if not isinstance(point, dict) or set(point) != {"case", "sample", "metrics"}:
            raise ValueError("point schema is invalid")
        case = point["case"]
        sample = point["sample"]
        metrics = point["metrics"]
        if (
            not isinstance(case, dict)
            or not case
            or not all(
                isinstance(name, str) and name and isinstance(value, str)
                for name, value in case.items()
            )
        ):
            raise ValueError("case must be a non-empty string-to-string object")
        if isinstance(sample, bool) or not isinstance(sample, int) or sample < 0:
            raise ValueError("sample must be a non-negative integer")
        identity = json.dumps([case, sample], sort_keys=True)
        if identity in result:
            raise ValueError("duplicate case/sample")
        if not isinstance(metrics, dict) or not metrics:
            raise ValueError("metrics must be an object")
        for name, measurement in metrics.items():
            if not isinstance(name, str) or not name:
                raise ValueError("metric names must be non-empty strings")
            if (
                not isinstance(measurement, dict)
                or set(measurement) != {"value", "unit"}
                or not isinstance(measurement["unit"], str)
                or not measurement["unit"]
                or not _finite_number(measurement["value"])
            ):
                raise ValueError(f"metric schema, unit, or value is invalid for {name}")
        result[identity] = metrics
    return result


def verify_reference(actual_path: Path, reference_path: Path, *, expected_points: int = 32) -> None:
    """Validate and compare two producer-bound ngspice regression bundles."""

    if isinstance(expected_points, bool) or not isinstance(expected_points, int):
        raise ValueError("expected_points must be an integer")
    if expected_points <= 0 or expected_points > 100_000:
        raise ValueError("expected_points is outside the supported range")

    actual_bundle = _load(actual_path)
    reference_bundle = _load(reference_path)
    if actual_bundle["run"]["producer_identity"] != reference_bundle["run"]["producer_identity"]:
        raise ValueError("producer implementation identity differs from the reference")
    if (
        actual_bundle["run"]["aggregate_activity_id"]
        != reference_bundle["run"]["aggregate_activity_id"]
    ):
        raise ValueError("aggregate activity identity differs from the reference")
    actual_points = _points(actual_bundle, expected_points)
    reference_points = _points(reference_bundle, expected_points)
    if set(actual_points) != set(reference_points):
        raise ValueError("case/sample sets differ from the reference")
    for identity in sorted(reference_points):
        observed = actual_points[identity]
        expected = reference_points[identity]
        if set(observed) != set(expected):
            raise ValueError(f"metric set differs for {identity}")
        for name, expected_measurement in expected.items():
            measurement = observed[name]
            if measurement["unit"] != expected_measurement["unit"]:
                raise ValueError(f"metric unit differs for {name}")
            value = measurement["value"]
            expected_value = expected_measurement["value"]
            if not math.isclose(value, expected_value, rel_tol=1e-6, abs_tol=1e-18):
                raise ValueError(f"metric {name} differs from the ngspice reference")


def validate_bundle(path: Path, *, expected_points: int) -> None:
    """Validate one bundle for compatibility smoke tests without numeric authority."""
    if isinstance(expected_points, bool) or not isinstance(expected_points, int):
        raise ValueError("expected_points must be an integer")
    if expected_points <= 0 or expected_points > 100_000:
        raise ValueError("expected_points is outside the supported range")
    _points(_load(path), expected_points)


def _validate_common_source_bundle(
    path: Path, *, process: str, voltages: tuple[str, str, str]
) -> None:
    bundle = _load(path)
    _points(bundle, 27)
    expected_cases = {
        (corner, vdd, temperature)
        for corner in ("tt", "ss", "ff")
        for vdd in voltages
        for temperature in ("-40", "27", "125")
    }
    observed_cases: set[tuple[str, str, str]] = set()
    expected_units = {
        "output_v": "V",
        "output_pp_v": "V",
        "gain_100khz": "1",
        "supply_current_a": "A",
        "power_w": "W",
    }
    for point in bundle["points"]:
        case = point["case"]
        if set(case) != {"CORNER", "VDD", "TEMP_C"}:
            raise ValueError(f"{process} point has an unexpected sweep field")
        observed_cases.add((case["CORNER"], case["VDD"], case["TEMP_C"]))
        metrics = point["metrics"]
        if {name: measurement["unit"] for name, measurement in metrics.items()} != expected_units:
            raise ValueError(f"{process} metric names or units differ from the contract")
        output_v = float(metrics["output_v"]["value"])
        output_pp_v = float(metrics["output_pp_v"]["value"])
        gain = float(metrics["gain_100khz"]["value"])
        current = float(metrics["supply_current_a"]["value"])
        power = float(metrics["power_w"]["value"])
        vdd = float(case["VDD"])
        if not 0.05 < output_v < vdd - 0.05:
            raise ValueError(f"{process} output bias is at or too near a supply rail")
        if not 0.0 < output_pp_v < 0.25 or not 0.1 < gain < 100.0:
            raise ValueError(f"{process} transient gain is outside the characterization bounds")
        if not math.isclose(gain, output_pp_v / 0.002, rel_tol=2e-5, abs_tol=1e-9):
            raise ValueError(f"{process} gain and peak-to-peak measurements are inconsistent")
        if not 0.0 < current < 0.01 or not 0.0 < power < 0.1:
            raise ValueError(f"{process} current or power is outside the characterization bounds")
        if not math.isclose(power, vdd * current, rel_tol=2e-5, abs_tol=1e-12):
            raise ValueError(f"{process} power and supply-current measurements are inconsistent")
    if observed_cases != expected_cases:
        raise ValueError(f"{process} bundle does not contain the exact 27-point PVT product")


def validate_gf180_bundle(path: Path) -> None:
    """Validate the exact 27-point GF180 PVT contract and physical invariants."""
    _validate_common_source_bundle(path, process="GF180", voltages=("2.97", "3.30", "3.63"))


def validate_sky130_bundle(path: Path) -> None:
    """Validate the exact 27-point SKY130 PVT contract and physical invariants."""
    _validate_common_source_bundle(path, process="SKY130", voltages=("1.62", "1.80", "1.98"))
