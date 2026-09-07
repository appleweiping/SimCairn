from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest

from simcairn import compile_plan, load_manifest
from simcairn.adapters import NgspiceAdapter
from simcairn.provenance import current_producer_identity
from simcairn.reference import (
    validate_bundle,
    validate_gf180_bundle,
    validate_sky130_bundle,
    verify_reference,
)

ROOT = Path(__file__).parents[1]
REFERENCE = ROOT / "benchmarks" / "results" / "ngspice-42-rc-pvt.json"
GF180_REFERENCE = ROOT / "benchmarks" / "results" / "ngspice-42-gf180-pvt.json"
SKY130_REFERENCE = ROOT / "benchmarks" / "results" / "ngspice-42-sky130-pvt.json"
CURRENT_ACTIVITY_ID = "a" * 64


def _current_actual(
    source: Path = REFERENCE, *, activity_id: str = CURRENT_ACTIVITY_ID
) -> dict[str, Any]:
    value = json.loads(source.read_text(encoding="utf-8"))
    value["run"]["producer_identity"] = current_producer_identity().as_dict()
    value["run"]["aggregate_activity_id"] = activity_id
    return value


def _write_bundle(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def test_reference_verifier_accepts_recorded_bundle_and_detects_drift(tmp_path: Path) -> None:
    validate_bundle(REFERENCE, expected_points=32)
    with pytest.raises(ValueError, match="31 points"):
        validate_bundle(REFERENCE, expected_points=31)
    actual = _write_bundle(tmp_path / "actual.json", _current_actual())
    verify_reference(actual, REFERENCE, expected_activity_id=CURRENT_ACTIVITY_ID)
    value = _current_actual()
    value["points"][0]["metrics"]["cutoff_hz"]["value"] *= 1.1
    changed = _write_bundle(tmp_path / "changed.json", value)
    with pytest.raises(ValueError, match="differs"):
        verify_reference(changed, REFERENCE, expected_activity_id=CURRENT_ACTIVITY_ID)


def test_historical_benchmark_manifests_still_bind_their_exact_artifacts() -> None:
    records = (
        ("manifest.json", REFERENCE, "observations", "real_ngspice"),
        ("gf180-manifest.json", GF180_REFERENCE, "observation", None),
        ("sky130-manifest.json", SKY130_REFERENCE, "observation", None),
    )
    for name, bundle_path, observation_key, nested_key in records:
        manifest = json.loads((ROOT / "benchmarks" / name).read_text(encoding="utf-8"))
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
        assert manifest["schema_version"] == 2
        assert manifest["producer_identity"] == bundle["run"]["producer_identity"]
        observation = manifest[observation_key]
        if nested_key is not None:
            observation = observation[nested_key]
        assert observation["aggregate_activity_id"] == bundle["run"]["aggregate_activity_id"]
        assert manifest["expected"]["points"] == len(bundle["points"])
        for relative, expected in manifest["artifacts"].items():
            assert sha256((ROOT / relative).read_bytes()).hexdigest() == expected


def test_ngspice_reference_is_bound_to_the_fixed_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        NgspiceAdapter,
        "identity",
        lambda _self: "simcairn-ngspice/2:ngspice-42",
    )
    plan = compile_plan(load_manifest(ROOT / "examples" / "rc_pvt" / "ngspice.toml"))
    assert plan.activities[-1].kind == "aggregate"
    actual = _write_bundle(
        tmp_path / "current-reference.json",
        _current_actual(activity_id=plan.activities[-1].id),
    )
    verify_reference(actual, REFERENCE, expected_activity_id=plan.activities[-1].id)
    with pytest.raises(ValueError, match="current plan"):
        verify_reference(actual, REFERENCE, expected_activity_id="b" * 64)


def test_reference_verifier_rejects_ambiguous_and_invalid_contracts(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":2,"schema_version":2}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        verify_reference(duplicate, REFERENCE)
    nonfinite = tmp_path / "nonfinite.json"
    nonfinite.write_text('{"schema_version":NaN}', encoding="utf-8")
    with pytest.raises(ValueError, match="non-finite"):
        verify_reference(nonfinite, REFERENCE)

    original = _current_actual()
    mutations = [
        (lambda value: value.update(schema_version=True), "schema"),
        (lambda value: value.update(schema_version=1.0), "schema"),
        (lambda value: value.update(run={}), "provenance"),
        (
            lambda value: value["run"].update(aggregate_activity_id="0" * 64),
            "activity identity",
        ),
        (lambda value: value.update(points=[]), "32 points"),
        (lambda value: value["points"][0].update(extra=True), "point schema"),
        (lambda value: value["points"][1].update(value["points"][0]), "duplicate"),
        (lambda value: value["points"][0].update(metrics=[]), "metrics"),
        (
            lambda value: value["points"][0]["metrics"]["cutoff_hz"].update(value=10**400),
            "metric schema",
        ),
    ]
    for index, (mutate, message) in enumerate(mutations):
        value = json.loads(json.dumps(original))
        mutate(value)
        path = tmp_path / f"invalid-{index}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        with pytest.raises(ValueError, match=message):
            verify_reference(path, REFERENCE, expected_activity_id=CURRENT_ACTIVITY_ID)


def test_v1_bundle_is_rejected_fail_closed(tmp_path: Path) -> None:
    value = json.loads(REFERENCE.read_text(encoding="utf-8"))
    value["schema_version"] = 1
    value["run"]["contract"] = "regressistor.measurement-bundle/1"
    value["run"].pop("producer_identity")
    path = tmp_path / "v1.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported schema"):
        verify_reference(path, REFERENCE)


def test_reference_verifier_binds_exact_producer_identity(tmp_path: Path) -> None:
    original = _current_actual()

    changed = json.loads(json.dumps(original))
    changed["run"]["producer_identity"]["package_tree_sha256"] = "0" * 64
    changed_path = tmp_path / "changed-producer.json"
    changed_path.write_text(json.dumps(changed), encoding="utf-8")
    with pytest.raises(ValueError, match="imported implementation"):
        verify_reference(changed_path, REFERENCE, expected_activity_id=CURRENT_ACTIVITY_ID)

    invalid = json.loads(json.dumps(original))
    invalid["run"]["producer_identity"]["adapter_implementation_sha256"] = "A" * 64
    invalid_path = tmp_path / "invalid-producer.json"
    invalid_path.write_text(json.dumps(invalid), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid producer identity"):
        verify_reference(invalid_path, REFERENCE, expected_activity_id=CURRENT_ACTIVITY_ID)


def test_reference_verifier_bounds_json_resources(tmp_path: Path) -> None:
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (8 * 1024 * 1024 + 1))
    with pytest.raises(ValueError, match="8 MiB"):
        validate_bundle(oversized, expected_points=32)

    deeply_nested = tmp_path / "deep.json"
    deeply_nested.write_text("[" * 1_500 + "]" * 1_500, encoding="utf-8")
    with pytest.raises(ValueError, match="maximum depth"):
        validate_bundle(deeply_nested, expected_points=32)


@pytest.mark.parametrize("expected_points", [True, 0, -1, 100_001])
def test_bundle_validator_rejects_invalid_expected_count(expected_points: int) -> None:
    with pytest.raises(ValueError, match="expected_points"):
        validate_bundle(REFERENCE, expected_points=expected_points)


def test_gf180_reference_validator_checks_physical_invariants(tmp_path: Path) -> None:
    validate_gf180_bundle(GF180_REFERENCE)
    original = json.loads(GF180_REFERENCE.read_text(encoding="utf-8"))
    mutations = [
        (
            lambda value: value["points"][0]["metrics"]["output_v"].update(value=0.0),
            "supply rail",
        ),
        (
            lambda value: value["points"][0]["metrics"]["gain_100khz"].update(value=3.0),
            "inconsistent",
        ),
        (
            lambda value: value["points"][0]["metrics"]["power_w"].update(value=0.01),
            "inconsistent",
        ),
        (
            lambda value: value["points"][0]["metrics"]["power_w"].update(unit="mW"),
            "names or units",
        ),
        (lambda value: value["points"][0]["case"].update(extra="x"), "sweep field"),
    ]
    for index, (mutate, message) in enumerate(mutations):
        value = json.loads(json.dumps(original))
        mutate(value)
        path = tmp_path / f"gf180-invalid-{index}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        with pytest.raises(ValueError, match=message):
            validate_gf180_bundle(path)


def test_sky130_reference_validator_checks_physical_invariants() -> None:
    validate_sky130_bundle(SKY130_REFERENCE)
