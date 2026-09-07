from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from simcairn import compile_plan, load_manifest
from simcairn.adapters import NgspiceAdapter
from simcairn.provenance import current_producer_identity
from simcairn.reference_replay import _numeric_drift, build_replay_report

ROOT = Path(__file__).parents[1]
REFERENCE = ROOT / "benchmarks" / "results" / "ngspice-42-rc-pvt.json"
INVENTORY = ROOT / "benchmarks" / "ciel-assets.json"


def _write_json(path: Path, value: object) -> Path:
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


def _current_bundle(activity_id: str) -> dict[str, Any]:
    value = json.loads(REFERENCE.read_text(encoding="utf-8"))
    value["run"]["producer_identity"] = current_producer_identity().as_dict()
    value["run"]["aggregate_activity_id"] = activity_id
    return value


def test_numeric_report_distinguishes_exact_from_tolerated_drift() -> None:
    reference = json.loads(REFERENCE.read_text(encoding="utf-8"))
    actual = json.loads(json.dumps(reference))
    expected = actual["points"][0]["metrics"]["cutoff_hz"]["value"]
    actual["points"][0]["metrics"]["cutoff_hz"]["value"] = expected * (1.0 + 1e-8)
    report = _numeric_drift(actual, reference)
    assert report["exact_changed_count"] == 1
    assert report["tolerance_changed_count"] == 0
    assert report["maximum_absolute_difference"] > 0.0
    actual["points"][0]["metrics"]["cutoff_hz"]["value"] = expected * 1.01
    assert _numeric_drift(actual, reference)["tolerance_changed_count"] == 1


def test_report_packages_only_the_explicit_non_pdk_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        NgspiceAdapter,
        "identity",
        lambda _self: "simcairn-ngspice/2:ngspice-42",
    )
    plan = compile_plan(load_manifest(ROOT / "examples" / "rc_pvt" / "ngspice.toml"))
    aggregate_id = plan.activities[-1].id
    actual = _write_json(tmp_path / "actual.json", _current_bundle(aggregate_id))
    plan_path = _write_json(tmp_path / "plan.json", plan.as_dict())
    run_result = {
        "run_id": "test-run",
        "plan_id": plan.id,
        "status": "succeeded",
        "counts": {"succeeded": len(plan.activities)},
        "run_directory": str(tmp_path / "store" / "runs" / "test-run"),
        "outcomes": [
            {
                "activity_id": activity.id,
                "status": "succeeded",
                "duration_seconds": 0.0,
                "message": "",
            }
            for activity in plan.activities
        ],
    }
    run_result_path = _write_json(tmp_path / "run-result.json", run_result)
    wheel = tmp_path / "simcairn-test.whl"
    wheel.write_bytes(b"test wheel")
    environment = tmp_path / "environment.txt"
    environment.write_text("ngspice-42\nKLU Direct Linear Solver\n", encoding="ascii")
    output = tmp_path / "evidence" / "rc"
    summary = build_replay_report(
        "rc",
        inventory_path=INVENTORY,
        actual_path=actual,
        plan_path=plan_path,
        run_result_path=run_result_path,
        wheel_path=wheel,
        environment_path=environment,
        output_path=output,
    )
    assert summary["numeric_drift"]["exact_changed_count"] == 0
    assert summary["current"]["successful_activities"] == 97
    assert {path.name for path in output.iterdir()} == {
        "actual-bundle.json",
        "environment.txt",
        "plan.json",
        "run-result.json",
        "summary.json",
        "wheel.sha256",
    }
    assert "test wheel" not in "\n".join(path.name for path in output.iterdir())


def test_report_rejects_outcome_that_is_not_bound_to_the_current_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        NgspiceAdapter,
        "identity",
        lambda _self: "simcairn-ngspice/2:ngspice-42",
    )
    plan = compile_plan(load_manifest(ROOT / "examples" / "rc_pvt" / "ngspice.toml"))
    actual = _write_json(tmp_path / "actual.json", _current_bundle(plan.activities[-1].id))
    plan_path = _write_json(tmp_path / "plan.json", plan.as_dict())
    outcomes = [
        {
            "activity_id": activity.id,
            "status": "succeeded",
            "duration_seconds": 0.0,
            "message": "",
        }
        for activity in plan.activities
    ]
    outcomes[-1]["activity_id"] = outcomes[0]["activity_id"]
    run_result = {
        "run_id": "test-run",
        "plan_id": plan.id,
        "status": "succeeded",
        "counts": {"succeeded": len(plan.activities)},
        "run_directory": "unused",
        "outcomes": outcomes,
    }
    with pytest.raises(ValueError, match="every current activity"):
        build_replay_report(
            "rc",
            inventory_path=INVENTORY,
            actual_path=actual,
            plan_path=plan_path,
            run_result_path=_write_json(tmp_path / "run-result.json", run_result),
            wheel_path=_write_json(tmp_path / "wheel.whl", {}),
            environment_path=_write_json(tmp_path / "environment.txt", {}),
            output_path=tmp_path / "evidence",
        )
