import asyncio
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from simcairn.adapters import AdapterError
from simcairn.api import Runner
from simcairn.cli import main
from simcairn.executor import ActivityExecutor, ExecutionError
from simcairn.manifest import load_manifest
from simcairn.model import Activity, ActivityOutcome, canonical_json
from simcairn.planner import compile_plan
from simcairn.scheduler import execute_plan
from simcairn.store import ArtifactStore

EXAMPLE = Path(__file__).parents[1] / "examples" / "rc_sweep" / "simcairn.toml"


def test_real_mock_subprocess_run_collect_and_cache(tmp_path):
    manifest = load_manifest(EXAMPLE)
    runner = Runner(tmp_path / "store")
    first = runner.run(manifest)
    assert first.status == "succeeded"
    assert first.counts == {"succeeded": 19}
    rows = runner.collect(first.run_id)
    assert len(rows) == 6
    assert rows[0]["R"] == "1k"
    assert rows[0]["C"] == "1n"
    assert rows[0]["cutoff_hz"] == pytest.approx(159154.94309189534)

    second = runner.run(manifest)
    assert second.status == "succeeded"
    assert second.counts == {"cached": 19}
    assert runner.collect(second.run_id) == rows
    assert runner.status(second.run_id)["status"] == "succeeded"


def test_resume_reuses_verified_completed_artifacts(tmp_path):
    runner = Runner(tmp_path / "store")
    first = runner.run(load_manifest(EXAMPLE))
    resumed = runner.resume(first.run_id)
    assert resumed.run_id == first.run_id
    assert resumed.counts == {"cached": 19}
    status = runner.status(first.run_id)
    assert status["events"] > 20


def test_explain_reports_verified_cache_and_unknown_miss(tmp_path):
    runner = Runner(tmp_path / "store")
    report = runner.run(load_manifest(EXAMPLE))
    plan = runner.store.load_plan(report.run_id)
    hit = runner.explain(plan.activities[0].id)
    assert hit["cached"] is True
    assert hit["artifacts"]
    miss = runner.explain("f" * 64)
    assert miss["cached"] is False
    assert "manifest unavailable" in miss["reason"]


class RecordingExecutor:
    def __init__(self, *, fail_kind: str | None = None) -> None:
        self.fail_kind = fail_kind
        self.active = 0
        self.maximum = 0
        self.simulator_active = 0
        self.simulator_maximum = 0

    async def execute(self, activity: Activity) -> ActivityOutcome:
        self.active += 1
        self.maximum = max(self.maximum, self.active)
        if activity.kind == "simulate":
            self.simulator_active += 1
            self.simulator_maximum = max(self.simulator_maximum, self.simulator_active)
        await asyncio.sleep(0.01)
        status = "failed" if activity.kind == self.fail_kind else "succeeded"
        if activity.kind == "simulate":
            self.simulator_active -= 1
        self.active -= 1
        return ActivityOutcome(activity.id, status, 0.01, "injected" if status == "failed" else "")


def _empty_run(store: ArtifactStore, plan):
    run_id, _ = store.create_run(plan)
    return run_id


def test_scheduler_honors_jobs_and_named_simulator_resource(tmp_path):
    manifest = load_manifest(EXAMPLE)
    plan = compile_plan(manifest)
    plan = replace(plan, jobs=4, resource_limits=(("simulator", 1),))
    store = ArtifactStore(tmp_path / "store")
    executor = RecordingExecutor()
    report = asyncio.run(execute_plan(plan, store, _empty_run(store, plan), executor=executor))
    assert report.status == "succeeded"
    assert executor.maximum <= 4
    assert executor.maximum >= 2
    assert executor.simulator_maximum == 1


def test_scheduler_continues_independent_points_and_skips_dependents(tmp_path):
    plan = compile_plan(load_manifest(EXAMPLE))
    store = ArtifactStore(tmp_path / "store")
    executor = RecordingExecutor(fail_kind="simulate")
    report = asyncio.run(execute_plan(plan, store, _empty_run(store, plan), executor=executor))
    assert report.status == "failed"
    assert report.counts["failed"] == 6
    assert report.counts["skipped"] == 7


def test_fail_fast_stops_unscheduled_work(tmp_path):
    plan = replace(compile_plan(load_manifest(EXAMPLE)), fail_fast=True, jobs=1)
    store = ArtifactStore(tmp_path / "store")
    executor = RecordingExecutor(fail_kind="render")
    report = asyncio.run(execute_plan(plan, store, _empty_run(store, plan), executor=executor))
    assert report.status == "failed"
    assert report.counts == {"failed": 1, "skipped": 18}


class SlowAdapter:
    name = "slow"

    def identity(self):
        return "slow/1"

    def command(self, sandbox, payload):
        del sandbox, payload
        return [sys.executable, "-c", "import time; time.sleep(5)"]

    def expected_artifacts(self):
        return ("stdout.log", "stderr.log", "metrics.json")

    def collect(self, sandbox, payload):
        del sandbox, payload
        raise AdapterError("unreachable")


def test_simulator_timeout_terminates_subprocess(tmp_path, monkeypatch):
    monkeypatch.setattr("simcairn.executor.create_adapter", lambda config: SlowAdapter())
    store = ArtifactStore(tmp_path / "store")
    activity = Activity(
        "a" * 64,
        "simulate",
        None,
        (),
        (),
        ("stdout.log", "stderr.log", "metrics.json"),
        (),
        0.05,
        canonical_json({"adapter": "mock-rc", "executable": None, "environment": {}}),
    )
    outcome = asyncio.run(ActivityExecutor(store).execute(activity))
    assert outcome.status == "failed"
    assert "timed out" in outcome.message


def test_render_detects_input_changed_after_planning(tmp_path):
    manifest_path = tmp_path / "simcairn.toml"
    deck = tmp_path / "deck.sp.tmpl"
    deck.write_text("R1 a b @{R}\nC1 b 0 @{C}\n", encoding="utf-8")
    manifest_path.write_text(
        """version=1
[simulator]
adapter="mock-rc"
[template]
deck="deck.sp.tmpl"
[sweep]
R=["1k"]
C=["1n"]
[run]
jobs=1
[[measure]]
name="cutoff_hz"
""",
        encoding="utf-8",
    )
    plan = compile_plan(load_manifest(manifest_path))
    deck.write_text("changed @{R} @{C}\n", encoding="utf-8")
    store = ArtifactStore(tmp_path / "store")
    outcome = asyncio.run(ActivityExecutor(store).execute(plan.activities[0]))
    assert outcome.status == "failed"
    assert "changed after planning" in outcome.message


def test_cli_validate_plan_run_status_collect_explain_and_resume(tmp_path, capsys):
    store = tmp_path / "cli store"
    assert main(["validate", str(EXAMPLE)]) == 0
    assert "valid manifest" in capsys.readouterr().out
    assert main(["plan", str(EXAMPLE)]) == 0
    plan_payload = json.loads(capsys.readouterr().out)
    assert len(plan_payload["activities"]) == 19

    assert main(["run", str(EXAMPLE), "--store", str(store), "--jobs", "2"]) == 0
    report = json.loads(capsys.readouterr().out)
    run_id = report["run_id"]
    assert report["status"] == "succeeded"
    assert main(["status", run_id, "--store", str(store)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "succeeded"

    output = tmp_path / "nested" / "results.json"
    assert main(["collect", run_id, "--store", str(store), "-o", str(output)]) == 0
    assert len(json.loads(output.read_text(encoding="utf-8"))) == 6
    activity_id = Runner(store).store.load_plan(run_id).activities[0].id
    assert main(["explain", activity_id, "--store", str(store)]) == 0
    assert json.loads(capsys.readouterr().out)["cached"] is True
    assert main(["resume", run_id, "--store", str(store)]) == 0
    assert json.loads(capsys.readouterr().out)["counts"] == {"cached": 19}


def test_cli_errors_are_status_two_and_cache_miss_is_one(tmp_path, capsys):
    assert main(["validate", str(tmp_path / "missing.toml")]) == 2
    assert "simcairn:" in capsys.readouterr().err
    assert main(["run", str(EXAMPLE), "--jobs", "0", "--store", str(tmp_path)]) == 2
    assert "positive" in capsys.readouterr().err
    assert main(["explain", "e" * 64, "--store", str(tmp_path / "store")]) == 1
    assert json.loads(capsys.readouterr().out)["cached"] is False


def test_cli_force_unlock_is_audited(tmp_path, capsys):
    runner = Runner(tmp_path / "store")
    plan = compile_plan(load_manifest(EXAMPLE))
    run_id, directory = runner.store.create_run(plan)
    (directory / "run.lock").write_text(
        canonical_json(
            {
                "schema_version": 1,
                "pid": 7,
                "host": "remote-host",
                "process_start": "remote-start",
                "nonce": "a" * 32,
            }
        ),
        encoding="utf-8",
    )
    assert main(["unlock", run_id, "--store", str(tmp_path / "store"), "--force"]) == 0
    assert json.loads(capsys.readouterr().out)["removed"] is True
    assert (directory / "unlock-audit.jsonl").is_file()


def test_subprocess_environment_is_allowlisted(monkeypatch):
    monkeypatch.setenv("SECRET_SHOULD_NOT_LEAK", "hidden")
    environment = ActivityExecutor._environment({"EXPLICIT": "visible"})
    assert environment["EXPLICIT"] == "visible"
    assert "SECRET_SHOULD_NOT_LEAK" not in environment
    assert environment["PYTHONIOENCODING"] == "utf-8"


class ExitAdapter:
    name = "exit"

    def command(self, sandbox, payload):
        del sandbox, payload
        return [sys.executable, "-c", "import sys; sys.stderr.write('bad deck'); sys.exit(7)"]

    def collect(self, sandbox, payload):
        del sandbox, payload


class RejectingAdapter:
    name = "reject"

    def command(self, sandbox, payload):
        del sandbox, payload
        return [sys.executable, "-c", "pass"]

    def collect(self, sandbox, payload):
        del sandbox, payload
        raise AdapterError("measurement output missing")


def _simulate_activity(identifier="c" * 64):
    return Activity(
        identifier,
        "simulate",
        None,
        (),
        (),
        ("stdout.log", "stderr.log"),
        (),
        5,
        canonical_json({"adapter": "mock-rc", "executable": None, "environment": {}}),
    )


@pytest.mark.parametrize(
    ("adapter", "message"),
    [(ExitAdapter(), "status 7: bad deck"), (RejectingAdapter(), "measurement output missing")],
)
def test_simulator_process_and_collection_failures_are_actionable(
    tmp_path, monkeypatch, adapter, message
):
    monkeypatch.setattr("simcairn.executor.create_adapter", lambda config: adapter)
    outcome = asyncio.run(
        ActivityExecutor(ArtifactStore(tmp_path / "store")).execute(_simulate_activity())
    )
    assert outcome.status == "failed"
    assert message in outcome.message


def test_cancelling_simulator_terminates_child_and_cleans_sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr("simcairn.executor.create_adapter", lambda config: SlowAdapter())
    store = ArtifactStore(tmp_path / "store")

    async def cancel_running_activity():
        task = asyncio.create_task(ActivityExecutor(store).execute(_simulate_activity()))
        await asyncio.sleep(0.1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel_running_activity())
    assert list(store.work_root.iterdir()) == []


def _extraction_activity(payload):
    return Activity(
        "d" * 64,
        "extract",
        None,
        (),
        (),
        ("extracted.json",),
        (),
        5,
        canonical_json(payload),
    )


@pytest.mark.parametrize(
    ("content", "measure", "message"),
    [
        ("not-json", {"name": "gain", "source": "metrics.json", "field": "gain"}, "cannot read"),
        ("[]", {"name": "gain", "source": "metrics.json", "field": "gain"}, "not a JSON object"),
        (
            '{"gain": true}',
            {"name": "gain", "source": "metrics.json", "field": "gain"},
            "non-finite",
        ),
        (
            '{"gain": 1}',
            {"name": "noise", "source": "metrics.json", "field": "noise"},
            "non-finite",
        ),
    ],
)
def test_extraction_rejects_malformed_or_invalid_measurements(tmp_path, content, measure, message):
    (tmp_path / "metrics.json").write_text(content, encoding="utf-8")
    activity = _extraction_activity({"measures": [measure], "point_index": 0, "point": {}})
    with pytest.raises(ExecutionError, match=message):
        ActivityExecutor._extract(activity, tmp_path)


def test_aggregate_rejects_malformed_dependency_output(tmp_path):
    dependency = "e" * 64
    path = tmp_path / "deps" / dependency
    path.mkdir(parents=True)
    (path / "extracted.json").write_text("not-json", encoding="utf-8")
    activity = Activity(
        "f" * 64,
        "aggregate",
        None,
        (dependency,),
        (),
        ("results.json", "results.csv"),
        (),
        5,
        canonical_json({}),
    )
    with pytest.raises(ExecutionError, match="cannot aggregate"):
        ActivityExecutor._aggregate(activity, tmp_path)


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ([], "not an object"),
        ({"point_index": True, "point": {}, "metrics": {}}, "point_index"),
        ({"point_index": 0, "point": [], "metrics": {}}, "point is not an object"),
        ({"point_index": 0, "point": {}, "metrics": []}, "metrics is not an object"),
    ],
)
def test_aggregate_validates_dependency_schema(tmp_path, value, message):
    dependency = "1" * 64
    path = tmp_path / "deps" / dependency
    path.mkdir(parents=True)
    (path / "extracted.json").write_text(json.dumps(value), encoding="utf-8")
    activity = Activity(
        "2" * 64,
        "aggregate",
        None,
        (dependency,),
        (),
        ("results.json", "results.csv"),
        (),
        5,
        canonical_json({}),
    )
    with pytest.raises(ExecutionError, match=message):
        ActivityExecutor._aggregate(activity, tmp_path)


def test_unknown_activity_kind_returns_failed_outcome(tmp_path):
    activity = replace(_simulate_activity(), kind="unknown")
    outcome = asyncio.run(ActivityExecutor(ArtifactStore(tmp_path / "store")).execute(activity))
    assert outcome.status == "failed"
    assert "unknown activity kind" in outcome.message


def test_impossible_resource_request_fails_without_deadlock(tmp_path):
    activity = replace(_simulate_activity(), resources=(("simulator", 2),))
    base = compile_plan(load_manifest(EXAMPLE))
    plan = replace(
        base,
        activities=(activity,),
        jobs=1,
        resource_limits=(("simulator", 1),),
    )
    store = ArtifactStore(tmp_path / "store")

    async def run_with_deadline():
        return await asyncio.wait_for(
            execute_plan(plan, store, _empty_run(store, plan), executor=RecordingExecutor()),
            timeout=10,
        )

    report = asyncio.run(run_with_deadline())
    assert report.counts == {"failed": 1}
    assert "exceeds available limit" in report.outcomes[0].message
