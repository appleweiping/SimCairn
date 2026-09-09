import asyncio
import json
import subprocess
import sys
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest

from simcairn import __version__
from simcairn import scheduler as scheduler_module
from simcairn.adapters import AdapterError
from simcairn.api import Runner
from simcairn.cli import main
from simcairn.coordination import StoreReadLease, StoreWriteLease
from simcairn.executor import ActivityExecutor, ExecutionError
from simcairn.journal import RunLock, run_lock_state
from simcairn.manifest import load_manifest
from simcairn.model import Activity, ActivityOutcome, canonical_json
from simcairn.planner import compile_plan
from simcairn.reference import verify_reference
from simcairn.scheduler import SchedulerError, execute_plan
from simcairn.store import ArtifactStore, StoreError

EXAMPLE = Path(__file__).parents[1] / "examples" / "rc_sweep" / "simcairn.toml"


def test_cli_version_uses_installed_distribution(capsys):
    with pytest.raises(SystemExit) as result:
        main(["--version"])
    assert result.value.code == 0
    assert capsys.readouterr().out.strip() == f"simcairn {__version__}"


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


def test_collect_strictly_rejects_ambiguous_results_json(tmp_path):
    runner = Runner(tmp_path / "store")
    plan = compile_plan(load_manifest(EXAMPLE))
    run_id, _directory = runner.store.create_run(plan)
    aggregate = plan.activities[-1]
    sandbox = tmp_path / "aggregate"
    sandbox.mkdir()
    (sandbox / "results.json").write_text('[{"R":"1k","R":"2k"}]\n', encoding="utf-8")
    (sandbox / "results.csv").write_text("R\n1k\n", encoding="utf-8")
    (sandbox / "regression-bundle.json").write_text("{}\n", encoding="utf-8")
    runner.store.publish(aggregate, sandbox)
    with pytest.raises(StoreError, match="duplicate"):
        runner.collect(run_id)


def test_collect_rejects_an_unpublished_aggregate_without_running_the_plan(tmp_path):
    runner = Runner(tmp_path / "store")
    plan = compile_plan(load_manifest(EXAMPLE))
    run_id, _directory = runner.store.create_run(plan)

    with pytest.raises(StoreError, match="aggregate result is unavailable"):
        runner.collect(run_id)


@pytest.mark.parametrize("payload", [{"not": "an array"}, [1]])
def test_collect_rejects_results_that_are_not_an_array_of_objects(tmp_path, monkeypatch, payload):
    runner = Runner(tmp_path / "store")
    plan = compile_plan(load_manifest(EXAMPLE))
    run_id, _directory = runner.store.create_run(plan)
    cache = tmp_path / "verified-cache"
    (cache / "files").mkdir(parents=True)
    (cache / "files" / "results.json").write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(ArtifactStore, "verify", lambda _store, _activity_id: (True, ""))
    monkeypatch.setattr(ArtifactStore, "cache_path", lambda _store, _activity_id: cache)

    with pytest.raises(StoreError, match="not an array of objects"):
        runner.collect(run_id)


def test_resume_reuses_verified_completed_artifacts(tmp_path):
    runner = Runner(tmp_path / "store")
    first = runner.run(load_manifest(EXAMPLE))
    resumed = runner.resume(first.run_id)
    assert resumed.run_id == first.run_id
    assert resumed.counts == {"cached": 19}
    status = runner.status(first.run_id)
    assert status["events"] > 20


def test_runner_releases_a_run_lock_when_the_store_barrier_exit_fails(tmp_path, monkeypatch):
    class FailingExitLease:
        def __init__(self, _root):
            pass

        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc_value, _traceback):
            raise RuntimeError("injected barrier exit failure")

    runner = Runner(tmp_path / "store")
    plan = compile_plan(load_manifest(EXAMPLE))
    monkeypatch.setattr("simcairn.api.StoreReadLease", FailingExitLease)

    with pytest.raises(RuntimeError, match="barrier exit failure"):
        runner.run(plan)
    run_id = next(runner.store.run_root.iterdir()).name
    assert run_lock_state(runner.store.run_directory(run_id)) is None

    with pytest.raises(RuntimeError, match="barrier exit failure"):
        runner.resume(run_id)
    assert run_lock_state(runner.store.run_directory(run_id)) is None


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


class BlockingExecutor:
    def __init__(self) -> None:
        self.started = 0
        self.cancelled = 0

    async def execute(self, activity: Activity) -> ActivityOutcome:
        self.started += 1
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled += 1
            raise
        return ActivityOutcome(activity.id, "succeeded", 0.0)


def test_scheduler_cancels_children_before_releasing_its_run_lock(tmp_path):
    plan = replace(compile_plan(load_manifest(EXAMPLE)), jobs=2)
    store = ArtifactStore(tmp_path / "cancel-store")
    run_id = _empty_run(store, plan)
    executor = BlockingExecutor()

    async def cancel_scheduler() -> None:
        task = asyncio.create_task(execute_plan(plan, store, run_id, executor=executor))
        while executor.started < 2:
            await asyncio.sleep(0)
        assert run_lock_state(store.run_directory(run_id)) == "alive"
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel_scheduler())
    assert executor.cancelled == 2
    assert run_lock_state(store.run_directory(run_id)) is None


def test_repeated_scheduler_cancellation_cannot_interrupt_child_cleanup(tmp_path):
    plan = replace(compile_plan(load_manifest(EXAMPLE)), jobs=1)
    store = ArtifactStore(tmp_path / "repeated-cancel-store")
    run_id = _empty_run(store, plan)
    cleaned = False

    async def exercise() -> None:
        nonlocal cleaned
        started = asyncio.Event()
        cleaning = asyncio.Event()
        finish_cleanup = asyncio.Event()

        class CleanupExecutor:
            async def execute(self, activity: Activity) -> ActivityOutcome:
                nonlocal cleaned
                started.set()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    cleaning.set()
                    await finish_cleanup.wait()
                    cleaned = True
                    raise
                return ActivityOutcome(activity.id, "succeeded", 0.0)

        scheduler = asyncio.create_task(
            execute_plan(plan, store, run_id, executor=CleanupExecutor())
        )
        await started.wait()
        scheduler.cancel()
        await cleaning.wait()
        scheduler.cancel()
        await asyncio.sleep(0)
        assert run_lock_state(store.run_directory(run_id)) == "alive"
        finish_cleanup.set()
        with pytest.raises(asyncio.CancelledError):
            await scheduler

    asyncio.run(exercise())
    assert cleaned is True
    assert run_lock_state(store.run_directory(run_id)) is None


def test_scheduler_releases_an_owned_lock_when_initialization_raises(tmp_path, monkeypatch):
    plan = compile_plan(load_manifest(EXAMPLE))
    store = ArtifactStore(tmp_path / "init-failure-store")
    run_id = _empty_run(store, plan)

    def fail_executor(_store):
        raise RuntimeError("injected initialization failure")

    monkeypatch.setattr("simcairn.scheduler.ActivityExecutor", fail_executor)
    with pytest.raises(RuntimeError, match="initialization failure"):
        asyncio.run(execute_plan(plan, store, run_id))
    assert run_lock_state(store.run_directory(run_id)) is None


def test_scheduler_releases_a_lock_when_the_store_barrier_exit_fails(tmp_path, monkeypatch):
    class FailingExitLease:
        def __init__(self, _root):
            pass

        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc_value, _traceback):
            raise RuntimeError("injected barrier exit failure")

    plan = compile_plan(load_manifest(EXAMPLE))
    store = ArtifactStore(tmp_path / "store")
    run_id = _empty_run(store, plan)
    monkeypatch.setattr(scheduler_module, "StoreReadLease", FailingExitLease)

    with pytest.raises(RuntimeError, match="barrier exit failure"):
        asyncio.run(execute_plan(plan, store, run_id, executor=RecordingExecutor()))
    assert run_lock_state(store.run_directory(run_id)) is None


def test_cancellation_wins_when_background_lock_acquisition_fails(tmp_path, monkeypatch):
    store = ArtifactStore(tmp_path / "store")
    started = threading.Event()
    release = threading.Event()

    def fail_after_cancellation(_store, _run_id):
        started.set()
        assert release.wait(timeout=5)
        raise SchedulerError("injected acquisition failure")

    monkeypatch.setattr(scheduler_module, "_acquire_run_lock", fail_after_cancellation)

    async def cancel_worker():
        task = asyncio.create_task(scheduler_module._acquire_run_lock_async(store, "run"))
        while not started.is_set():
            await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(cancel_worker())


def test_event_loop_shutdown_drains_lock_acquisition_worker():
    script = """
import asyncio
import threading
from pathlib import Path

from simcairn import scheduler

started = threading.Event()
finish = threading.Event()
released = []


class AcquiredLock:
    def __exit__(self, _exc_type, _exc_value, _traceback):
        released.append(True)


def acquire_after_shutdown_starts(_store, _run_id):
    started.set()
    if not finish.wait(timeout=5):
        raise AssertionError("acquisition worker was not released")
    return Path("run"), AcquiredLock()


async def leave_acquisition_pending():
    scheduler._acquire_run_lock = acquire_after_shutdown_starts
    asyncio.create_task(scheduler._acquire_run_lock_async(object(), "run"))
    while not started.is_set():
        await asyncio.sleep(0)
    threading.Timer(0.05, finish.set).start()


asyncio.run(leave_acquisition_pending())
if released != [True]:
    raise AssertionError(f"acquired lock was not released exactly once: {released!r}")
"""

    try:
        completed = subprocess.run(
            [sys.executable, "-c", script],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("event-loop shutdown abandoned the acquisition worker")
    assert completed.returncode == 0, completed.stderr


def test_cancelled_acquisition_worker_is_not_reawaited(tmp_path, monkeypatch):
    store = ArtifactStore(tmp_path / "store")
    release = threading.Event()
    shield_calls = 0
    original_shield = asyncio.shield

    def cancel_acquisition(_store, _run_id):
        assert release.wait(timeout=2)
        raise asyncio.CancelledError

    def bounded_shield(awaitable):
        nonlocal shield_calls
        shield_calls += 1
        if shield_calls > 1:
            raise AssertionError("a completed acquisition worker was awaited again")
        release.set()
        return original_shield(awaitable)

    monkeypatch.setattr(scheduler_module, "_acquire_run_lock", cancel_acquisition)
    monkeypatch.setattr(scheduler_module.asyncio, "shield", bounded_shield)

    async def observe_worker_cancellation():
        with pytest.raises(asyncio.CancelledError):
            await scheduler_module._acquire_run_lock_async(store, "run")

    asyncio.run(observe_worker_cancellation())
    assert shield_calls == 1


def test_undefined_resource_failure_reaches_an_async_activity_callback(tmp_path):
    base = compile_plan(load_manifest(EXAMPLE))
    activity = replace(base.activities[0], resources=(("license-seat", 1),))
    plan = replace(base, activities=(activity,))
    store = ArtifactStore(tmp_path / "store")
    run_id = _empty_run(store, plan)
    observed = []

    async def observe(outcome):
        await asyncio.sleep(0)
        observed.append(outcome)

    report = asyncio.run(
        execute_plan(
            plan,
            store,
            run_id,
            executor=RecordingExecutor(),
            on_activity=observe,
        )
    )

    assert report.counts == {"failed": 1}
    assert "undefined resource 'license-seat'" in report.outcomes[0].message
    assert observed == [report.outcomes[0]]


def test_scheduler_rejects_a_cycle_and_releases_its_lock(tmp_path):
    base = compile_plan(load_manifest(EXAMPLE))
    activity = replace(base.activities[0], dependencies=(base.activities[0].id,))
    plan = replace(base, activities=(activity,))
    store = ArtifactStore(tmp_path / "store")
    run_id = _empty_run(store, plan)

    with pytest.raises(SchedulerError, match="cyclic or has an unknown dependency"):
        asyncio.run(execute_plan(plan, store, run_id, executor=RecordingExecutor()))
    assert run_lock_state(store.run_directory(run_id)) is None


def test_scheduler_rejects_a_supplied_lock_for_another_run(tmp_path):
    plan = compile_plan(load_manifest(EXAMPLE))
    store = ArtifactStore(tmp_path / "wrong-lock-store")
    target = _empty_run(store, plan)
    _other_id, other_directory = store.create_run(plan)
    wrong_lock = RunLock(other_directory)
    wrong_lock.__enter__()
    try:
        with pytest.raises(SchedulerError, match="not acquired for this run"):
            asyncio.run(execute_plan(plan, store, target, run_lock=wrong_lock))
        assert run_lock_state(other_directory) == "alive"
    finally:
        wrong_lock.__exit__(None, None, None)


def test_store_coordination_wait_does_not_block_the_async_event_loop(tmp_path):
    plan = replace(compile_plan(load_manifest(EXAMPLE)), jobs=1)
    store = ArtifactStore(tmp_path / "responsive-store")
    run_id = _empty_run(store, plan)
    writer = StoreWriteLease(store.root)
    writer.__enter__()

    async def run_while_writer_finishes() -> int:
        ticks = 0
        task = asyncio.create_task(execute_plan(plan, store, run_id, executor=RecordingExecutor()))
        for _ in range(5):
            await asyncio.sleep(0.02)
            ticks += 1
        assert not task.done()
        writer.__exit__(None, None, None)
        await task
        return ticks

    try:
        assert asyncio.run(run_while_writer_finishes()) == 5
    finally:
        writer.__exit__(None, None, None)


def test_repeated_cancellation_while_waiting_cannot_abandon_a_run_lock(tmp_path):
    plan = compile_plan(load_manifest(EXAMPLE))
    store = ArtifactStore(tmp_path / "cancelled-acquisition-store")
    run_id = _empty_run(store, plan)
    writer = StoreWriteLease(store.root)
    writer.__enter__()

    async def cancel_waiter() -> None:
        task = asyncio.create_task(execute_plan(plan, store, run_id, executor=RecordingExecutor()))
        await asyncio.sleep(0.05)
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        writer.__exit__(None, None, None)
        with pytest.raises(asyncio.CancelledError):
            await task

    try:
        asyncio.run(cancel_waiter())
    finally:
        writer.__exit__(None, None, None)
    assert run_lock_state(store.run_directory(run_id)) is None


def test_writer_release_retries_transient_windows_style_sharing_violation(tmp_path, monkeypatch):
    store = ArtifactStore(tmp_path / "sharing-store")
    writer = StoreWriteLease(store.root)
    writer.__enter__()
    original_unlink = Path.unlink
    blocked = False

    def busy_once(path, *args, **kwargs):
        nonlocal blocked
        if not blocked and path.name.startswith("owner-"):
            blocked = True
            raise PermissionError("injected sharing violation")
        return original_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", busy_once)
    writer.__exit__(None, None, None)
    assert blocked
    assert not (store.root / ".locks" / "gc" / "run.lock").exists()


def test_run_lock_release_retries_busy_empty_directory_and_allows_reacquire(tmp_path, monkeypatch):
    run = tmp_path / "run"
    run.mkdir()
    lock = RunLock(run)
    lock.__enter__()
    original_rmdir = Path.rmdir
    blocked = False

    def busy_once(path, *args, **kwargs):
        nonlocal blocked
        if not blocked and path == run / "run.lock":
            blocked = True
            raise PermissionError("injected directory sharing violation")
        return original_rmdir(path, *args, **kwargs)

    monkeypatch.setattr(Path, "rmdir", busy_once)
    lock.__exit__(None, None, None)
    assert blocked
    assert not (run / "run.lock").exists()
    with RunLock(run):
        assert (run / "run.lock").is_dir()


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


class FloodAdapter:
    name = "flood"

    def command(self, sandbox, payload):
        del sandbox, payload
        return [
            sys.executable,
            "-c",
            "import sys;sys.stdout.buffer.write(bytes([120])*(8*1024*1024+1))",
        ]

    def collect(self, sandbox, payload):
        del sandbox, payload
        raise AdapterError("unreachable")


class DescendantAdapter:
    name = "descendant"

    def __init__(self, sentinel, started):
        self.sentinel = sentinel
        self.started = started

    def command(self, sandbox, payload):
        del sandbox, payload
        child = "".join(
            (
                "import pathlib,sys,time;time.sleep(6);",
                "pathlib.Path(sys.argv[1]).write_text('orphan')",
            )
        )
        parent = (
            "import pathlib,subprocess,sys,time;"
            f"subprocess.Popen([sys.executable,'-c',{child!r},sys.argv[1]],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
            "pathlib.Path(sys.argv[2]).write_text('started');time.sleep(30)"
        )
        return [sys.executable, "-c", parent, str(self.sentinel), str(self.started)]

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


def test_generic_simulator_stdout_is_bounded_during_capture(tmp_path, monkeypatch):
    monkeypatch.setattr("simcairn.executor.create_adapter", lambda config: FloodAdapter())
    outcome = asyncio.run(
        ActivityExecutor(ArtifactStore(tmp_path / "store")).execute(_simulate_activity())
    )
    assert outcome.status == "failed"
    assert "stdout exceeded 8388608 bytes" in outcome.message


def test_generic_simulator_timeout_terminates_descendants(tmp_path, monkeypatch):
    sentinel = tmp_path / "orphan.txt"
    started = tmp_path / "started.txt"
    monkeypatch.setattr(
        "simcairn.executor.create_adapter", lambda config: DescendantAdapter(sentinel, started)
    )
    activity = replace(_simulate_activity(), timeout_seconds=5)
    outcome = asyncio.run(ActivityExecutor(ArtifactStore(tmp_path / "store")).execute(activity))
    assert outcome.status == "failed"
    assert "timed out" in outcome.message
    assert started.exists()
    time.sleep(2)
    assert not sentinel.exists()


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


def test_offline_pvt_workflow_emits_strict_regression_bundle(tmp_path):
    manifest = load_manifest(EXAMPLE.parent.parent / "rc_pvt" / "offline-mock.toml")
    store = ArtifactStore(tmp_path / "pvt-store")
    report = Runner(store.root).run(manifest)
    assert report.status == "succeeded", report.as_dict()
    plan = store.load_plan(report.run_id)
    aggregate = plan.activities[-1]
    path = store.cache_path(aggregate.id) / "files" / "regression-bundle.json"
    bundle = json.loads(path.read_text(encoding="utf-8"))
    assert bundle["schema_version"] == 2
    assert bundle["run"]["contract"] == "regressistor.measurement-bundle/2"
    assert len(bundle["points"]) == 32
    assert set(bundle["points"][0]) == {"case", "sample", "metrics"}
    assert bundle["points"][0]["metrics"]["cutoff_hz"]["unit"] == "Hz"
    golden = EXAMPLE.parent.parent / "rc_pvt" / "offline-golden.json"
    verify_reference(path, golden, expected_activity_id=aggregate.id)


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


def test_cli_unlock_respects_collection_and_reports_contention(tmp_path, capsys, monkeypatch):
    runner = Runner(tmp_path / "coordinated-unlock")
    plan = compile_plan(load_manifest(EXAMPLE))
    run_id, directory = runner.store.create_run(plan)
    lock = RunLock(directory)
    lock.__enter__()
    writer = StoreWriteLease(runner.store.root)
    writer.__enter__()
    monkeypatch.setattr(
        "simcairn.cli.StoreReadLease",
        lambda root: StoreReadLease(root, timeout_seconds=0),
    )
    try:
        assert main(["unlock", run_id, "--store", str(runner.store.root), "--force"]) == 2
        assert "collection is still in progress" in capsys.readouterr().err
        assert run_lock_state(directory) == "alive"
    finally:
        writer.__exit__(None, None, None)

    assert main(["unlock", run_id, "--store", str(runner.store.root), "--force"]) == 0
    assert json.loads(capsys.readouterr().out)["removed"] is True
    lock.__exit__(None, None, None)


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
            '{"gain": 1, "gain": 2}',
            {"name": "gain", "source": "metrics.json", "field": "gain"},
            "duplicate",
        ),
        (
            '{"gain": NaN}',
            {"name": "gain", "source": "metrics.json", "field": "gain"},
            "non-finite JSON",
        ),
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
        canonical_json(
            {
                "measures": [
                    {
                        "name": "cutoff_hz",
                        "source": "metrics.json",
                        "field": "cutoff_hz",
                        "unit": "Hz",
                    }
                ]
            }
        ),
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
        (
            {"point_index": 0, "point": {}, "metrics": {"unexpected": 1.0}},
            "finite measures",
        ),
        (
            {"point_index": 0, "point": {}, "metrics": {"cutoff_hz": float("nan")}},
            "non-finite JSON",
        ),
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
        canonical_json(
            {
                "measures": [
                    {
                        "name": "cutoff_hz",
                        "source": "metrics.json",
                        "field": "cutoff_hz",
                        "unit": "Hz",
                    }
                ]
            }
        ),
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
