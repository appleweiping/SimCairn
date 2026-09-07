"""Surveying, verifying, and reclaiming the store without losing anything."""

from __future__ import annotations

import json
import os
import shutil
import socket
from pathlib import Path

import pytest

from simcairn import maintenance as maintenance_module
from simcairn.api import Runner, compile_plan, load_manifest
from simcairn.cli import main
from simcairn.coordination import StoreReadLease, StoreWriteLease
from simcairn.fingerprints import canonical_json
from simcairn.journal import run_lock_state
from simcairn.maintenance import (
    DEFAULT_KEEP_RUNS,
    CollectionPlan,
    apply_collection,
    directory_bytes,
    plan_collection,
    survey,
    verify_all,
)
from simcairn.store import ArtifactStore, StoreError

EXAMPLES = Path(__file__).parents[1] / "examples"
MANIFEST = EXAMPLES / "rc_pvt" / "offline-mock.toml"


@pytest.fixture(scope="module")
def finished_store(tmp_path_factory) -> ArtifactStore:
    """One completed run, reused by every test that only reads the store."""

    root = tmp_path_factory.mktemp("cairn") / "store"
    store = ArtifactStore(root)
    report = Runner(store.root).run(load_manifest(MANIFEST))
    assert report.status == "succeeded"
    return store


def write_lock(store: ArtifactStore, run_id: str, owner: dict[str, object]) -> Path:
    path = store.run_root / run_id / "run.lock"
    path.write_bytes(canonical_json(owner).encode("utf-8"))
    return path


def owner(**changes: object) -> dict[str, object]:
    base: dict[str, object] = {
        "schema_version": 1,
        "pid": os.getpid(),
        "host": socket.gethostname(),
        "process_start": "unknown",
        "nonce": "0" * 32,
    }
    base.update(changes)
    return base


# ---------------------------------------------------------------------------
# Reading a lock without changing it.
# ---------------------------------------------------------------------------


def test_an_unlocked_run_reports_no_lock(finished_store: ArtifactStore) -> None:
    run_id = sorted(path.name for path in finished_store.run_root.iterdir())[0]
    assert run_lock_state(finished_store.run_root / run_id) is None


def test_inspecting_a_lock_leaves_it_in_place(finished_store: ArtifactStore, tmp_path) -> None:
    """The reason this exists separately from `clear_run_lock`.

    Deciding whether a run is busy must not be the same act as ending it.
    """

    store = ArtifactStore(tmp_path / "peek")
    directory = store.run_root / "r-0001"
    directory.mkdir(parents=True)
    path = write_lock(store, "r-0001", owner())
    assert run_lock_state(directory) is not None
    assert path.exists()
    assert run_lock_state(directory) is not None


def test_a_lock_from_another_host_is_not_called_stale(tmp_path) -> None:
    store = ArtifactStore(tmp_path / "foreign")
    directory = store.run_root / "r-0001"
    directory.mkdir(parents=True)
    write_lock(store, "r-0001", owner(host="somewhere-else"))
    assert run_lock_state(directory) == "foreign"


def test_an_unreadable_lock_is_called_unknown_not_stale(tmp_path) -> None:
    store = ArtifactStore(tmp_path / "garbled")
    directory = store.run_root / "r-0001"
    directory.mkdir(parents=True)
    (directory / "run.lock").write_bytes(b"not json at all")
    assert run_lock_state(directory) == "unknown"


# ---------------------------------------------------------------------------
# Surveying.
# ---------------------------------------------------------------------------


def test_a_survey_accounts_for_every_area(finished_store: ArtifactStore) -> None:
    found = survey(finished_store)
    assert found.entries
    assert found.runs
    assert found.cache_size > 0
    assert found.total_size == found.cache_size + found.run_size + found.work_size


def test_a_survey_changes_nothing(finished_store: ArtifactStore) -> None:
    before = {path.name for path in finished_store.cache_root.iterdir()}
    survey(finished_store)
    assert {path.name for path in finished_store.cache_root.iterdir()} == before


def test_every_published_entry_is_reachable_from_its_run(
    finished_store: ArtifactStore,
) -> None:
    found = survey(finished_store)
    assert not found.orphaned
    assert not found.unreadable


def test_a_survey_serializes_its_totals(finished_store: ArtifactStore) -> None:
    payload = survey(finished_store).as_dict()
    assert payload["cache"]["entries"] > 0
    assert payload["total_size"] > 0
    json.dumps(payload, allow_nan=False)


def test_directory_size_ignores_links_rather_than_following_them(tmp_path) -> None:
    # A link out of the store must not inflate the total, or be walked into.
    target = tmp_path / "outside"
    target.mkdir()
    (target / "big").write_bytes(b"x" * 5000)
    inside = tmp_path / "inside"
    inside.mkdir()
    (inside / "small").write_bytes(b"y" * 10)
    try:
        (inside / "link").symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are not available here")
    assert directory_bytes(inside) == 10


# ---------------------------------------------------------------------------
# Verifying.
# ---------------------------------------------------------------------------


def test_a_healthy_store_verifies_clean(finished_store: ArtifactStore) -> None:
    assert verify_all(finished_store) == ()


def test_a_corrupted_artifact_is_found(tmp_path) -> None:
    """Bit rot in a cached artifact is otherwise noticed only by reusing it."""

    store = ArtifactStore(tmp_path / "rot")
    Runner(store.root).run(load_manifest(MANIFEST))
    entry = sorted(store.cache_root.iterdir())[0]
    target = next(path for path in (entry / "files").rglob("*") if path.is_file())
    target.write_bytes(target.read_bytes() + b"corrupted")
    broken = verify_all(store)
    assert len(broken) == 1
    assert broken[0].activity_id == entry.name
    assert broken[0].reason


def test_a_crashed_publish_directory_is_reported_and_can_be_explicitly_removed(tmp_path) -> None:
    store = ArtifactStore(tmp_path / "crashed-publish")
    leftover = store.cache_root / ".publish-leftover"
    leftover.mkdir()
    (leftover / "partial").write_text("incomplete", encoding="utf-8")

    found = survey(store)
    assert len(found.unreadable) == 1
    assert found.unreadable[0].activity_id == leftover.name
    plan = plan_collection(store, keep_runs=0, include_unreadable=True)
    assert plan.entries == (leftover.name,)

    report = apply_collection(store, plan)
    assert report.removed_entries == (leftover.name,)
    assert report.failures == ()
    assert not leftover.exists()


# ---------------------------------------------------------------------------
# Planning a collection.
# ---------------------------------------------------------------------------


def test_planning_removes_nothing(finished_store: ArtifactStore) -> None:
    before = {path.name for path in finished_store.cache_root.iterdir()}
    plan_collection(finished_store, keep_runs=0)
    assert {path.name for path in finished_store.cache_root.iterdir()} == before


def test_a_recent_run_and_its_entries_are_kept(finished_store: ArtifactStore) -> None:
    plan = plan_collection(finished_store, keep_runs=DEFAULT_KEEP_RUNS)
    assert plan.runs == ()
    assert plan.entries == ()
    assert plan.empty


def test_dropping_the_last_run_makes_its_entries_collectable(
    finished_store: ArtifactStore,
) -> None:
    plan = plan_collection(finished_store, keep_runs=0)
    assert plan.runs
    assert plan.entries
    assert plan.freed > 0


def test_a_locked_run_is_kept_whatever_its_age(tmp_path) -> None:
    """A run that may still be writing is not old, it is busy."""

    store = ArtifactStore(tmp_path / "busy")
    report = Runner(store.root).run(load_manifest(MANIFEST))
    write_lock(store, report.run_id, owner(host="somewhere-else"))
    plan = plan_collection(store, keep_runs=0)
    assert plan.runs == ()
    assert plan.entries == ()
    assert report.run_id in plan.protected_runs


def test_a_stale_lock_does_not_protect_a_run(tmp_path) -> None:
    store = ArtifactStore(tmp_path / "stale")
    report = Runner(store.root).run(load_manifest(MANIFEST))
    write_lock(store, report.run_id, owner(pid=2**30, process_start="1"))
    plan = plan_collection(store, keep_runs=0)
    assert run_lock_state(store.run_root / report.run_id) == "stale"
    assert plan.runs == (report.run_id,)


def test_work_sandboxes_are_kept_while_any_run_is_locked(tmp_path) -> None:
    # A sandbox does not record which run owns it, so a live run anywhere means
    # none of them can be attributed and none can be removed.
    store = ArtifactStore(tmp_path / "sandbox")
    report = Runner(store.root).run(load_manifest(MANIFEST))
    (store.work_root / "leftover").mkdir()
    write_lock(store, report.run_id, owner(host="elsewhere"))
    plan = plan_collection(store, keep_runs=0)
    assert plan.sandboxes == ()
    assert any("live lock" in note for note in plan.notes)


def test_a_leftover_sandbox_is_collectable_once_nothing_is_locked(tmp_path) -> None:
    store = ArtifactStore(tmp_path / "swept")
    Runner(store.root).run(load_manifest(MANIFEST))
    (store.work_root / "leftover").mkdir()
    (store.work_root / "leftover" / "f").write_bytes(b"z" * 100)
    plan = plan_collection(store, keep_runs=0)
    assert plan.sandboxes == ("leftover",)


def test_work_can_be_left_alone_on_request(tmp_path) -> None:
    store = ArtifactStore(tmp_path / "keepwork")
    Runner(store.root).run(load_manifest(MANIFEST))
    (store.work_root / "leftover").mkdir()
    assert plan_collection(store, keep_runs=0, include_work=False).sandboxes == ()


def test_an_unreadable_entry_is_kept_as_evidence(tmp_path) -> None:
    """Deleting evidence of a failure to reclaim a few megabytes is a bad trade."""

    store = ArtifactStore(tmp_path / "evidence")
    Runner(store.root).run(load_manifest(MANIFEST))
    entry = sorted(store.cache_root.iterdir())[0]
    (entry / "manifest.json").write_text("{}", encoding="utf-8")
    plan = plan_collection(store, keep_runs=0)
    assert entry.name in plan.kept_unreadable
    assert entry.name not in plan.entries
    assert any("evidence" in note for note in plan.notes)


def test_an_unreadable_entry_can_be_removed_when_asked(tmp_path) -> None:
    store = ArtifactStore(tmp_path / "sweepbad")
    Runner(store.root).run(load_manifest(MANIFEST))
    entry = sorted(store.cache_root.iterdir())[0]
    (entry / "manifest.json").write_text("{}", encoding="utf-8")
    plan = plan_collection(store, keep_runs=0, include_unreadable=True)
    assert entry.name in plan.entries
    assert plan.kept_unreadable == ()


def test_a_run_with_an_unreadable_plan_is_kept_so_nothing_looks_orphaned(
    tmp_path,
) -> None:
    """Its activity references are unknown, so removing it would strand entries."""

    store = ArtifactStore(tmp_path / "badplan")
    report = Runner(store.root).run(load_manifest(MANIFEST))
    (store.run_root / report.run_id / "plan.json").write_text("{}", encoding="utf-8")
    plan = plan_collection(store, keep_runs=0)
    assert plan.runs == ()
    # Keeping the run is not enough: its activity list came back empty because
    # the plan would not parse, and believing that emptiness would orphan the
    # whole cache.
    assert plan.entries == ()
    assert plan.freed == 0
    assert any("unreadable plan" in note for note in plan.notes)
    assert any("cannot be determined" in note for note in plan.notes)


@pytest.mark.parametrize("keep", [-1, 1.5, True, "2"])
def test_a_bad_retention_count_is_refused(finished_store: ArtifactStore, keep: object) -> None:
    with pytest.raises(ValueError, match="non-negative integer"):
        plan_collection(finished_store, keep_runs=keep)  # type: ignore[arg-type]


def test_a_plan_serializes_what_it_would_do(finished_store: ArtifactStore) -> None:
    payload = plan_collection(finished_store, keep_runs=0).as_dict()
    assert payload["entries"]
    assert payload["freed"] > 0
    json.dumps(payload, allow_nan=False)


# ---------------------------------------------------------------------------
# Applying one.
# ---------------------------------------------------------------------------


def test_applying_a_plan_removes_exactly_what_it_named(tmp_path) -> None:
    store = ArtifactStore(tmp_path / "apply")
    Runner(store.root).run(load_manifest(MANIFEST))
    plan = plan_collection(store, keep_runs=0)
    report = apply_collection(store, plan)
    assert set(report.removed_entries) == set(plan.entries)
    assert set(report.removed_runs) == set(plan.runs)
    assert report.failures == ()
    assert report.freed > 0
    assert not list(store.cache_root.iterdir())


def test_an_empty_plan_removes_nothing(finished_store: ArtifactStore) -> None:
    plan = plan_collection(finished_store, keep_runs=DEFAULT_KEEP_RUNS)
    report = apply_collection(finished_store, plan)
    assert report.removed_entries == ()
    assert report.removed_runs == ()
    assert report.freed == 0


def test_a_run_locked_after_the_plan_was_made_is_skipped(tmp_path) -> None:
    """The plan may be older than the situation, so it is re-checked."""

    store = ArtifactStore(tmp_path / "raced")
    report = Runner(store.root).run(load_manifest(MANIFEST))
    plan = plan_collection(store, keep_runs=0)
    assert report.run_id in plan.runs
    write_lock(store, report.run_id, owner(host="elsewhere"))
    result = apply_collection(store, plan)
    assert report.run_id not in result.removed_runs
    assert any("acquired a lock" in reason for _path, reason in result.failures)
    assert (store.run_root / report.run_id).is_dir()


def test_a_missing_entry_is_not_a_failure(tmp_path) -> None:
    # Two collections in a row must not report the second as broken.
    store = ArtifactStore(tmp_path / "twice")
    Runner(store.root).run(load_manifest(MANIFEST))
    plan = plan_collection(store, keep_runs=0)
    apply_collection(store, plan)
    again = apply_collection(store, plan)
    assert again.failures == ()
    assert again.removed_entries == ()


def test_a_run_created_after_planning_keeps_the_entries_it_references(tmp_path) -> None:
    store = ArtifactStore(tmp_path / "new-run")
    manifest = load_manifest(MANIFEST)
    Runner(store.root).run(manifest)
    plan = plan_collection(store, keep_runs=0)

    new_run_id, _ = store.create_run(compile_plan(manifest))
    result = apply_collection(store, plan)

    assert (store.run_root / new_run_id).is_dir()
    assert result.removed_entries == ()
    assert any("became referenced" in reason for _path, reason in result.failures)
    assert list(store.cache_root.iterdir())


def test_a_recreated_run_cannot_reuse_the_generation_named_by_an_old_plan(
    tmp_path, monkeypatch
) -> None:
    store = ArtifactStore(tmp_path / "run-generation")
    manifest = load_manifest(MANIFEST)
    prefix = compile_plan(manifest).id[:12]
    values = iter((f"{prefix}-{'a' * 32}", f"{prefix}-{'b' * 32}"))
    monkeypatch.setattr(ArtifactStore, "new_run_id", lambda _self, _plan_id: next(values))
    first = Runner(store.root).run(manifest)
    plan = plan_collection(store, keep_runs=0)
    shutil.rmtree(store.run_root / first.run_id)

    second_run_id, _ = store.create_run(compile_plan(manifest))
    result = apply_collection(store, plan)

    assert second_run_id != first.run_id
    assert (store.run_root / second_run_id).is_dir()
    assert result.removed_runs == ()
    assert result.removed_entries == ()
    assert any("became referenced" in reason for _path, reason in result.failures)


def test_a_run_locked_after_planning_keeps_its_entries_and_work(tmp_path) -> None:
    store = ArtifactStore(tmp_path / "late-lock")
    report = Runner(store.root).run(load_manifest(MANIFEST))
    sandbox = store.work_root / "still-in-use"
    sandbox.mkdir()
    plan = plan_collection(store, keep_runs=0)
    assert sandbox.name in plan.sandboxes

    write_lock(store, report.run_id, owner(host="elsewhere"))
    result = apply_collection(store, plan)

    assert (store.run_root / report.run_id).is_dir()
    assert list(store.cache_root.iterdir())
    assert sandbox.is_dir()
    reasons = [reason for _path, reason in result.failures]
    assert any("acquired a lock" in reason for reason in reasons)
    assert any("referenced" in reason for reason in reasons)
    assert any("live lock" in reason for reason in reasons)


def test_a_failed_run_removal_keeps_the_entries_it_references(tmp_path, monkeypatch) -> None:
    store = ArtifactStore(tmp_path / "failed-removal")
    report = Runner(store.root).run(load_manifest(MANIFEST))
    plan = plan_collection(store, keep_runs=0)
    run_directory = store.run_root / report.run_id
    real_rmtree = shutil.rmtree

    def fail_for_run(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if Path(path) == run_directory:
            raise OSError("injected run removal failure")
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr("simcairn.maintenance.shutil.rmtree", fail_for_run)
    result = apply_collection(store, plan)

    assert run_directory.is_dir()
    assert list(store.cache_root.iterdir())
    assert result.removed_entries == ()
    assert any("injected run removal failure" in reason for _path, reason in result.failures)
    assert any("became referenced" in reason for _path, reason in result.failures)


def test_an_unsafe_run_name_is_refused(tmp_path) -> None:
    from simcairn.maintenance import CollectionPlan

    store = ArtifactStore(tmp_path / "unsafe-run")
    outside = store.root / "outside"
    outside.mkdir()
    (outside / "sentinel").write_text("keep me", encoding="utf-8")

    report = apply_collection(store, CollectionPlan(runs=("../outside",)))

    assert outside.is_dir()
    assert (outside / "sentinel").read_text(encoding="utf-8") == "keep me"
    assert report.removed_runs == ()
    assert any("unsafe run name" in reason for _path, reason in report.failures)


def test_an_unsafe_cache_entry_name_is_refused(tmp_path) -> None:
    from simcairn.maintenance import CollectionPlan

    store = ArtifactStore(tmp_path / "unsafe-entry")
    outside = store.root / "outside"
    outside.mkdir()
    (outside / "sentinel").write_text("keep me", encoding="utf-8")

    report = apply_collection(store, CollectionPlan(entries=("../outside",)))

    assert outside.is_dir()
    assert report.removed_entries == ()
    assert any("unsafe cache-entry name" in reason for _path, reason in report.failures)


def test_a_redirected_cache_root_is_refused_before_deletion(tmp_path) -> None:
    from simcairn.maintenance import CollectionPlan

    store = ArtifactStore(tmp_path / "redirected-store")
    outside = tmp_path / "outside-cache"
    victim = outside / ("a" * 64)
    victim.mkdir(parents=True)
    sentinel = victim / "sentinel"
    sentinel.write_text("keep me", encoding="utf-8")
    store.cache_root.rmdir()
    try:
        store.cache_root.symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlinks are unavailable: {error}")

    report = apply_collection(store, CollectionPlan(entries=("a" * 64,)))

    assert report.removed_entries == ()
    assert any("redirected cache" in reason for _path, reason in report.failures)
    assert sentinel.read_text(encoding="utf-8") == "keep me"


def test_an_unsafe_sandbox_name_is_refused(tmp_path) -> None:
    from simcairn.maintenance import CollectionPlan

    store = ArtifactStore(tmp_path / "unsafe")
    report = apply_collection(store, CollectionPlan(sandboxes=("../escape",)))
    assert report.removed_sandboxes == ()
    assert report.failures


def test_a_report_serializes_its_failures(tmp_path) -> None:
    from simcairn.maintenance import CollectionPlan

    store = ArtifactStore(tmp_path / "report")
    payload = apply_collection(store, CollectionPlan(sandboxes=("../escape",))).as_dict()
    assert payload["failures"]
    json.dumps(payload, allow_nan=False)


# ---------------------------------------------------------------------------
# Filesystem failures and command-line reporting.
# ---------------------------------------------------------------------------


def test_directory_size_tolerates_a_file_disappearing_during_stat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = tmp_path / "changing"
    directory.mkdir()
    file = directory / "artifact"
    file.write_bytes(b"payload")
    original_is_file = Path.is_file
    original_is_symlink = Path.is_symlink
    original_stat = Path.stat

    def report_file(path: Path) -> bool:
        return True if path == file else original_is_file(path)

    def report_not_symlink(path: Path) -> bool:
        return False if path == file else original_is_symlink(path)

    def fail_late_stat(path: Path, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        if path == file:
            raise FileNotFoundError(path)
        return original_stat(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "is_file", report_file)
    monkeypatch.setattr(Path, "is_symlink", report_not_symlink)
    monkeypatch.setattr(Path, "stat", fail_late_stat)
    assert directory_bytes(directory) == 0


def test_survey_ignores_stray_files_and_tolerates_entry_metadata_races(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ArtifactStore(tmp_path / "store")
    (store.cache_root / "stray-file").write_text("ignore", encoding="utf-8")
    entry = store.cache_root / ("a" * 64)
    entry.mkdir()
    original_is_dir = Path.is_dir
    original_is_symlink = Path.is_symlink
    original_stat = Path.stat

    def preserve_entry_directory(path: Path) -> bool:
        return True if path == entry else original_is_dir(path)

    def report_entry_not_symlink(path: Path) -> bool:
        return False if path == entry else original_is_symlink(path)

    def fail_entry_stat(path: Path, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        if path == entry:
            raise FileNotFoundError(path)
        return original_stat(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "is_dir", preserve_entry_directory)
    monkeypatch.setattr(Path, "is_symlink", report_entry_not_symlink)
    monkeypatch.setattr(Path, "stat", fail_entry_stat)
    found = survey(store)

    assert len(found.entries) == 1
    assert found.entries[0].activity_id == entry.name
    assert found.entries[0].modified == 0
    assert not found.entries[0].readable


def test_survey_tolerates_a_run_disappearing_during_metadata_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ArtifactStore(tmp_path / "store")
    (store.run_root / "stray-file").write_text("ignore", encoding="utf-8")
    run = store.run_root / "broken-run"
    run.mkdir()
    original_is_dir = Path.is_dir
    original_is_symlink = Path.is_symlink
    original_stat = Path.stat

    def preserve_run_directory(path: Path) -> bool:
        return True if path == run else original_is_dir(path)

    def report_run_not_symlink(path: Path) -> bool:
        return False if path == run else original_is_symlink(path)

    def fail_run_stat(path: Path, *args: object, **kwargs: object):  # type: ignore[no-untyped-def]
        if path == run:
            raise FileNotFoundError(path)
        return original_stat(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "is_dir", preserve_run_directory)
    monkeypatch.setattr(Path, "is_symlink", report_run_not_symlink)
    monkeypatch.setattr(Path, "stat", fail_run_stat)
    found = survey(store)

    assert len(found.runs) == 1
    assert found.runs[0].run_id == run.name
    assert found.runs[0].modified == 0
    assert not found.runs[0].readable


def test_collection_refuses_a_target_that_cannot_be_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ArtifactStore(tmp_path / "store")
    sandbox = store.work_root / "candidate"
    sandbox.mkdir()
    sentinel = sandbox / "sentinel"
    sentinel.write_text("keep", encoding="utf-8")
    original_resolve = Path.resolve

    def fail_target_resolution(path: Path, *args: object, **kwargs: object) -> Path:
        if path == sandbox:
            raise OSError("injected resolution failure")
        return original_resolve(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "resolve", fail_target_resolution)
    report = apply_collection(store, CollectionPlan(sandboxes=(sandbox.name,)))

    assert report.removed_sandboxes == ()
    assert any("cannot resolve sandbox" in reason for _path, reason in report.failures)
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_collection_refuses_a_store_root_that_cannot_be_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ArtifactStore(tmp_path / "store")
    sandbox = store.work_root / "candidate"
    sandbox.mkdir()
    original_resolve = Path.resolve

    def fail_root_resolution(path: Path, *args: object, **kwargs: object) -> Path:
        if path == store.work_root:
            raise OSError("injected root resolution failure")
        return original_resolve(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "resolve", fail_root_resolution)
    report = apply_collection(store, CollectionPlan(sandboxes=(sandbox.name,)))

    assert report.removed_sandboxes == ()
    assert any("redirected work" in reason for _path, reason in report.failures)
    assert sandbox.is_dir()


def test_collection_revalidates_every_target_after_taking_the_writer_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ArtifactStore(tmp_path / "store")
    calls = 0

    def change_after_lock(_store: ArtifactStore, _plan: CollectionPlan):  # type: ignore[no-untyped-def]
        nonlocal calls
        calls += 1
        return () if calls == 1 else (("candidate", "injected post-lock redirection"),)

    monkeypatch.setattr(maintenance_module, "_validate_collection_targets", change_after_lock)
    report = apply_collection(store, CollectionPlan())

    assert calls == 2
    assert report.removed_runs == ()
    assert report.failures == (("candidate", "injected post-lock redirection"),)
    assert run_lock_state(store.root / ".locks" / "gc") is None


def test_collection_reports_writer_contention_without_mutating_the_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ArtifactStore(tmp_path / "store")
    monkeypatch.setattr(
        maintenance_module,
        "StoreWriteLease",
        lambda root: StoreWriteLease(root, timeout_seconds=0),
    )

    with StoreReadLease(store.root):
        report = apply_collection(store, CollectionPlan())

    assert report.removed_runs == ()
    assert report.failures
    assert "active or uncertain reader" in report.failures[0][1]


def test_collection_treats_already_missing_targets_as_success(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "store")
    report = apply_collection(
        store,
        CollectionPlan(runs=("missing-run",), entries=("a" * 64,), sandboxes=("missing",)),
    )

    assert report.removed_runs == ()
    assert report.removed_entries == ()
    assert report.removed_sandboxes == ()
    assert report.failures == ()


def test_an_unreadable_surviving_run_blocks_cache_deletion(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "store")
    run = store.run_root / "unreadable-run"
    run.mkdir()
    (run / "plan.json").write_text("{}", encoding="utf-8")
    entry = store.cache_root / ("b" * 64)
    entry.mkdir()
    sentinel = entry / "sentinel"
    sentinel.write_text("keep", encoding="utf-8")

    report = apply_collection(store, CollectionPlan(entries=(entry.name,)))

    assert report.removed_entries == ()
    assert any("unreadable plan" in reason for _path, reason in report.failures)
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_collection_reports_cache_and_sandbox_deletion_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ArtifactStore(tmp_path / "store")
    entry = store.cache_root / ("c" * 64)
    entry.mkdir()
    (entry / "artifact").write_bytes(b"cache")
    sandbox = store.work_root / "sandbox"
    sandbox.mkdir()
    (sandbox / "artifact").write_bytes(b"work")
    original_rmtree = shutil.rmtree

    def refuse_targets(path, *args, **kwargs):  # type: ignore[no-untyped-def]
        if Path(path) in {entry, sandbox}:
            raise PermissionError(f"injected removal failure for {Path(path).name}")
        return original_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(maintenance_module.shutil, "rmtree", refuse_targets)
    report = apply_collection(
        store, CollectionPlan(entries=(entry.name,), sandboxes=(sandbox.name,))
    )

    assert report.removed_entries == ()
    assert report.removed_sandboxes == ()
    assert len(report.failures) == 2
    assert entry.is_dir()
    assert sandbox.is_dir()


def test_collection_removes_a_named_sandbox_and_counts_its_bytes(tmp_path: Path) -> None:
    store = ArtifactStore(tmp_path / "store")
    sandbox = store.work_root / "sandbox"
    sandbox.mkdir()
    (sandbox / "artifact").write_bytes(b"work")

    report = apply_collection(store, CollectionPlan(sandboxes=(sandbox.name,)))

    assert report.removed_sandboxes == (sandbox.name,)
    assert report.freed == 4
    assert report.failures == ()
    assert not sandbox.exists()


def test_store_cli_reports_status_verification_and_dry_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = tmp_path / "store"

    assert main(["store-status", "--store", str(store)]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["cache"]["entries"] == 0

    assert main(["store-verify", "--store", str(store)]) == 0
    verification = json.loads(capsys.readouterr().out)
    assert verification == {"checked": True, "entries": [], "failed": 0}

    assert main(["store-gc", "--store", str(store), "--keep-runs", "0"]) == 0
    dry_run = json.loads(capsys.readouterr().out)
    assert dry_run["applied"] is False
    assert dry_run["plan"]["runs"] == []


def test_store_cli_verification_failure_uses_a_distinct_status(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = ArtifactStore(tmp_path / "store")
    incomplete = store.cache_root / ".publish-incomplete"
    incomplete.mkdir()

    assert main(["store-verify", "--store", str(store.root)]) == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["failed"] == 1
    assert payload["entries"][0]["activity_id"] == incomplete.name


def test_store_cli_applies_collection_and_reports_contention(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    store = ArtifactStore(tmp_path / "store")
    sandbox = store.work_root / "leftover"
    sandbox.mkdir()
    assert main(["store-gc", "--store", str(store.root), "--keep-runs", "0", "--apply"]) == 0
    applied = json.loads(capsys.readouterr().out)
    assert applied["applied"] is True
    assert applied["result"]["removed_sandboxes"] == [sandbox.name]

    monkeypatch.setattr(
        maintenance_module,
        "StoreWriteLease",
        lambda root: StoreWriteLease(root, timeout_seconds=0),
    )
    with StoreReadLease(store.root):
        assert main(["store-gc", "--store", str(store.root), "--keep-runs", "0", "--apply"]) == 3
    blocked = json.loads(capsys.readouterr().out)
    assert blocked["result"]["failures"]


@pytest.mark.parametrize(
    ("command", "backend"),
    [
        ("store-status", "survey"),
        ("store-verify", "verify_all"),
        ("store-gc", "plan_collection"),
    ],
)
def test_store_cli_backend_errors_are_actionable_status_two(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    backend: str,
) -> None:
    def fail(*_args: object, **_kwargs: object) -> None:
        raise StoreError(f"injected {backend} failure")

    monkeypatch.setattr(maintenance_module, backend, fail)
    assert main([command, "--store", str(tmp_path / "store")]) == 2
    assert f"simcairn: injected {backend} failure" in capsys.readouterr().err
