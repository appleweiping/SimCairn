"""Surveying, verifying, and reclaiming the store without losing anything."""

from __future__ import annotations

import json
import os
import socket
from pathlib import Path

import pytest

from simcairn.api import Runner, load_manifest
from simcairn.fingerprints import canonical_json
from simcairn.journal import run_lock_state
from simcairn.maintenance import (
    DEFAULT_KEEP_RUNS,
    apply_collection,
    directory_bytes,
    plan_collection,
    survey,
    verify_all,
)
from simcairn.store import ArtifactStore

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
