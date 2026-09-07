from __future__ import annotations

import json
import os
import socket
from pathlib import Path
from types import SimpleNamespace

import pytest

from simcairn.coordination import (
    StoreCoordinationError,
    StoreReadLease,
    StoreRunLock,
    StoreWriteLease,
)
from simcairn.journal import JournalError, RunLock, run_lock_state


def test_multiple_readers_can_coexist_and_leave_no_markers(tmp_path: Path) -> None:
    root = tmp_path / "store"
    with StoreReadLease(root) as first, StoreReadLease(root) as second:
        assert first.directory is not None
        assert second.directory is not None
        assert first.directory != second.directory
        assert run_lock_state(first.directory) == "alive"
        assert run_lock_state(second.directory) == "alive"

    assert list((root / ".locks" / "readers").iterdir()) == []


def test_writer_refuses_to_guess_while_a_reader_is_active(tmp_path: Path) -> None:
    root = tmp_path / "store"
    with (
        StoreReadLease(root),
        pytest.raises(StoreCoordinationError, match="active or uncertain reader"),
        StoreWriteLease(root, timeout_seconds=0),
    ):
        pytest.fail("the writer must not overlap the reader")

    with StoreWriteLease(root, timeout_seconds=0):
        assert run_lock_state(root / ".locks" / "gc") == "alive"
    assert run_lock_state(root / ".locks" / "gc") is None


def test_reader_refuses_to_enter_while_collection_is_active(tmp_path: Path) -> None:
    root = tmp_path / "store"
    with (
        StoreWriteLease(root),
        pytest.raises(StoreCoordinationError, match="collection is still in progress"),
        StoreReadLease(root, timeout_seconds=0),
    ):
        pytest.fail("the reader must not overlap the writer")

    with StoreReadLease(root, timeout_seconds=0):
        pass


def test_a_stale_reader_is_reaped_before_collection(tmp_path: Path) -> None:
    root = tmp_path / "store"
    reader = root / ".locks" / "readers" / "abandoned"
    lock = reader / "run.lock"
    lock.mkdir(parents=True)
    owner = {
        "schema_version": 1,
        "pid": 2_147_483_647,
        "host": socket.gethostname(),
        "process_start": "definitely-not-this-process",
        "nonce": "a" * 32,
    }
    (lock / f"owner-{'a' * 32}.json").write_text(
        json.dumps(owner, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    assert run_lock_state(reader) == "stale"

    with StoreWriteLease(root, timeout_seconds=0):
        assert not reader.exists()


def test_an_empty_crashed_reader_is_reaped(tmp_path: Path) -> None:
    root = tmp_path / "store"
    readers = root / ".locks" / "readers"
    readers.mkdir(parents=True)
    crashed = readers / "crashed-before-lock"
    crashed.mkdir()

    with StoreWriteLease(root, timeout_seconds=0):
        assert not crashed.exists()


def test_an_uncertain_reader_marker_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "store"
    readers = root / ".locks" / "readers"
    readers.mkdir(parents=True)
    marker = readers / "uncertain"
    marker.write_text("not a lease", encoding="utf-8")

    with (
        pytest.raises(StoreCoordinationError, match="active or uncertain reader"),
        StoreWriteLease(root, timeout_seconds=0),
    ):
        pytest.fail("uncertain state must block deletion")
    assert marker.exists()
    assert run_lock_state(root / ".locks" / "gc") is None


def test_failure_to_reap_a_stale_reader_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "store"
    reader = root / ".locks" / "readers" / "stale"
    reader.mkdir(parents=True)
    monkeypatch.setattr("simcairn.coordination.run_lock_state", lambda _path: "stale")

    original_enter = RunLock.__enter__

    def refuse_replacement(lock: RunLock) -> RunLock:
        if lock.path.parent == reader:
            raise JournalError("injected refusal")
        return original_enter(lock)

    monkeypatch.setattr(RunLock, "__enter__", refuse_replacement)
    with (
        pytest.raises(StoreCoordinationError, match="active or uncertain reader"),
        StoreWriteLease(root, timeout_seconds=0),
    ):
        pytest.fail("an unreaped reader must block deletion")
    assert reader.exists()


def test_transient_stale_reader_removal_failure_is_recoverable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "store"
    reader = root / ".locks" / "readers" / "stale"
    lock = reader / "run.lock"
    lock.mkdir(parents=True)
    owner = {
        "schema_version": 1,
        "pid": 2_147_483_647,
        "host": socket.gethostname(),
        "process_start": "definitely-not-this-process",
        "nonce": "a" * 32,
    }
    (lock / f"owner-{'a' * 32}.json").write_text(
        json.dumps(owner, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("simcairn.journal._probe_process", lambda _pid: ("dead", None))
    monkeypatch.setattr(
        "simcairn.journal._probe_current_process", lambda _pid: ("alive", "test-start")
    )
    original_rmdir = Path.rmdir
    attempts = 0

    def fail_reader_once(path: Path) -> None:
        nonlocal attempts
        if path == reader:
            attempts += 1
            if attempts == 1:
                raise OSError("injected transient removal failure")
        original_rmdir(path)

    monkeypatch.setattr(Path, "rmdir", fail_reader_once)
    with StoreWriteLease(root, timeout_seconds=1):
        assert not reader.exists()
    assert attempts == 2


def test_store_run_lock_uses_the_transition_barrier(tmp_path: Path) -> None:
    root = tmp_path / "store"
    run = root / "runs" / "run-0001"
    run.mkdir(parents=True)

    with StoreRunLock(root, run), StoreWriteLease(root, timeout_seconds=0):
        assert run_lock_state(run) == "alive"
    assert run_lock_state(run) is None


@pytest.mark.parametrize("value", [-1, True, float("nan"), float("inf"), "1"])
def test_invalid_timeouts_are_rejected(tmp_path: Path, value: object) -> None:
    with pytest.raises(ValueError, match="finite non-negative"):
        StoreReadLease(tmp_path, timeout_seconds=value).__enter__()
    with pytest.raises(ValueError, match="finite non-negative"):
        StoreWriteLease(tmp_path, timeout_seconds=value).__enter__()


def test_reader_release_failure_is_explicit(tmp_path: Path) -> None:
    lease = StoreReadLease(tmp_path / "store")
    lease.__enter__()
    assert lease.directory is not None
    obstruction = lease.directory / "unexpected"
    obstruction.write_text("do not guess", encoding="utf-8")

    with pytest.raises(StoreCoordinationError, match="cannot remove store reader lease"):
        lease.__exit__(None, None, None)

    obstruction.unlink()
    assert lease.directory is not None
    lease.__exit__(None, None, None)
    assert lease.directory is None
    assert lease.lock is None


def test_writer_rejects_a_second_writer(tmp_path: Path) -> None:
    root = tmp_path / "store"
    with (
        StoreWriteLease(root),
        pytest.raises(StoreCoordinationError, match="another store collection"),
    ):
        StoreWriteLease(root, timeout_seconds=0).__enter__()


def test_store_run_lock_releases_after_an_exception(tmp_path: Path) -> None:
    root = tmp_path / "store"
    run = root / "runs" / "run-0001"
    run.mkdir(parents=True)

    with pytest.raises(RuntimeError, match="boom"), StoreRunLock(root, run):
        raise RuntimeError("boom")
    assert run_lock_state(run) is None
    assert os.listdir(root / ".locks" / "readers") == []


def test_reader_name_collision_never_removes_another_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "store"
    collision = root / ".locks" / "readers" / ("a" * 32)
    collision.mkdir(parents=True)
    sentinel = collision / "sentinel"
    sentinel.write_text("belongs to another reader", encoding="utf-8")
    names = iter(("a" * 32, "b" * 32))
    monkeypatch.setattr(
        "simcairn.coordination.secrets",
        SimpleNamespace(token_hex=lambda _size: next(names)),
    )

    with StoreReadLease(root) as lease:
        assert lease.directory is not None
        assert lease.directory.name == "b" * 32
        assert sentinel.read_text(encoding="utf-8") == "belongs to another reader"


def test_reader_cleans_up_when_the_second_writer_check_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "store"
    calls = 0

    def fail_second_check(_root: Path) -> bool:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise StoreCoordinationError("injected second-check failure")
        return False

    monkeypatch.setattr("simcairn.coordination._writer_active", fail_second_check)
    with pytest.raises(StoreCoordinationError, match="second-check"):
        StoreReadLease(root).__enter__()
    assert list((root / ".locks" / "readers").iterdir()) == []


def test_writer_cleans_up_when_reader_root_initialization_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "store"

    def fail_reader_root(_root: Path) -> Path:
        raise StoreCoordinationError("injected reader-root failure")

    monkeypatch.setattr("simcairn.coordination._reader_root", fail_reader_root)
    with pytest.raises(StoreCoordinationError, match="reader-root"):
        StoreWriteLease(root).__enter__()
    assert run_lock_state(root / ".locks" / "gc") is None


def test_redirected_coordination_root_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "store"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    sentinel = outside / "sentinel"
    sentinel.write_text("keep", encoding="utf-8")
    try:
        (root / ".locks").symlink_to(outside, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlinks are unavailable: {error}")

    with pytest.raises(StoreCoordinationError, match="not a regular directory"):
        StoreReadLease(root).__enter__()
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_a_store_path_that_is_a_file_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "not-a-directory"
    root.write_text("store data", encoding="utf-8")

    with pytest.raises(StoreCoordinationError, match="cannot access store root"):
        StoreReadLease(root).__enter__()


def test_coordination_directory_creation_errors_are_actionable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "store"
    root.mkdir()
    coordination_root = root / ".locks"
    original_mkdir = Path.mkdir

    def fail_coordination_root(path: Path, *args: object, **kwargs: object) -> None:
        if path == coordination_root:
            raise OSError("injected permissions failure")
        original_mkdir(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "mkdir", fail_coordination_root)
    with pytest.raises(StoreCoordinationError, match="cannot create store coordination directory"):
        StoreReadLease(root).__enter__()


def test_reader_publish_failure_removes_its_partial_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "store"
    original_enter = RunLock.__enter__

    def reject_reader_lock(lock: RunLock) -> RunLock:
        if lock.path.parent.parent.name == "readers":
            raise JournalError("injected reader lock failure")
        return original_enter(lock)

    monkeypatch.setattr(RunLock, "__enter__", reject_reader_lock)
    with pytest.raises(StoreCoordinationError, match="cannot publish a store reader lease"):
        StoreReadLease(root, timeout_seconds=0).__enter__()

    assert list((root / ".locks" / "readers").iterdir()) == []


def test_reader_that_loses_the_writer_race_releases_its_marker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "store"
    checks = iter((False, True))
    monkeypatch.setattr("simcairn.coordination._writer_active", lambda _root: next(checks))

    with pytest.raises(StoreCoordinationError, match="won the reader race"):
        StoreReadLease(root, timeout_seconds=0).__enter__()

    assert list((root / ".locks" / "readers").iterdir()) == []


def test_reader_release_tolerates_a_concurrent_marker_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    lease = StoreReadLease(tmp_path / "store")
    lease.__enter__()
    assert lease.directory is not None
    directory = lease.directory
    original_rmdir = Path.rmdir

    def remove_then_report_missing(path: Path) -> None:
        if path == directory:
            original_rmdir(path)
            raise FileNotFoundError(path)
        original_rmdir(path)

    monkeypatch.setattr(Path, "rmdir", remove_then_report_missing)
    lease.__exit__(None, None, None)

    assert lease.directory is None
    assert lease.lock is None
    assert not directory.exists()


def test_writer_tolerates_an_empty_reader_disappearing_during_reap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "store"
    reader = root / ".locks" / "readers" / "vanished"
    reader.mkdir(parents=True)
    original_rmdir = Path.rmdir

    def remove_then_report_missing(path: Path) -> None:
        if path == reader:
            original_rmdir(path)
            raise FileNotFoundError(path)
        original_rmdir(path)

    monkeypatch.setattr(Path, "rmdir", remove_then_report_missing)
    with StoreWriteLease(root, timeout_seconds=0):
        assert not reader.exists()


def test_writer_fails_closed_when_an_empty_reader_cannot_be_removed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "store"
    reader = root / ".locks" / "readers" / "unremovable"
    reader.mkdir(parents=True)
    original_rmdir = Path.rmdir

    def refuse_reader_removal(path: Path) -> None:
        if path == reader:
            raise PermissionError("injected permissions failure")
        original_rmdir(path)

    monkeypatch.setattr(Path, "rmdir", refuse_reader_removal)
    with pytest.raises(StoreCoordinationError, match="active or uncertain reader"):
        StoreWriteLease(root, timeout_seconds=0).__enter__()

    assert reader.is_dir()
    assert run_lock_state(root / ".locks" / "gc") is None


def test_store_run_lock_rejects_a_run_path_that_cannot_be_resolved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "store"
    run = root / "runs" / "run-0001"
    run.mkdir(parents=True)
    original_resolve = Path.resolve

    def fail_run_resolution(path: Path, *args: object, **kwargs: object) -> Path:
        if path == run:
            raise OSError("injected resolution failure")
        return original_resolve(path, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "resolve", fail_run_resolution)
    with pytest.raises(StoreCoordinationError, match="redirected, missing, or invalid"):
        StoreRunLock(root, run).__enter__()

    assert run_lock_state(run) is None
    assert list((root / ".locks" / "readers").iterdir()) == []
