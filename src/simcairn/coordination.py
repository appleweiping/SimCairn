"""Cross-platform coordination between short store operations and collection.

The protocol uses only atomic directory creation, so it works on every
platform supported by SimCairn. Readers are short leases used while a run is
registered or a run lock is acquired. Collection holds the exclusive writer
lease. A reader publishes its lease and then checks the writer again; a writer
publishes first and waits for every reader. Therefore one side of every race
observes the other before it mutates the store. Lock release is atomic and can
only make a writer's earlier decision more conservative, so it never waits.
"""

from __future__ import annotations

import math
import secrets
import shutil
import time
from pathlib import Path
from types import TracebackType

from simcairn.journal import JournalError, RunLock, run_lock_state

_DEFAULT_WAIT_SECONDS = 10.0
_POLL_SECONDS = 0.02


class StoreCoordinationError(RuntimeError):
    """The store could not be coordinated without guessing about an owner."""


def _deadline(timeout_seconds: object) -> float:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, int | float)
        or not math.isfinite(timeout_seconds)
        or timeout_seconds < 0
    ):
        raise ValueError("timeout_seconds must be a finite non-negative number")
    return time.monotonic() + float(timeout_seconds)


def _direct_directory(parent: Path, name: str) -> Path:
    """Create one direct child and reject symlink or junction redirection."""

    path = parent / name
    try:
        path.mkdir(exist_ok=True)
        resolved = path.resolve()
    except (OSError, RuntimeError) as error:
        raise StoreCoordinationError(
            f"cannot create store coordination directory: {error}"
        ) from error
    if path.is_symlink() or not path.is_dir() or resolved != parent / name:
        raise StoreCoordinationError(f"store coordination path is not a regular directory: {path}")
    return path


def _coordination_root(root: Path) -> Path:
    try:
        canonical = root.resolve()
        canonical.mkdir(parents=True, exist_ok=True)
    except (OSError, RuntimeError) as error:
        raise StoreCoordinationError(f"cannot access store root: {error}") from error
    if not canonical.is_dir():
        raise StoreCoordinationError(f"store root is not a regular directory: {canonical}")
    return _direct_directory(canonical, ".locks")


def _writer_directory(root: Path) -> Path:
    return _direct_directory(_coordination_root(root), "gc")


def _reader_root(root: Path) -> Path:
    return _direct_directory(_coordination_root(root), "readers")


def _writer_active(root: Path) -> bool:
    state = run_lock_state(_writer_directory(root))
    return state not in (None, "stale")


class StoreReadLease:
    """Publish a short reader lease, retrying if collection wins the race."""

    def __init__(self, root: Path, *, timeout_seconds: float = _DEFAULT_WAIT_SECONDS) -> None:
        self.root = root
        self.timeout_seconds = timeout_seconds
        self.directory: Path | None = None
        self.lock: RunLock | None = None

    def _release(self) -> None:
        if self.lock is not None:
            self.lock.__exit__(None, None, None)
        if self.directory is not None:
            try:
                self.directory.rmdir()
            except FileNotFoundError:
                pass
            except OSError as error:
                raise StoreCoordinationError(
                    f"cannot remove store reader lease: {error}"
                ) from error
        self.lock = None
        self.directory = None

    def __enter__(self) -> StoreReadLease:
        deadline = _deadline(self.timeout_seconds)
        readers = _reader_root(self.root)
        while True:
            if _writer_active(self.root):
                if time.monotonic() >= deadline:
                    raise StoreCoordinationError("store collection is still in progress")
                time.sleep(_POLL_SECONDS)
                continue

            directory = readers / secrets.token_hex(16)
            created = False
            try:
                directory.mkdir()
                created = True
                lock = RunLock(directory)
                lock.__enter__()
            except (OSError, JournalError) as error:
                if created:
                    shutil.rmtree(directory, ignore_errors=True)
                if time.monotonic() >= deadline:
                    raise StoreCoordinationError("cannot publish a store reader lease") from error
                time.sleep(_POLL_SECONDS)
                continue
            self.directory = directory
            self.lock = lock
            try:
                if not _writer_active(self.root):
                    return self
            except BaseException:
                self._release()
                raise
            self._release()
            if time.monotonic() >= deadline:
                raise StoreCoordinationError("store collection won the reader race")
            time.sleep(_POLL_SECONDS)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self._release()


class StoreWriteLease:
    """Exclude new readers and wait for every published reader to leave."""

    def __init__(self, root: Path, *, timeout_seconds: float = _DEFAULT_WAIT_SECONDS) -> None:
        self.root = root
        self.timeout_seconds = timeout_seconds
        self.lock: RunLock | None = None

    @staticmethod
    def _reap_abandoned_reader(directory: Path) -> bool:
        state = run_lock_state(directory)
        if state is None:
            # A process may die after publishing its reader directory but
            # before publishing the inner lock. With the writer already held,
            # an empty directory cannot become a valid reader: a racing reader
            # must perform the second writer check and retry.
            try:
                directory.rmdir()
            except FileNotFoundError:
                return True
            except OSError:
                return False
            return True
        if state == "stale":
            try:
                # Re-acquiring a positively stale lock replaces it with one
                # owned by this process. Releasing that lock leaves the reader
                # directory empty, so a transient failure to remove the
                # directory remains recoverable on the next scan. Using the
                # audited unlock path here would leave unlock-audit.jsonl
                # behind and turn one failed rmtree into a permanent blocker.
                with RunLock(directory):
                    pass
                directory.rmdir()
            except (OSError, JournalError):
                return False
            return True
        return False

    def __enter__(self) -> StoreWriteLease:
        deadline = _deadline(self.timeout_seconds)
        writer = _writer_directory(self.root)
        try:
            lock = RunLock(writer)
            lock.__enter__()
        except JournalError as error:
            raise StoreCoordinationError("another store collection is in progress") from error
        self.lock = lock

        try:
            readers = _reader_root(self.root)
            while True:
                blockers: list[Path] = []
                for directory in tuple(readers.iterdir()):
                    if directory.is_symlink() or not directory.is_dir():
                        blockers.append(directory)
                        continue
                    if self._reap_abandoned_reader(directory):
                        continue
                    # A nonempty reader with no valid lock, or any live/foreign
                    # lock, is uncertain and must block deletion.
                    blockers.append(directory)
                if not blockers:
                    return self
                if time.monotonic() >= deadline:
                    raise StoreCoordinationError(
                        f"store still has {len(blockers)} active or uncertain reader lease(s)"
                    )
                time.sleep(_POLL_SECONDS)
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        if self.lock is not None:
            self.lock.__exit__(None, None, None)
            self.lock = None


class StoreRunLock:
    """Change a per-run lock only while collection cannot take a snapshot."""

    def __init__(self, root: Path, run_directory: Path) -> None:
        self.root = root
        self.lock = RunLock(run_directory)

    def __enter__(self) -> RunLock:
        with StoreReadLease(self.root):
            run_directory = self.lock.path.parent
            expected_runs = self.root.resolve() / "runs"
            try:
                redirected = (
                    expected_runs.is_symlink()
                    or expected_runs.resolve() != expected_runs
                    or run_directory.is_symlink()
                    or not run_directory.is_dir()
                    or run_directory.resolve() != expected_runs / run_directory.name
                )
            except (OSError, RuntimeError):
                redirected = True
            if redirected:
                raise StoreCoordinationError("run directory is redirected, missing, or invalid")
            return self.lock.__enter__()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        # Releasing a lock cannot make collection unsafe. A writer that saw the
        # lock keeps the run; a writer that sees it gone does so only after this
        # atomic marker removal has completed. Only acquisition needs a reader
        # lease to stop a writer from classifying the run as idle first.
        self.lock.__exit__(exc_type, exc_value, traceback)
