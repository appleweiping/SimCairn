"""Surveying, verifying, and reclaiming the store.

A cairn store only grows. Every run publishes content-addressed entries that
outlive it on purpose, which is the point of a cache and also the reason the
directory becomes the largest thing on the disk. There was no way to see what
it held, no way to tell whether it had rotted, and no way to reclaim any of it
short of deleting the whole directory and losing every cached result.

Reclaiming is the part that has to be careful, because the failure is silent
and permanent: an entry removed while something still needs it turns a cache
hit into a re-simulation at best, and into a broken resume at worst. Three
rules keep that from happening.

Nothing is removed unless asked. `plan_collection` reports what it would take
and changes nothing; only `apply_collection` deletes, and only the plan it is
handed.

A run that might still be running is untouchable, and so is everything it
references. A lock is judged live unless it is positively stale -- a lock owned
by another host, or one whose owner cannot be identified, counts as live. The
uncertain case has to be the safe one.

An entry that cannot be read is kept by default rather than swept up. A
corrupt cairn is evidence about a failure someone may want to look at, and
deleting evidence to reclaim a few megabytes is the wrong trade.

The fourth rule is the one that is easy to get wrong. Retaining a run whose
plan will not parse is not enough on its own, because the list of activities it
refers to comes back empty and an empty list reads exactly like "refers to
nothing". Believing it would mark every entry in the store orphaned and remove
all of them. While any retained run cannot be read, nothing is collectable.
"""

from __future__ import annotations

import shutil
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from simcairn.coordination import StoreCoordinationError, StoreWriteLease
from simcairn.journal import run_lock_state
from simcairn.store import ArtifactStore, StoreError

#: Runs kept by default. Enough to resume recent work and compare against the
#: previous attempt, without keeping a year of sweeps alive.
DEFAULT_KEEP_RUNS = 10


def directory_bytes(path: Path) -> int:
    """Total size of the regular files under `path`.

    Symbolic links are ignored rather than followed, so a link out of the
    store cannot inflate the total or, worse, be walked into.
    """

    total = 0
    for item in path.rglob("*"):
        if item.is_symlink() or not item.is_file():
            continue
        try:
            total += item.stat().st_size
        except OSError:
            continue
    return total


@dataclass(frozen=True, slots=True)
class CacheEntry:
    """One published cairn."""

    activity_id: str
    size: int
    modified: float
    readable: bool
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "activity_id": self.activity_id,
            "size": self.size,
            "modified": self.modified,
            "readable": self.readable,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class RunSummary:
    """One run directory and what it keeps alive."""

    run_id: str
    size: int
    modified: float
    lock_state: str | None
    activity_ids: frozenset[str]
    readable: bool
    reason: str = ""

    @property
    def protected(self) -> bool:
        """Whether this run may still be running.

        Only a positively stale lock releases a run. A lock held on another
        host, or one whose owner cannot be identified, is treated as live: the
        uncertain case has to be the safe one.
        """

        return self.lock_state is not None and self.lock_state != "stale"

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "size": self.size,
            "modified": self.modified,
            "lock_state": self.lock_state,
            "protected": self.protected,
            "activities": len(self.activity_ids),
            "readable": self.readable,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class StoreSurvey:
    """What the store holds right now."""

    root: str
    entries: tuple[CacheEntry, ...]
    runs: tuple[RunSummary, ...]
    work_size: int
    work_sandboxes: int

    @property
    def cache_size(self) -> int:
        return sum(entry.size for entry in self.entries)

    @property
    def run_size(self) -> int:
        return sum(run.size for run in self.runs)

    @property
    def total_size(self) -> int:
        return self.cache_size + self.run_size + self.work_size

    @property
    def unreadable(self) -> tuple[CacheEntry, ...]:
        return tuple(entry for entry in self.entries if not entry.readable)

    @property
    def reachable(self) -> frozenset[str]:
        """Activity ids any surviving run refers to."""

        found: set[str] = set()
        for run in self.runs:
            found |= run.activity_ids
        return frozenset(found)

    @property
    def orphaned(self) -> tuple[CacheEntry, ...]:
        """Entries no run refers to any more."""

        reachable = self.reachable
        return tuple(entry for entry in self.entries if entry.activity_id not in reachable)

    def as_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "cache": {
                "entries": len(self.entries),
                "size": self.cache_size,
                "unreadable": len(self.unreadable),
                "orphaned": len(self.orphaned),
            },
            "runs": {
                "count": len(self.runs),
                "size": self.run_size,
                "protected": sum(run.protected for run in self.runs),
            },
            "work": {"sandboxes": self.work_sandboxes, "size": self.work_size},
            "total_size": self.total_size,
        }


@dataclass(frozen=True, slots=True)
class CollectionPlan:
    """What a collection would remove, before anything is removed."""

    runs: tuple[str, ...] = ()
    entries: tuple[str, ...] = ()
    sandboxes: tuple[str, ...] = ()
    freed: int = 0
    protected_runs: tuple[str, ...] = ()
    kept_unreadable: tuple[str, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def empty(self) -> bool:
        return not (self.runs or self.entries or self.sandboxes)

    def as_dict(self) -> dict[str, Any]:
        return {
            "runs": list(self.runs),
            "entries": list(self.entries),
            "sandboxes": list(self.sandboxes),
            "freed": self.freed,
            "protected_runs": list(self.protected_runs),
            "kept_unreadable": list(self.kept_unreadable),
            "notes": list(self.notes),
        }


@dataclass(frozen=True, slots=True)
class CollectionReport:
    """What a collection actually removed."""

    removed_runs: tuple[str, ...]
    removed_entries: tuple[str, ...]
    removed_sandboxes: tuple[str, ...]
    freed: int
    failures: tuple[tuple[str, str], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "removed_runs": list(self.removed_runs),
            "removed_entries": list(self.removed_entries),
            "removed_sandboxes": list(self.removed_sandboxes),
            "freed": self.freed,
            "failures": [{"path": path, "error": error} for path, error in self.failures],
        }


def _cache_entries(store: ArtifactStore) -> tuple[CacheEntry, ...]:
    entries = []
    for path in sorted(store.cache_root.iterdir()):
        if not path.is_dir():
            continue
        if path.is_symlink():
            readable, reason = False, "cache entry is a symbolic link"
        else:
            try:
                readable, reason = store.verify(path.name)
            except StoreError as error:
                readable, reason = False, str(error)
        try:
            modified = path.stat().st_mtime
        except OSError:
            modified = 0.0
        entries.append(
            CacheEntry(
                activity_id=path.name,
                size=directory_bytes(path),
                modified=modified,
                readable=readable,
                reason="" if readable else reason,
            )
        )
    return tuple(entries)


def _run_summaries(store: ArtifactStore) -> tuple[RunSummary, ...]:
    runs = []
    for path in sorted(store.run_root.iterdir()):
        if not path.is_dir():
            continue
        readable = True
        reason = ""
        activity_ids: frozenset[str] = frozenset()
        if path.is_symlink():
            readable = False
            reason = "run directory is a symbolic link"
        else:
            try:
                plan = store.load_plan(path.name)
                activity_ids = frozenset(activity.id for activity in plan.activities)
            except StoreError as error:
                readable = False
                reason = str(error)
        try:
            modified = path.stat().st_mtime
        except OSError:
            modified = 0.0
        runs.append(
            RunSummary(
                run_id=path.name,
                size=directory_bytes(path),
                modified=modified,
                lock_state="unknown" if path.is_symlink() else run_lock_state(path),
                activity_ids=activity_ids,
                readable=readable,
                reason=reason,
            )
        )
    return tuple(runs)


def survey(store: ArtifactStore) -> StoreSurvey:
    """Describe the store without changing any of it."""

    sandboxes = [path for path in sorted(store.work_root.iterdir()) if path.is_dir()]
    return StoreSurvey(
        root=str(store.root),
        entries=_cache_entries(store),
        runs=_run_summaries(store),
        work_size=sum(directory_bytes(path) for path in sandboxes),
        work_sandboxes=len(sandboxes),
    )


def verify_all(store: ArtifactStore) -> tuple[CacheEntry, ...]:
    """Re-hash every published cairn and report the ones that no longer match.

    `ArtifactStore.verify` already checks one entry against its manifest. This
    applies it to the whole store, which is the only way bit rot in a cached
    artifact is noticed before a run silently reuses it.
    """

    return tuple(entry for entry in _cache_entries(store) if not entry.readable)


def _keep_runs(runs: Iterable[RunSummary], keep: int) -> tuple[set[str], list[RunSummary]]:
    """Split runs into those retained and those a collection may remove.

    Retention is by modification time, newest first, and a protected run is
    retained whatever its age: a run that may still be writing is not old, it
    is busy.
    """

    ordered = sorted(runs, key=lambda run: (-run.modified, run.run_id))
    retained: set[str] = set()
    removable: list[RunSummary] = []
    for position, run in enumerate(ordered):
        if run.protected or position < keep:
            retained.add(run.run_id)
        else:
            removable.append(run)
    return retained, removable


def plan_collection(
    store: ArtifactStore,
    *,
    keep_runs: int = DEFAULT_KEEP_RUNS,
    include_unreadable: bool = False,
    include_work: bool = True,
) -> CollectionPlan:
    """Decide what could be reclaimed. Removes nothing.

    A cache entry is collectable when no retained run refers to it. A run is
    collectable when it is neither protected nor among the newest kept. Work
    sandboxes are collectable only when no run in the store is protected, since
    a sandbox carries no record of which run owns it and a live run may be
    writing into one right now.
    """

    if isinstance(keep_runs, bool) or not isinstance(keep_runs, int) or keep_runs < 0:
        raise ValueError("keep_runs must be a non-negative integer")
    current = survey(store)
    retained_ids, removable_runs = _keep_runs(current.runs, keep_runs)
    notes: list[str] = []

    unreadable_runs = [run for run in removable_runs if not run.readable]
    if unreadable_runs and not include_unreadable:
        # A run whose plan will not load refers to an unknown set of activities,
        # so removing it would make entries look orphaned that are not.
        notes.append(
            f"{len(unreadable_runs)} run(s) have an unreadable plan and were kept; "
            "their activity references are unknown"
        )
        removable_runs = [run for run in removable_runs if run.readable]
        retained_ids |= {run.run_id for run in unreadable_runs}

    still_reachable: set[str] = set()
    blind = False
    for run in current.runs:
        if run.run_id not in retained_ids:
            continue
        still_reachable |= run.activity_ids
        # Keeping such a run is not enough. Its activity list came back empty
        # because the plan would not parse, not because it refers to nothing,
        # so treating that emptiness as fact would mark every entry orphaned
        # and delete the whole cache. While one retained run cannot be read,
        # no entry can be classified at all.
        blind = blind or not run.readable

    kept_unreadable: list[str] = []
    entries: list[str] = []
    freed = 0
    if blind:
        notes.append(
            "no cache entry was collected: a retained run has an unreadable plan, "
            "so which entries are still referenced cannot be determined"
        )
    else:
        for entry in current.entries:
            if entry.activity_id in still_reachable:
                continue
            if not entry.readable and not include_unreadable:
                kept_unreadable.append(entry.activity_id)
                continue
            entries.append(entry.activity_id)
            freed += entry.size
    if kept_unreadable:
        notes.append(
            f"{len(kept_unreadable)} unreadable cache entr(y/ies) were kept as evidence; "
            "pass include_unreadable to remove them"
        )

    protected = tuple(run.run_id for run in current.runs if run.protected)
    sandboxes: list[str] = []
    if include_work:
        if protected:
            notes.append(
                "work sandboxes were kept because a run holds a live lock and a "
                "sandbox does not record which run owns it"
            )
        else:
            for path in sorted(store.work_root.iterdir()):
                if path.is_dir():
                    sandboxes.append(path.name)
                    freed += directory_bytes(path)

    for run in removable_runs:
        freed += run.size
    return CollectionPlan(
        runs=tuple(sorted(run.run_id for run in removable_runs)),
        entries=tuple(sorted(entries)),
        sandboxes=tuple(sandboxes),
        freed=freed,
        protected_runs=protected,
        kept_unreadable=tuple(sorted(kept_unreadable)),
        notes=tuple(notes),
    )


def _safe_target(root: Path, name: object, kind: str) -> tuple[Path | None, str | None]:
    """Resolve one exact direct child without accepting platform-specific escapes."""

    if (
        not isinstance(name, str)
        or not name
        or name in {".", ".."}
        or "/" in name
        or "\\" in name
        or ":" in name
        or Path(name).name != name
        or Path(name).anchor
    ):
        return None, f"unsafe {kind} name"
    target = root / name
    try:
        expected = root.resolve() / name
        resolved = target.resolve()
    except (OSError, RuntimeError) as error:
        return None, f"cannot resolve {kind}: {error}"
    if target.is_symlink() or resolved != expected:
        return None, f"refusing redirected {kind}"
    return target, None


def _validate_collection_targets(
    store: ArtifactStore, plan: CollectionPlan
) -> tuple[tuple[str, str], ...]:
    failures: list[tuple[str, str]] = []
    groups = (
        (store.run_root, "runs", plan.runs, "run"),
        (store.cache_root, "cache", plan.entries, "cache-entry"),
        (store.work_root, "work", plan.sandboxes, "sandbox"),
    )
    for root, expected_name, names, kind in groups:
        try:
            redirected = (
                root.is_symlink()
                or not root.is_dir()
                or root.resolve() != store.root / expected_name
            )
        except (OSError, RuntimeError):
            redirected = True
        if redirected:
            failures.append((str(root), f"refusing redirected {expected_name} store root"))
            continue
        for name in names:
            _target, reason = _safe_target(root, name, kind)
            if reason is not None:
                failures.append((str(name), reason))
    return tuple(failures)


def apply_collection(store: ArtifactStore, plan: CollectionPlan) -> CollectionReport:
    """Safely apply a previously reported collection plan.

    Every target is validated before the first mutation. The exclusive store
    lease then freezes run registration and run-lock transitions while the
    current store is surveyed again. Existing simulations keep running; their
    visible run locks protect their run, reachable entries, and work area.
    """

    failures = _validate_collection_targets(store, plan)
    if failures:
        return CollectionReport((), (), (), 0, failures)
    try:
        with StoreWriteLease(store.root):
            failures = _validate_collection_targets(store, plan)
            if failures:
                return CollectionReport((), (), (), 0, failures)
            return _apply_collection_locked(store, plan)
    except StoreCoordinationError as error:
        return CollectionReport((), (), (), 0, ((str(store.root), str(error)),))


def _apply_collection_locked(store: ArtifactStore, plan: CollectionPlan) -> CollectionReport:
    """Remove exact, prevalidated targets while the writer lease is held.

    The plan is re-checked against the store as it is applied. A run that
    acquired a lock is skipped; every surviving plan is reloaded before cache
    entries are removed; and work is retained if a live lock appeared. The
    plan may be older than the situation, so current reachability wins.
    """

    removed_runs: list[str] = []
    removed_entries: list[str] = []
    removed_sandboxes: list[str] = []
    failures: list[tuple[str, str]] = []
    freed = 0

    for run_id in plan.runs:
        directory = store.run_root / run_id
        if not directory.is_dir():
            continue
        if run_lock_state(directory) not in (None, "stale"):
            failures.append((str(directory), "run acquired a lock after the plan was made"))
            continue
        size = directory_bytes(directory)
        try:
            shutil.rmtree(directory)
        except OSError as error:
            failures.append((str(directory), str(error)))
            continue
        removed_runs.append(run_id)
        freed += size

    # The plan is only a snapshot. Runs may have appeared, acquired a lock, or
    # failed to be removed since it was made. Re-read the surviving plans
    # before deleting a cache entry so an entry that is now reachable is kept.
    # If any surviving plan cannot be read, no entry can be classified safely.
    remaining_runs = _run_summaries(store)
    unreadable_runs = tuple(run for run in remaining_runs if not run.readable)
    reachable = frozenset(activity_id for run in remaining_runs for activity_id in run.activity_ids)

    for activity_id in plan.entries:
        try:
            directory = store.cache_path(activity_id)
        except StoreError:
            # A crashed atomic publish may leave a direct `.publish-*`
            # directory that is intentionally not a valid activity id. It is
            # still an exact child of the cache and can be removed when an
            # include-unreadable plan explicitly names it.
            directory = store.cache_root / activity_id
        if not directory.is_dir():
            continue
        if unreadable_runs:
            failures.append(
                (
                    str(directory),
                    "cache entry kept because a remaining run has an unreadable plan",
                )
            )
            continue
        if activity_id in reachable:
            failures.append(
                (str(directory), "cache entry became referenced after the plan was made")
            )
            continue
        size = directory_bytes(directory)
        try:
            shutil.rmtree(directory)
        except OSError as error:
            failures.append((str(directory), str(error)))
            continue
        removed_entries.append(activity_id)
        freed += size

    protected_runs = tuple(run for run in _run_summaries(store) if run.protected)
    for name in plan.sandboxes:
        directory = store.work_root / name
        if not directory.is_dir():
            continue
        if protected_runs:
            failures.append(
                (str(directory), "work sandbox kept because a run now holds a live lock")
            )
            continue
        size = directory_bytes(directory)
        try:
            shutil.rmtree(directory)
        except OSError as error:
            failures.append((str(directory), str(error)))
            continue
        removed_sandboxes.append(name)
        freed += size

    return CollectionReport(
        removed_runs=tuple(removed_runs),
        removed_entries=tuple(removed_entries),
        removed_sandboxes=tuple(removed_sandboxes),
        freed=freed,
        failures=tuple(failures),
    )
