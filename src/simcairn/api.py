"""Public orchestration API."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from simcairn.coordination import StoreReadLease
from simcairn.fingerprints import stable_json
from simcairn.gf180 import configure_gf180
from simcairn.journal import RunLock, latest_activity_states, replay
from simcairn.manifest import Manifest, load_manifest
from simcairn.model import Plan, RunReport, strict_json_loads
from simcairn.planner import compile_plan
from simcairn.scheduler import execute_plan
from simcairn.sky130 import configure_sky130
from simcairn.store import ArtifactStore, StoreError


class Runner:
    def __init__(self, store: str | Path = ".simcairn") -> None:
        self.store = ArtifactStore(store)

    def run(self, manifest_or_plan: Manifest | Plan) -> RunReport:
        plan = (
            compile_plan(manifest_or_plan)
            if isinstance(manifest_or_plan, Manifest)
            else manifest_or_plan
        )
        run_lock: RunLock | None = None
        try:
            with StoreReadLease(self.store.root):
                run_id, directory = self.store.create_run(plan)
                run_lock = RunLock(directory)
                run_lock.__enter__()
        except BaseException:
            if run_lock is not None:
                run_lock.__exit__(None, None, None)
            raise
        return self._execute_locked(plan, run_id, run_lock)

    def resume(self, run_id: str) -> RunReport:
        run_lock: RunLock | None = None
        try:
            with StoreReadLease(self.store.root):
                plan = self.store.load_plan(run_id)
                directory = self.store.run_directory(run_id)
                run_lock = RunLock(directory)
                run_lock.__enter__()
        except BaseException:
            if run_lock is not None:
                run_lock.__exit__(None, None, None)
            raise
        return self._execute_locked(plan, run_id, run_lock)

    def _execute_locked(self, plan: Plan, run_id: str, run_lock: RunLock) -> RunReport:
        try:
            return asyncio.run(execute_plan(plan, self.store, run_id, run_lock=run_lock))
        finally:
            run_lock.__exit__(None, None, None)

    def status(self, run_id: str) -> dict[str, Any]:
        with StoreReadLease(self.store.root):
            directory = self.store.run_directory(run_id)
            events = replay(directory / "events.jsonl")
            states = latest_activity_states(events)
            counts: dict[str, int] = {}
            for event in states.values():
                state = str(event["state"])
                counts[state] = counts.get(state, 0) + 1
            final_events = [event for event in events if event.get("state") == "run-finished"]
            return {
                "run_id": run_id,
                "status": final_events[-1]["message"] if final_events else "incomplete",
                "counts": dict(sorted(counts.items())),
                "events": len(events),
            }

    def collect(self, run_id: str) -> list[dict[str, Any]]:
        with StoreReadLease(self.store.root):
            plan = self.store.load_plan(run_id)
            aggregate = plan.activities[-1]
            valid, reason = self.store.verify(aggregate.id)
            if not valid:
                raise StoreError(f"aggregate result is unavailable: {reason}")
            path = self.store.cache_path(aggregate.id) / "files" / "results.json"
            try:
                data = strict_json_loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as error:
                raise StoreError(f"aggregate results.json is invalid: {error}") from error
            if not isinstance(data, list) or not all(isinstance(item, dict) for item in data):
                raise StoreError("aggregate results.json is not an array of objects")
            return data

    def collect_text(self, run_id: str) -> str:
        return stable_json(self.collect(run_id))

    def explain(self, activity_id: str) -> dict[str, Any]:
        with StoreReadLease(self.store.root):
            valid, reason = self.store.verify(activity_id)
            if not valid:
                return {"activity_id": activity_id, "cached": False, "reason": reason}
            manifest = self.store.explain(activity_id)
            return {
                "activity_id": activity_id,
                "cached": True,
                "reason": "all declared artifacts match their SHA-256 digests",
                "activity": manifest["activity"],
                "artifacts": manifest["artifacts"],
            }


__all__ = [
    "Runner",
    "compile_plan",
    "configure_gf180",
    "configure_sky130",
    "load_manifest",
]
