"""Bounded DAG scheduling with cache validation and named resource slots."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from simcairn.executor import ActivityExecutor
from simcairn.journal import Journal, RunLock
from simcairn.model import Activity, ActivityOutcome, Plan, RunReport
from simcairn.store import ArtifactStore


class SchedulerError(RuntimeError):
    pass


async def execute_plan(
    plan: Plan,
    store: ArtifactStore,
    run_id: str,
    *,
    executor: ActivityExecutor | None = None,
    on_activity: Callable[[ActivityOutcome], Awaitable[None] | None] | None = None,
) -> RunReport:
    run_directory = store.run_directory(run_id)
    journal = Journal(run_directory / "events.jsonl")
    activity_executor = executor or ActivityExecutor(store)
    activities = plan.activity_map()
    statuses: dict[str, str] = {}
    outcomes: dict[str, ActivityOutcome] = {}
    pending = set(activities)
    running: dict[asyncio.Task[ActivityOutcome], str] = {}
    resource_semaphores = {name: asyncio.Semaphore(limit) for name, limit in plan.resource_limits}
    resource_limits = dict(plan.resource_limits)
    job_limit = asyncio.Semaphore(plan.jobs)

    async def run_one(activity: Activity) -> ActivityOutcome:
        acquired: list[asyncio.Semaphore] = []
        await job_limit.acquire()
        try:
            for name, amount in sorted(activity.resources):
                limit = resource_limits.get(name)
                if limit is None:
                    return ActivityOutcome(activity.id, "failed", 0, f"undefined resource {name!r}")
                if amount < 1 or amount > limit:
                    return ActivityOutcome(
                        activity.id,
                        "failed",
                        0,
                        f"resource {name!r} request {amount} exceeds available limit {limit}",
                    )
                for _ in range(amount):
                    await resource_semaphores[name].acquire()
                    acquired.append(resource_semaphores[name])
            journal.append("started", activity_id=activity.id)
            return await activity_executor.execute(activity)
        finally:
            for semaphore in reversed(acquired):
                semaphore.release()
            job_limit.release()

    async def record(outcome: ActivityOutcome) -> None:
        statuses[outcome.activity_id] = outcome.status
        outcomes[outcome.activity_id] = outcome
        journal.append(
            outcome.status,
            activity_id=outcome.activity_id,
            message=outcome.message,
            duration_seconds=outcome.duration_seconds,
        )
        if on_activity:
            callback_result = on_activity(outcome)
            if callback_result is not None:
                await callback_result

    with RunLock(run_directory):
        journal.append("run-started", message=plan.id)
        for activity in plan.activities:
            valid, _ = store.verify(activity.id)
            if valid:
                await record(ActivityOutcome(activity.id, "cached", 0.0))
                pending.remove(activity.id)

        while pending or running:
            failed = any(status == "failed" for status in statuses.values())
            made_progress = False
            available_slots = plan.jobs - len(running)
            for activity in plan.activities:
                if activity.id not in pending:
                    continue
                dependency_states = [statuses.get(item) for item in activity.dependencies]
                if any(state in {"failed", "skipped"} for state in dependency_states):
                    pending.remove(activity.id)
                    await record(ActivityOutcome(activity.id, "skipped", 0.0, "dependency failed"))
                    made_progress = True
                elif plan.fail_fast and failed:
                    pending.remove(activity.id)
                    await record(
                        ActivityOutcome(activity.id, "skipped", 0.0, "fail-fast stopped run")
                    )
                    made_progress = True
                elif available_slots > 0 and all(
                    state in {"succeeded", "cached"} for state in dependency_states
                ):
                    task = asyncio.create_task(run_one(activity))
                    running[task] = activity.id
                    pending.remove(activity.id)
                    available_slots -= 1
                    made_progress = True

            if running:
                done, _ = await asyncio.wait(running, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    running.pop(task)
                    await record(task.result())
                made_progress = True
            if not made_progress and pending:
                raise SchedulerError("activity graph is cyclic or has an unknown dependency")

        final_status = (
            "failed"
            if any(outcome.status in {"failed", "skipped"} for outcome in outcomes.values())
            else "succeeded"
        )
        journal.append("run-finished", message=final_status)

    ordered = tuple(outcomes[activity.id] for activity in plan.activities)
    return RunReport(run_id, plan.id, final_status, ordered, run_directory)
