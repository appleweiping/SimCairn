# Architecture

## Invariants

SimCairn is organized around six invariants:

1. A sweep has one stable, inspectable activity graph.
2. Commands are argv arrays and never pass through a shell.
3. Successful artifacts are published atomically and verified by content.
4. Journal replay never treats an uncommitted activity as successful.
5. Failure in one branch does not silently change another branch.
6. Operational concurrency does not affect activity identities or result order.

```text
simcairn.toml
      |
      v
strict manifest -- template/input SHA-256 -- adapter identity
      |
      v
stable sweep points
      |
      v
render -> simulate -> extract --+
render -> simulate -> extract --+--> aggregate
      |
      v
scheduler + resource semaphores
      |
      +--> JSONL journal
      +--> temporary sandbox
      +--> content-addressed cache
```

## Manifest boundary

`manifest.load_manifest` validates types and cross-field rules before planning.
It canonicalizes input paths relative to the manifest directory and rejects
resolved escapes. Sweep values are converted to safe deterministic strings.
The library never executes TOML content as code.

## Planning

`planner.compile_plan` expands product or zip sweeps in declaration order. Each
point produces a render, simulate, and extract chain. One aggregate activity
depends on every extract activity.

Activity identities use canonical JSON SHA-256. Runtime-only absolute paths are
stored in payloads but excluded from identity. Logical file names and content
hashes are included. Dependency IDs transitively carry upstream inputs into
downstream identities.

The saved plan contains complete activities and can be replayed without
reinterpreting a changed manifest.

## Execution sandboxes

Each activity receives a unique temporary directory below the store. Dependency
artifacts are copied from verified cache entries. Render verifies source hashes
again, preventing a file changed between planning and execution from being
published under an obsolete key.

Simulator execution uses `asyncio.create_subprocess_exec`. The process receives
an allowlisted environment and the activity sandbox as cwd. Timeout first sends
terminate, waits for a short grace period, then kills. Cancellation follows the
same cleanup path.

Extraction accepts finite JSON numbers only. Aggregation restores sweep point
order before writing stable JSON and CSV.

## Scheduling

The scheduler maintains status by immutable activity ID. An activity becomes
ready only after all dependencies are `succeeded` or `cached`. A failed or
skipped dependency skips descendants. The global job semaphore and named
resource semaphores are acquired before executor entry and always released in
reverse order.

All cache entries are verified before scheduling. A fully cached second run
therefore records cache outcomes without launching processes.

## Artifact store

Every cache entry contains:

```text
cache/<activity-id>/
  manifest.json
  files/<declared artifacts>
```

The manifest includes the complete activity description plus artifact names,
sizes, and hashes. Publication builds a sibling temporary directory and uses an
atomic rename only after validation. Materialization refuses an invalid entry.

## Journal and recovery

Events carry a monotonic sequence number, UTC timestamp, state, activity ID,
message, and optional duration. Each append is flushed and fsynced. Replay
requires contiguous sequence numbers and valid JSON except for one incomplete
final record.

Cache verification is the source of truth during resume. A prior `started`
event without a valid published artifact causes the activity to run again. A
successful event with a corrupt artifact is also rerun.

Run locks record host, PID, a random nonce, and an operating-system process
start marker. This distinguishes a live owner from a reused PID. Same-host
stale locks are recovered automatically; unknown and foreign-host ownership is
conservative. Forced operator unlocks append an fsync-backed audit record
before removing the lock.

The lock is a directory containing one nonce-named owner marker. Context-manager
release removes only its own marker and then removes the directory only if empty,
so an older owner cannot unlink a successor after an audited forced unlock.
Persisted plan, journal, owner, and cache JSON rejects duplicate keys and
non-standard finite constants; saved activity and plan fingerprints are
recomputed before execution.

Activity decoding also cross-checks operational payloads: render paths and
copies are bound to input digests, simulator executable, environment, and
measure fields are bound to its identity, and extraction or aggregation data
is bound to the declared point and measure identity.

## Public API

- `load_manifest(path)` validates TOML and local inputs.
- `compile_plan(manifest)` creates the immutable graph.
- `Runner.run(manifest_or_plan)` creates a new journal and executes.
- `Runner.resume(run_id)` replays the saved plan.
- `Runner.status(run_id)` summarizes journal state.
- `Runner.collect(run_id)` returns aggregate rows.
- `Runner.explain(activity_id)` reports cache evidence.
