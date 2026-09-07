# Changelog

All notable changes are documented here. Versions follow Semantic Versioning.

## Unreleased

### Added

- `simcairn store-status`: what the store holds, broken down by cache, runs and work, with
  entry counts, sizes, how many entries no run refers to any more, and how many cannot be read.
- `simcairn store-verify`: re-hash every published cairn against its manifest. Bit rot in a
  cached artifact is otherwise noticed only when a run silently reuses it. Exits 3 on any
  mismatch.
- `simcairn store-gc`: reclaim space, reporting a plan by default and removing only with
  `--apply`. `--keep-runs` sets retention, `--include-unreadable` allows sweeping up damaged
  entries, and `--keep-work` leaves sandboxes alone.
- `journal.run_lock_state`: read a run lock without changing it. `clear_run_lock` already
  decided whether an owner was stale, but decided it in order to remove the lock; anything that
  needs to know whether a run is busy must be able to ask without changing the answer.
- `simcairn.maintenance` as a Python API: `survey`, `verify_all`, `plan_collection`,
  `apply_collection`, and `directory_bytes`.

### Safety

- A run is protected unless its lock is positively stale. A lock held on another host, or one
  whose owner cannot be identified, counts as live.
- A run whose `plan.json` will not parse blocks cache collection entirely. Keeping that run is
  not sufficient on its own: its activity list comes back empty, which reads exactly like
  "refers to nothing", and acting on that would orphan and delete the whole cache.
- Unreadable cache entries are retained as evidence by default rather than swept up.
- A collection plan is re-checked as it is applied, so a run that acquired a lock after the
  plan was made is skipped rather than removed.
- Work sandboxes are removed only when no run holds a live lock, since a sandbox records no
  owner.
- Directory sizing counts symbolic links as links rather than following them, so a link out of
  the store can neither inflate a total nor be walked into.

## [0.2.0] - 2026-08-31

- Added manifest-declared measurement units and the strict, producer-bound
  `regressistor.measurement-bundle/2` aggregate artifact. Version-1 bundles
  are rejected fail closed because they do not identify the implementation
  that produced and validates their measurements.
- Added a 32-point RC PVT/parameter reference with separate offline-mock and
  real-ngspice validation evidence.
- Added externally anchored, content-pinned SKY130A and GF180MCU 27-point PVT
  configuration flows with portable provenance.
- Added distribution-derived runtime versioning and a frozen, attested release pipeline.

## [0.1.0] - 2026-08-31

### Added

- Strict TOML manifests, product/zip sweeps, and safe deck templates.
- Immutable content-addressed render, simulate, extract, and aggregate plans.
- Bounded async scheduling with named resource limits.
- Mock RC and ngspice subprocess adapters.
- Atomic artifact cache, append-only journal, resume, status, and explain.
- JSON/CSV collection, synthetic example, and cross-platform tests.

### Fixed

- Bounded the scheduler's queued work so fail-fast leaves unscheduled branches
  untouched after the first observed failure.
- Rejected impossible resource requests, case-variant artifact collisions, and
  malformed aggregate records before execution or publication.
- Tightened ngspice measurement parsing and versioned its adapter identity.
- Bound every persisted activity payload to its content identity and rejected
  malformed, duplicate-key, and non-finite persistent JSON.
- Replaced file-lock release with a nonce-marker directory protocol so a stale
  owner cannot remove a successor's lock.
