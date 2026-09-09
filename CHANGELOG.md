# Changelog

All notable changes are documented here. Versions follow Semantic Versioning.

## [0.4.0] - 2026-09-08

### Added

- A real, argv-only Xyce executable adapter and a strict PVT characterization API/CLI covering
  operating-point, DC, AC, transient and noise analyses.
- Content-bound model/waveform inputs, deterministic characterization cache keys, normalized
  Xyce/ngspice trace tables, no-clobber reports and complete provenance artifacts.
- An original synthetic SRAM-like example and a non-simulation plan/render benchmark.

### Safety

- Content-addressed characterization publishers now take a nonce-owned per-key claim and use
  native atomic no-replace rename operations; even a non-cooperating local racer cannot have
  an existing destination replaced.
- Pull requests require an author-matching DCO sign-off on every commit. Releases require an
  SSH-signed annotated tag from the trusted-main signer policy and an exact successful main-push
  CI run. The pinned Syft SPDX 2.3 release profile binds the isolated wheel RECORD and launcher;
  an exact four-asset set is checksum-verified before provenance and publication.
- Source distributions carry the frozen dependency lock and trusted workflow evidence and are
  safely unpacked and fully retested after their archive shape passes validation.
- Xyce stdout, stderr, logs, tables, rows, columns, run count and execution time are bounded;
  timeout, cancellation and overflow terminate and reap the process tree.
- External include/library/file references are transitively declared and hashed. Cache hits
  revalidate confined artifacts, execution identity and normalized content from the raw table
  before reuse. Plan, deck and recursive inputs share one immutable execution snapshot.
- Trace probes require dimensionally correct units, DC evidence must contain its observed axis,
  and all simulator adapters share bounded output capture and process-tree cleanup.
- Structured DC plans now require a physical `axis_expression` that is emitted by `.PRINT` and
  matched exactly during normalization. Manifest Xyce runs bind `measure_analysis` and select
  the documented `.mt0`, `.ms0`, or `.ma0` output family without filesystem guessing.
- Manifest Xyce runs require every requested result to have unique, finite and numerically
  consistent positive evidence in the complete `Measure Functions` log section. Explicit
  `FAILED` diagnostics, suppressed/ambiguous evidence and step-indexed scalar output fail closed,
  so a numeric `MEASFAIL=0 DEFAULT_VAL=0` value cannot be published as measured cache evidence.
  The scalar-adapter identity was advanced so caches from the earlier acceptance profile are not
  reused.
- DCO pagination is unique, count-bound and required to terminate at the exact pull-request head;
  the trusted-base gate also binds base repository/ref/SHA and resets status on retarget edits.
- Controlled executable fixtures carry a distinct evidence class and cannot masquerade as real
  circuit results.

## [0.3.0] - 2026-09-07

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
- Current-reference entrypoints that bind a fresh bundle to the currently imported source and
  fixed current plan while preserving the identities of frozen 0.2.0 observations.
- An authenticated manual replay of the frozen RC, SKY130A, and GF180MCU references using a
  freshly built wheel, exact Ciel assets, ngspice 42, and bounded verification evidence.
- A reusable distribution audit that rejects ambiguous, unsafe, or incomplete wheel and sdist
  archive shapes before release.

### Changed

- New run IDs use a 128-bit generation suffix instead of recycling the lowest numeric suffix.
  Existing numeric run IDs remain readable. This prevents an old collection plan from naming a
  different run created later and removes the concurrent same-plan allocation race.

### Safety

- A run is protected unless its lock is positively stale. A lock held on another host, or one
  whose owner cannot be identified, counts as live.
- A run whose `plan.json` will not parse blocks cache collection entirely. Keeping that run is
  not sufficient on its own: its activity list comes back empty, which reads exactly like
  "refers to nothing", and acting on that would orphan and delete the whole cache.
- Unreadable cache entries are retained as evidence by default rather than swept up.
- A collection plan is re-checked as it is applied: a run that acquired a lock is skipped,
  surviving plans are reloaded before cache deletion, and newly protected work is retained.
- Run registration and lock acquisition use a cross-platform reader/writer barrier with
  collection. Abandoned readers are reaped only when ownership is provably stale or their
  unpublished directory is empty; uncertain ownership fails closed.
- Every deletion target and store-area root is validated before mutation and again under the
  writer lease. Path traversal, symbolic-link and junction redirection are refused.
- Scheduler cancellation drains every child activity before releasing the run lock. Lock
  acquisition remains owned through repeated cancellation and event-loop shutdown, so a worker
  result is either propagated or its acquired lock is released.
- Work sandboxes are removed only when no run holds a live lock, since a sandbox records no
  owner.
- Directory sizing ignores symbolic links rather than following them, so a link out of the
  store can neither inflate a total nor be walked into.
- Windows process start markers use the native kernel API instead of a child PowerShell process;
  current-process markers are cached by PID without caching arbitrary owners' liveness.
- Real-PDK replay authenticates every archive member before selective materialization, pins all
  executable inputs by digest, proves a canonical clean checkout, and never uploads PDK content.

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
