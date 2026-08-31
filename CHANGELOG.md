# Changelog

All notable changes are documented here. Versions follow Semantic Versioning.

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
