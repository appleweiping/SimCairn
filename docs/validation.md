# Validation and reference evidence

The RC PVT reference has two explicitly separated evidence classes:

- `examples/rc_pvt/ngspice.toml` runs an installed ngspice executable.
- `examples/rc_pvt/offline-mock.toml` uses the repository's analytic mock and
  provides deterministic offline fixtures when ngspice is unavailable.

The machine contract is `regressistor.measurement-bundle/2`. Its artifact is
strict JSON with `schema_version`, producer metadata, ordered points, canonical
sweep cases, sample IDs, finite metric values, and manifest-declared units.
Every plan and bundle binds the actual imported SimCairn version, a
path-independent SHA-256 of every imported package Python source file, the
packaged `simcairn/reference.py` validation implementation, and the simulator
adapter implementation. Version-1 bundles are rejected fail closed: they do
not carry this producer identity and cannot be upgraded by relabeling.
Regressistor validates the artifact again rather than trusting SimCairn.
The recorded aggregate activity ID is a transitive content address: it binds
the extract dependencies, which bind simulator identity, rendered input
digests, environment, requested fields, and measurement units. It is not a
hash of the bundle containing itself.

CI always runs the offline tests. Its dedicated reference job uses the fixed
`ubuntu-24.04` runner image and fails unless the distribution-installed
simulator identifies itself as ngspice major version 42, then runs
the full 32-point workflow and compares its numeric bundle with the checked-in
reference. The simulator identity is part of the aggregate activity ID, so a
different binary version cannot be accepted merely because its numbers happen
to be close.

The checked-in ngspice-42 reference is reproducible with the version and Linux
platform recorded in the benchmark manifest. Its producer identity and
aggregate activity ID remain immutable historical provenance, and the sidecar
manifest binds both of them plus the bundle and verifier hashes. They are not
rewritten when SimCairn changes.

`benchmarks/verify_current_reference.py` independently requires the fresh bundle to
identify the SimCairn implementation currently imported by the verifier and to
match the aggregate activity ID compiled from the fixed current manifest. It
then compares every case/sample identity, unit, and value with the frozen
reference at a relative tolerance of `1e-6`. Current and historical producer
or activity identities are intentionally not required to be equal: source and
content addresses legitimately change across releases. This separation keeps
both claims checkable without relabelling old measurements as new ones.

The manifest records the verifier entrypoint's own SHA-256; the producer field
`validation_implementation_sha256` refers specifically to the packaged
`simcairn/reference.py` bytes rather than claiming to cover the entrypoint.
The `producer_distribution` wheel digest records the exact wheel used for the
historical reference run. Each later release independently recomputes the
new wheel's package-tree, validator, and adapter identities from the checked-out
source, installs that wheel for a smoke test, and requires real-ngspice CI on
the exact release commit.

The numeric tolerance covers insignificant repeat-run rounding and is not an
electrical acceptance limit. The CI package source is distribution-managed,
but the explicit simulator-version gate prevents an unnoticed runner-image
upgrade from being treated as reference evidence.
