# Benchmarks

The ngspice 42 reference covers 32 RC cases. The GF180 and SKY130 records each
cover a real 27-point TT/SS/FF × voltage × temperature common-source
characterization and use the same producer-bound
`regressistor.measurement-bundle/2` contract.
Runtime is reported as observed wall-clock evidence, not a performance
guarantee. See the JSON manifests for exact commands, provenance, expected
point counts, simulator identity, producer wheel and source identities,
validation entrypoint identity, and artifact hashes. `validation_implementation_sha256`
names the packaged `simcairn/reference.py` bytes; each manifest separately
binds the actual benchmark entrypoint script used with that implementation.

The checked-in bundles are immutable historical observations. A fresh
comparison must identify the currently imported SimCairn source and match the
aggregate activity compiled from its current fixed run manifest. Numeric
points, units, and case identities are then compared with the historical
bundle; historical producer and activity identities are verified against their
sidecars rather than falsely replaced with current values.

The `Replay real references` Actions workflow is deliberately manual. It
builds the selected commit into a clean wheel and replays RC, SKY130A, and
GF180MCU on Ubuntu 24.04 with ngspice 42. PDK jobs acquire only content-pinned
Ciel assets, scan every tar member, and materialize only the small regular-file
allowlist in `ciel-assets.json`. Reports are temporary workflow artifacts; the
workflow has no write permission and no path points at the checked-in results.
See [`docs/real-reference-replay.md`](../docs/real-reference-replay.md) for the
trust anchors, evidence boundary, and manual procedure.

`benchmark_xyce_characterization.py` measures strict JSON validation and deck
compilation for the synthetic SRAM-like plan. It does not invoke a simulator or
report physical performance:

```bash
python benchmarks/benchmark_xyce_characterization.py --iterations 100
```
