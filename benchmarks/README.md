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
