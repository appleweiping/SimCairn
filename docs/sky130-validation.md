# SKY130 real-simulator validation record

On 2026-08-31 the generated 27-point configuration was run with ngspice 42
(KLU) and the pinned Ciel SKY130A release. The authoritative input was
`BiasWeave/benchmarks/sky130-sizing-decision.json`, decision digest
`b2c8682f543233727c395d9ce5b260a3201c9ebbaf71b97085add08eaf6393d8`.

SimCairn plan `16c58dafaf31b7f6eec3da35250076452ce3723f7b9b42773014817ce0667395`
completed with 82 successful activities and no failures. Collection produced
27 rows. Its aggregate activity is
`12fd500280c8efe2e52959353ce7d5e8e77d4fe78e2569d0135281becd18b5f3`.
The checked-in bundle `benchmarks/results/ngspice-42-sky130-pvt.json` has
SHA-256 `155b2d1d2e3eed4196b170a06d5bbaff7edd9fd011b0af060139db695e26e5dc`
and passed the exact PVT product and electrical-invariant validator.

| Measure | Minimum | Maximum |
|---|---:|---:|
| output_v | 1.17083 V | 1.90003 V |
| output_pp_v | 0.00311158 V | 0.00820282 V |
| gain_100khz | 1.55579 | 4.10141 |
| supply_current_a | 5.16028e-6 A | 3.04816e-5 A |
| power_w | 8.35966e-6 W | 6.03536e-5 W |

Artifact SHA-256 values from that run:

| Artifact | SHA-256 |
|---|---|
| simcairn.toml | `e56598b0875a9820af63a60ea864d679b0d7cae27543818d4b236df9c439e5a8` |
| deck template | `2ee7ce34f163ea07f60ddb82525b7d2ebccd1a0049ee54b8cfb443820f020a86` |
| PDK provenance | `0282934f73c4693ac892cae147b7df21ae5a60905116a2ce96c27598fbf25ec1` |
| collected rows | `15f76f3d66c3de040089ddba4be5148658b9fc57e64ea7dd9d4ccccf660a56d4` |
| collected CSV | `02cff00cf22c82490051cfacd1f386f2926db169f8accc0422cc87d7fedb5147` |
| run report | `d65a27f1220ce62e52bb2fc41b226b1e7b5be6ee1253b78797c12af9f977c4d3` |
| regression bundle | `155b2d1d2e3eed4196b170a06d5bbaff7edd9fd011b0af060139db695e26e5dc` |

The simulator adapter identity was `simcairn-ngspice/2:ngspice-42`; the
`/usr/bin/ngspice` executable hash was
`820658317b0b54035208da41936fd6871ce924036e5ea4113a4168b821b7fc45`.
`benchmarks/sky130-manifest.json` records the official Ciel asset hashes,
installed nodeinfo hash, every selected model hash, platform, and full command.

The real run used the frozen SimCairn 0.2.0 wheel with SHA-256
`35cb0d7aa3aebff1459d8c5ee1936c0aab47de462f8e66b61fceb3a027c0dbff`.
This digest identifies the validation-run archive. Release wheels are bound by
recomputing the same package-tree, validator, and adapter identities rather than
by assuming ZIP archives are byte-for-byte reproducible.
The producer-bound bundle records package-tree SHA-256
`8abfa550a6b576a176d3d81bb251d6d1cdefc440a32a6cf75911e4ab3ad702d0`,
`simcairn/reference.py` SHA-256
`90e27f73e3261bc58646bb49d8310d524afa29899a7a5523d789f383329ef4c4`,
and adapter implementation SHA-256
`aaa76bb2654444ba0b5e8aee7c1e5908f9146c705c84aa6f766168d45eda6c4e`.
The manifest separately binds `benchmarks/validate_sky130.py`, the entrypoint
that invoked the packaged validation implementation.

These results are reproducibility evidence for the software path, not circuit
specifications, PDK sign-off, or silicon measurements.
