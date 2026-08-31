# GF180MCU real-simulator validation record

On 2026-08-31 the content-pinned GF180MCU configuration was run through all
27 TT/SS/FF × 2.97/3.30/3.63 V × -40/27/125 °C points with ngspice 42 and
the KLU solver. Plan
`6e4b875410387ad3868451b8135dbebbfed64485faebbb6d22c3e4fcd300ac32`
completed all 82 activities without a failure. The aggregate activity is
`7a45b6055af057e35acab4f10b9a56ba3e469dc0af48e65865155abc432de6f6`.

The checked-in measurement bundle is
`benchmarks/results/ngspice-42-gf180-pvt.json` (SHA-256
`f4e4b661eb1a141d17d66e785b55d93a0110524d1d3173f390e71408d7866fbc`).
It passed the exact-product, metric/unit, finite-value, output-rail, gain,
current, and power consistency checks in `benchmarks/validate_gf180.py`.

The real run used the frozen SimCairn 0.2.0 wheel with SHA-256
`35cb0d7aa3aebff1459d8c5ee1936c0aab47de462f8e66b61fceb3a027c0dbff`.
This digest identifies the validation-run archive. Release wheels are bound by
recomputing the same package-tree, validator, and adapter identities rather than
by assuming ZIP archives are byte-for-byte reproducible.
The bundle binds package-tree SHA-256
`8abfa550a6b576a176d3d81bb251d6d1cdefc440a32a6cf75911e4ab3ad702d0`,
`simcairn/reference.py` SHA-256
`90e27f73e3261bc58646bb49d8310d524afa29899a7a5523d789f383329ef4c4`,
and adapter implementation SHA-256
`aaa76bb2654444ba0b5e8aee7c1e5908f9146c705c84aa6f766168d45eda6c4e`.
The manifest separately binds the actual `benchmarks/validate_gf180.py`
entrypoint SHA-256, so the packaged validation implementation and its invoking
script are not conflated.

| Measure | Minimum | Maximum |
|---|---:|---:|
| output_v | 0.233442 V | 3.0636 V |
| output_pp_v | 0.00237312 V | 0.0239693 V |
| gain_100khz | 1.18656 | 11.9847 |
| supply_current_a | 1.65503e-5 A | 9.52725e-5 A |
| power_w | 4.91545e-5 W | 3.45839e-4 W |

The official Ciel revision is
`1689ac3f2dc763876eaf967227c7dfe831b031ae`. The downloaded
`common.tar.zst` and `gf180mcu_fd_pr.tar.zst` hashes are respectively
`256586ecaea68886ce57942d83a86f82e6e1bc081badf6c9c9b70755f3456a41`
and `6b26fbf4aed755bddefcdb3610f5f957cc0a8a019e72c3abc9c611f9947d1f62`.
Installed `nodeinfo.json` hashes to
`8b96003d04744651f80946144035a78ed8862c25e87e879c4ee573bee08f7705`.
The actual copied model hashes and all other evidence are recorded in
`benchmarks/gf180-manifest.json`.

The model cache is portable: a second configuration generated under a
different output root contained the same nine files with byte-identical
SHA-256 values. Neither the generated deck nor PDK provenance contains an
absolute host path. The local model bytes remain Apache-2.0 PDK material and
are intentionally not committed.

This record validates the software integration and reproducible measurement
path. It is not foundry sign-off, a circuit-performance specification, or
silicon data.
