# RC PVT/parameter reference

`ngspice.toml` is the real-simulator workflow. It sweeps a resistor process
scale, supply-voltage context, temperature, nominal resistance, and
capacitance. The passive transfer function is intentionally simple and does
not represent a PDK or silicon result.

`offline-mock.toml` exercises the identical cross-tool data contract with
SimCairn's deterministic analytic mock. Its values are project-generated
fixtures, not ngspice measurements.

Every successful aggregate writes `regression-bundle.json`, a version-2
Regressistor measurement bundle. Measurement units come from the manifest;
case values are the canonical sweep strings and sample is integer zero. The
bundle binds the imported SimCairn package tree, packaged validator module,
and simulator-adapter implementation. Version-1 bundles are intentionally
rejected because they lack this producer identity.
