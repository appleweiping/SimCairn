# SKY130 sizing-decision materialization

This example is generated offline because Apache-2.0 PDK model files are not
vendored in this repository. It turns a verified BiasWeave sizing decision into
a self-contained SimCairn configuration whose copied model bytes participate in
the plan and cache digests.

```console
simcairn configure-sky130 ../BiasWeave/benchmarks/sky130-sizing-decision.json configured \
  --expected-topology TL-00052f7b8c5e \
  --expected-signature 086ce3f4158fa05ea8fddf2e7552af1d9774f95faffbe4dee11fae262d8857c8 \
  --expected-decision-sha256 b2c8682f543233727c395d9ce5b260a3201c9ebbaf71b97085add08eaf6393d8 \
  --expected-benchmark-sha256 7f128312cad0b25b73a0c73e19ebd3fed8841428a237a8145f4d9699d3989214 \
  --expected-comparison-sha256 0b265d1236aa3d273dc68e772f14c9002eaa2cf99a8feb3dfc11d747a059d267 \
  --pdk-root /opt/pdks/sky130A
simcairn validate configured/simcairn.toml
simcairn run configured/simcairn.toml --store configured/.simcairn
```

The expected digests are trust anchors obtained through the release or review
channel, not values copied from an untrusted decision at run time. The PDK path
may be a Ciel `sky130A` symlink, but it must resolve inside the
pinned release. SimCairn checks the release metadata and each required model
against built-in hashes. It never downloads a PDK and never accepts digest
claims from the command line.

The materialized circuit is a common-source reference characterization, not a
claim that it implements the selected TopologyLantern topology. Width and
length map directly to the MOS instance. Compensation maps to its load
capacitance. Bias maps deterministically to a resistor using `R = 0.75 V / I`,
so 50 uA gives 15 kohm. This is a reproducible integration heuristic, not the
optimizer's analytic physics or a silicon specification.
