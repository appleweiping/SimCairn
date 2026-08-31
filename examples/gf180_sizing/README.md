# GF180MCU sizing-decision materialization

The foundry PDK is intentionally not vendored. Install the pinned Ciel release,
then generate a self-contained local run directory:

```console
simcairn configure-gf180 ../BiasWeave/benchmarks/sky130-sizing-decision.json configured \
  --expected-topology TL-00052f7b8c5e \
  --expected-signature 086ce3f4158fa05ea8fddf2e7552af1d9774f95faffbe4dee11fae262d8857c8 \
  --expected-decision-sha256 b2c8682f543233727c395d9ce5b260a3201c9ebbaf71b97085add08eaf6393d8 \
  --expected-benchmark-sha256 7f128312cad0b25b73a0c73e19ebd3fed8841428a237a8145f4d9699d3989214 \
  --expected-comparison-sha256 0b265d1236aa3d273dc68e772f14c9002eaa2cf99a8feb3dfc11d747a059d267 \
  --pdk-root /opt/pdks/gf180mcuC
simcairn validate configured/simcairn.toml
simcairn run configured/simcairn.toml --store configured/.simcairn
```

Obtain the expected hashes through a reviewed release or another authenticated
channel; copying them out of an untrusted decision defeats their purpose. The
PDK path may be a `gf180mcuC` symlink but must resolve inside the pinned Ciel
revision.

Width and length map directly to the 3.3 V NMOS instance. Compensation maps to
load capacitance. Bias maps to `R = 1.65 V / I`, the nominal half-supply drop,
so 50 µA gives 33 kΩ. The fixed 1.0 V gate bias is a reproducible integration
heuristic. This circuit does not claim to implement the selected
TopologyLantern topology or reproduce BiasWeave's proxy physics.
