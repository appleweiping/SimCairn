# Synthetic SRAM-like Xyce example

This example exercises SimCairn's structured Xyce characterization contract
over three process/voltage/temperature corners and five analysis families. The
six-transistor level-1 deck and its parameters are educational fixtures; they
are not extracted from a PDK, OpenRAM, a memory compiler, or measured silicon.

Run it only when a real Xyce executable is installed:

```bash
mkdir -p build
simcairn characterize-xyce examples/xyce_sram/characterization.json \
  --output build/xyce-sram-report.json
```

The command creates a content-addressed cache and a no-clobber report. See
[`docs/xyce-characterization.md`](../../docs/xyce-characterization.md) for the
plan schema, evidence boundary and controlled-test-double policy.
