# Xyce PVT characterization

SimCairn can compile a strict characterization plan into one Xyce run per
process-voltage-temperature corner and analysis. The workflow is intended for
repeatable circuit characterization, including SRAM-like cells, without
embedding a technology kit in the package.

The adapter invokes Xyce directly as an argv array. It never uses a shell. It
probes `Xyce -v`, hashes the executable and any wrapper files, fixes the random
seed, bounds stdout, stderr, the Xyce log, the result table, rows, columns and
run count, and terminates the process tree on timeout or cancellation. Xyce
7.10 is the current tested command-line contract; see the official
[Xyce documentation](https://xyce.sandia.gov/documentation-tutorials/) and
[7.10 Reference Guide](https://xyce.sandia.gov/download/2068/?tmstv=1754510749).

## Synthetic example

The checked-in [`examples/xyce_sram`](../examples/xyce_sram) circuit is an
original educational six-transistor SRAM-like deck using level-1 MOS models.
It is not a foundry model, silicon evidence, or an OpenRAM golden result.

With a real Xyce executable installed:

```bash
mkdir -p build
simcairn characterize-xyce examples/xyce_sram/characterization.json \
  --xyce Xyce \
  --cache .simcairn-characterization \
  --output build/xyce-characterization.json
```

Both the cache parent and report parent must already exist and be canonical
directories. An existing report is never overwritten. A successful example
contains 15 executions: three PVT corners times OP, DC, AC, transient and noise
analyses.

Tests use a controlled executable that emits deterministic tables without
solving circuit equations. Its version banner and every resulting report say
`controlled-test-double`; SimCairn refuses to label that fixture as real. Such
tables test orchestration and normalization only and must not be cited as
electrical results. Conversely, `real` is a caller assertion bound to the
probed executable bytes, not a certification of the binary's publisher.

## Plan contract

A plan is duplicate-key-free JSON with schema version 1. It names a UTF-8 deck,
optional content-bound inputs, PVT corners, analyses and resource limits. Two
exact marker lines are replaced:

```spice
* SIMCAIRN:PVT
* SIMCAIRN:ANALYSIS
```

PVT values are injected only as finite numeric `.PARAM` and `.TEMP` cards.
Analysis names, sources, nodes and probes use closed grammars. AC and noise
outputs must use explicit scalar forms such as `VM(q)`, `VDB(out)`, `IR(VDD)`,
`ONOISE` or `INOISE`; ambiguous complex-valued `V()` and `I()` probes are
rejected for frequency analyses.

Supported analysis objects are:

- `op`, with one result row;
- `dc`, sweeping an independent voltage or current source and requiring an
  `axis_expression` that Xyce prints as the observed physical sweep coordinate;
- `ac`, with `lin`, `dec` or `oct` spacing;
- `tran`, with fixed output step, start and stop times;
- `noise`, with output/reference nodes, input source and frequency sweep.

Before a simulator starts, SimCairn calculates the expected row count and
rejects a plan that exceeds its limits. A returned table must have every
requested scalar probe, the exact number of rows and the declared monotonic
axis. A DC plan emits its explicit `axis_expression` before the requested output
probes and accepts only that column as the sweep coordinate; a table that merely
has the right row count, or labels some other numeric column as an axis, fails.
Probe units are constrained by physical dimension (`V`, `A`, `W`,
`dB`, degrees, or source-dependent noise spectral density). Truncated,
dimensionally mislabeled and wrong-grid output fails closed.

For transient work, the plan's `step_seconds` is an evidence-grid interval.
Xyce itself interprets the first `.TRAN` value as an initial integration step,
not as a print interval. SimCairn therefore emits a bounded
`.OPTIONS OUTPUT OUTPUTTIMEPOINTS=...` schedule containing the exact declared
grid (including the final stop time). Xyce may still integrate adaptively
between those requested points, while the persisted table shape stays
deterministic.

### Model and waveform inputs

Every external file must appear in `inputs` using its execution-relative path.
Parsing captures one immutable byte snapshot of the plan, deck and every input.
Identity, transitive-reference validation, deck rendering and sandbox
materialization all consume that same snapshot; the original paths are checked
before execution and again before publication. Materialized inputs are verified
after Xyce exits and removed before cache publication. PDK/model contents are
therefore not copied into evidence.

SimCairn recognizes `.INC`, `.INCL`, `.INCLUDE`, external `.LIB file section`,
and direct `FILE=` references (for example a PWL waveform). Single quotes,
double quotes and bare safe paths are accepted. References in declared input
files are checked transitively; absolute paths, traversal, unlisted files and
unsupported include syntax are rejected. This closed contract intentionally
does not support external-file syntax hidden inside arbitrary behavioral
expressions: rewrite such a deck to use one of the declared forms first.

## Evidence and cache identity

The deterministic cache key covers:

- the source plan, deck and declared input hashes;
- the full corner, analysis and limit contract;
- SimCairn's current producer identity;
- Xyce version, executable hash, size, command-prefix hash and evidence class;
- an allowlisted child environment (values are represented by hashes), OS,
  architecture and Python runtime;
- the per-execution timeout.

Each execution stores the rendered deck, raw simulator table, normalized JSON,
stdout, stderr and Xyce log with sizes and hashes. The cache manifest also binds
the report. Cache hits revalidate path confinement, every artifact digest,
execution order, plan identity and canonical metadata, then reparse each raw
table and require it to reproduce the embedded and persisted normalized result. Publication
uses a reusable nonce-owned per-key claim and the operating system's native
atomic no-replace rename. The Windows, Linux and macOS implementations fail
closed when exclusive rename is unavailable. A destination created by an
untrusted local racer is never replaced; incomplete or conflicting evidence is
never silently accepted.

The normalized Python API is simulator-neutral:

```python
from simcairn.characterization import load_characterization_plan
from simcairn.xyce import XyceCommand, characterize_xyce

plan = load_characterization_plan("examples/xyce_sram/characterization.json")
report = characterize_xyce(
    plan,
    command=XyceCommand.real("Xyce"),
    cache=".simcairn-characterization",
    output="build/xyce-characterization.json",
)
```

`normalize_result_table` accepts bounded Xyce CSV or ngspice whitespace/CSV
tables and maps both to named axes, units and finite scalar traces. This
normalizes representation, not simulator physics: cross-simulator agreement
still requires equivalent device models, options and a stated numeric
tolerance.

## Scalar `.MEASURE` manifest activities

The manifest `xyce` adapter is separate from the table-based characterization
API above. It accepts one analysis family and one scalar result set per activity.
For every requested field, SimCairn requires both the finite value in Xyce's
documented `.mt0`, `.ms0`, or `.ma0` file and a unique, numerically identical
successful summary in the single complete `***** Measure Functions *****`
section of `xyce.log`. A numeric default without that positive summary is not
measurement evidence, even when Xyce exits successfully. Explicit `FAILED`
diagnostics, missing or duplicated summaries, conflicting values and additional
step-indexed result files all fail closed.

Embedded `.STEP` cards are intentionally unsupported for this adapter because
Xyce emits a separate indexed measurement file for every iteration. Put sweep
dimensions in the SimCairn manifest instead; its planner gives each point a
separate activity and cache identity.
