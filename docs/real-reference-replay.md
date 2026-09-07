# Manual real-reference replay

The `Replay real references` GitHub Actions workflow independently reruns the
three checked-in real-ngspice records. It is a diagnostic replay, never a
baseline-update mechanism. It has only `contents: read` permission, runs only
through `workflow_dispatch`, writes all generated material beneath
`RUNNER_TEMP`, and verifies that tracked, untracked, and ignored checkout state
is unchanged at the end.

## Fixed execution environment

Each matrix entry uses Ubuntu 24.04, Python 3.11.16, uv 0.11.21,
`ngspice=42+ds-3build1`, and `zstd=1.5.5+dfsg2-2build1.1`. The workflow
authenticates both downloaded Debian packages and both installed executables,
and requires the simulator banner to name ngspice 42 and the KLU solver. Every
reusable GitHub Action is referenced by a full commit SHA. It also fails unless
the requested commit is exactly the canonical `origin/main`, and unless the
initial tracked, untracked, and ignored checkout state is clean. A clean wheel
is built outside the checkout, installed into a separate environment, and used
for planning, execution, and validation.

The hosted-runner image and shared libraries remain a moving operating-system
surface. The report therefore records the kernel, package, executable hashes,
linked libraries, Python, uv, ngspice, and zstd identities. Numeric comparison
against the frozen bundle is the final behavioral gate; this is intentionally
not presented as a bit-hermetic container build.

## Ciel acquisition and extraction

Both PDK families use Ciel revision
`1689ac3f2dc763876eaf967227c7dfe831b031ae`. The machine-readable lock is
[`benchmarks/ciel-assets.json`](../benchmarks/ciel-assets.json). Its exact
SHA-256 is also embedded in `simcairn.pdk_replay`, so a release-API response or
an edited JSON file cannot redefine trust. The lock fixes the Ciel repository
numeric ID, release and asset IDs, compressed size and SHA-256, decompressed
tar size and SHA-256, and every selected member's canonical path, size, and
SHA-256.

The source endpoints are the official Ciel release repository and GitHub REST
API:

- <https://github.com/fossi-foundation/ciel-releases>
- <https://api.github.com/repos/fossi-foundation/ciel-releases/releases/tags/sky130-1689ac3f2dc763876eaf967227c7dfe831b031ae>
- <https://api.github.com/repos/fossi-foundation/ciel-releases/releases/tags/gf180mcu-1689ac3f2dc763876eaf967227c7dfe831b031ae>
- <https://docs.github.com/en/rest/releases/releases#get-a-release-by-tag-name>
- <https://docs.github.com/en/rest/releases/assets#get-a-release-asset>

The downloader rejects automatic or relative redirects, permits at most one
explicit HTTPS redirect to a GitHub asset host, and removes authorization on a
cross-host redirect. It rejects response content encoding, overlong bodies,
and every metadata, size, or digest difference. Ciel currently reports both
fixed releases as mutable; the independently committed byte hashes are
therefore authoritative, not the release tag or API digest.

After authenticating the compressed body, the helper runs zstd without a shell
or credential-bearing environment and supervises the entire process with a
hard deadline. It first bounds and authenticates the complete raw tar, then
scans every member before materializing any file. Absolute paths, traversal,
control characters, invalid or non-normalized Unicode, Windows drive or
backslash paths, links, sparse or special files, duplicate or normalized
case-folding names, file/directory prefix collisions, excessive names, and
over-limit members all fail closed. Only the exact node metadata and simulator
model files listed in the lock are copied to the temporary PDK tree. Archives,
models, configured decks, and the SimCairn cache are never uploaded.

The selected SKY130 model source is Apache-2.0 at
<https://github.com/fossi-foundation/skywater-pdk-libs-sky130_fd_pr/blob/403964dc7f9cca5ec1a8cc7b4f2a6f532b781676/LICENSE>.
The selected GF180MCU model source is Apache-2.0 at
<https://github.com/fossi-foundation/globalfoundries-pdk-libs-gf180mcu_fd_pr/blob/4d0b4cef59c7686fac5fd3f4c6fb41d251d1f90c/LICENSE>.
Only the selected files are described here; no blanket licensing claim is
made for unselected bytes in the upstream archives.

## Decision and comparison binding

The PDK jobs fetch the sizing decision from an exact BiasWeave commit. The raw
file size and SHA-256 are verified before parsing, then its canonical decision
digest, topology, topology signature, benchmark digest, and comparison digest
are checked independently. The generated manifest is compiled again with the
installed current wheel. A fresh bundle must identify that imported wheel and
the current aggregate activity, while the frozen bundle remains bound to the
historical producer and activity recorded by its sidecar.

The current validators compare the exact case/sample product, metric names,
units, and finite numeric values with the historical observation. The report
also records exact changed-value count and maximum absolute and relative drift;
this prevents a tolerance-only pass from being mistaken for byte-identical
numeric output.

## Artifacts and interpretation

Each successful matrix job uploads only these bounded files for seven days:

- current measurement bundle;
- current compiled plan and run report;
- environment record and wheel SHA-256;
- replay summary;
- for PDK jobs, download/extraction provenance without PDK bytes.

Artifact names include the case, source commit, and workflow attempt, and
overwrite is disabled. A replay result is software-path reproducibility
evidence. It is not foundry sign-off, a circuit specification, or silicon
measurement.
