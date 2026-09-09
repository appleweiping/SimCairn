# Contributing

## Development

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
ruff check .
ruff format --check .
pytest --cov=simcairn --cov-report=term-missing
python -m build
```

## Requirements

- Keep runtime dependencies at zero unless a focused issue demonstrates why a
  dependency is necessary and maintainable.
- Never construct shell command strings. Simulator invocation must remain an
  argv list passed to a non-shell process API.
- Include all result-affecting state in an activity fingerprint.
- Treat cache manifests and journals as untrusted persisted data.
- Add deterministic tests for cache hit, miss, corruption, failure, and resume.
- Use only original synthetic decks and fixtures with no PDK or proprietary
  model content.
- Update public documentation and the changelog when contracts change.

Open an issue before introducing an adapter, manifest schema field, or persisted
format. Pull requests should report exact commands actually run and identify
cross-platform behavior. Contributors must follow the Code of Conduct.

## Developer Certificate of Origin

Every pull-request commit must certify the
[Developer Certificate of Origin 1.1](https://developercertificate.org/) with a
`Signed-off-by` trailer whose name and email match that commit's author. Git can
add it automatically:

```bash
git commit --signoff -m "Describe the change"
```

The DCO workflow checks every commit independently. Amend and re-sign a commit
instead of adding one blanket sign-off in the pull-request description. Repository
rules should require the immutable `DCO / commits` status published on the pull-request
head; the workflow runs only code from the trusted base revision and never checks out
contributor-controlled code.

The verifier binds the base repository, ref and SHA together with the head SHA and
declared commit count before and after paginated metadata download and again before
publishing its result. Retarget edits rerun the workflow and reset the event head to
pending. Because a `pull_request_target` workflow cannot trust code introduced by its
own bootstrap pull request, manually review every bootstrap commit's sign-off, merge
the verifier, confirm `DCO / commits` on a follow-up pull request, and only then make
that context required on protected `main`. Do not publish 0.4.0 before this rollout.

## Release integrity

Release tags are annotated SSH-signed tags. The release workflow accepts only
keys from the signer policy on trusted `main`, verifies both the tag and GitHub's
release-commit signature, requires the tagged commit to be on `main`, and waits for
a successful `push` CI run on that exact `main` commit. A release contains exactly
one wheel, one source archive, `SBOM.spdx.json`, and `SHA256SUMS`. The pinned Syft
SBOM's required document-header profile and release-specific file relationships bind
the isolated installed wheel, its exact RECORD set, and the console launcher with
SHA-1 and SHA-256; this is not a general SPDX conformance claim. Checksums are
revalidated before build provenance attestation and immutable publication. The source
archive carries its frozen lockfile, workflow evidence, and tests; release CI safely
unpacks the audited archive and reruns its full test suite from that archive. Changing an
allowed signer is a security-sensitive review.
