## Summary

## Manifest/API and compatibility impact

## Fingerprint and recovery impact

## Verification

- [ ] Every commit has an author-matching `Signed-off-by` DCO trailer.
- [ ] `ruff check .`
- [ ] `ruff format --check .`
- [ ] `pytest --cov=simcairn --cov-report=term-missing`
- [ ] `python -m build`

## Safety

- [ ] Subprocesses use argv arrays and never a shell command string.
- [ ] Cache keys include all result-affecting state.
- [ ] Fixtures are original and contain no proprietary data.
- [ ] Failure, corruption, and resume paths have deterministic tests.
