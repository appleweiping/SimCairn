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
