# Contributing

## Development Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Checks

```bash
make lint      # ruff check
make typecheck # mypy --strict
make test      # pytest (all tests)
make test-cov  # pytest with coverage (99%+ required)
```

## Code Style

- Python 3.12+; 88-char lines; ruff with rules E, F, UP, B.
- All public functions must have typed signatures.
- No circular imports. `models.py` must stay import-free (leaf module).

## Pull Requests

1. Branch from `main`.
2. Add tests for any new functionality.
3. Ensure `make test` and `make typecheck` pass.
4. Keep coverage at 99%+.
5. Update CHANGELOG.md.

## Releasing

1. Update version in `pyproject.toml`.
2. Add entry to CHANGELOG.md.
3. Tag with `v<version>`.
4. Push tag to trigger the release workflow.
