# Dependencies

## Runtime

| Package | Version | Required | Condition | Purpose |
|---------|---------|----------|-----------|---------|
| `typer` | ≥0.12 | Yes (CLI) | — | CLI argument parsing for `bitcoin extract` etc. |
| `coincurve` | ≥2.1 | No | `[extra]` | Optional libsecp256k1 C bindings for accelerated curve operations |

`typer` is only needed when using the CLI. The Python API has zero runtime dependencies outside the standard library.

## Development (`[dev]` extra)

| Package | Version | Purpose |
|---------|---------|---------|
| `pytest` | ≥8.0 | Test runner |
| `pytest-cov` | — | Coverage reporting |
| `hypothesis` | ≥6.0 | Property-based and stateful fuzz testing |
| `mypy` | ≥1.8 | Static type checking (`--strict`) |
| `ruff` | ≥0.4 | Linter (pyupgrade, bugbear, pycodestyle) |
| `yapf` | — | Code formatter (pre-commit hook) |
| `pre-commit` | — | Git hook runner |
| `coincurve` | ≥2.1 | Libsecp backend tests |

## CI (`[ci]` extra)

`pip install -e ".[ci]"` installs dev dependencies + any CI-specific tooling.

## Build

| Tool | Version | Purpose |
|------|---------|---------|
| `setuptools` | ≥74.0 | Build backend |
| `setuptools-scm` | — | Version from git |

## Transitive

| Package | Transitive from | Note |
|---------|-----------------|------|
| `click` | `typer` | Not a direct dependency |
| `shellingham` | `typer` | CLI shell detection |
| `rich` | `typer` | Pretty CLI output (optional) |
| `typing_extensions` | `typer` | Backport for older Python |
