# Dependencies

## Runtime

| Package | Version | Required | Condition | Purpose |
|---------|---------|----------|-----------|---------|
| `typer` | ≥0.12, <1 | Yes (CLI) | — | CLI argument parsing for `bitcoin extract` etc. |
| `coincurve` | ≥18, <19 | No | `[coincurve]` | Optional libsecp256k1 C bindings for accelerated curve operations |

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
| `coincurve` | ≥18, <19 | Libsecp backend tests |

## CI

`uv sync --extra dev` installs all dev dependencies for CI.

## Build

| Tool | Version | Purpose |
|------|---------|---------|
| `setuptools` | ≥69.0 | Build backend |

## Transitive

| Package | Transitive from | Note |
|---------|-----------------|------|
| `click` | `typer` | Not a direct dependency |
| `shellingham` | `typer` | CLI shell detection |
| `rich` | `typer` | Pretty CLI output (optional) |
| `typing_extensions` | `typer` | Backport for older Python |
