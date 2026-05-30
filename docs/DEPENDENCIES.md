# Dependencies

## Runtime

| Package | Min Version | Purpose | Risk |
|---------|-------------|---------|------|
| `typer` | — | CLI framework | Low; well-maintained CLI library |
| `click` | — | CLI argument parsing (Typer dependency) | Low |
| `coincurve` | (optional) | C-based ECC via libsecp256k1 bindings | Low; pure-Python fallback exists |

Note: HTTP fetches use `urllib.request` from the Python standard library — no `requests` dependency needed.

## Development

| Package | Purpose |
|---------|---------|
| `pytest` | Test runner |
| `pytest-cov` | Coverage reporting |
| `pytest-hypothesis` | Property-based testing |
| `pytest-benchmark` | Benchmarking |
| `pytest-asyncio` | Async test support |
| `mypy` | Static type checking |
| `ruff` | Linting and formatting |

## Not Installed/Required

- No cryptographic library dependency for signing or verification — the package only parses and extracts (no private keys).
- No `asyncio` dependency — the async plugin is only for test isolation.
- No `numpy` — all arithmetic is pure Python integer/bigint.

## Transitive Risk

- `requests` depends on `urllib3`, `certifi`, `charset-normalizer`, `idna` — all widely deployed and maintained.
- `typer` depends on `click`, `shellingham`, `rich` (optional) — low risk.
- `coincurve` depends on `asn1crypto`, `cffi` (for libsecp256k1 C bindings) — low risk; only activated on explicit `set_backend(CoincurveBackend())`.

## Optional Dependency Detection

`CoincurveBackend.__init__()` checks for `coincurve` availability when instantiated. If unavailable, it raises `ImportError` with a message to `pip install coincurve`. The pure-Python backend is always available and is the default.
