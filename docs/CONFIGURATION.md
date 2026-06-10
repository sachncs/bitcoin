# Configuration

## Settings Object — `bitcoin.settings`

A global `Settings` singleton exposed as `bitcoin.settings`:

```python
from bitcoin import settings

settings.strict_mode                    # bool (default False)
settings.default_backend                # str | None (default None → "native")
settings.max_extraction_inputs           # int (default 100_000)
```

## Backend Selection

Two backends are available:

| Backend | Class | Availability |
|---------|-------|-------------|
| Pure Python | `NativeBackend` | Always (default) |
| C-backed (libsecp256k1) | `LibsecpBackend` | Requires `uv sync --extra coincurve` or `uv pip install coincurve` |

```python
from bitcoin import set_backend, get_backend

set_backend("native")               # activate pure Python (default)
set_backend("libsecp")              # activate C-backed (ImportError if coincurve missing)

backend = get_backend()             # → CurveBackend
```

## Former Config File Support

The old `Config` class (file + env-var loading) has been replaced by the simpler `Settings` singleton. Environment variables (`BITCOIN_ECC_BACKEND`, `BITCOIN_NETWORK`, etc.) are no longer supported; configuration is done programmatically.
