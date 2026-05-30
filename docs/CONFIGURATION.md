# Configuration

## Environment Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `BITCOIN_ECC_BACKEND` | str | `"python"` | ECC backend: `"python"` or `"coincurve"` |
| `BITCOIN_NETWORK` | str | `"mainnet"` | Network: `"mainnet"`, `"testnet"`, `"signet"` |
| `BITCOIN_FETCH_TIMEOUT` | int | `30` | HTTP fetch timeout in seconds |
| `BITCOIN_STRICT_PARSING` | bool | `True` | Reject non-standard transactions |

Boolean parsing: accepts `"1"`, `"true"`, `"yes"` (case-insensitive) as `True`.

## Config File

`Config.load(path)` reads JSON config files.

```json
{
  "ecc_backend": "python",
  "network": "testnet",
  "fetch_timeout": 60,
  "strict_parsing": false
}
```

If the file is missing or has an unsupported format, `load()` logs an error and returns defaults.

## Precedence

1. Environment variables (highest)
2. Config file values
3. Code defaults (lowest)

## Programmatic Usage

```python
from bitcoin.config import Config

# From defaults
config = Config()

# From env vars
config = Config.from_env()

# From file with env overrides
config = Config.load("~/.bitcoin/config.json")

# Access
config.ecc_backend  # → "python"
config.fetch_timeout  # → 30
```

## Validation

- `fetch_timeout`: must be convertible to `int`; `ValueError` on failure is caught and re-raised with a clear message
- `bool` fields: only `"1"`, `"true"`, `"yes"` evaluate to `True`; all others (including `"0"`, `"false"`, `"no"`) evaluate to `False`
