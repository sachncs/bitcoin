# Frequently Asked Questions

## General

### What is the bitcoin library?

The bitcoin library is a pure-Python package for parsing Bitcoin transactions, extracting ECDSA and Schnorr signatures, and performing cryptographic operations on the secp256k1 curve. It's designed for security research, transaction analysis, and building Bitcoin tools.

### Is it production-ready?

Yes. The library has:
- 99%+ test coverage
- Strict type checking with mypy
- Comprehensive CI/CD pipeline
- Security scanning with pip-audit
- Well-documented API

### Does it require network access?

No. The core library is completely offline. Network access is only needed for the optional blockchain data providers (Blockstream, Blockchain.info, Mempool.space).

## Installation

### What Python versions are supported?

Python 3.12 and later (3.12, 3.13, 3.14).

### Do I need to install coincurve?

No. `coincurve` is optional. The library includes a pure-Python backend that's always available. Install `coincurve` only if you need accelerated point multiplication:

```bash
pip install bitcoin[coincurve]
```

### Can I use it with virtual environments?

Yes. We recommend using virtual environments:

```bash
python -m venv .venv
source .venv/bin/activate
pip install bitcoin
```

## Usage

### How do I parse a raw transaction?

```python
from bitcoin import parse_tx

raw_hex = "0200000001..."
tx, bytes_consumed = parse_tx(bytes.fromhex(raw_hex))
```

### How do I extract signatures?

```python
from bitcoin import parse_tx, extract_signatures

tx, _ = parse_tx(bytes.fromhex(raw_hex))
records = extract_signatures(tx)
```

For SegWit transactions, provide UTXO metadata:

```python
records = extract_signatures(tx,
    utxo_script_pubkeys=[bytes.fromhex(script_hex)],
    utxo_values=[100000000],
)
```

### How do I verify a signature?

```python
from bitcoin import verify_sig

ok = verify_sig(message_hash, der_sig, public_key)
```

### How do I detect nonce reuse?

```python
from bitcoin.signature.linearization.coefficients import (
    LinearCoefficientCollection, derive_linear_coefficients,
)
from bitcoin.signature.attack import detect_nonce_reuse, recover_from_nonce_reuse

collection = LinearCoefficientCollection(records=tuple(
    derive_linear_coefficients(r=rec.r, s=rec.s, z=rec.z, input_index=i)
    for i, rec in enumerate(records)
))

groups = detect_nonce_reuse(collection)

for group in groups:
    result = recover_from_nonce_reuse(
        collection.records[group.indices[0]],
        collection.records[group.indices[1]],
    )
```

### What script types are supported?

- P2PK (legacy)
- P2PKH (legacy)
- P2SH multisig (legacy)
- P2WPKH (segwit v0)
- P2WSH multisig (segwit v0)
- P2SH-P2WPKH / P2SH-P2WSH (nested segwit v0)
- P2TR key-path and script-path (taproot)

## CLI

### How do I use the CLI?

```bash
# Check version
bitcoin version

# Decode a transaction
bitcoin decode <tx-hex>

# Extract signatures
bitcoin extract <tx-hex>

# Output as JSON
bitcoin extract <tx-hex> --json

# Linearize signatures
bitcoin linearize <tx-hex>
```

### Can I use it via python -m?

Yes:

```bash
python -m bitcoin.cli decode <tx-hex>
python -m bitcoin.cli extract <tx-hex>
python -m bitcoin.cli linearize <tx-hex>
python -m bitcoin.cli version
python -m bitcoin.cli health
```

## Troubleshooting

### "ImportError: No module named 'coincurve'"

Install the optional coincurve dependency:

```bash
pip install bitcoin[coincurve]
```

Or use the pure-Python backend (default):

```python
from bitcoin import set_backend
set_backend("native")
```

### "ParsingError: Invalid transaction format"

Ensure your hex string is valid:
- No whitespace
- No "0x" prefix
- Valid hexadecimal characters

```python
raw_hex = raw_hex.strip()  # Remove whitespace
raw_hex = raw_hex.replace("0x", "")  # Remove prefix
tx, _ = parse_tx(bytes.fromhex(raw_hex))
```

### "UnsupportedScriptPathError"

The transaction uses a script feature not yet supported (e.g., OP_CODESEPARATOR). Check the exception message for details.

### How do I enable debug logging?

```bash
export BITCOIN_LOG_LEVEL=DEBUG
```

Or programmatically:

```python
import os
os.environ["BITCOIN_LOG_LEVEL"] = "DEBUG"
```

## Contributing

### How do I contribute?

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Run `make all` to verify
6. Submit a pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for detailed guidelines.

### How do I run tests?

```bash
make test          # Run all tests
make test-cov      # Run with coverage
```

### How do I run linting?

```bash
make lint          # Run ruff
make typecheck     # Run mypy
```

## Security

### How do I report a vulnerability?

See [SECURITY.md](../SECURITY.md) for private disclosure instructions.

### Is this library audited?

The library is open-source and undergoes:
- Automated security scanning (pip-audit)
- Strict type checking (mypy)
- Comprehensive test coverage (99%+)
- CI/CD pipeline with security checks

## License

### What license is used?

MIT License. See [LICENSE](../LICENSE) for details.

### Can I use this in commercial projects?

Yes. The MIT license permits commercial use, modification, and distribution.
