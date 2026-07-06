[![CI](https://github.com/sachn-cs/bitcoin/actions/workflows/ci.yml/badge.svg)](https://github.com/sachn-cs/bitcoin/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/bitcoin.svg)](https://pypi.org/project/bitcoin/)
[![Python versions](https://img.shields.io/pypi/pyversions/bitcoin.svg)](https://pypi.org/project/bitcoin/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![codecov](https://codecov.io/gh/sachn-cs/bitcoin/branch/main/graph/badge.svg)](https://codecov.io/gh/sachn-cs/bitcoin)

# bitcoin

A pure-Python library for parsing raw Bitcoin transactions, extracting ECDSA and Schnorr signatures (`r`, `s`, `z`), deriving linearized ECDSA relations, recovering nonce reuse, and verifying signatures — all on the secp256k1 curve. No network dependencies.

## Features

- **Transaction Parsing** — Decode raw Bitcoin transactions (legacy, SegWit v0, Taproot)
- **Signature Extraction** — Extract ECDSA and Schnorr signatures from all standard script types
- **Nonce Reuse Detection** — Detect and exploit nonce reuse to recover private keys
- **Sighash Computation** — Legacy, SegWit, and Taproot sighash with all flag combinations
- **PSBT Support** — Parse, edit, and extract signatures from Partially Signed Bitcoin Transactions
- **Script Analysis** — Classify, parse, and build Bitcoin scripts (P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
- **Transaction Construction** — Build transactions with fluent API or dict-based construction
- **Batch Processing** — Parallel extraction and verification across multiple transactions
- **Pluggable Backends** — Pure Python (default) or accelerated via `coincurve`/libsecp256k1
- **CLI Tool** — Command-line interface for quick transaction analysis
- **Blockchain Providers** — Fetch transaction data from Blockstream, Blockchain.info, or Mempool.space

## Installation

```bash
pip install bitcoin
```

For accelerated point multiplication (optional):

```bash
pip install bitcoin[coincurve]
```

From source:

```bash
git clone https://github.com/sachn-cs/bitcoin.git
cd bitcoin
pip install -e ".[dev]"
```

## Quick Start

### Python API

```python
import bitcoin

# Parse a raw transaction
tx, _ = bitcoin.parse_tx(bytes.fromhex(raw_hex))

# Extract signatures
records = bitcoin.extract_signatures(tx)

# Linearize (sort) signatures
sorted_records = bitcoin.linearize_signatures(records)

# Verify a signature
ok = bitcoin.verify_sig(message_hash, der_sig, public_key)
```

### CLI

```bash
# Decode a raw transaction
bitcoin decode <tx-hex>

# Extract signatures
bitcoin extract <tx-hex>

# With UTXO metadata (needed for segwit v0 sighash)
bitcoin extract <tx-hex> --utxo-value 100000000

# Output as JSON
bitcoin extract <tx-hex> --json

# Linearize (sort) signatures by txid/vin
bitcoin linearize <tx-hex>

# Run health checks
bitcoin health
```

## Usage

### Extract Signatures

```python
from bitcoin import parse_tx, extract_signatures, encode_hex

tx, _ = parse_tx(bytes.fromhex(raw_hex))
records = extract_signatures(tx)

for rec in records:
    print(encode_hex(rec.txid), rec.input_index, encode_hex(rec.signature))
```

SegWit v0 inputs need UTXO values and/or scriptPubKeys:

```python
records = extract_signatures(tx,
    utxo_script_pubkeys=[bytes.fromhex(script_hex)],
    utxo_values=[100000000],
)
```

### Batch Extraction

Extract signatures across multiple transactions in parallel:

```python
from bitcoin import batch_extract, correlate_across_transactions

tx_hexes = ["...", "..."]
results = batch_extract(tx_hexes)

# Find nonce-reuse correlations across transactions
correlations = correlate_across_transactions(results)
```

### Nonce Reuse Detection

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
    # result.private_key, result.nonce
```

### Transaction Construction

```python
from bitcoin import make_tx, Tx, TxIn, TxOut, OutPoint, Witness

tx = make_tx(version=2, inputs=[txin], outputs=[txout], lock_time=0)
```

Or use the fluent builder:

```python
from bitcoin.transaction import TransactionBuilder

tx = (TransactionBuilder(version=2)
      .add_input(txid=b'\x00' * 32, vout=0)
      .add_output(value=50000, script_pubkey=b'...')
      .build())
```

### Sighash Computation

```python
from bitcoin import (
    sighash_legacy, sighash_segwit, sighash_taproot,
    SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY,
)

hash = sighash_segwit(tx, input_index, script_code, amount, SIGHASH_ALL)
```

### Verification & Key Recovery

```python
from bitcoin import verify_sig, verify_schnorr_sig, verify_all, recover_public_key

ok = verify_sig(message_hash, der_sig, public_key)
ok = verify_schnorr_sig(message_hash, schnorr_sig, x_only_pubkey)
ok = verify_all(message_hash, signatures, public_keys)  # batch verify

pubkey = recover_public_key(message_hash, der_sig, recid)
```

### Script Classification

```python
from bitcoin import (
    parse_script, serialize_script,
    classify_script_pubkey, classify_script_sig,
    classify_detailed, is_op_return, is_bare_multisig, has_timelocks,
    P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR, MULTISIG, TIMELOCK,
)

detail = classify_detailed(script)
print(detail.type)  # P2WPKH, P2SH, P2TR, MULTISIG, ...
```

### PSBT Support

```python
from bitcoin import parse_psbt, serialize_psbt, psbt_extract_signatures

psbt = parse_psbt(raw_psbt_bytes)
raw_out = serialize_psbt(psbt)
records = psbt_extract_signatures(psbt)
```

### Blockchain Data Providers

```python
from bitcoin import BlockstreamProvider, BlockchainInfoProvider, MempoolSpaceProvider

provider = BlockstreamProvider()
tx_hex = provider.fetch_tx_hex("txid...")
utxo_value = provider.fetch_utxo_value("txid...", vout=0)
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BITCOIN_LOG_LEVEL` | `WARNING` | Log verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) |

### Settings

```python
from bitcoin import settings

settings.strict_mode = True               # raise on non-fatal issues
settings.default_backend = "libsecp"      # or "native" / None
settings.max_extraction_inputs = 5000
```

### .env.example

See [`.env.example`](.env.example) for a template configuration file.

## Project Structure

```
bitcoin/
├── __init__.py          # Public API surface
├── cli/                 # Typer CLI commands
├── curve/               # secp256k1 point operations & backends
├── descriptor/          # Output descriptor parsing
├── encoding/            # Hex, varint, DER, SEC, hashing
├── exceptions.py        # Exception hierarchy
├── field/               # Modular arithmetic
├── health.py            # Runtime health checks
├── psbt/                # PSBT parse/serialize/edit
├── script/              # Script parse/classify/build
├── services/            # Blockchain data providers
├── settings.py          # Settings singleton
├── sighash/             # Sighash computation
├── signature/           # Extraction, verification, signing
└── transaction/         # Tx parse/build/serialize
tests/                   # Test suite
docs/                    # Documentation
```

## Development

### Commands

| Command | Description |
|---------|-------------|
| `make setup` | Create venv and install dependencies |
| `make venv` | Create venv without running tests |
| `make lint` | Run ruff linter |
| `make typecheck` | Run mypy type checker |
| `make test` | Run pytest |
| `make test-cov` | Run tests with coverage report |
| `make docs` | Build Sphinx documentation |
| `make clean` | Remove caches and build artifacts |

### Quick Start

```bash
./setup.sh                          # uv venv + sync + test
make venv                           # same, without test
make test                           # pytest
make typecheck                      # mypy
make lint                           # ruff
make test-cov                       # pytest + coverage (99%+)
./cleanup.sh                        # remove caches, .venv, egg-info
```

## Tech Stack

- **Language:** Python 3.12+
- **CLI:** [Typer](https://typer.tiangolo.com/)
- **Testing:** [pytest](https://docs.pytest.org/), [Hypothesis](https://hypothesis.readthedocs.io/)
- **Linting:** [Ruff](https://docs.astral.sh/ruff/)
- **Type Checking:** [mypy](https://mypy-lang.org/)
- **Build:** [setuptools](https://setuptools.pypa.io/)
- **Package Manager:** [uv](https://github.com/astral-sh/uv)
- **Optional:** [coincurve](https://github.com/ofek/coincurve) (libsecp256k1 bindings)

## Supported Script Types

- P2PK (legacy)
- P2PKH (legacy)
- P2SH multisig (legacy)
- P2WPKH (segwit v0)
- P2WSH multisig (segwit v0)
- P2SH-P2WPKH / P2SH-P2WSH (nested segwit v0)
- P2TR key-path and script-path (taproot)

## Roadmap

- [ ] Full output descriptor support
- [ ] Miniscript integration
- [ ] Batch transaction fetching
- [ ] Taproot tree parsing
- [ ] Additional blockchain providers
- [ ] Rust backend option for maximum performance

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:

- Development setup
- Code style and conventions
- Pull request process
- Testing requirements

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to its terms.

## Security

For reporting security vulnerabilities, please see [SECURITY.md](SECURITY.md).

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built on the [secp256k1](https://www.secg.org/sec2-v2.pdf) elliptic curve
- Inspired by the Bitcoin ecosystem and its need for robust tooling
