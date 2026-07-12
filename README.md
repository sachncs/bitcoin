<p align="center">
  <h1 align="center">bitcoin</h1>
  <p align="center">Pure-Python parsing, signature extraction, and nonce-reuse analysis for the Bitcoin secp256k1 stack.</p>
  <p align="center">
    <a href="#installation"><img src="https://img.shields.io/badge/python-3.12%20%7C%203.13%20%7C%203.14-blue" alt="Python"></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-green" alt="License"></a>
    <a href="https://github.com/sachn-cs/bitcoin/actions"><img src="https://img.shields.io/github/actions/workflow/status/sachn-cs/bitcoin/ci.yml?branch=master" alt="CI"></a>
    <a href="https://codecov.io/gh/sachn-cs/bitcoin"><img src="https://codecov.io/gh/sachn-cs/bitcoin/branch/main/graph/badge.svg" alt="Coverage"></a>
    <a href="https://mypy-lang.org/"><img src="https://img.shields.io/badge/mypy-strict-green.svg" alt="Checked with mypy"></a>
  </p>
</p>

**bitcoin** is a pure-Python library for parsing raw Bitcoin transactions,
extracting ECDSA and Schnorr signatures (`r`, `s`, `z`), deriving
linearised ECDSA relations, recovering nonce reuse, and verifying
signatures — all on the secp256k1 curve.  The core library has **no
network dependencies**; blockchain data fetching lives behind an
optional, isolated services layer.

---

## Features

- **Transaction Parsing** — Legacy, SegWit v0 (BIP-143), and Taproot (BIP-341) wire format
- **Signature Extraction** — ECDSA and Schnorr from P2PK, P2PKH, P2SH-multisig, P2WPKH, P2WSH, P2SH-P2WPKH/WSH, P2TR key-path and script-path
- **Nonce Reuse Detection** — `d = α·k − β` algebra with both *same-nonce* and *related-nonce* recovery
- **Sighash Computation** — Legacy, SegWit v0, and Taproot with all SIGHASH flag combinations
- **PSBT Support** — BIP-174 parse, edit, sign, and extract
- **Script Analysis** — Classify, parse, and build standard Bitcoin scripts
- **Transaction Construction** — Immutable `Tx` models, fluent `TransactionBuilder`, and `PsbtEditor`
- **Batch Processing** — `ThreadPoolExecutor` and `ProcessPoolExecutor` pipelines with graceful shutdown
- **Pluggable Backends** — Pure Python (default) or `coincurve`/libsecp256k1
- **CLI** — Typer-based `decode`, `extract`, `linearize`, `broadcast`, `health` commands
- **Blockchain Providers** — Blockstream, Mempool.space, blockchain.info, plus a generic HTTP provider
- **All-public API** — No semi-private `_foo` identifiers; every helper is a documented, importable symbol

---

## Installation

### From PyPI

```bash
pip install bitcoin
```

For accelerated point multiplication via libsecp256k1 (optional):

```bash
pip install bitcoin[coincurve]
```

### From source

```bash
git clone https://github.com/sachn-cs/bitcoin.git
cd bitcoin
pip install -e ".[dev]"
```

**Requirements**: Python ≥ 3.12, no runtime dependencies (Typer is the only runtime requirement; `coincurve` is optional).

---

## Quick Start

### Python API

```python
import bitcoin

# Parse a raw transaction
tx, _ = bitcoin.parse_tx(bytes.fromhex(raw_hex))

# Extract signatures
records = bitcoin.extract_signatures(tx)

# Linearise (sort) signatures
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

# With UTXO metadata (needed for SegWit v0 sighash)
bitcoin extract <tx-hex> --utxo-value 100000000

# Output as JSON
bitcoin extract <tx-hex> --json

# Linearise (sort) signatures by txid/vin
bitcoin linearize <tx-hex>

# Run health checks
bitcoin health
```

---

## Public API

The package root re-exports every public symbol so callers can do
`from bitcoin import name` without reaching into a submodule.  The
`__all__` list contains 191 deduplicated, alphabetised names spanning
the curve, encoding, script, sighash, transaction, signature,
descriptor, PSBT, and services layers.

### Core functions

| Function | Purpose |
|----------|---------|
| `parse_tx`, `make_tx`, `TransactionBuilder`, `tx_from_dict` | Transaction construction and parsing |
| `extract_signatures`, `linearize_signatures`, `batch_extract`, `correlate_across_transactions` | Signature extraction pipeline |
| `verify_sig`, `verify_schnorr_sig`, `verify_all`, `recover_public_key` | ECDSA / Schnorr verification |
| `sighash_legacy`, `sighash_segwit`, `sighash_taproot` | Sighash computation |
| `parse_psbt`, `serialize_psbt`, `psbt_extract_signatures`, `PsbtEditor` | PSBT (BIP-174) |
| `parse_public_key`, `serialize_public_key`, `multiply`, `add`, `double` | secp256k1 curve ops |
| `analyze_descriptor`, `compile_descriptor`, `extract_keys` | Miniscript descriptor tools |
| `BlockstreamProvider`, `BlockchainInfoProvider`, `MempoolSpaceProvider`, `GenericHttpProvider` | Blockchain data fetching |

### Newly promoted helpers

The following helpers are part of the public API and are also
re-exported from their submodules:

| Helper | Module |
|--------|--------|
| `collect_info`, `collect_keys`, `contains_op`, `estimate_satisfaction`, `sorted_unique` | `bitcoin.descriptor` |
| `split_args`, `emit_script` | `bitcoin.descriptor` |
| `DescriptorError`, `DescriptorInfo`, `DescriptorNode`, `ESTIMATED_SATISFACTION` | `bitcoin.descriptor` |
| `parse_psbt_impl`, `parse_psbt_worker`, `process_psbt_batch`, `process_psbt_batch_with` | `bitcoin.psbt` |
| `process_single_worker`, `BUILTINS_REGISTERED` | `bitcoin.signature` |
| `registry` | `bitcoin.signature.extraction.plugins` |
| `LOGGING_CONFIGURED` | `bitcoin.cli` |
| `CURVE_A`, `CURVE_B` | `bitcoin.curve` |

---

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
records = extract_signatures(
    tx,
    utxo_script_pubkeys=[bytes.fromhex(script_hex)],
    utxo_values=[100000000],
)
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

### Sighash Computation

```python
from bitcoin import (
    sighash_legacy, sighash_segwit, sighash_taproot,
    SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY,
)

h = sighash_segwit(tx, input_index, script_code, amount, SIGHASH_ALL)
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
print(detail)  # P2WPKH, P2SH, P2TR, MULTISIG, ...
```

### Blockchain Data Providers

```python
from bitcoin import BlockstreamProvider, BlockchainInfoProvider, MempoolSpaceProvider

provider = BlockstreamProvider()
tx_hex = provider.get_transaction_hex("txid...")
utxo_value = provider.get_utxo_value("txid...", vout=0)
```

---

## Architecture

The library is intentionally organised around a layered architecture
so each layer can be understood and tested in isolation:

```
┌─────────────────────────────────────────────────────────────────┐
│  bitcoin.cli            Typer-based command-line interface       │
├─────────────────────────────────────────────────────────────────┤
│  bitcoin.services       Blockchain data providers + async batch   │
├─────────────────────────────────────────────────────────────────┤
│  bitcoin.signature      Extraction, linearisation, attacks, sig  │
├─────────────────────────────────────────────────────────────────┤
│  bitcoin.descriptor     Miniscript parsing, compilation, analyse │
│  bitcoin.psbt           BIP-174 parse, edit, extract, batch     │
│  bitcoin.sighash        Legacy, SegWit v0, Taproot sighash        │
│  bitcoin.transaction    Tx models, parser, builder, fee, RBF     │
│  bitcoin.script         Script parse, classify, build, Taproot   │
├─────────────────────────────────────────────────────────────────┤
│  bitcoin.encoding       hex, varint, DER, SEC, hasher            │
│  bitcoin.field          inverse, sqrt (Tonelli-Shanks, p≡3 mod 4)│
│  bitcoin.curve          secp256k1 params, point, operations,     │
│                         dispatch, batch, pluggable backends      │
└─────────────────────────────────────────────────────────────────┘
```

Layering rules:

- The **curve** and **field** layers are independent of every other
  layer and have no Bitcoin-specific knowledge.
- The **encoding** layer is purely byte-level and contains no
  transaction or script logic.
- The **script**, **sighash**, and **transaction** layers depend only
  on the curve, field, and encoding layers.
- The **signature** layer depends on every layer below it.
- The **services** layer is the only place that performs network I/O.

### Design invariants

- All public dataclasses are `frozen=True, slots=True` for value
  semantics and predictable hashing.
- The package root re-exports every public symbol; no need to
  chase submodules.
- No `from bitcoin.foo import _bar` is ever required — every
  documented helper has a plain public name.
- Network I/O is opt-in: the core library is import-safe in
  air-gapped environments.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BITCOIN_LOG_LEVEL` | `WARNING` | Log verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`) |

### Settings singleton

```python
from bitcoin import settings

settings.strict_mode = True               # raise on non-fatal issues
settings.default_backend = "libsecp"      # or "native" / None
settings.max_extraction_inputs = 5000
```

---

## Project Structure

```
bitcoin/
├── __init__.py          # Public API surface (191 symbols)
├── cli/                 # Typer CLI commands
├── curve/               # secp256k1 point operations & pluggable backends
│   ├── backend/         # CurveBackend ABC, native (pure-Python), libsec (coincurve)
│   └── dispatch.py      # Backend singleton + fixed-base multiplication
├── descriptor/          # Miniscript descriptor parsing & analysis
├── encoding/            # Hex, varint, DER, SEC, hashing
├── exceptions.py        # Exception hierarchy
├── field/               # Modular arithmetic
├── health.py            # Runtime health checks
├── psbt/                # BIP-174 parse, serialize, edit, batch
├── script/              # Script parse, classify, build, Taproot
├── services/            # Blockchain data providers + async batch
├── settings.py          # Settings singleton
├── sighash/             # Legacy, SegWit v0, Taproot sighash
├── signature/           # Extraction, linearisation, verification, signing
│   ├── extraction/      # ExtractorPlugin registry + engine
│   └── linearization/   # (α, β) coefficient derivation
└── transaction/         # Tx parse, build, serialize, fee, RBF
tests/                   # Test suite (868 passing)
docs/                    # Documentation
```

---

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

### Code Style

- Line length: 88 (per `pyproject.toml`)
- Quotes: double (`"`)
- Formatting: `ruff format` (PEP 8 + project rules)
- Type hints: required on all public signatures; mypy runs in strict-ish mode
- Docstrings: Google-style with "what" and "why"
- **No semi-private naming (`_foo`)** — every helper is part of the documented public API and is re-exported from the appropriate `__init__.py`

### Commit Conventions

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Taproot script-path signature extraction
fix: handle non-canonical DER encoding
docs: expand module docstrings across the signature pipeline
refactor: promote semi-private helpers to public API
test: add parity tests for cached vs streamed memory
chore: update ruff config
```

---

## Tech Stack

| Category | Technology |
|----------|------------|
| Language | Python 3.12+ |
| CLI | [Typer](https://typer.tiangolo.com/) |
| Testing | [pytest](https://docs.pytest.org/), [Hypothesis](https://hypothesis.readthedocs.io/) |
| Lint / Format | [Ruff](https://docs.astral.sh/ruff/) |
| Type Check | [mypy](https://mypy-lang.org/) |
| Build | [setuptools](https://setuptools.pypa.io/) |
| Package Manager | [uv](https://github.com/astral-sh/uv) |
| Optional | [coincurve](https://github.com/ofek/coincurve) (libsecp256k1 bindings) |

---

## Supported Script Types

- P2PK (legacy)
- P2PKH (legacy)
- P2SH multisig (legacy)
- P2WPKH (SegWit v0)
- P2WSH multisig (SegWit v0)
- P2SH-P2WPKH / P2SH-P2WSH (nested SegWit v0)
- P2TR key-path and script-path (Taproot)

---

## References

- [SEC-2 v2.0](https://www.secg.org/sec2-v2.pdf) — secp256k1 curve parameters
- [BIP-141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki) — Segregated Witness
- [BIP-143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki) — SegWit v0 sighash
- [BIP-174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki) — PSBT format
- [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) — Schnorr signatures
- [BIP-341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki) — Taproot
- [RFC-6979](https://datatracker.ietf.org/doc/html/rfc6979) — Deterministic ECDSA nonces

---

## Roadmap

- [ ] Full Miniscript integration
- [ ] Taproot tree parsing
- [ ] Additional blockchain providers
- [ ] Optional Rust backend for maximum performance

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on:

- Development setup
- Code style and conventions
- Pull request process
- Testing requirements

## Code of Conduct

This project follows the [Contributor Covenant v2.1](CODE_OF_CONDUCT.md).
By participating you agree to abide by its terms.

## Security

For reporting security vulnerabilities, please see [SECURITY.md](SECURITY.md).

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built on the [secp256k1](https://www.secg.org/sec2-v2.pdf) elliptic curve
- Inspired by the Bitcoin ecosystem and its need for robust tooling
