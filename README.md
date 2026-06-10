# bitcoin

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**bitcoin** is a pure-Python library for parsing raw Bitcoin transactions,
extracting ECDSA and Schnorr signatures (`r`, `s`, `z`), deriving linearized
ECDSA relations, recovering nonce reuse, and verifying signatures — all on the
secp256k1 curve. No network dependencies.

Version **0.4.0**.

## Install

```bash
uv pip install bitcoin
```

For accelerated point multiplication (optional):

```bash
uv pip install bitcoin[coincurve]
# or: uv sync --extra coincurve
```

## CLI

```bash
# Decode a raw transaction (JSON output)
bitcoin decode <tx-hex>

# Extract signatures from a raw transaction
bitcoin extract <tx-hex>

# With UTXO metadata (needed for segwit v0 sighash)
bitcoin extract <tx-hex> --utxo-value 100000000

# Output as JSON
bitcoin extract <tx-hex> --json

# Output as CSV
bitcoin extract <tx-hex> --csv

# Read tx hex from a file, show progress
bitcoin extract --input-file tx.hex --progress

# Linearize (sort) signatures by txid/vin
bitcoin linearize <tx-hex>

# Print version
bitcoin version

# Run health checks (JSON report)
bitcoin health
```

Or via `python -m bitcoin.cli`:

```bash
python -m bitcoin.cli decode <tx-hex>
python -m bitcoin.cli extract <tx-hex>
python -m bitcoin.cli linearize <tx-hex>
python -m bitcoin.cli version
python -m bitcoin.cli health
```

### CLI reference

| Command | Description |
|---|---|
| `decode` | Decode a raw transaction and print as JSON |
| `extract` | Extract ECDSA/Schnorr signatures from a raw transaction hex |
| `linearize` | Extract and sort signatures by txid/input_index |
| `health` | Run health checks and print a JSON status report |
| `version` | Print the installed package version |

`extract` options: `--utxo-script`, `--utxo-value`, `--json`, `--csv`, `--format` (text/json/csv), `--input-file`, `--progress`/`-p`.

`linearize` options: `--json`, `--csv`, `--format`, `--input-file`, `--progress`/`-p`.

Logs are emitted as **JSON** to stderr. Set ``BITCOIN_LOG_LEVEL`` (default ``WARNING``) to control
verbosity (``DEBUG``, ``INFO``, ``WARNING``, ``ERROR``, ``CRITICAL``).

## Python API

All public symbols are available at the top level:

```python
import bitcoin

tx, _ = bitcoin.parse_tx(bytes.fromhex(raw_hex))
records = bitcoin.extract_signatures(tx)
```

### Extract signatures

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

### Batch extraction

Extract signatures across multiple transactions in parallel:

```python
from bitcoin import batch_extract, correlate_across_transactions

tx_hexes = ["...", "..."]  # raw transaction hexes
results = batch_extract(tx_hexes)

# Find nonce-reuse correlations across transactions
correlations = correlate_across_transactions(results)
```

### Linearization

```python
from bitcoin import linearize_signatures

sorted_recs = linearize_signatures(records)
# sorted by (txid, input_index) — ready for nonce-reuse analysis
```

### Point & curve math

```python
from bitcoin import Point, multiply, GENERATOR, CURVE_ORDER

pub = multiply(private_key_scalar, GENERATOR)
```

### Backend management

```python
from bitcoin import (
    get_backend, set_backend, CurveBackend, NativeBackend, LibsecpBackend,
    INFINITY, FIELD_PRIME, negate, add, double, is_on_curve,
)

set_backend("native")          # or "libsecp" (if coincurve installed)
backend = get_backend()

p2 = add(point1, point2)
assert is_on_curve(p2)
```

### Field arithmetic

```python
from bitcoin import inverse, sqrt, pow_mod, validate_non_negative

inv = inverse(a, CURVE_ORDER)
root = sqrt(a)                   # sqrt modulo FIELD_PRIME
```

### Encoding utilities

```python
from bitcoin import (
    encode_hex, decode_hex,
    encode_der, decode_der,
    encode_varint, decode_varint,
    sha256, hash256, hash160, tagged_hash,
    parse_sec, serialize_sec,
    bytes_to_int, int_to_bytes,
)
```

### Script

```python
from bitcoin import (
    parse_script, serialize_script,
    classify_script_pubkey, classify_script_sig,
    classify_detailed, is_op_return, is_bare_multisig, has_timelocks,
    P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR, MULTISIG, TIMELOCK,
)

detail = classify_detailed(script)
print(detail.type)              # P2WPKH, P2SH, P2TR, MULTISIG, ...
print(detail.is_op_return())
print(detail.has_timelocks())
```

Script builders:

```python
from bitcoin import (
    build_p2pk, build_p2pkh, build_p2sh,
    build_p2wpkh, build_p2wsh, build_p2tr,
)

script = build_p2pkh(pubkey_hash)
script = build_p2tr(x_only_pubkey)
```

Taproot helpers:

```python
from bitcoin import get_x_only_pubkey, parse_taproot_witness_stack

xonly = get_x_only_pubkey(script_pubkey)
stack = parse_taproot_witness_stack(witness)
```

### Transaction construction

```python
from bitcoin import make_tx, Tx, TxIn, TxOut, OutPoint, Witness

tx = make_tx(version=2, inputs=[txin], outputs=[txout], lock_time=0)
```

Or use the fluent builder:

```python
from bitcoin.transaction import TransactionBuilder
from bitcoin import tx_from_dict

tx = (TransactionBuilder(version=2)
      .add_input(txid=b'\x00' * 32, vout=0)
      .add_output(value=50000, script_pubkey=b'...')
      .build())

# Build from a dict
tx = tx_from_dict({"version": 2, "inputs": [...], "outputs": [...]})
```

Transaction utilities:

```python
from bitcoin import is_opt_in_rbf, has_sequence_lock

assert is_opt_in_rbf(tx)
assert has_sequence_lock(txin)
```

### Sighash computation

```python
from bitcoin import (
    sighash_legacy, sighash_segwit, sighash_taproot,
    SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY,
)

hash = sighash_segwit(tx, input_index, script_code, amount, SIGHASH_ALL)
```

### Verification & key recovery

```python
from bitcoin import verify_sig, verify_schnorr_sig, verify_all, recover_public_key

ok = verify_sig(message_hash, der_sig, public_key)
ok = verify_schnorr_sig(message_hash, schnorr_sig, x_only_pubkey)
ok = verify_all(message_hash, signatures, public_keys)  # batch verify

pubkey = recover_public_key(message_hash, der_sig, recid)
```

### Signing

```python
from bitcoin import sign, sign_tx_input

# Low-level ECDSA signing (HMAC-DRBG deterministic k)
der_sig = sign(message_hash, private_key)

# Sign a transaction input
sig_with_flag = sign_tx_input(tx, vin, private_key,
                               script=script_code, value=amount)
```

### Nonce reuse detection

```python
from bitcoin.signature.linearization.coefficients import (
    LinearCoefficientCollection, derive_linear_coefficients,
)
from bitcoin.signature.attack import detect_nonce_reuse, recover_from_nonce_reuse

# Detect pairs of signatures sharing the same nonce
collection = LinearCoefficientCollection(records=tuple(
    derive_linear_coefficients(r=rec.r, s=rec.s, z=rec.z,
                                input_index=i)
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

### PSBT

```python
from bitcoin import parse_psbt, serialize_psbt, parse_psbt_hex

psbt = parse_psbt(raw_psbt_bytes)
raw_out = serialize_psbt(psbt)
```

PSBT editing:

```python
from bitcoin.psbt import PsbtEditor

editor = PsbtEditor.from_tx(unsigned_tx)
editor.set_input_utxo(0, witness_utxo=utxo_bytes)
editor.add_input_partial_sig(0, pubkey, sig)
psbt = editor.build()
```

PSBT signature extraction:

```python
from bitcoin import psbt_extract_signatures, parse_keypath_value

records = psbt_extract_signatures(psbt)
keypath = parse_keypath_value(b'...')
```

### Blockchain data providers

Fetch transaction data from public APIs:

```python
from bitcoin import BlockstreamProvider, BlockchainInfoProvider, MempoolSpaceProvider
from bitcoin import enrich_transaction

provider = BlockstreamProvider()   # also BlockchainInfoProvider, MempoolSpaceProvider
tx_hex = provider.fetch_tx_hex("txid...")
utxo_value = provider.fetch_utxo_value("txid...", vout=0)

# Attach UTXO metadata to a parsed transaction
tx, _ = parse_tx(bytes.fromhex(tx_hex))
enrich_transaction(tx, provider=provider)
```

### Serialization

```python
from bitcoin import serialize_tx, serialize_legacy_tx, tx_to_json

raw = serialize_tx(tx)
j = tx_to_json(tx)
```

### Health check

```python
from bitcoin.health import health, check_backend, check_imports

status = health()
# {'version': '0.4.0', 'imports': {...}, 'backends': {...}, 'curve_operation': {...}}
```

### Settings

```python
from bitcoin import settings

settings.strict_mode = True               # raise on non-fatal issues
settings.default_backend = "libsecp"      # or "native" / None
settings.max_extraction_inputs = 5000
```

### Exceptions

```python
from bitcoin import (
    BitcoinError, NotInvertible, PointError,
    ParsingError, UnsupportedScriptPathError,
)

try:
    tx, _ = parse_tx(data)
except ParsingError as exc:
    ...
```

## Supported extraction paths

- P2PK (legacy)
- P2PKH (legacy)
- P2SH multisig (legacy)
- P2WPKH (segwit v0)
- P2WSH multisig (segwit v0)
- P2SH-P2WPKH / P2SH-P2WSH (nested segwit v0)
- P2TR key-path and script-path (taproot)

## Nonce reuse detection

When two inputs share the same nonce `k` (identical `r` value), the library
can recover the private key:

```python
from bitcoin.signature.linearization.coefficients import (
    LinearCoefficientCollection, derive_linear_coefficients,
)
from bitcoin.signature.attack import detect_nonce_reuse, recover_from_nonce_reuse

coeffs = LinearCoefficientCollection(records=tuple(
    derive_linear_coefficients(r=r, s=s, z=z, input_index=i)
    for i, (r, s, z) in enumerate(zip(rs, ss, zs))
))
for group in detect_nonce_reuse(coeffs):
    key = recover_from_nonce_reuse(coeffs.records[group.indices[0]],
                                   coeffs.records[group.indices[1]])
```

## Linear coefficient derivation

Given ECDSA identity `s ≡ k⁻¹(z + rd) (mod n)`, the linearized form
`d ≡ αk − β (mod n)` is derived:

```python
from bitcoin.signature.linearization.coefficients import derive_linear_coefficients

lc = derive_linear_coefficients(r, s, z)
# lc.alpha ≡ s · r⁻¹ (mod n)
# lc.beta  ≡ z · r⁻¹ (mod n)
```

## Development

```bash
./setup.sh                          # uv venv + sync + test
make venv                           # same, without test
make test                           # pytest
make typecheck                      # mypy
make lint                           # ruff
make test-cov                       # pytest + coverage (99%+)
./cleanup.sh                        # remove caches, .venv, egg-info
```

### Environment

| Variable | Default | Purpose |
|---|---|---|
| `BITCOIN_LOG_LEVEL` | `WARNING` | JSON log verbosity (DEBUG/INFO/WARNING/ERROR/CRITICAL) |
