# bitcoin

**bitcoin** is a pure-Python library for parsing raw Bitcoin transactions,
extracting ECDSA signatures (`r`, `s`, `z`), deriving linearized ECDSA
relations, recovering nonce reuse, and verifying signatures — all on the
secp256k1 curve. No network dependencies.

Version **0.4.0**.

## Install

```bash
pip install bitcoin
```

For accelerated point multiplication (optional):

```bash
pip install bitcoin[coincurve]
```

## CLI

```bash
# Extract signatures from a raw transaction
bitcoin extract <tx-hex>

# With UTXO metadata (needed for segwit v0 sighash)
bitcoin extract <tx-hex> --utxo-value 100000000

# Output as JSON
bitcoin extract <tx-hex> --json

# Output as CSV
bitcoin extract <tx-hex> --csv

# Read tx hex from a file
bitcoin extract --input-file tx.hex

# Linearize (sort) signatures by txid/vin
bitcoin linearize <tx-hex>

# Print version
bitcoin version
```

Or via `python -m bitcoin.cli`:

```bash
python -m bitcoin.cli extract <tx-hex>
python -m bitcoin.cli linearize <tx-hex>
python -m bitcoin.cli version
```

### CLI reference

| Command | Description |
|---|---|
| `extract` | Extract ECDSA signatures from a raw transaction hex |
| `linearize` | Extract and sort signatures by txid/input_index |
| `version` | Print the installed package version |

`extract` options: `--utxo-script`, `--utxo-value`, `--json`, `--csv`, `--format` (text/json/csv), `--input-file`.

`linearize` options: `--json`, `--csv`, `--format`, `--input-file`.

## Python API

All public symbols are available at the top level:

```python
import bitcoin

tx = bitcoin.parse_tx(bytes.fromhex(raw_hex))
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
    classify_script_pubkey,
    P2PKH, P2SH, P2WPKH, P2WSH, P2TR,
)
```

### Transaction construction

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

### Sighash computation

```python
from bitcoin import sighash_legacy, sighash_segwit, sighash_taproot

hash = sighash_segwit(tx, input_index, script_code, amount, sighash_flag)
```

### Verification & key recovery

```python
from bitcoin import verify_sig

ok = verify_sig(message_hash, der_sig, public_key)
```

### Nonce reuse detection

```python
from bitcoin.signature import LinearCoefficientCollection, derive_linear_coefficients
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
from bitcoin import parse_psbt, serialize_psbt

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

### Signing

```python
from bitcoin.signature import sign, sign_tx_input

# Low-level ECDSA signing (deterministic k via SHA256)
der_sig = sign(message_hash, private_key)

# Sign a transaction input
sig_with_flag = sign_tx_input(tx, vin, private_key,
                               script=script_code, value=amount)
```

### Settings

```python
from bitcoin import settings

settings.strict_mode = True                 # raise on non-fatal issues
settings.default_backend = "libsecp"         # or "native" / None
settings.max_extraction_inputs = 5000
```

## Supported extraction paths

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
from bitcoin.signature.attack import detect_nonce_reuse, recover_from_nonce_reuse
from bitcoin.signature import derive_linear_coefficients, LinearCoefficientCollection

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
from bitcoin.signature import derive_linear_coefficients

lc = derive_linear_coefficients(r, s, z)
# lc.alpha ≡ s · r⁻¹ (mod n)
# lc.beta  ≡ z · r⁻¹ (mod n)
```

## Development

```bash
pip install -e ".[dev]"
pytest tests/
mypy bitcoin/ tests/
ruff check .
```

`mypy` runs with `--strict`. `ruff` enforces pyupgrade, bugbear, and pycodestyle rules.
