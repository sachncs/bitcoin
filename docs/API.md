# API Reference

## Public CLI — `bitcoin.cli`

### Installation

```bash
pip install bitcoin
# or with optional coincurve backend:
pip install "bitcoin[coincurve]"
```

### Commands

All commands share: `--tx <hex>` (required), `--input-values <csv>` (optional), `--compact` (optional).

#### `parse`

```bash
bitcoin parse --tx <raw-transaction-hex>
```

Output: JSON with `raw_hex`, `version`, `segwit`, `locktime`, `inputs[]`, `outputs[]`.

#### `extract`

```bash
bitcoin extract --tx <hex> [--input-values 100000,200000]
```

Output: JSON with `count`, `r[]`, `s[]`, `z[]`, `records[]`.

#### `linear`

```bash
bitcoin linear --tx <hex> [--input-values 100000,200000]
```

Output: JSON with `alpha`, `beta`, `equation`, `input_index` per record (or collection).

#### `points`

```bash
bitcoin points --tx <hex> [--input-values 100000,200000]
```

Output: JSON with `alpha`, `beta`, `equation`, `input_index`, `transformed_public_key` per record.

#### `transform`

```bash
bitcoin transform --tx <hex> [--input-values 100000,200000]
```

Output: JSON with `new_d_point`, `validation` per record.

### Exit Codes

| Code | Condition |
|------|-----------|
| 0 | Success |
| 1 | `BitcoinError`, `ValueError`, or unexpected error |
| 2 | Usage error (click.ClickException) |

## Public Python API

### Transaction Parsing

```python
from bitcoin.transaction import Transaction

# Parse from hex
tx = Transaction.parse_hex(raw_transaction_hex)

# Attach input values for SegWit sighash
tx = tx.with_input_values([100000, 200000])
# Raises ValueError if len(values) != len(tx.inputs)

# Extract signatures
sig_collection = tx.extract()
# Optional: provide script_pubkeys for Taproot detection
sig_collection = tx.extract(script_pubkeys=[pubkey_bytes, ...])
```

### Signature Collection

```python
from bitcoin.signature import SignatureCollection

# Properties
sig_collection.records    # tuple[SignatureRecord, ...]
sig_collection.r          # list[str]  (hex)
sig_collection.s          # list[str]  (hex)
sig_collection.z          # list[str]  (hex)
sig_collection.signatures # list[SignatureRecord]

# Derived operations
coeffs = sig_collection.linear()           # → LinearCoefficientCollection
points = sig_collection.linear_points()    # → LinearPointRelationCollection
transformed = sig_collection.transform_points()  # → TransformedPointCollection
```

### Nonce Reuse & Key Recovery

```python
from bitcoin.attack import (
    detect_nonce_reuse, recover_from_nonce_reuse,
    recover_from_related_nonces, NonceReuseGroup, RecoveredKey,
)
from bitcoin.signature import SignatureCollection

# Detect if any signatures share the same nonce (same r value)
collection: SignatureCollection = tx.extract()
groups: list[NonceReuseGroup] = detect_nonce_reuse(collection)

# Recover private key from two signatures with same nonce
if groups:
    group = groups[0]
    result: RecoveredKey = recover_from_nonce_reuse(
        collection.records[group.indices[0]],
        collection.records[group.indices[1]],
    )
    # result.private_key, result.nonce

# Recover from related nonces k₂ = k₁ + δ
result = recover_from_related_nonces(
    collection.records[0],
    collection.records[1],
    delta=1,
)
```

### ECC Point Operations

```python
from bitcoin.ecc import (
    Secp256k1Point, G, SECP256K1_INFINITY,
    point_negate, point_add, point_double, scalar_multiply,
    is_on_curve, field_sqrt,
    parse_sec_public_key, serialize_sec_public_key,
)

# Create points
inf = Secp256k1Point(infinity=True)
p = Secp256k1Point(x=123, y=456, infinity=False)

# Operations
neg = point_negate(p)
sum_pt = point_add(p, q)
dbl = point_double(p)
mult = scalar_multiply(5, G)

# Encoding
sec_bytes = serialize_sec_public_key(p, compressed=True)
p2 = parse_sec_public_key(sec_bytes)
```

### Backend Configuration

```python
from bitcoin.ecc_backend import set_backend, get_backend
from bitcoin.coincurve_backend import CoincurveBackend

# Activate coincurve backend (requires `pip install coincurve`)
set_backend(CoincurveBackend())

# Check current backend
backend = get_backend()  # → EccBackend | None

# Reset to pure Python (default — just don't call set_backend)
```

### Batch Processing

```python
from bitcoin.batch import BatchProcessor, batch_process

# Sequential
processor = BatchProcessor(network="mainnet", timeout=30)
results = processor.process_txids(["txid1", "txid2"])

# Lazy streaming
for txid, collection in processor.process_txids_iter(["txid1", "txid2"]):
    print(txid, collection)

# Convenience (parallel)
results = batch_process("txid1", "txid2", mp=True)
```

### PSBT

```python
from bitcoin.psbt import parse_psbt_hex, parse_psbt, psbt_extract_signatures

psbt = parse_psbt_hex(psbt_hex_string)
# or
psbt = parse_psbt(raw_bytes)

sigs = psbt_extract_signatures(psbt, input_values=[100000, 200000])
```

### Fetcher

```python
from bitcoin.fetcher import (
    fetch_transaction_hex, fetch_transaction,
    fetch_address_transactions, fetch_address_utxos,
    fetch_and_extract,
)

hex_str = fetch_transaction_hex("txid", network="mainnet", timeout=30)
tx = fetch_transaction("txid")
txs = fetch_address_transactions("address")
utxos = fetch_address_utxos("address")
sigs = fetch_and_extract("txid", input_values=[100000, 200000])
```

### Configuration

```python
from bitcoin.config import Config

# Load from environment variables
config = Config.from_env()

# Load from file with env overrides
config = Config.load("/path/to/config.json")

# Access values
config.ecc_backend      # "python"
config.network          # "mainnet"
config.fetch_timeout    # 30
config.strict_parsing   # True
```

### Signature Stream

```python
from bitcoin.batch import SignatureStream
from bitcoin.models import SignatureRecord

stream = SignatureStream(transaction)

# Filtering
stream = stream.filter(lambda r: r.script_type == "psbt-segwit")

# Mapping
for record in stream:
    print(record.r)

# Materialisation
records = stream.collect()           # → list[SignatureRecord]
collection = stream.to_collection()  # → SignatureCollection
```

## Internal APIs (Not Stable)

The following modules have no backward-compatibility guarantees:

- `bitcoin.arithmetic` — Low-level modular arithmetic; prefer `bitcoin.ecc.inverse_mod` and `bitcoin.ecc.normalize_non_negative` for domain-safe wrappers
- `bitcoin.der` — Public but may change; use `Transaction.extract()` instead
- `bitcoin.parser` — Public but may change; use `Transaction.parse_hex()` instead
- `bitcoin.script` — Public but may change; script classification may be restructured
