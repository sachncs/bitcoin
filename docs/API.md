# API Reference

## Top-level symbols (`bitcoin/__init__.py`)

```python
from bitcoin import (
    # Constants
    GENERATOR, INFINITY, CURVE_ORDER, FIELD_PRIME,
    P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR,
    MULTISIG, TIMELOCK, OP_RETURN,
    SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY,
    EMPTY_WITNESS,
    NULL,

    # Classes
    Point,
    Tx, TxIn, TxOut, OutPoint, Witness,
    ScriptChunk,
    Settings,
    Record,
    BitcoinError,

    # Functions
    extract_signatures,
    linearize_signatures,
    verify_sig,
    verify_schnorr_sig,
    verify_all,
    recover_public_key,
    parse_tx,
    make_tx,
    parse_psbt,
    serialize_psbt,
    sighash_legacy,
    sighash_segwit,
    sighash_taproot,
    parse_script,
    serialize_script,
    classify_script_pubkey,
    classify_script_sig,
    classify_detailed,
    is_op_return,
    is_bare_multisig,
    has_timelocks,
    build_p2pkh,
    build_p2wpkh,
    build_p2sh,
    build_p2wsh,
    build_p2tr,
    get_x_only_pubkey,
    parse_taproot_witness_stack,
    parse_sec,
    serialize_sec,
    encode_hex,
    decode_hex,
    encode_der,
    decode_der,
    encode_varint,
    decode_varint,
    serialize_tx,
    serialize_legacy_tx,
    tx_to_json,
    is_opt_in_rbf,
    has_sequence_lock,
    health,
    sha256,
    hash256,
    hash160,
    tagged_hash,
    bytes_to_int,
    int_to_bytes,
    negate,
    add,
    double,
    multiply,
    is_on_curve,
    sqrt_field,
    normalize,
    inverse,
    sqrt,
    pow_mod,
    set_backend,
    get_backend,
    validate_non_negative,
    settings,
    encode_sig_hash_flags,
)
```

---

## Signature Extraction

### `bitcoin.extract_signatures`

```python
def extract_signatures(
    tx: Tx,
    utxo_script_pubkeys: Sequence[bytes] | None = None,
    utxo_values: Sequence[int] | None = None,
) -> list[Record]:
```

Parse all signature-bearing inputs of a transaction. Returns a `list[Record]` — one entry per ECDSA signature found. Supports P2PKH, P2SH, P2WPKH, P2WSH, P2SH-P2WPKH, P2SH-P2WSH, P2TR key-path and script-path.

For SegWit v0 inputs, provide either `utxo_script_pubkeys` or `utxo_values` (amount needed for BIP-143 sighash).

### `bitcoin.Record`

```python
@dataclass(frozen=True, slots=True)
class Record:
    txid: bytes
    input_index: int
    signature: bytes
    public_key: Point
    parity: int
    sighash_flag: bytes
    script_type: str
    script_class: str
    amount: int | None
```

### `bitcoin.linearize_signatures`

```python
def linearize_signatures(
    records: list[Record],
) -> list[Record]:
```

Sort records by `(txid, vin)` ascending (lexicographic txid, numeric vin). Prepares records for nonce-reuse analysis.

---

## Transaction Parsing & Construction

### `bitcoin.parse_tx`

```python
def parse_tx(raw: bytes, /) -> tuple[Tx, int]:
```

Parse a raw Bitcoin transaction. Returns `(Tx, bytes_consumed)`. Supports both legacy and SegWit v0/v1 (taproot) transactions. Raises `ParsingError` on malformed data.

### `bitcoin.make_tx`

```python
def make_tx(
    version: int,
    inputs: list[TxIn],
    outputs: list[TxOut],
    lock_time: int = 0,
) -> Tx:
```

### `bitcoin.transaction.TransactionBuilder`

```python
class TransactionBuilder:
    def __init__(self, version: int = 2, lock_time: int = 0) -> None: ...
    def add_input(self, txid: bytes, vout: int, script_sig: bytes = b"", sequence: int = 0xffffffff, witness: Witness | None = None) -> TransactionBuilder: ...
    def add_output(self, value: int, script_pubkey: bytes) -> TransactionBuilder: ...
    def build(self) -> Tx: ...
```

### `bitcoin.transaction.tx_from_dict`

```python
def tx_from_dict(data: dict) -> Tx:
```

Validate and build a `Tx` from a dict with schema: `{"version": int, "inputs": [...], "outputs": [...], "lock_time": int}`.

---

## Sighash Computation

### `bitcoin.sighash_legacy`

```python
def sighash_legacy(tx: Tx, input_index: int, script_code: bytes, sighash_flag: int = SIGHASH_ALL) -> bytes:
```

Pre-SegWit (BIP-67) sighash. 32-byte double-SHA256 digest.

### `bitcoin.sighash_segwit`

```python
def sighash_segwit(tx: Tx, input_index: int, script_code: bytes, amount: int, sighash_flag: int = SIGHASH_ALL) -> bytes:
```

SegWit v0 (BIP-143) sighash. Requires `amount` (prevout value).

### `bitcoin.sighash_taproot`

```python
def sighash_taproot(tx: Tx, input_index: int, prevouts: list[bytes], amounts: list[int], script_path: bool = False, script: bytes | None = None, sighash_flag: int = SIGHASH_DEFAULT) -> bytes:
```

Taproot (BIP-341) sighash. Supports key-path and script-path spending.

---

## Signature Verification

### `bitcoin.verify_sig`

```python
def verify_sig(message_hash: bytes, der_sig: bytes, public_key: Point) -> bool:
```

Verify an ECDSA signature. Returns `True` if valid. Uses constant-time comparison internally.

### `bitcoin.recover_public_key`

```python
def recover_public_key(message_hash: bytes, der_sig: bytes, rec_id: int) -> Point:
```

Recover the public key from a message hash and signature with recovery ID (0–3).

### `bitcoin.verify_schnorr_sig`

```python
def verify_schnorr_sig(message_hash: bytes, schnorr_sig: bytes, x_only_pubkey: bytes) -> bool:
```

Verify a BIP-340 Schnorr signature.

### `bitcoin.verify_all`

```python
def verify_all(message_hash: bytes, signatures: list[bytes], public_keys: list[Point]) -> bool:
```

Batch-verify multiple ECDSA signatures against the same message hash.

---

## Nonce Reuse & Linearization

### `bitcoin.signature.derive_linear_coefficients`

```python
@dataclass(frozen=True, slots=True)
class LinearCoefficientRecord:
    alpha: int
    beta: int
    input_index: int

def derive_linear_coefficients(r: int, s: int, z: int, input_index: int) -> LinearCoefficientRecord:
```

Given ECDSA identity `s ≡ k⁻¹(z + rd)`, derive `α = s·r⁻¹ (mod n)` and `β = z·r⁻¹ (mod n)`.
Linearized form: `d ≡ α·k − β (mod n)`.

### `bitcoin.signature.attack.detect_nonce_reuse`

```python
@dataclass(frozen=True, slots=True)
class NonceReuseGroup:
    r_value: int
    indices: list[int]

def detect_nonce_reuse(collection: LinearCoefficientCollection) -> list[NonceReuseGroup]:
```

Find groups of signatures sharing the same `r` value within a `LinearCoefficientCollection`.

### `bitcoin.signature.attack.recover_from_nonce_reuse`

```python
@dataclass(frozen=True, slots=True)
class RecoveredKey:
    private_key: int
    nonce: int

def recover_from_nonce_reuse(record_1: LinearCoefficientRecord, record_2: LinearCoefficientRecord) -> RecoveredKey:
```

Recover private key and nonce from two signatures sharing the same `k`.

### `bitcoin.signature.attack.recover_from_related_nonces`

```python
def recover_from_related_nonces(
    r1: int, s1: int, z1: int,
    r2: int, s2: int, z2: int,
    delta: int,
) -> tuple[int, int]:
```

Recover private key and nonce when `k₂ = k₁ + δ` is known.

---

## Signing

### `bitcoin.signature.sign`

```python
def sign(message_hash: bytes, private_key: int) -> bytes:
```

Deterministic ECDSA signing using RFC 6979 (SHA256-based nonce generation). Returns DER-encoded signature.

### `bitcoin.signature.sign_tx_input`

```python
def sign_tx_input(
    tx: Tx,
    vin: int,
    private_key: int,
    *,
    script: bytes | None = None,
    value: int | None = None,
    sig_version: str = "segwit",
) -> bytes:
```

High-level transaction input signing. Automatically computes the correct sighash, signs, and appends the sighash flag byte. Returns DER-encoded signature with sighash flag.

---

## Batch & Pipeline

### `bitcoin.signature.batch_extract`

```python
def batch_extract(tx_raws: list[bytes], utxo_map: dict | None = None, max_workers: int | None = None) -> list[list[Record]]:
```

Extract signatures from multiple transactions in parallel using `concurrent.futures.ThreadPoolExecutor`.

### `bitcoin.signature.correlate_across_transactions`

```python
def correlate_across_transactions(grouped_records: list[list[Record]]) -> list[tuple[int, int, int]]:
```

Find nonce reuse across multiple transactions. Returns `(tx_a_idx, tx_b_idx, input_idx)` triples with matching `r` values.

---

## PSBT

### `bitcoin.parse_psbt`

```python
def parse_psbt(raw: bytes) -> Psbt:
```

Parse a BIP-174 PSBT. Returns `Psbt` with typed per-input/output maps.

### `bitcoin.serialize_psbt`

```python
def serialize_psbt(psbt: Psbt) -> bytes:
```

Serialize a `Psbt` back to binary.

### `bitcoin.serialize_tx`

```python
def serialize_tx(tx: Tx) -> bytes:
```

Serialize a transaction with segwit-awareness.

### `bitcoin.serialize_legacy_tx`

```python
def serialize_legacy_tx(tx: Tx) -> bytes:
```

Serialize a transaction in legacy (pre-segwit) format.

### `bitcoin.tx_to_json`

```python
def tx_to_json(tx: Tx) -> dict:
```

Convert a transaction to a JSON-serializable dict.

### `bitcoin.is_opt_in_rbf`

```python
def is_opt_in_rbf(tx: Tx) -> bool:
```

Check if a transaction signals opt-in RBF (sequence &lt; 0xfffffffe on any input).

### `bitcoin.has_sequence_lock`

```python
def has_sequence_lock(tx: Tx) -> bool:
```

Check if any input uses a sequence lock (sequence &lt; 0xffffffff with bit 22 set).

### `bitcoin.psbt.PsbtEditor`

```python
class PsbtEditor:
    @staticmethod
    def from_tx(tx: Tx) -> PsbtEditor: ...
    def set_input_utxo(self, vin: int, witness_utxo: bytes | None = None, non_witness_utxo: bytes | None = None) -> PsbtEditor: ...
    def add_input_partial_sig(self, vin: int, pubkey: bytes, sig: bytes) -> PsbtEditor: ...
    def build(self) -> Psbt: ...
    def serialize(self) -> bytes: ...
```

Fluent builder for constructing and editing PSBTs.

---

## Script Classification

### `bitcoin.classify_detailed`

```python
def classify_detailed(script: bytes) -> dict:
```

Returns a dict with keys: `"type"` (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, MULTISIG, TIMELOCK, OP_RETURN, NONSTANDARD).

### `bitcoin.is_op_return`

```python
def is_op_return(script: bytes) -> bool:
```

True if script starts with `OP_RETURN`.

### `bitcoin.is_bare_multisig`

```python
def is_bare_multisig(script: bytes) -> bool:
```

True if script is a bare multisig (M of N without pay-to-script-hash).

### `bitcoin.has_timelocks`

```python
def has_timelocks(script: bytes) -> bool:
```

True if script contains `OP_CHECKLOCKTIMEVERIFY` or `OP_CHECKSEQUENCEVERIFY`.

### `bitcoin.get_x_only_pubkey`

```python
def get_x_only_pubkey(script_pubkey: bytes) -> bytes | None:
```

Extract the 32-byte x-only public key from a P2TR output (OP_1 <32-byte-push>). Returns `None` for non-P2TR scripts.

### `bitcoin.parse_taproot_witness_stack`

```python
class TaprootScriptPath:
    script: bytes
    control_block: bytes

def parse_taproot_witness_stack(witness: Witness) -> tuple[Point | None, list[TaprootScriptPath]]:
```

Parse a taproot witness stack. Returns `(x_only_pubkey, list_of_script_paths)`.

---

## Blockchain Services

### `bitcoin.services.BlockstreamProvider`

```python
class BlockstreamProvider:
    def __init__(self, network: str = "mainnet") -> None: ...
    def fetch_raw_tx(self, txid: str) -> bytes: ...
    def fetch_outpoint_spend(self, txid: str, vout: int) -> dict | None: ...
```

Fetches transaction data from blockstream.info API. Optional runtime dependency via `urllib.request`.

### `bitcoin.services.BlockchainInfoProvider`

```python
class BlockchainInfoProvider:
    def __init__(self) -> None: ...
    def fetch_raw_tx(self, txid: str) -> bytes: ...
```

Fetches transaction data from blockchain.info API.

### `bitcoin.services.MempoolSpaceProvider`

```python
class MempoolSpaceProvider:
    def __init__(self, network: str = "mainnet") -> None: ...
    def fetch_raw_tx(self, txid: str) -> bytes: ...
```

Fetches transaction data from mempool.space API.

### `bitcoin.services.enrich_transaction`

```python
def enrich_transaction(tx: Tx, provider: BlockchainProvider | None = None) -> Tx:
```

Fetch UTXO details for each input and return an enriched transaction with metadata. Falls back to a default provider if none given.

---

## Settings

### `bitcoin.Settings`

```python
class Settings:
    strict_mode: bool = False
    default_backend: str | None = None
    max_extraction_inputs: int = 0
```

Global settings object via `bitcoin.settings`. Modify at runtime:

```python
from bitcoin import settings
settings.strict_mode = True
settings.default_backend = "libsecp"
settings.max_extraction_inputs = 5000
```

---

## Curve Backend

### `bitcoin.set_backend`

```python
def set_backend(backend_name: str) -> None:
```

Set the curve backend by name: `"native"` (pure Python) or `"libsecp"` (coincurve).

### `bitcoin.get_backend`

```python
def get_backend() -> CurveBackend:
```

Return the active backend instance.

---

## Health Check

### `bitcoin.health`

```python
def health() -> dict:
```

Run health checks and return a JSON status report with version, import info, backend status, and curve operation verification.
