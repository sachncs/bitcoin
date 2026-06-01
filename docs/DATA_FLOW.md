# Data Flow

## 1. CLI `extract` Command

```
User input (raw tx hex string)
        │
        ▼
  bitcoin/cli/app.py  (decode hex → bytes)
        │
        ▼
  bitcoin.transaction.parser.parse_tx()  →  (Tx, bytes_consumed)
        │
        ▼
  For each input:
    │
    ├─ P2PKH/P2SH scriptSig → script.parser.parse_script()
    ├─ P2WPKH/P2WSH witness → transaction.models.Witness
    └─ P2TR taproot        → script.taproot.parse_taproot_witness_stack()
        │
        ▼
  bitcoin.signature.extraction.engine.extract_signatures()
    │
    ├─ For each input:
    │   ├─ Determine script type (script.classifier)
    │   ├─ If SegWit v0: compute sighash_segwit()
    │   │   (requires utxo_value for amount)
    │   ├─ If Legacy:     compute sighash_legacy()
    │   ├─ If Taproot:    compute sighash_taproot()
    │   └─ Parse ECDSA DER signature + recover public key
    │
    └─ Returns list[Record] ──→ CLI prints table/JSON/CSV
```

**UTXO metadata resolution flow:**

```
User provides --utxo-value, --utxo-script
        │
        ▼
  If utxo_scripts provided → classify_script_pubkey() for each
  If utxo_values provided  → used directly for sighash_segwit()
  If not provided:
    │
    ├─ Legacy/P2SH → no sighash needed (sighash_legacy) gets script from tx witness/sig
    ├─ SegWit v0   → skips (no sighash)
    └─ Taproot     → skips (no sighash)
```

## 2. CLI `linearize` Command

```
extract() → list[Record] → linearize_signatures() → sort by (txid, vin)
        │
        ▼
  CLI prints sorted table (or JSON/CSV)
```

## 3. Batch Extraction (Python API)

```
bitcoin.signature.pipeline.batch_extract()
    │
    ├─ ThreadPoolExecutor(max_workers)
    │   └─ For each raw tx: parse_tx() → extract_signatures()
    │
    └─ Returns list[list[Record]]
```

Nonce correlation across transactions:

```
bitcoin.signature.pipeline.correlate_across_transactions()
    │
    ├─ Collect all r-values across grouped records
    ├─ Find r-value collisions between different transactions
    └─ Returns list of (tx_a_idx, tx_b_idx, input_idx) triples
```

## 4. Nonce Reuse Detection

```
LinearCoefficientRecords from signatures
        │
        ▼
  detect_nonce_reuse() → groups of matching r-values
        │
        ▼
  recover_from_nonce_reuse() → (private_key, nonce)
```

Derivation:

```
Given: s ≡ k⁻¹(z + rd) (mod n)
Multiply both sides by k:   s·k ≡ z + rd
                             s·k − rd ≡ z
                             rd ≡ s·k − z
                             d ≡ r⁻¹·s·k − r⁻¹·z
                             d ≡ α·k − β

α = s · r⁻¹ (mod n)
β = z · r⁻¹ (mod n)
```

## 5. PSBT Flow

```
Raw PSBT hex → parse_psbt()
    │
    ├─ Parse BIP-174 binary format
    ├─ Extract unsigned transaction
    ├─ Per-input maps: non_witness_utxo, witness_utxo, partial_sigs, redeem_script, witness_script, keypaths
    └─ Per-output maps: redeem_script, witness_script, keypaths
        │
        ▼
  psbt_extract_signatures() → list[Record]
```

PSBT editing:

```
PsbtEditor.from_tx(unsigned_tx)
    │
    ├─ set_input_utxo(vin, witness_utxo=..., non_witness_utxo=...)
    ├─ add_input_partial_sig(vin, pubkey, sig)
    └─ build() → Psbt → serialize_psbt() → bytes
```

## 6. Signing Flow

```
sign(message_hash, private_key)
    │
    ├─ Generate deterministic k via RFC 6979 (SHA256-based)
    ├─ Compute R = k·G, r = R.x
    ├─ s = k⁻¹(z + rd) mod n
    └─ Return DER-encoded (r, s)
```

Transaction signing:

```
sign_tx_input(tx, vin, private_key, script=..., value=...)
    │
    ├─ Determine sighash type (script path presence)
    ├─ Compute sighash (legacy/segwit/taproot)
    ├─ sign(sighash, private_key)
    └─ Append SIGHASH_ALL flag → returned as bytes
```

## 7. Transaction Building Flow

```
TransactionBuilder(version=2).add_input(...).add_output(...).build()
    │
    └─ Validates inputs → constructs Tx → returns Tx

tx_from_dict({"version": 2, "inputs": [...], "outputs": [...], ...})
    │
    ├─ Validates schema types
    ├─ Builds TxIn/TxOut/OutPoint/Witness from dict entries
    └─ Returns Tx
```

## 8. Enriched Transaction Flow

```
enrich_transaction(tx, provider=BlockstreamProvider())
    │
    ├─ For each input: fetch UTXO tx via provider.fetch_raw_tx()
    ├─ Parse UTXO tx to find the spent output
    ├─ Attach script_pubkey and value
    └─ Return enriched Tx with metadata
```

## File-by-file flow map

```
CLI (bitcoin/cli/app.py)
  ↓ calls
transaction/parser.py → transaction/models.py (Tx, TxIn, TxOut, Witness)
  ↓ calls
encoding/varint.py, encoding/hex.py, encoding/binary.py (raw byte parsing)
  ↓
sighash/ → encoding/hasher.py (sha256, hash256)
  ↓
signature/extraction/engine.py
  ├─ script/classifier.py (script type lookup)
  ├─ script/parser.py (script chunking)
  ├─ curve/ → field/modular.py (mod inverse)
  └─ encoding/der.py (DER signature parsing)
  ↓
signature/collection.py (Record containers)
  ↓
CLI output
```
