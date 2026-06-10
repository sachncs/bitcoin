# Modules

## `bitcoin.field` — Modular Arithmetic

**Submodules**: `modular.py`, `sqrt.py`

**Dependencies**: None (stdlib)

**Public API** (re-exported via `bitcoin.field`):
| Symbol | Kind | Description |
|--------|------|-------------|
| `inverse` | Function | Extended Euclidean modular inverse |
| `sqrt` | Function | Tonelli-Shanks sqrt (p ≡ 3 mod 4 specialization) |
| `pow_mod` | Function | Modular exponentiation |
| `validate_non_negative` | Function | Assert value is non-negative int |
| `NotInvertible` | Exception | Raised when value has no modular inverse |

**Consumers**: `bitcoin.curve`, `bitcoin.signature`

---

## `bitcoin.curve` — ECC Point Operations

**Submodules**: `params.py`, `point.py`, `operations.py`, `dispatch.py`, `libsecp256k1.py`, `backend/base.py`, `backend/native.py`, `backend/libsec.py`

**Dependencies**: `field`

**Public API**:
| Symbol | Kind | Description |
|--------|------|-------------|
| `Point` | Class | Frozen affine point with SEC serialization methods |
| `GENERATOR` | Constant | Secp256k1 generator point |
| `INFINITY` | Constant | Identity element |
| `CURVE_ORDER` | Constant | Curve order n |
| `FIELD_PRIME` | Constant | Field prime p |
| `CurveBackend` | ABC | Abstract backend interface |
| `NativeBackend` | Class | Pure Python backend |
| `LibsecpBackend` | Class | Coincurve-backed backend |
| `set_backend` / `get_backend` | Functions | Backend dispatch |
| `negate`, `add`, `double`, `multiply` | Functions | Point operations |
| `is_on_curve` | Function | Curve membership test |
| `sqrt_field` | Function | Field sqrt for y recovery |
| `parse_public_key` / `serialize_public_key` | Functions | SEC key I/O |
| `normalize` / `normalize_non_negative` | Functions | Scalar helpers |

**Consumers**: `encoding`, `signature`

---

## `bitcoin.encoding` — Binary Encoding

**Submodules**: `hex.py`, `binary.py`, `varint.py`, `der.py`, `sec.py`, `hasher.py`

**Dependencies**: None (stdlib)

**Public API**:
| Symbol | Kind | Description |
|--------|------|-------------|
| `encode_hex` / `decode_hex` | Functions | Hex I/O |
| `encode_varint` / `decode_varint` | Functions | Bitcoin varint |
| `encode_der` / `decode_der` | Functions | Strict BIP-66 DER |
| `parse_sec` / `serialize_sec` | Functions | SEC public key |
| `sha256`, `hash256`, `hash160` | Functions | Hashing |
| `tagged_hash` | Function | BIP-340 tagged hash |
| `bytes_to_int` / `int_to_bytes` | Functions | Integer conversion |
| `read_exactly` | Function | Bounded binary read |

**Consumers**: All packages (encoding, script, transaction, sighash, signature, etc.)

---

## `bitcoin.script` — Bitcoin Script

**Submodules**: `opcodes.py`, `parser.py`, `classifier.py`, `builder.py`, `taproot.py`

**Dependencies**: `encoding` (opcode values), `exceptions`

**Public API**:
| Symbol | Kind | Description |
|--------|------|-------------|
| `parse_script` | Function | Bytes → script element list |
| `serialize_script` | Function | Elements → bytes |
| `classify_script_pubkey` | Function | Output script → type constant |
| `classify_script_sig` | Function | Input script → type constant |
| `classify_detailed` | Function | Expanded classification (OP_RETURN, MULTISIG, TIMELOCK) |
| `ScriptChunk` | Dataclass | Parsed script element |
| `build_p2pkh`, `build_p2wpkh`, etc. | Functions | Script construction |
| `P2PK`, `P2PKH`, `P2SH`, `P2WPKH`, `P2WSH`, `P2TR` | Constants | Script type identifiers |
| `MULTISIG`, `TIMELOCK`, `OP_RETURN` | Constants | Additional script type identifiers |
| Opcode constants | Constants | `OP_DUP`, `OP_HASH160`, etc. |
| `is_op_return`, `is_bare_multisig`, `has_timelocks` | Functions | Script type predicates |
| `get_x_only_pubkey` | Function | Extract x-only pubkey from P2TR output |
| `parse_taproot_witness_stack` | Function | Parse Taproot witness stack into script paths |

**Consumers**: `transaction`, `sighash`, `signature`

---

## `bitcoin.transaction` — Transaction Models

**Submodules**: `models.py`, `parser.py`, `tx.py`, `builder.py`

**Dependencies**: `encoding`, `exceptions`

**Public API**:
| Symbol | Kind | Description |
|--------|------|-------------|
| `Tx` | Class | Frozen transaction with `txid()`, `is_segwit()` |
| `TxIn` | Class | Transaction input |
| `TxOut` | Class | Transaction output |
| `OutPoint` | Class | Previous output reference |
| `Witness` | Class | Witness stack |
| `EMPTY_WITNESS` | Constant | Empty witness singleton |
| `parse_tx` | Function | Raw bytes → `(Tx, bytes_consumed)` |
| `make_tx` | Function | Convenience tx builder (dict-based) |
| `TransactionBuilder` | Class | Fluent tx builder with `add_input`, `add_output`, `build` |
| `tx_from_dict` | Function | Validate and build Tx from dict |

**Consumers**: `sighash`, `signature`, `psbt`, `cli`, `services`

---

## `bitcoin.sighash` — Sighash Computation

**Submodules**: `flag.py`, `legacy.py`, `segwit.py`, `taproot.py`

**Dependencies**: `encoding`, `transaction`, `script`

**Public API**:
| Symbol | Kind | Description |
|--------|------|-------------|
| `sighash_legacy` | Function | Pre-SegWit hash |
| `sighash_segwit` | Function | BIP-143 SegWit v0 hash |
| `sighash_taproot` | Function | BIP-341 Taproot hash |
| `SIGHASH_ALL`, `SIGHASH_NONE`, etc. | Constants | Sighash flag values |
| `require_sighash_flag` | Function | Validate flag byte |

**Consumers**: `signature`

---

## `bitcoin.signature` — Signature Type, Extraction & Linearization

**Submodules**: `record.py`, `collection.py`, `check.py`, `attack.py`, `signer.py`, `schnorr.py`, `batch_verify.py`, `memzero.py`, `pipeline.py`, `extraction/engine.py`, `extraction/plugins.py`, `linearization/engine.py`, `linearization/coefficients.py`

**Dependencies**: `curve`, `encoding`, `transaction`, `sighash`, `field`, `script`, `exceptions`

**Public API**:
| Symbol | Kind | Description |
|--------|------|-------------|
| `Record` | Class | Frozen extraction result: `txid`, `input_index`, `signature`, `public_key`, `script_type`, `sighash_flag`, `amount` |
| `SignatureCollection` | Class | Collection of records with shared state |
| `extract_signatures` | Function | `Tx` → `list[Record]` |
| `linearize_signatures` | Function | `list[Record]` → sorted `list[Record]` |
| `verify_sig` | Function | Verify ECDSA signature |
| `verify_schnorr_sig` | Function | Verify Schnorr (BIP-340) signature |
| `verify_all` | Function | Batch verify multiple ECDSA signatures |
| `recover_public_key` | Function | Recover pubkey from message + signature |
| `derive_linear_coefficients` | Function | `(r, s, z)` → `LinearCoefficientRecord` |
| `LinearCoefficientRecord` | Dataclass | Single linearised signature with `alpha`, `beta` |
| `LinearCoefficientCollection` | Dataclass | Collection of linear coefficient records |
| `sign` | Function | Deterministic ECDSA signing (RFC 6979) |
| `sign_tx_input` | Function | Sign a transaction input with sighash |
| `batch_extract` | Function | Multi-transaction extraction with threading |
| `correlate_across_transactions` | Function | Nonce reuse detection across transactions |

From `bitcoin.signature.attack`:
| Symbol | Kind | Description |
|--------|------|-------------|
| `NonceReuseGroup` | Dataclass | Group of signatures sharing the same `r` |
| `RecoveredKey` | Dataclass | Recovered private key and nonce |
| `detect_nonce_reuse` | Function | Find `r`-value collisions |
| `recover_from_nonce_reuse` | Function | Recover key from same-nonce pair |
| `recover_from_related_nonces` | Function | Recover key when `k₂ = k₁ + δ` |

**Consumers**: `psbt`, `cli`

---

## `bitcoin.psbt` — PSBT Parsing

**Submodules**: `models.py`, `parser.py`, `editor.py`

**Dependencies**: `transaction`, `encoding`, `signature`, `script`

**Public API**:
| Symbol | Kind | Description |
|--------|------|-------------|
| `Psbt` | Class | Frozen PSBT with unsigned tx, input/output maps |
| `PsbtInput` / `PsbtOutput` | Classes | Per-input/output PSBT data |
| `parse_psbt` | Function | Raw bytes → `Psbt` |
| `serialize_psbt` | Function | `Psbt` → raw bytes |
| `parse_psbt_hex` | Function | Hex string → `Psbt` |
| `psbt_extract_signatures` | Function | Extract sigs from PSBT partial sigs |
| `parse_keypath_value` | Function | Parse BIP-32 keypath value |
| `PsbtEditor` | Class | Fluent PSBT construction and editing |

**Consumers**: `cli`, scripts

---

## `bitcoin.services` — Serialization & Blockchain

**Submodules**: `serializer.py`, `blockchain.py`

**Dependencies**: `transaction`, `encoding`

**Public API**:
| Symbol | Kind | Description |
|--------|------|-------------|
| `serialize_tx` | Function | `Tx` → segwit-aware raw bytes |
| `serialize_legacy_tx` | Function | `Tx` → legacy format bytes |
| `BlockchainProvider` | Protocol | Pluggable blockchain data provider |
| `BlockstreamProvider` | Class | Blockstream.info API provider |
| `BlockchainInfoProvider` | Class | Blockchain.info API provider |
| `enrich_transaction` | Function | Fetch UTXO scripts/values for a transaction |

---

## `bitcoin.cli` — CLI

**Submodules**: `app.py`

**Dependencies**: `typer`, `signature`, `encoding`, `transaction`, `services`

**Commands**:
| Command | Description |
|---------|-------------|
| `extract` | Parse tx hex, extract signatures (supports `--json`, `--csv`, `--format`, `--input-file`, `--utxo-script`, `--utxo-value`) |
| `linearize` | Extract + sort by txid/vin |
| `version` | Print version |

**Entry point**: `bitcoin` (console_scripts) or `python -m bitcoin.cli`

---

## `bitcoin.exceptions` — Exception Types

**Dependencies**: None

| Exception | Parent | Raised When |
|-----------|--------|-------------|
| `BitcoinError` | `ValueError` | Base for all package errors |
| `NotInvertible` | `BitcoinError` | Value has no modular inverse |
| `PointError` | `BitcoinError` | Invalid curve point |
| `InvalidSignature` | `BitcoinError` | Signature validation fails |
| `InvalidDerSignature` | `BitcoinError` | DER format violation |
| `ParsingError` | `BitcoinError` | Transaction/script parse failure |
| `UnsupportedScriptPathError` | `BitcoinError` | Unsupported script feature (e.g. OP_CODESEPARATOR) |
| `NotInvertibleError` | `BitcoinError` | Non-invertible linear coefficient (deprecated) |
| `InvalidLinearCoefficientError` | `BitcoinError` | Invalid linear coefficient |
| `NonInvertibleLinearCoefficientError` | `BitcoinError` | Non-invertible coefficient |

---

## `bitcoin.settings` — Global Settings

**Dependencies**: None

| Feature | Description |
|---------|-------------|
| `settings.strict_mode` | If True, raise on non-fatal issues |
| `settings.default_backend` | Backend name (`"native"`, `"libsecp"`, or `None`) |
| `settings.max_extraction_inputs` | Cap on inputs processed during extraction |
