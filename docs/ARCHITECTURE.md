# Architecture

## High-Level Design

The codebase is organized into three layers with strict dependency direction. No module in an upper layer imports from a module in the same or lower layer in a way that creates a cycle.

```
┌─────────────────────────────────────────────────────────────────┐
│                     CLI / Public API                             │
│  cli.py  │  psbt.py  │  batch.py  │  fetcher.py                 │
│  attack.py  │  __init__.py (package exports)                    │
└─────────────────────────────────────────────────────────────────┘
         │                    │                      ▲
         ▼                    ▼                      │
┌─────────────────────────────────────────────────────────────────┐
│                    Extraction Layer                              │
│  extractor.py  │  sighash.py  │  der.py                          │
│  script.py  │  parser.py  │  signature.py                       │
└─────────────────────────────────────────────────────────────────┘
         │                    │                      ▲
         ▼                    ▼                      │
┌─────────────────────────────────────────────────────────────────┐
│                     Arithmetic Layer                             │
│  ecc.py  │  linear.py  │  arithmetic.py                          │
│  ecc_backend.py  │  coincurve_backend.py                         │
└─────────────────────────────────────────────────────────────────┘
         │                    │                      ▲
         ▼                    ▼                      │
┌─────────────────────────────────────────────────────────────────┐
│                      Foundation Layer                            │
│  models.py  │  exceptions.py  │  utils.py  │  config.py          │
│  serializer.py                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Module Boundaries

See [MODULES.md](MODULES.md) for a detailed breakdown of every module's purpose, dependencies, and public API.

## Dependency Direction

- **No circular dependencies**. Verified by manual inspection of all import statements.
- **Foundation layer** (`models.py`, `exceptions.py`, `utils.py`, `config.py`, `serializer.py`) has minimal intra-package imports (`utils.py` → `exceptions.py`, `serializer.py` → `utils.py`).
- **Arithmetic layer** imports from Foundation only.
- **Extraction layer** imports from Arithmetic and Foundation.
- **CLI layer** imports from Extraction, Arithmetic, and Foundation.

## Layering Rules

1. **Foundation modules** never import from higher layers.
2. **Arithmetic modules** never import from Extraction or CLI layers.
3. **Backend modules** (`ecc_backend.py`, `coincurve_backend.py`) use `TYPE_CHECKING` imports for `Secp256k1Point` to avoid import-time coupling.
4. **`arithmetic.py`** holds pure modular arithmetic; its functions are re-exported through `ecc.py` and `linear.py` with domain-specific error wrapping.

## Main Runtime Paths

### Transaction Parsing & Signature Extraction

```
Transaction.parse_hex(hex_str)
  └─ validate_hex_string()          → utils.py
  └─ parse_transaction_bytes()      → parser.py
      └─ ByteReader                 → utils.py
  └─ Transaction.from_parsed()      → transaction.py

Transaction.extract()
  └─ extract_signatures()           → extractor.py
      └─ parse_script()             → script.py
      └─ dispatch by script type:
          ├─ _extract_legacy_p2pkh
          ├─ _extract_native_p2wpkh
          ├─ _extract_taproot_key_path
          └─ ...
      └─ _build_records()           → extractor.py
          ├─ parse_der_signature()  → der.py
          ├─ legacy_sighash()       → sighash.py
          └─ segwit_sighash()       → sighash.py
```

### Signature Linearization

```
SignatureCollection.linear()
  └─ derive_linear_coefficients()   → linear.py
      └─ inverse_mod()              → linear.py → arithmetic.py
      └─ returns LinearCoefficientRecord

SignatureCollection.linear_points()
  └─ derive_point_relation()        → ecc.py
      └─ derive_linear_coefficients → linear.py
      └─ scalar_multiply()          → ecc.py (→ backend or pure Python)
      └─ point_add()                → ecc.py (→ backend or pure Python)

SignatureCollection.transform_points()
  └─ derive_transformed_point()     → ecc.py
      └─ same as linear_points path
```

### Batch Processing

```
batch_process(*txids, mp=True)
  └─ multiprocessing.Pool
      └─ _extract_one() per txid    → batch.py
          └─ fetch_transaction()    → fetcher.py (HTTP → blockstream.info)
          └─ Transaction.extract()  → extractor.py

BatchProcessor.process_txids(txids)
  └─ process_txid() per txid        → batch.py (sequential)
      └─ same as above
```

## Public Interfaces

The public API surface is defined by:

1. **`bitcoin/__init__.py`** — explicit `__all__` controlling `from bitcoin import *`
2. **`bitcoin/ecc.py`** — explicit `__all__` for ECC operations
3. **`bitcoin/linear.py`** — explicit `__all__` for linearization
4. **`bitcoin/cli.py`** — CLI commands via `typer`

## Ownership Responsibilities

| Module | Owns | Does Not Own |
|--------|------|-------------|
| `arithmetic.py` | Pure modular arithmetic (inversion, non-negative validation) | Domain-specific error types |
| `ecc.py` | Point arithmetic, SEC encoding, public wrappers | Parsing, extraction |
| `linear.py` | Scalar linearization formulas | Point arithmetic |
| `extractor.py` | Script dispatch, record building | Sighash computation, DER parsing |
| `sighash.py` | Legacy/SegWit/Taproot sighash | Transaction structure |
| `script.py` | Script parsing and classification | Script execution |
| `fetcher.py` | HTTP API interaction | Transaction models |
| `serializer.py` | JSON I/O formatting | Domain logic |
