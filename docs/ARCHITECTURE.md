# Architecture

## High-Level Design

10 packages with strict one-way dependency. No package imports from a package at the same or deeper level in a way that creates a cycle.

```
field  →  curve  →  encoding  →  script  →  transaction  →  sighash  →  signature  →  psbt
                                                                                  │
                                                                                  ▼
                                                                             services  →  cli
```

## Package Boundaries

| Package | Submodules | Owns |
|---------|------------|------|
| `field` | `modular.py`, `sqrt.py` | Modular inverse, field square root, validation |
| `curve` | `params.py`, `point.py`, `operations.py`, `dispatch.py`, `libsecp256k1.py`, `backend/base.py`, `backend/native.py`, `backend/libsec.py` | Point type, affine ops, SEC encoding, pluggable backends |
| `encoding` | `hex.py`, `binary.py`, `varint.py`, `der.py`, `sec.py`, `hasher.py` | Binary formats, DER/SEC parsing, SHA256, hash160 |
| `script` | `opcodes.py`, `parser.py`, `classifier.py`, `builder.py`, `taproot.py` | Script chunking, type classification, building, tapscript parsing |
| `transaction` | `models.py`, `parser.py`, `tx.py`, `builder.py` | TxIn/TxOut/Tx structs, raw byte parsing, construction, fluent builder |
| `sighash` | `flag.py`, `legacy.py`, `segwit.py`, `taproot.py` | Sighash flag parsing, legacy/SegWit/Taproot digest |
| `signature` | `record.py`, `collection.py`, `check.py`, `attack.py`, `memzero.py`, `signer.py`, `pipeline.py`, `extraction/engine.py`, `extraction/plugins.py`, `linearization/engine.py`, `linearization/coefficients.py` | Record, extraction, verification, nonce-reuse attack, signing, batch processing, linearization, plugin registry |
| `psbt` | `models.py`, `parser.py`, `editor.py` | PSBT structs, BIP-174 parse/serialize, fluent editing |
| `services` | `serializer.py`, `blockchain.py` | Transaction serialization, blockchain data fetching |
| `cli` | `app.py` | Typer commands: `extract`, `linearize`, `version` |

## Layering Rules

1. `field` — stdlib only, no internal imports
2. `curve` — imports `field` only
3. `encoding` — stdlib only
4. `script` — imports `encoding` (for opcode values), `exceptions`
5. `transaction` — imports `encoding`, `exceptions`
6. `sighash` — imports `encoding`, `transaction`, `script`
7. `signature` — imports `curve`, `encoding`, `transaction`, `sighash`, `field`, `script`
8. `psbt` — imports `transaction`, `encoding`, `signature`
9. `services` — imports `transaction`, `encoding`
10. `cli` — imports `signature`, `encoding`, `transaction`, `services`

## Public Interface

The public API surface is defined in `bitcoin/__init__.py` with an explicit `__all__`. Every public symbol is re-exported from the top-level `bitcoin` package.

## Backend Architecture

Curve operations support pluggable backends:

- **NativeBackend** — pure Python implementation (always available, default)
- **LibsecpBackend** — wraps `coincurve` (libsecp256k1 C bindings, optional)

`set_backend(backend)` installs a backend; `get_backend()` returns it. All point operations (`add`, `double`, `multiply`, `negate`) dispatch through `curve/dispatch.py`.

`settings.default_backend` controls which backend `__resolve_backend()` returns when no explicit backend is set.

## Key Design Decisions

- **Frozen dataclasses with slots** for all value objects (`Point`, `Tx`, `Record`, `Psbt`, etc.)
- **Exhaustive type annotations** — `mypy --strict` clean across all source files
- **`__init__.py` is the public API surface** — submodules are implementation details
- **models.py is the zero-import leaf** — `transaction/models.py` imports nothing from the package, avoiding circular deps
- **Pure Python first, C optional** — core library has zero runtime dependencies (only `typer` for CLI)
