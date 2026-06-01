# Changelog

All notable changes to this project will be documented in this file.

## [0.4.0] - 2026-05-31

### Added
- `TransactionBuilder` and `tx_from_dict` for programmatic transaction construction.
- `PsbtEditor` for fluent PSBT construction and editing.
- `sign()` and `sign_tx_input()` for deterministic ECDSA signing (RFC 6979).
- `batch_extract()` and `correlate_across_transactions()` for multi-tx processing with `ThreadPoolExecutor`.
- `BlockstreamProvider`, `BlockchainInfoProvider` for fetching blockchain data (optional runtime dep).
- `enrich_transaction()` to attach UTXO metadata to transactions.
- `TaprootScriptPath` type and `parse_taproot_witness_stack()` for taproot witness parsing.
- `get_x_only_pubkey()` to extract x-only pubkey from P2TR outputs.
- `classify_detailed()` with `is_op_return()`, `is_bare_multisig()`, `has_timelocks()`.
- `OP_RETURN`, `MULTISIG`, `TIMELOCK` script type constants.
- `ExtractorPlugin` registry for custom extraction logic.
- Structured logging with per-type telemetry in extraction engine.
- CLI output formats: `--json`, `--csv`, `--format`, `--input-file`.
- `settings.default_backend`, `settings.max_extraction_inputs` configuration.
- `UnsupportedScriptPathError` exception for unsupported script features.
- Hypothesis stateful testing via `RuleBasedStateMachine`.

### Changed
- CLI entry point renamed from `secp` to `bitcoin`.
- `Settings` singleton replaces old file/env-var `Config`.
- All exception classes now inherit from `BitcoinError(ValueError)`.
- `verify_sig` uses constant-time comparison (`hmac.compare_digest`).
- DoS limits enforced: `MAX_INPUTS`, `MAX_OUTPUTS`, `MAX_WITNESS_ITEMS`.

### Removed
- Dead code: `bitcoin/compat.py`, `bitcoin/signature/memzero.py`.
- Duplicate exception classes from `exceptions.py` (canonical versions in `attack.py`).
- `InvalidSecp256k1PointError` (never raised).
- Dead `logger` imports and definitions from `dispatch.py`, `blockchain.py`, `attack.py`.

## [0.3.0] - 2026-05-30

### Added
- `scripts/taproot.py` with taproot witness stack parsing.
- P2TR public key extraction from scriptPubKey.
- PSBT editing via `psbt/editor.py`.
- Batch extraction pipeline (`signature/pipeline.py`).
- Deterministic signing (`signature/signer.py`).
- Blockchain data providers (`services/blockchain.py`).
- Structured logging in extraction engine.

### Changed
- Script classification split into `classifier.py` and `taproot.py`.
- `backend/` subpackage with base, native, and libsec backends.
- `signature/extraction/` subpackage with plugins.

### Fixed
- `_extract_taproot` uses real x-only pubkey from scriptPubKey (not `INFINITY`).
- Backend dispatch consumes `settings.default_backend`.

## [0.2.0] - 2026-05-29

### Added
- CI/CD: GitHub Actions workflow (lint, typecheck, test on 3.12/3.13).
- `py.typed` marker for PEP 561 typed-package distribution.
- Property-based tests for ECC operations and field arithmetic.
- Docstrings on all public functions.
- MIT `LICENSE` and `CONTRIBUTING.md`.
- Optional `coincurve` backend for accelerated curve operations.

### Changed
- Package renamed from `secp` to `bitcoin`.
- `models.py` is now a zero-import leaf module (no circular import risk).
- Codebase restructured into 10 packages with strict layering.

## [0.1.0] - 2026-05-20

### Added
- Initial release: tx parsing, signature extraction, ECC operations, CLI.
- DER signature parsing, sighash computation, secp256k1 arithmetic.
- Linear coefficient derivation and verification.
- Nonce reuse detection and private key recovery.
