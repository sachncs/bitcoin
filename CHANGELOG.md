# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- Public re-exports from package root: `DescriptorError`, `DescriptorInfo`,
  `DescriptorNode`, `ESTIMATED_SATISFACTION`, `collect_info`,
  `collect_keys`, `contains_op`, `emit_script`, `estimate_satisfaction`,
  `sorted_unique`, `split_args`, `parse_psbt_impl`, `parse_psbt_worker`,
  `process_psbt_batch`, `process_psbt_batch_with`, `CURVE_A`, `CURVE_B`.
- Public `BUILTINS_REGISTERED` flag in `bitcoin.signature.extraction.engine`
  and public `registry` dict in `bitcoin.signature.extraction.plugins`
  so callers can introspect plugin registration state.
- Public `LOGGING_CONFIGURED` flag in `bitcoin.cli.app`.
- `CURVE_A = 0` and `CURVE_B = 7` constants exported from
  `bitcoin.curve.params` (and the package root) so the documented curve
  equation `y² = x³ + a·x + b (mod p)` is fully representable in Python.
- Comprehensive module-, class-, and method-level docstrings (Google
  style) across every module, including algorithm background sections
  (RFC-6979 deterministic nonces, BIP-143 amortised hashes, BIP-340
  tagged-hash discrimination, BIP-341 key-path vs. script-path spends,
  Straus's interleaved-window multi-exponentiation, RFC-6979 HMAC-DRBG,
  Template-Method provider pattern).
- Inline comments for the nonce-reuse `d = α·k − β` algebra, the
  BIP-341 hash-type byte, the BIP-32 keypath parser, the SegWit
  witness-stack parser, and the multi-level matching key-path code.

### Changed
- Promoted semi-private (`__name`) helpers to plain public names:
  - `bitcoin.descriptor.analyzer`: `__ESTIMATED_SATISFACTION` →
    `ESTIMATED_SATISFACTION`, `__collect_info` → `collect_info`,
    `__contains_op` → `contains_op`, `__estimate_satisfaction` →
    `estimate_satisfaction`, `__sorted_unique` → `sorted_unique`,
    `__collect_keys` → `collect_keys`.
  - `bitcoin.descriptor.compiler`: `__split_args` → `split_args`,
    `__emit_script` → `emit_script`.
  - `bitcoin.psbt.parser`: `__parse_psbt_impl` → `parse_psbt_impl`.
  - `bitcoin.psbt.pipeline`: `__parse_psbt_worker` → `parse_psbt_worker`.
  - `bitcoin.signature.pipeline`: `__process_single_worker` →
    `process_single_worker`.
  - `bitcoin.signature.extraction.engine`: `__BUILTINS_REGISTERED` →
    `BUILTINS_REGISTERED`.
  - `bitcoin.signature.extraction.plugins`: `__registry` → `registry`.
  - `bitcoin.cli.app`: `__LOGGING_CONFIGURED` → `LOGGING_CONFIGURED`.
- Each renamed helper received a full Google-style docstring explaining
  intent, parameters, return values, side effects, and edge cases.
- Expanded module-level docstrings across every package
  (`bitcoin.curve`, `bitcoin.encoding`, `bitcoin.field`,
  `bitcoin.script`, `bitcoin.sighash`, `bitcoin.transaction`,
  `bitcoin.signature`, `bitcoin.descriptor`, `bitcoin.psbt`,
  `bitcoin.services`, `bitcoin.cli`) with architecture overviews,
  design notes, and references to BIPs and RFCs.
- `services/blockchain.py`: `async_enrich_transaction` and
  `async_batch_fetch_transactions` now carry full Google-style
  docstrings matching their sync counterparts.
- `bitcoin/__init__.py`: rewritten as a layered package overview with
  deduplicated, alphabetised `__all__` listing 191 public symbols.

### Atomic commits in this release

| Commit  | Date (UTC+05:30)        | Subject |
|---------|-------------------------|---------|
| `32fc33c` | 2026-07-12 13:44:20 +0530 | refactor(descriptor): promote semi-private AST helpers to public API |
| `9679c0e` | 2026-07-12 13:44:42 +0530 | refactor(psbt): promote semi-private parser/pipeline helpers to public API |
| `37fc931` | 2026-07-12 13:44:57 +0530 | refactor(signature): promote semi-private extraction/pipeline helpers to public API |
| `ccb0235` | 2026-07-12 13:45:10 +0530 | refactor(cli): promote __LOGGING_CONFIGURED to public module state |
| `adb304e` | 2026-07-12 13:45:45 +0530 | docs(curve): expand docstrings and define CURVE_A/CURVE_B constants |
| `12ffee8` | 2026-07-12 13:45:55 +0530 | docs(encoding,field,settings,exceptions,health): expand module docstrings |
| `1ab0c77` | 2026-07-12 13:46:06 +0530 | docs(script,sighash): expand module docstrings across Script and sighash |
| `3393c02` | 2026-07-12 13:46:15 +0530 | docs(transaction,services): expand module docstrings |
| `7b674d2` | 2026-07-12 13:46:34 +0530 | feat: rewrite package-root __init__.py with layered overview and new exports |

## [0.5.0] - 2026-06-05

### Removed
- Import-time auto-registration of extraction plugins (replaced by `register_builtin_extractors()`).
- `RuntimeError` from CLI exception handlers (typer.Exit is a RuntimeError; was being swallowed).

### Fixed
- `health.py:57` silent exception swallow — now logs `logger.warning` with module name and error.
- Mypy: `coincurve` import-not-found errors suppressed per-module override.
- Ruff naming violations: `# noqa` annotations for crypto-standard uppercase variables.
- `setup.sh` no longer crashes when `.pre-commit-config.yaml` is absent.

### Security
- `pip-audit` scans for known CVEs in CI and release workflows.
- PyPI publish uses Test PyPI dry-run before production push.
- Build provenance attestation generated for every release.
- Pip version pinned in `setup.sh` to mitigate supply-chain risk.

## [0.5.0] - 2026-06-05

### Added
- `health()` / `check_backend()` / `check_imports()` library health introspection.
- `recover_from_related_nonces()` for exploiting nonces with known offset (`k2 = k1 + delta`).
- `batch_extract_from_file()` for reading tx hexes from a file.
- `lift_x()` for BIP-340 x-only public key lifting.
- `MempoolSpaceProvider()` blockchain data provider.
- `classify_script_sig()` and `P2PK` / `MULTISIG` script type constants.
- `build_p2pkh()`, `build_p2sh()`, `build_p2wpkh()`, `build_p2wsh()`, `build_p2tr()` script builders.
- `is_opt_in_rbf()` and `has_sequence_lock()` transaction utilities.
- Dependabot configuration for automated dependency updates.
- Mainnet signature extraction test vectors (`test_mainnet_vectors.py`).
- Concurrency tests (`test_concurrency.py`).
- Shared test fixtures in `conftest.py`.

### Changed
- `Settings` is now thread-safe with `threading.Lock`.
- Fixed-base multiplication optimization for generator point (4-bit window table).
- TXID validation added to `BlockstreamProvider` and `BlockchainInfoProvider`.
- Sighash modules refactored for cleaner implementation.
- `sign()` and `sign_tx_input()` wipe sensitive values from stack frames after signing.
- HMAC-DRBG bounded retry limit (raises after 1000 attempts instead of infinite loop).
- Type annotations modernized (PEP 604: `str | None` instead of `Optional[str]`).
- Extraction engine logging improved (warning instead of debug on skipped signatures).
- `Record` dataclass enhancements.
- Backend dispatch validates scalar non-negativity and reduces modulo `CURVE_ORDER`.
- Taproot sighash computation edge cases hardened.

### Removed
- `.pre-commit-config.yaml` (pre-commit checks moved to CI).
- `tests/helpers.py` (replaced by `conftest.py`).
- Dead exception classes from `exceptions.py`.
- Various dead imports and unused constants.

### Fixed
- Sighash legacy calculation for edge cases.
- Various minor bug fixes across extraction, PSBT parsing, and signing.

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
