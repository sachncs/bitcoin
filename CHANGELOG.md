# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added
- `bitcoin health` CLI command for runtime introspection (runs health checks, prints JSON).
- JSON structured logging via `JSONFormatter`; configurable via `BITCOIN_LOG_LEVEL` env var.
- `register_builtin_extractors()` — plugin registration moved from import-time side effect to an explicit idempotent call.
- Library health module (`health.py`) now logs import failures instead of silently swallowing them.
- `MAINTAINERS.md`, `SECURITY.md`, `SUPPORT.md`, `CODE_OF_CONDUCT.md` governance files.
- GitHub issue templates (`bug_report.md`, `feature_request.md`) and pull request template.
- `.github/FUNDING.yml` skeleton for sponsors.
- `pip-audit` dependency CVE scanning step in CI and release workflows.
- Concurrency control (`cancel-in-progress: true`) and path filtering on CI.
- Dependency caching for `astral-sh/setup-uv` in all CI jobs.
- `workflow_dispatch` trigger on both CI and release workflows.
- Test PyPI publish and build provenance attestation (`attest-build-provenance`) in release pipeline.
- Build artifacts uploaded as workflow artifacts in releases.
- Environment variable reference and JSON logging callout in README.
- License badge to README.

### Changed
- CLI error handling: `main()` now returns `1` on unhandled exceptions (was always `0`).
- CLI exception coverage broadened to `ValueError`, `OSError`, `IndexError`, `TypeError`, `AttributeError`.
- Logging format switched from plain text to JSON (all log entries are now machine-parseable).
- `verify_signature()` in `signature/check.py` now logs per-path debug messages on each failure mode.
- `pyproject.toml`: expanded Ruff ruleset (`I`, `N`), added `maintainers`/`keywords`/`urls`, added `Python 3.14` classifier.
- `cleanup.sh`: merged redundant `find` calls and fixed `.cover` glob typo.
- `Makefile`: changed `python` to `python3` in test targets for consistency.
- `setup.sh`: pins pip version (`>=24,<25`), guards `pre-commit install` behind file existence check.
- `.gitignore`: added `.env`, `.env.*`, `*.log` patterns.
- `release.yml`: release notes now sourced from `CHANGELOG.md`.
- CI test jobs depend on `lint-typecheck` (fail-fast on lint errors).

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
