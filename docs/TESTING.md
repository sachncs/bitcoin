# Testing

## Running Tests

```bash
pytest tests/ -v
```

With coverage:

```bash
pytest tests/ --cov=bitcoin
```

## Test Files

| File | Coverage |
|------|----------|
| `test_field.py` | Modular inverse, sqrt, pow_mod |
| `test_curve.py` | Point ops, backends, SEC encoding |
| `test_encoding.py` | Hex, varint, DER, hashing |
| `test_script.py` | Script parse/serialize/classify |
| `test_transaction.py` | Tx parse, Tx struct, make_tx |
| `test_sighash.py` | Legacy, segwit, taproot sighash |
| `test_sighash_full.py` | Comprehensive sighash test vectors (requires external JSON) |
| `test_extraction.py` | Signature extraction (P2PKH, P2WPKH, P2SH, P2WSH, P2TR) |
| `test_extraction_coverage.py` | Edge cases: empty scripts, coinbase, unknown types, DOGE/ERC compatibility |
| `test_linearize.py` | Linearization, nonce-reuse attack |
| `test_psbt.py` | PSBT parse/serialize/signatures |
| `test_psbt_parser.py` | PSBT edge cases (malformed, segwit, taproot) |
| `test_signature.py` | Verify, recover, DER parsing |
| `test_cli.py` | CLI commands via Typer `CliRunner` |
| `test_cli_coverage.py` | CLI edge cases (file input, CSV, empty, etc.) |
| `test_cli_integration.py` | End-to-end CLI tests |
| `test_settings.py` | Settings defaults and mutations |
| `test_exceptions.py` | Exception hierarchy and aliases |
| `test_stateful.py` | Hypothesis `RuleBasedStateMachine` for extraction invariants |
| `test_mainnet.py` | Live mainnet transaction parsing |
| `test_fuzzing.py` | Hypothesis property-based tests (script, DER, fields) |
| `test_misc_coverage.py` | Remaining branch coverage (helpers, builder, non-linear coeffs) |
| `test_low_coverage_modules.py` | Hard-to-reach code paths |

## Coverage

The project targets **99%+ line coverage**. Current CI gate rejects drops below 99%.

Run:

```bash
pytest tests/ --cov=bitcoin --cov-fail-under=99
```

## Linting & Type Checking

```bash
mypy bitcoin/ tests/ --strict
ruff check bitcoin/ tests/
yapf -dr bitcoin/ tests/
```

## CI Matrix

GitHub Actions runs three configurations:

| Job | Python | Extras |
|-----|--------|--------|
| `test` | 3.11, 3.12, 3.13 | None |
| `test-coincurve` | 3.11 | `[dev]` |
| `benchmark` | 3.11 | `[dev]` |

## Property-Based Tests

Hypothesis strategies in `test_fuzzing.py` test:

- Roundtrip: parse → serialize → parse for scripts, transactions, PSBTs
- Field: `inverse(inverse(a)) ≡ a`
- Curve: point addition associativity
- DER: `decode(encode(sig)) ≡ sig`
- Sighash: malleability invariants
- Stateful: extraction pipeline invariants via `RuleBasedStateMachine`
