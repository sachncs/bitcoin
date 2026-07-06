# Benchmarking

This document explains how to run and interpret benchmarks for the bitcoin library.

## Running Benchmarks

### Local Benchmarks

```bash
# Run all benchmarks
uv run pytest tests/test_benchmarks.py --benchmark-only

# Run benchmarks and save results to JSON
uv run pytest tests/test_benchmarks.py --benchmark-only --benchmark-json=benchmark.json

# Compare against a previous benchmark
uv run pytest tests/test_benchmarks.py --benchmark-only --benchmark-compare=benchmark.json

# Run specific benchmark
uv run pytest tests/test_benchmarks.py --benchmark-only -k "test_parse_tx"
```

### CI Benchmarks

Benchmarks run automatically in CI on every push to `master`. The CI:

1. Runs benchmarks on Python 3.13
2. Saves results to `benchmark.json`
3. Compares against previous results
4. Comments on PRs if performance regresses >10%
5. Fails CI if performance regresses >10%

## Benchmark Categories

### Transaction Parsing

| Benchmark | Description |
|-----------|-------------|
| `test_parse_tx_small` | Parse a simple 1-input, 2-output transaction |
| `test_parse_tx_medium` | Parse a 10-input, 5-output transaction |
| `test_parse_tx_large` | Parse a 100-input, 50-output transaction |
| `test_parse_tx_segwit` | Parse a SegWit transaction |
| `test_parse_tx_taproot` | Parse a Taproot transaction |

### Signature Extraction

| Benchmark | Description |
|-----------|-------------|
| `test_extract_p2pkh` | Extract from P2PKH input |
| `test_extract_p2wpkh` | Extract from P2WPKH input |
| `test_extract_p2sh` | Extract from P2SH multisig input |
| `test_extract_p2tr_keypath` | Extract from Taproot key-path input |
| `test_extract_p2tr_scriptpath` | Extract from Taproot script-path input |
| `test_batch_extract` | Batch extraction across multiple transactions |

### Cryptographic Operations

| Benchmark | Description |
|-----------|-------------|
| `test_point_multiply` | Scalar multiplication on secp256k1 |
| `test_point_add` | Point addition |
| `test_ecdsa_verify` | ECDSA signature verification |
| `test_schnorr_verify` | Schnorr signature verification |
| `test_der_encode` | DER signature encoding |
| `test_der_decode` | DER signature decoding |

### Encoding

| Benchmark | Description |
|-----------|-------------|
| `test_sha256` | SHA-256 hash |
| `test_hash256` | Double SHA-256 hash |
| `test_hash160` | RIPEMD160(SHA-256) hash |
| `test_tagged_hash` | BIP-340 tagged hash |
| `test_varint_encode` | Varint encoding |
| `test_varint_decode` | Varint decoding |

### Script Operations

| Benchmark | Description |
|-----------|-------------|
| `test_parse_script` | Parse script bytes |
| `test_serialize_script` | Serialize script elements |
| `test_classify_p2pkh` | Classify P2PKH script |
| `test_classify_p2wpkh` | Classify P2WPKH script |
| `test_classify_p2tr` | Classify P2TR script |

## Interpreting Results

### Metrics

- **Min**: Minimum execution time (best case)
- **Max**: Maximum execution time (worst case)
- **Mean**: Average execution time
- **StdDev**: Standard deviation (lower is more consistent)
- **Median**: Median execution time (50th percentile)
- **IQR**: Interquartile range (75th - 25th percentile)
- **OPS**: Operations per second (higher is better)

### Example Output

```
Benchmarking test_parse_tx_small
---------------------------------
Name                   (iterations)         min         max      mean      stddev    median     iqr    outliers     ops    rounds  iterations
---------------------------------------------------------------------------------------------------------------------------------------------
test_parse_tx_small         (1000)     1.23ms     1.45ms     1.28ms     0.05ms     1.27ms  0.08ms       2; 2      781      1000           1
```

This means:
- The benchmark ran 1000 iterations
- Minimum time: 1.23ms per iteration
- Mean time: 1.28ms per iteration
- Operations per second: 781

### Performance Targets

| Operation | Target | Warning | Critical |
|-----------|--------|---------|----------|
| Transaction parsing | < 2ms | > 5ms | > 10ms |
| Signature extraction | < 5ms | > 10ms | > 20ms |
| ECDSA verification | < 1ms | > 2ms | > 5ms |
| Schnorr verification | < 1ms | > 2ms | > 5ms |
| SHA-256 | < 0.01ms | > 0.05ms | > 0.1ms |

## Benchmark Comparison

### Comparing Versions

```bash
# Save baseline
uv run pytest tests/test_benchmarks.py --benchmark-only --benchmark-json=baseline.json

# Make changes...

# Compare against baseline
uv run pytest tests/test_benchmarks.py --benchmark-only --benchmark-compare=baseline.json
```

### CI Comparison

CI automatically compares:
- Current run vs previous successful run on `master`
- Results are posted as PR comments
- Performance regressions >10% cause CI failure

## Writing New Benchmarks

### Example

```python
import pytest
from bitcoin import parse_tx


@pytest.fixture
def sample_tx():
    """Fixture returning a sample transaction bytes."""
    return bytes.fromhex("0200000001...")


@pytest.mark.benchmark
def test_my_benchmark(sample_tx):
    """Benchmark my function."""
    parse_tx(sample_tx)
```

### Best Practices

1. **Use fixtures** for test data setup
2. **Warm up** the benchmark with a few iterations
3. **Isolate** the function under test
4. **Avoid I/O** in benchmarks (mock network calls)
5. **Use `--benchmark-disable`** to skip benchmarks in regular test runs

## Performance Profiling

### CPU Profiling

```bash
# Profile a specific benchmark
uv run python -m cProfile -s cumulative tests/test_benchmarks.py::test_parse_tx_small
```

### Memory Profiling

```bash
# Install memory profiler
uv pip install memory_profiler

# Profile memory usage
uv run python -m memory_profiler tests/test_benchmarks.py::test_parse_tx_small
```

### Line Profiling

```bash
# Install line_profiler
uv pip install line_profiler

# Profile specific function
uv run kernprof -l -v tests/test_benchmarks.py::test_parse_tx_small
```

## Troubleshooting

### Benchmark Instability

- Run more iterations: `--benchmark-min-rounds=1000`
- Use `--benchmark-warmup=on` for JIT warmup
- Check for background processes affecting results

### CI Benchmark Failures

- Check for network issues in CI
- Verify benchmark data is consistent
- Review regression thresholds in `ci.yml`

### Performance Regression Investigation

1. Check recent commits for changes
2. Run `git bisect` with benchmarks
3. Profile to identify hotspots
4. Review algorithm complexity
5. Check for unnecessary allocations
