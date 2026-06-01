"""Benchmarks for ECC operations."""
from __future__ import annotations

from typing import TYPE_CHECKING

from bitcoin.curve import (
    INFINITY,
    GENERATOR,
    add,
    double,
    multiply,
    negate,
    serialize_public_key,
)

if TYPE_CHECKING:
    from pytest_benchmark.fixture import BenchmarkFixture


def test_bench_point_add(benchmark: BenchmarkFixture) -> None:
    p1 = multiply(42, GENERATOR)
    p2 = multiply(123, GENERATOR)
    result = benchmark(add, p1, p2)
    assert not result.infinity


def test_bench_point_double(benchmark: BenchmarkFixture) -> None:
    p = multiply(42, GENERATOR)
    result = benchmark(double, p)
    assert not result.infinity


def test_bench_scalar_multiply(benchmark: BenchmarkFixture) -> None:
    result = benchmark(multiply, 123456789, GENERATOR)
    assert not result.infinity


def test_bench_scalar_multiply_large(benchmark: BenchmarkFixture) -> None:
    scalar = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - 2
    result = benchmark(multiply, scalar, GENERATOR)
    assert not result.infinity


def test_bench_point_negate(benchmark: BenchmarkFixture) -> None:
    p = multiply(42, GENERATOR)
    result = benchmark(negate, p)
    assert not result.infinity


def test_bench_serialize_compressed(benchmark: BenchmarkFixture) -> None:
    p = multiply(42, GENERATOR)
    result = benchmark(serialize_public_key, p)
    assert len(result) == 33


def test_bench_serialize_uncompressed(benchmark: BenchmarkFixture) -> None:
    p = multiply(42, GENERATOR)
    result = benchmark(serialize_public_key, p, compressed=False)
    assert len(result) == 65


def test_bench_infinity_add(benchmark: BenchmarkFixture) -> None:
    p = multiply(42, GENERATOR)
    result = benchmark(add, INFINITY, p)
    assert result == p
