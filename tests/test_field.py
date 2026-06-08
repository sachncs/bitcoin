"""Tests for the new field/ package (modular arithmetic, sqrt)."""

import pytest

from bitcoin.field import inverse, sqrt, pow_mod, validate_non_negative
from bitcoin.exceptions import NotInvertible


class TestInverse:

    def test_basic(self) -> None:
        assert inverse(3, 7) == 5
        assert (3 * inverse(3, 7)) % 7 == 1

    def test_large_modulus(self) -> None:
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        inv = inverse(2, p)
        assert (2 * inv) % p == 1

    def test_zero_not_invertible(self) -> None:
        with pytest.raises(NotInvertible):
            inverse(0, 7)

    def test_not_coprime(self) -> None:
        with pytest.raises(NotInvertible):
            inverse(6, 9)

    def test_modulus_one(self) -> None:
        with pytest.raises(ValueError, match="Modulus must be > 1"):
            inverse(3, 1)

    def test_negative_value(self) -> None:
        with pytest.raises(ValueError, match="Value must be non-negative"):
            inverse(-3, 7)

    def test_type_errors(self) -> None:
        with pytest.raises(TypeError):
            inverse("3", 7)  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            inverse(3, "7")  # type: ignore[arg-type]


class TestSqrt:

    def test_sqrt_known(self) -> None:
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        val = pow(42, 2, p)
        root = sqrt(val, p)
        assert (root * root) % p == val

    def test_sqrt_secp256k1(self) -> None:
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
        y_sq = (pow(gx, 3, p) + 7) % p
        root = sqrt(y_sq, p)
        assert (root * root) % p == y_sq

    def test_non_residue(self) -> None:
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        with pytest.raises(Exception):
            sqrt(3, p)

    def test_pow_mod(self) -> None:
        assert pow_mod(2, 10, 1000) == 24
        assert pow_mod(5, 0, 7) == 1


class TestValidateNonNegative:

    def test_valid(self) -> None:
        assert validate_non_negative(0) == 0
        assert validate_non_negative(42) == 42

    def test_negative(self) -> None:
        with pytest.raises(ValueError, match="must be non-negative"):
            validate_non_negative(-1)

    def test_type_error(self) -> None:
        with pytest.raises(TypeError):
            validate_non_negative("42")  # type: ignore[arg-type]


class TestRoundtrip:

    def test_inverse_sqrt_interop(self) -> None:
        p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
        inv = inverse(4, p)
        assert (4 * inv) % p == 1
        val = pow(9, 2, p)
        root = sqrt(val, p)
        assert (root * root) % p == val
