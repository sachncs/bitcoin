"""Tests for the attack module (ECDSA nonce/key recovery)."""
from __future__ import annotations

import pytest

from bitcoin.curve import GENERATOR, multiply
from bitcoin.curve.params import CURVE_ORDER
from bitcoin.field import inverse as field_inverse
from bitcoin.signature.attack import (
    NonceReuseGroup,
    RecoveredKey,
    SameNonceError,
    detect_nonce_reuse,
    recover_from_nonce_reuse,
    recover_from_related_nonces,
)
from bitcoin.signature.linearization.coefficients import (
    LinearCoefficientCollection,
    derive_linear_coefficients,
)


def __sign(d: int, k: int, z: int) -> tuple[int, int]:
    """Sign a message hash ``z`` with private key ``d`` and nonce ``k``."""
    k = k % CURVE_ORDER
    R = multiply(k, GENERATOR)
    rx = R.x
    if rx is None:
        raise ValueError("Expected affine point, got infinity.")
    r = rx
    s = (field_inverse(k, CURVE_ORDER) * (z + r * d)) % CURVE_ORDER
    return r, s


def test_recover_from_nonce_reuse() -> None:
    """Recover private key and nonce from two signatures with same r."""
    d = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    k = 0xFEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321
    z1 = 0xAAAA
    z2 = 0xBBBB

    r, s1 = __sign(d, k, z1)
    r2, s2 = __sign(d, k, z2)
    assert r == r2, "same nonce must produce same r"

    lin1 = derive_linear_coefficients(r, s1, z1)
    lin2 = derive_linear_coefficients(r, s2, z2)

    result = recover_from_nonce_reuse(lin1, lin2)
    assert result.private_key == d
    assert result.nonce == k


def test_recover_from_nonce_reuse_different_r() -> None:
    """SameNonceError when r values differ."""
    k1 = 0x1111111111111111111111111111111111111111111111111111111111111111
    k2 = 0x2222222222222222222222222222222222222222222222222222222222222222
    r1, s1 = __sign(1, k1, 0xAAAA)
    r2, s2 = __sign(1, k2, 0xBBBB)

    lin1 = derive_linear_coefficients(r1, s1, 0xAAAA)
    lin2 = derive_linear_coefficients(r2, s2, 0xBBBB)

    with pytest.raises(SameNonceError):
        recover_from_nonce_reuse(lin1, lin2)


def test_recover_from_related_nonces() -> None:
    """Recover private key and nonce when k2 = k1 + delta."""
    d = 0xCAFEBABE
    k1 = 0x1111111111111111111111111111111111111111111111111111111111111111
    delta = 7
    k2 = k1 + delta
    z1 = 0xAAAA
    z2 = 0xBBBB

    r1, s1 = __sign(d, k1, z1)
    r2, s2 = __sign(d, k2, z2)

    lin1 = derive_linear_coefficients(r1, s1, z1)
    lin2 = derive_linear_coefficients(r2, s2, z2)

    result = recover_from_related_nonces(lin1, lin2, delta)
    assert result.private_key == d
    assert result.nonce == k1


def test_detect_nonce_reuse_empty() -> None:
    """Empty collection yields no reuse groups."""
    col = LinearCoefficientCollection(records=())
    groups = detect_nonce_reuse(col)
    assert groups == []


def test_detect_nonce_reuse_no_reuse() -> None:
    """Collection with all-unique r values yields no groups."""
    col = LinearCoefficientCollection(records=(
        derive_linear_coefficients(1, 1, 1, input_index=0),
        derive_linear_coefficients(2, 2, 2, input_index=1),
        derive_linear_coefficients(3, 3, 3, input_index=2),
    ))
    groups = detect_nonce_reuse(col)
    assert groups == []


def test_detect_nonce_reuse_finds_group() -> None:
    """Collection with repeated r yields one group."""
    col = LinearCoefficientCollection(records=(
        derive_linear_coefficients(99, 1, 0xAAAA, input_index=0),
        derive_linear_coefficients(99, 2, 0xBBBB, input_index=1),
        derive_linear_coefficients(99, 3, 0xCCCC, input_index=2),
    ))
    groups = detect_nonce_reuse(col)
    assert len(groups) == 1
    assert groups[0].r == 99
    assert groups[0].count == 3


def test_recovered_key_dataclass() -> None:
    """RecoveredKey fields."""
    rk = RecoveredKey(
        private_key=1,
        nonce=2,
        input_index_1=0,
        input_index_2=1,
    )
    assert rk.private_key == 1
    assert rk.nonce == 2


def test_nonce_reuse_group_dataclass() -> None:
    """NonceReuseGroup fields."""
    g = NonceReuseGroup(r=99, indices=(0, 2, 5))
    assert g.r == 99
    assert g.count == 3
