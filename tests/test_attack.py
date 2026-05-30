"""Tests for the attack module."""

from __future__ import annotations

import pytest

from bitcoin.attack import (
    NoNonceReuseError,
    NonceReuseGroup,
    RecoveredKey,
    SameNonceError,
    detect_nonce_reuse,
    recover_from_nonce_reuse,
    recover_from_related_nonces,
)
from bitcoin.ecc import SECP256K1_ORDER, G, scalar_multiply
from bitcoin.linear import (
    SECP256K1_ORDER as ORDER,
    LinearCoefficientCollection,
    LinearCoefficientRecord,
    derive_linear_coefficients,
    inverse_mod,
)
from bitcoin.models import SignatureRecord
from bitcoin.signature import SignatureCollection


def _make_record(
    r: int,
    s: int,
    z: int,
    input_index: int = 0,
    script_type: str = "test",
    public_key: str | None = None,
) -> SignatureRecord:
    return SignatureRecord(
        r=format(r, "x"),
        s=format(s, "x"),
        z=format(z, "x"),
        sighash_flag=1,
        input_index=input_index,
        public_key=public_key,
        script_type=script_type,
    )


def _sign(d: int, k: int, z: int) -> tuple[int, int]:
    """Sign a message hash ``z`` with private key ``d`` and nonce ``k``."""
    k = k % ORDER
    R = scalar_multiply(k, G)
    assert R.x is not None
    r = R.x
    s = (inverse_mod(k, ORDER) * (z + r * d)) % ORDER
    return r, s


def test_recover_from_nonce_reuse() -> None:
    """Recover private key and nonce from two signatures with same r."""
    d = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
    k = 0xFEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321
    z1 = 0xAAAA
    z2 = 0xBBBB

    r1, s1 = _sign(d, k, z1)
    r2, s2 = _sign(d, k, z2)
    assert r1 == r2, "same nonce must produce same r"

    sig1 = _make_record(r1, s1, z1)
    sig2 = _make_record(r2, s2, z2)

    result = recover_from_nonce_reuse(sig1, sig2)
    assert result.private_key == d
    assert result.nonce == k


def test_recover_from_nonce_reuse_via_linear() -> None:
    """Recover using LinearCoefficientRecord directly."""
    d = 0xDEADBEEF
    k = 0xCAFEBABE
    z1 = 0x1111
    z2 = 0x2222

    r, s1 = _sign(d, k, z1)
    _, s2 = _sign(d, k, z2)

    lin1 = derive_linear_coefficients(_make_record(r, s1, z1))
    lin2 = derive_linear_coefficients(_make_record(r, s2, z2))

    result = recover_from_nonce_reuse(lin1, lin2)
    assert result.private_key == d
    assert result.nonce == k


def test_recover_from_nonce_reuse_different_r() -> None:
    """SameNonceError when r values differ."""
    k1 = 0x1111111111111111111111111111111111111111111111111111111111111111
    k2 = 0x2222222222222222222222222222222222222222222222222222222222222222
    r1, s1 = _sign(1, k1, 0xAAAA)
    r2, s2 = _sign(1, k2, 0xBBBB)

    sig1 = _make_record(r1, s1, 0xAAAA)
    sig2 = _make_record(r2, s2, 0xBBBB)

    with pytest.raises(SameNonceError):
        recover_from_nonce_reuse(sig1, sig2)


def test_recover_from_related_nonces() -> None:
    """Recover private key and nonce when k2 = k1 + delta."""
    d = 0xCAFEBABE
    k1 = 0x1111111111111111111111111111111111111111111111111111111111111111
    delta = 7
    k2 = k1 + delta
    z1 = 0xAAAA
    z2 = 0xBBBB

    r1, s1 = _sign(d, k1, z1)
    r2, s2 = _sign(d, k2, z2)

    sig1 = _make_record(r1, s1, z1)
    sig2 = _make_record(r2, s2, z2)

    result = recover_from_related_nonces(sig1, sig2, delta)
    assert result.private_key == d
    assert result.nonce == k1


def test_detect_nonce_reuse_empty() -> None:
    """Empty collection yields no reuse groups."""
    col = SignatureCollection(records=())
    groups = detect_nonce_reuse(col)
    assert groups == []


def test_detect_nonce_reuse_no_reuse() -> None:
    """Collection with all-unique r values yields no groups."""
    col = SignatureCollection(records=(
        _make_record(1, 1, 1, input_index=0),
        _make_record(2, 2, 2, input_index=1),
        _make_record(3, 3, 3, input_index=2),
    ))
    groups = detect_nonce_reuse(col)
    assert groups == []


def test_detect_nonce_reuse_finds_group() -> None:
    """Collection with repeated r yields one group."""
    sig1 = _make_record(99, 1, 0xAAAA, input_index=0)
    sig2 = _make_record(99, 2, 0xBBBB, input_index=1)
    sig3 = _make_record(99, 3, 0xCCCC, input_index=2)
    col = SignatureCollection(records=(sig1, sig2, sig3))
    groups = detect_nonce_reuse(col)
    assert len(groups) == 1
    assert groups[0].r == 99
    assert groups[0].count == 3


def test_detect_nonce_reuse_via_coefficients() -> None:
    """detect_nonce_reuse works with LinearCoefficientCollection directly."""
    sig1 = _make_record(99, 1, 0xAAAA, input_index=0)
    sig2 = _make_record(99, 2, 0xBBBB, input_index=1)
    col = SignatureCollection(records=(sig1, sig2))
    coeffs = col.linear()
    groups = detect_nonce_reuse(coeffs)
    assert len(groups) == 1
    assert groups[0].r == 99


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
