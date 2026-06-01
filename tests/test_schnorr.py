"""Tests for BIP-340 Schnorr signature verification."""
from __future__ import annotations

from bitcoin.signature.schnorr import verify_schnorr_sig, lift_x
from bitcoin.curve.params import FIELD_PRIME, CURVE_ORDER
from bitcoin.encoding.hasher import sha256


def test_verify_schnorr_bad_pubkey_length() -> None:
    assert not verify_schnorr_sig(b"\x00" * 31, b"\x00" * 64, b"\x00" * 32)
    assert not verify_schnorr_sig(b"\x00" * 33, b"\x00" * 64, b"\x00" * 32)


def test_verify_schnorr_bad_sig_length() -> None:
    assert not verify_schnorr_sig(b"\x00" * 32, b"\x00" * 63, b"\x00" * 32)
    assert not verify_schnorr_sig(b"\x00" * 32, b"\x00" * 65, b"\x00" * 32)


def test_verify_schnorr_bad_msg_length() -> None:
    assert not verify_schnorr_sig(b"\x00" * 32, b"\x00" * 64, b"\x00" * 31)
    assert not verify_schnorr_sig(b"\x00" * 32, b"\x00" * 64, b"\x00" * 33)


def test_verify_schnorr_r_geq_p() -> None:
    pubkey = lift_x(1)
    assert pubkey is not None
    pubkey_bytes = pubkey[0].to_bytes(32, "big")
    r = FIELD_PRIME
    s = 1
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    msg = sha256(b"hello")
    assert not verify_schnorr_sig(pubkey_bytes, sig, msg)


def test_verify_schnorr_s_geq_n() -> None:
    pubkey = lift_x(1)
    assert pubkey is not None
    pubkey_bytes = pubkey[0].to_bytes(32, "big")
    r = 1
    s = CURVE_ORDER
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    msg = sha256(b"hello")
    assert not verify_schnorr_sig(pubkey_bytes, sig, msg)


def test_verify_schnorr_x_not_on_curve() -> None:
    pubkey_bytes = b"\xff" * 32
    sig = b"\x01" * 64
    msg = b"\x00" * 32
    assert not verify_schnorr_sig(pubkey_bytes, sig, msg)


def test_lift_x_success() -> None:
    p = lift_x(1)
    assert p is not None
    x, y = p
    assert (y * y) % FIELD_PRIME == (pow(x, 3, FIELD_PRIME) + 7) % FIELD_PRIME
    assert y & 1 == 0


def test_lift_x_x_geq_p() -> None:
    assert lift_x(FIELD_PRIME) is None
    assert lift_x(FIELD_PRIME + 1) is None


def test_lift_x_x_not_on_curve() -> None:
    assert lift_x(0) is None
