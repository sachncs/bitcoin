"""Tests for BIP-340 Schnorr signature verification."""
from __future__ import annotations

from bitcoin.curve.params import CURVE_ORDER, FIELD_PRIME
from bitcoin.encoding.hasher import sha256
from bitcoin.signature.schnorr import lift_x, verify_schnorr_sig


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


def test_verify_valid_bip340_vector() -> None:
    """Verify known-valid BIP-340 test vectors (vectors 0-3 from BIP-340)."""
    # Test vector 1 (index 0): standard key path spending
    pubkey = bytes.fromhex(
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
    msg = bytes.fromhex(
        "0000000000000000000000000000000000000000000000000000000000000000")
    sig = bytes.fromhex(
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0")
    assert verify_schnorr_sig(pubkey, sig, msg)

    # Test vector 2 (index 1): standard key path spending
    pubkey = bytes.fromhex(
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659")
    msg = bytes.fromhex(
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
    sig = bytes.fromhex(
        "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
        "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A")
    assert verify_schnorr_sig(pubkey, sig, msg)

    # Test vector 3 (index 2): standard key path spending
    pubkey = bytes.fromhex(
        "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8")
    msg = bytes.fromhex(
        "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C")
    sig = bytes.fromhex(
        "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B"
        "AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7")
    assert verify_schnorr_sig(pubkey, sig, msg)

    # Test vector 4 (index 3): test fails if msg is reduced modulo p or n
    pubkey = bytes.fromhex(
        "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517")
    msg = bytes.fromhex(
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
    sig = bytes.fromhex(
        "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC"
        "97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3")
    assert verify_schnorr_sig(pubkey, sig, msg)
