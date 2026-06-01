"""Tests for the new encoding/ package."""

import pytest

from bitcoin.encoding import (
    encode_hex,
    decode_hex,
    encode_varint,
    decode_varint,
    encode_der,
    decode_der,
    parse_sec,
    serialize_sec,
    sha256,
    hash256,
    hash160,
    tagged_hash,
    int_to_bytes,
    bytes_to_int,
    read_exactly,
)
from bitcoin.curve import GENERATOR, INFINITY


class TestHex:
    def test_roundtrip(self) -> None:
        data = b"hello world"
        assert decode_hex(encode_hex(data)) == data

    def test_encode_empty(self) -> None:
        assert encode_hex(b"") == ""

    def test_decode_invalid(self) -> None:
        with pytest.raises(ValueError):
            decode_hex("xyz")
        with pytest.raises(TypeError):
            decode_hex(123)  # type: ignore[arg-type]


class TestVarint:
    def test_encode_decode(self) -> None:
        for val in [0, 1, 0xFC, 0xFD, 0xFFFF, 0x10000, 0xFFFFFFFF, 0x100000000]:
            encoded = encode_varint(val)
            decoded, _ = decode_varint(encoded)
            assert decoded == val

    def test_negative(self) -> None:
        with pytest.raises(ValueError, match="negative"):
            encode_varint(-1)

    def test_truncated(self) -> None:
        with pytest.raises(ValueError, match="truncated|Truncated"):
            decode_varint(b"\xfd")

    def test_offset(self) -> None:
        data = b"\x00" + encode_varint(42)
        val, pos = decode_varint(data, 1)
        assert val == 42
        assert pos == 2


class TestDer:
    def test_roundtrip(self) -> None:
        r = 0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
        s = 0xFEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321
        sig = encode_der(r, s)
        decoded_r, decoded_s = decode_der(sig)
        assert decoded_r == r
        assert (decoded_s == s) or (decoded_s == CURVE_ORDER - s)

    def test_s_high_ok(self) -> None:
        from bitcoin.curve.params import CURVE_ORDER
        half = CURVE_ORDER // 2
        r = 1
        s = half + 100
        sig = encode_der(r, s, s_high_ok=True)
        decoded_r, decoded_s = decode_der(sig)
        assert decoded_r == r
        assert decoded_s == s

    def test_invalid_sig(self) -> None:
        with pytest.raises(ValueError):
            decode_der(b"\x00\x00")

    def test_trailing_data(self) -> None:
        sig = bytes([0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0xee])
        with pytest.raises(ValueError, match="Trailing"):
            decode_der(sig)

    def test_invalid_integer_tag(self) -> None:
        sig = bytes([0x30, 0x06, 0x03, 0x01, 0x01, 0x02, 0x01, 0x02])
        with pytest.raises(ValueError, match="Invalid DER integer"):
            decode_der(sig)

    def test_truncated_integer(self) -> None:
        sig = bytes([0x30, 0x04, 0x02, 0x03, 0x01, 0x02])
        with pytest.raises(ValueError, match="Truncated"):
            decode_der(sig)


CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


class TestSec:
    def test_roundtrip_compressed(self) -> None:
        ser = serialize_sec(GENERATOR, compressed=True)
        assert len(ser) == 33
        parsed = parse_sec(ser)
        assert parsed == GENERATOR

    def test_roundtrip_uncompressed(self) -> None:
        ser = serialize_sec(GENERATOR, compressed=False)
        assert len(ser) == 65
        parsed = parse_sec(ser)
        assert parsed == GENERATOR

    def test_infinity_raises(self) -> None:
        with pytest.raises(ValueError, match="Cannot serialize"):
            serialize_sec(INFINITY)

    def test_invalid_sec(self) -> None:
        with pytest.raises(ValueError, match="Invalid SEC key length"):
            parse_sec(b"\x00" * 10)

    def test_point_not_on_curve(self) -> None:
        bad = b"\x04" + b"\x01" * 32 + b"\x02" * 32
        with pytest.raises(ValueError, match="not on the secp256k1 curve"):
            parse_sec(bad)


class TestHasher:
    def test_sha256(self) -> None:
        result = sha256(b"hello")
        assert len(result) == 32

    def test_hash256(self) -> None:
        result = hash256(b"hello")
        assert len(result) == 32

    def test_hash160(self) -> None:
        result = hash160(b"hello")
        assert len(result) == 20

    def test_tagged_hash(self) -> None:
        result = tagged_hash("TapSighash", b"data")
        assert len(result) == 32

    def test_sha256_deterministic(self) -> None:
        assert sha256(b"test") == sha256(b"test")
        assert sha256(b"test") != sha256(b"Test")


class TestBinary:
    def test_int_roundtrip(self) -> None:
        assert bytes_to_int(int_to_bytes(42, 4)) == 42

    def test_read_exactly(self) -> None:
        chunk, pos = read_exactly(b"abcdef", 3)
        assert chunk == b"abc"
        assert pos == 3

    def test_read_exactly_truncated(self) -> None:
        with pytest.raises(ValueError, match="Requested"):
            read_exactly(b"abc", 5)
