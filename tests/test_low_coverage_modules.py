"""Coverage for libsec.py, binary.py, script/parser.py."""
from __future__ import annotations

import pytest

from bitcoin.curve import GENERATOR, INFINITY, Point, set_backend, get_backend
from bitcoin.curve.backend.libsec import LibsecpBackend
from bitcoin.encoding.binary import bytes_to_int, int_to_bytes, read_exactly, iter_bytes
from bitcoin.script.parser import (
    parse_script,
    parse_script_chunks,
    serialize_script,
    script_to_string,
    chunks_to_pushes,
    reject_code_separators,
    parse_multisig_redeem_script,
    ScriptChunk,
)
from bitcoin.script.opcodes import (
    OP_CHECKSIG,
    OP_DUP,
    OP_HASH160,
    OP_EQUALVERIFY,
    OP_CHECKSIG,
)
from bitcoin.exceptions import UnsupportedScriptPathError

# ── libsec.py ────────────────────────────────────────────────────────

HAS_LIBSEC = True
try:
    import coincurve  # noqa: F401
except ImportError:
    HAS_LIBSEC = False


@pytest.mark.skipif(not HAS_LIBSEC, reason="coincurve not installed")
class TestLibsecBackend:
    def setup_method(self) -> None:
        self.backend = LibsecpBackend()
        self.pt = GENERATOR

    def test_negate(self) -> None:
        result = self.backend.negate(self.pt)
        assert result != self.pt
        assert self.backend.add(self.pt, result) == INFINITY

    def test_add(self) -> None:
        doubled = self.backend.add(self.pt, self.pt)
        assert not doubled.infinity

    def test_double(self) -> None:
        doubled = self.backend.double(self.pt)
        assert not doubled.infinity

    def test_multiply(self) -> None:
        result = self.backend.multiply(2, self.pt)
        assert not result.infinity

    def test_is_on_curve_true(self) -> None:
        assert self.backend.is_on_curve(self.pt) is True

    def test_is_on_curve_false(self) -> None:
        assert self.backend.is_on_curve(INFINITY) is False

    def test_sqrt(self) -> None:
        from bitcoin.curve.params import FIELD_PRIME
        val = 42
        root = self.backend.sqrt(val)
        assert (root * root) % FIELD_PRIME == val

    def test_parse_sec(self) -> None:
        data = self.backend.serialize_sec(self.pt)
        parsed = self.backend.parse_sec(data)
        assert parsed == self.pt

    def test_serialize_sec_compressed(self) -> None:
        data = self.backend.serialize_sec(self.pt, compressed=True)
        assert len(data) == 33

    def test_serialize_sec_uncompressed(self) -> None:
        data = self.backend.serialize_sec(self.pt, compressed=False)
        assert len(data) == 65

    def test_parse_sec_roundtrip(self) -> None:
        data = self.backend.serialize_sec(self.pt)
        pt2 = self.backend.parse_sec(data)
        data2 = self.backend.serialize_sec(pt2)
        assert data == data2


# ── binary.py ────────────────────────────────────────────────────────

class TestBinary:
    def test_bytes_to_int(self) -> None:
        assert bytes_to_int(b"\x01\x00", "big") == 256
        assert bytes_to_int(b"\x01\x00", "little") == 1

    def test_int_to_bytes(self) -> None:
        assert int_to_bytes(256, 2) == b"\x01\x00"
        assert int_to_bytes(1, 2, "little") == b"\x01\x00"

    def test_read_exactly_normal(self) -> None:
        chunk, pos = read_exactly(b"abcdef", 3)
        assert chunk == b"abc"
        assert pos == 3

    def test_read_exactly_truncated(self) -> None:
        with pytest.raises(ValueError, match="Requested"):
            read_exactly(b"abc", 5)

    def test_read_exactly_with_offset(self) -> None:
        chunk, pos = read_exactly(b"abcdef", 2, offset=4)
        assert chunk == b"ef"
        assert pos == 6

    def test_iter_bytes_empty(self) -> None:
        assert list(iter_bytes(b"", 2)) == []

    def test_iter_bytes_exact(self) -> None:
        assert list(iter_bytes(b"abcd", 2)) == [b"ab", b"cd"]

    def test_iter_bytes_partial_last(self) -> None:
        assert list(iter_bytes(b"abcde", 2)) == [b"ab", b"cd", b"e"]


# ── script/parser.py ─────────────────────────────────────────────────

class TestScriptParser:
    def test_parse_script_empty(self) -> None:
        assert parse_script(b"") == []

    def test_parse_script_op_0(self) -> None:
        assert parse_script(b"\x00") == [b""]

    def test_parse_script_op_1negate(self) -> None:
        assert parse_script(b"\x4f") == [0x4f]

    def test_parse_script_small_push(self) -> None:
        result = parse_script(b"\x02ab")
        assert result == [b"ab"]

    def test_parse_script_pushdata1(self) -> None:
        data = b"\x4c" + bytes([3]) + b"abc"
        assert parse_script(data) == [b"abc"]

    def test_parse_script_pushdata2(self) -> None:
        data = b"\x4d" + (3).to_bytes(2, "little") + b"abc"
        assert parse_script(data) == [b"abc"]

    def test_parse_script_pushdata4(self) -> None:
        data = b"\x4e" + (3).to_bytes(4, "little") + b"abc"
        assert parse_script(data) == [b"abc"]

    def test_parse_script_op_1_to_16(self) -> None:
        assert parse_script(b"\x51") == [0x51]
        assert parse_script(b"\x60") == [0x60]

    def test_parse_script_unknown_op(self) -> None:
        assert parse_script(b"\xba") == [0xba]

    def test_parse_script_multi_element(self) -> None:
        script = b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac"
        result = parse_script(script)
        assert len(result) == 5
        assert result[0] == 0x76
        assert result[1] == 0xa9
        assert isinstance(result[2], bytes)
        assert len(result[2]) == 20
        assert result[3] == 0x88
        assert result[4] == 0xac


class TestParseScriptChunks:
    def test_empty(self) -> None:
        assert parse_script_chunks(b"") == []

    def test_op_0(self) -> None:
        chunks = parse_script_chunks(b"\x00")
        assert len(chunks) == 1
        assert chunks[0].opcode == 0x00
        assert chunks[0].data == b""
        assert chunks[0].is_push

    def test_op_1negate(self) -> None:
        chunks = parse_script_chunks(b"\x4f")
        assert chunks[0].opcode == 0x4f
        assert chunks[0].data is None
        assert not chunks[0].is_push

    def test_small_push(self) -> None:
        chunks = parse_script_chunks(b"\x02ab")
        assert chunks[0].data == b"ab"

    def test_pushdata1(self) -> None:
        data = b"\x4c" + bytes([3]) + b"abc"
        chunks = parse_script_chunks(data)
        assert chunks[0].data == b"abc"

    def test_pushdata2(self) -> None:
        data = b"\x4d" + (3).to_bytes(2, "little") + b"abc"
        chunks = parse_script_chunks(data)
        assert chunks[0].data == b"abc"

    def test_pushdata4(self) -> None:
        data = b"\x4e" + (3).to_bytes(4, "little") + b"abc"
        chunks = parse_script_chunks(data)
        assert chunks[0].data == b"abc"

    def test_op_1_to_16(self) -> None:
        chunks = parse_script_chunks(b"\x51")
        assert chunks[0].opcode == 0x51
        assert chunks[0].data is None

    def test_other_opcode(self) -> None:
        chunks = parse_script_chunks(b"\xab")
        assert chunks[0].opcode == 0xab
        assert chunks[0].data is None


class TestChunksToPushes:
    def test_basic(self) -> None:
        chunks = [
            ScriptChunk(opcode=0x00, data=b""),
            ScriptChunk(opcode=0x51, data=None),
            ScriptChunk(opcode=0x02, data=b"ab"),
        ]
        result = chunks_to_pushes(chunks)
        assert result == [b"", b"ab"]


class TestRejectCodeSeparators:
    def test_no_separator(self) -> None:
        assert reject_code_separators(b"\x51\x52") == b"\x51\x52"

    def test_separator_raises(self) -> None:
        with pytest.raises(UnsupportedScriptPathError, match="OP_CODESEPARATOR"):
            reject_code_separators(b"\xab")


class TestSerializeScript:
    def test_empty(self) -> None:
        assert serialize_script([]) == b""

    def test_empty_bytes_push(self) -> None:
        assert serialize_script([b""]) == b"\x00"

    def test_small_push(self) -> None:
        data = b"\x01" * 75
        result = serialize_script([data])
        assert result[0] == 75
        assert result[1:] == data

    def test_pushdata1(self) -> None:
        data = b"\x01" * 76
        result = serialize_script([data])
        assert result[0] == 0x4c
        assert result[1] == 76
        assert result[2:] == data

    def test_pushdata2(self) -> None:
        data = b"\x01" * 256
        result = serialize_script([data])
        assert result[0] == 0x4d
        assert int.from_bytes(result[1:3], "little") == 256
        assert result[3:] == data

    def test_pushdata4(self) -> None:
        data = b"\x01" * 65536
        result = serialize_script([data])
        assert result[0] == 0x4e
        assert int.from_bytes(result[1:5], "little") == 65536
        assert result[5:] == data

    def test_int_0(self) -> None:
        assert serialize_script([0]) == b"\x00"

    def test_int_1_to_16(self) -> None:
        assert serialize_script([1]) == b"\x01"
        assert serialize_script([16]) == b"\x10"

    def test_int_unknown(self) -> None:
        assert serialize_script([0xba]) == b"\xba"

    def test_type_error(self) -> None:
        with pytest.raises(TypeError, match="Unexpected"):
            serialize_script([None])  # type: ignore[list-item]

    def test_p2pkh_roundtrip(self) -> None:
        script = b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac"
        parsed = parse_script(script)
        assert serialize_script(parsed) == script


class TestScriptToString:
    def test_bytes_element(self) -> None:
        assert script_to_string([b"\x00\x01"]) == "0001"

    def test_known_opcode(self) -> None:
        assert script_to_string([0x76]) == "OP_DUP"

    def test_unknown_opcode(self) -> None:
        assert script_to_string([0xba]) == "OP_UNKNOWN(186)"

    def test_mixed(self) -> None:
        result = script_to_string([0x76, b"\x00" * 20, 0xac])
        assert result == "OP_DUP 0000000000000000000000000000000000000000 OP_CHECKSIG"


class TestParseMultisigRedeemScript:
    def test_valid_2_of_3(self) -> None:
        pk1 = b"\x02" + b"\x01" * 32
        pk2 = b"\x03" + b"\x02" * 32
        pk3 = b"\x02" + b"\x03" * 32
        script = (
            bytes([0x52])   # OP_2
            + bytes([len(pk1)]) + pk1
            + bytes([len(pk2)]) + pk2
            + bytes([len(pk3)]) + pk3
            + bytes([0x53])   # OP_3
            + bytes([0xac])   # OP_CHECKSIG
        )
        m, pubkeys = parse_multisig_redeem_script(script)
        assert m == 2
        assert len(pubkeys) == 3

    def test_too_short(self) -> None:
        with pytest.raises(UnsupportedScriptPathError, match="too short"):
            parse_multisig_redeem_script(b"\x51")

    def test_no_checksig(self) -> None:
        with pytest.raises(UnsupportedScriptPathError, match="missing"):
            parse_multisig_redeem_script(b"\x51\x51\x51")

    def test_bad_pubkey_type(self) -> None:
        """First element is a push (data not None) → invalid structure."""
        script = b"\x02ab\x51\x51\xac"
        with pytest.raises(UnsupportedScriptPathError, match="invalid structure"):
            parse_multisig_redeem_script(script)

    def test_invalid_m_value(self) -> None:
        script = b"\x50\x02ab\x51\xac"
        with pytest.raises(UnsupportedScriptPathError, match="m value"):
            parse_multisig_redeem_script(script)

    def test_invalid_n_value(self) -> None:
        script = b"\x51\x02ab\x50\xac"
        with pytest.raises(UnsupportedScriptPathError, match="n value"):
            parse_multisig_redeem_script(script)

    def test_pubkey_count_mismatch(self) -> None:
        script = b"\x51\x02ab\x53\xac"
        with pytest.raises(UnsupportedScriptPathError, match="inconsistent"):
            parse_multisig_redeem_script(script)

    def test_bad_pubkey_length(self) -> None:
        pk = b"\x01" * 10
        script = b"\x51" + bytes([len(pk)]) + pk + b"\x51\xac"
        with pytest.raises(UnsupportedScriptPathError, match="public key length"):
            parse_multisig_redeem_script(script)

    def test_invalid_threshold(self) -> None:
        pk1 = b"\x02" + b"\x01" * 32
        pk2 = b"\x03" + b"\x02" * 32
        script = (
            bytes([0x53])           # OP_3 (m=3)
            + bytes([len(pk1)]) + pk1
            + bytes([len(pk2)]) + pk2
            + bytes([0x52])         # OP_2 (n=2)
            + bytes([0xac])         # OP_CHECKSIG
        )
        with pytest.raises(UnsupportedScriptPathError, match="threshold"):
            parse_multisig_redeem_script(script)
