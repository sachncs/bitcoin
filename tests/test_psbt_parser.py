# mypy: ignore-errors
"""Comprehensive tests for PSBT parser (>95% branch coverage)."""

from __future__ import annotations

import pytest

from bitcoin.encoding.varint import encode_varint
from bitcoin.psbt.parser import (
    parse_psbt,
    serialize_psbt,
    parse_psbt_hex,
    parse_keypath_value,
    psbt_extract_signatures,
    parse_key_value_map,
    serialize_key_value,
    parse_input_map,
    serialize_input_map,
    parse_output_map,
    serialize_output_map,
    parse_witness_stack,
)
from bitcoin.psbt.models import Psbt, PsbtInput, PsbtOutput
from bitcoin.transaction.models import Tx, TxIn, TxOut, OutPoint, Witness
from bitcoin.services.serializer import serialize_legacy_tx
from bitcoin.curve import parse_public_key
from bitcoin.signature.collection import SignatureCollection

# ── Helper helpers ─────────────────────────────────────────────────────────

PSBT_MAGIC = b"psbt\xff"
PSBT_GLOBAL_UNSIGNED_TX = 0x00
PSBT_IN_NON_WITNESS_UTXO = 0x00
PSBT_IN_WITNESS_UTXO = 0x01
PSBT_IN_PARTIAL_SIG = 0x02
PSBT_IN_SIGHASH_TYPE = 0x03
PSBT_IN_REDEEM_SCRIPT = 0x04
PSBT_IN_WITNESS_SCRIPT = 0x05
PSBT_IN_BIP32_DERIVATION = 0x06
PSBT_IN_FINAL_SCRIPTSIG = 0x07
PSBT_IN_FINAL_SCRIPTWITNESS = 0x08
PSBT_OUT_REDEEM_SCRIPT = 0x00
PSBT_OUT_WITNESS_SCRIPT = 0x01
PSBT_OUT_BIP32_DERIVATION = 0x02


def build_raw_tx(*, num_inputs: int = 0, num_outputs: int = 0) -> bytes:
    inputs = tuple(
        TxIn(
            previous_output=OutPoint(txid=bytes([i + 1] * 32), vout=0),
            script_sig=b"",
            sequence=0xFFFFFFFF,
            witness=Witness(()),
        ) for i in range(num_inputs))
    outputs = tuple(
        TxOut(value=1000 * (i + 1), script_pubkey=bytes([0x00] * 20))
        for i in range(num_outputs))
    tx = Tx(version=1, inputs=inputs, outputs=outputs, lock_time=0)
    return serialize_legacy_tx(tx)


def input_kv(key_type: int,
             value: bytes,
             key_data: bytes | None = None) -> bytes:
    kd = key_data or b""
    key_len = 1 + len(kd)
    return (encode_varint(key_len) + bytes([key_type]) + kd +
            encode_varint(len(value)) + value)


def output_kv(key_type: int,
              value: bytes,
              key_data: bytes | None = None) -> bytes:
    return input_kv(key_type, value, key_data)


def global_kv(value: bytes) -> bytes:
    return serialize_key_value(PSBT_GLOBAL_UNSIGNED_TX, value, [b"\x00"])


def build_witness_stack(items: list[bytes]) -> bytes:
    result = bytearray()
    for item in items:
        result.extend(encode_varint(len(item)))
        result.extend(item)
    return bytes(result)


# ── parse_psbt ─────────────────────────────────────────────────────────────


class TestParsePsbt:

    def test_invalid_magic(self):
        with pytest.raises(ValueError, match="magic"):
            parse_psbt(b"\x00" * 10)

    def test_missing_unsigned_tx(self):
        data = PSBT_MAGIC + b"\x00" + b"\x00" + b"\x00"
        with pytest.raises(ValueError, match="unsigned"):
            parse_psbt(data)

    def test_valid_empty(self):
        tx_bytes = build_raw_tx()
        data = PSBT_MAGIC + global_kv(tx_bytes) + b"\x00"
        psbt = parse_psbt(data)
        assert psbt.tx == tx_bytes
        assert len(psbt.inputs) == 0
        assert len(psbt.outputs) == 0

    def test_with_input_output(self):
        tx_bytes = build_raw_tx(num_inputs=1, num_outputs=1)
        ikv = input_kv(PSBT_IN_NON_WITNESS_UTXO, tx_bytes)
        okv = output_kv(PSBT_OUT_REDEEM_SCRIPT, b"\xab")
        # Format: magic + global_kv + 00 + [input_kv + 00] + 00 + [output_kv + 00]
        data = (PSBT_MAGIC + global_kv(tx_bytes) + b"\x00" + ikv + b"\x00" +
                okv + b"\x00")
        psbt = parse_psbt(data)
        assert len(psbt.inputs) == 1
        assert len(psbt.outputs) == 1
        assert psbt.inputs[0].non_witness_utxo == tx_bytes
        assert psbt.outputs[0].redeem_script == b"\xab"

    def test_input_loop_short_break(self):
        tx_bytes = build_raw_tx()
        data = PSBT_MAGIC + global_kv(tx_bytes) + b"\x00"
        psbt = parse_psbt(data)
        assert len(psbt.inputs) == 0
        assert len(psbt.outputs) == 0

    def test_output_loop_terminator_break(self):
        """Output map parsing terminates correctly."""
        tx_bytes = build_raw_tx(num_inputs=1, num_outputs=1)
        ikv = input_kv(0x09, b"x")
        okv = output_kv(PSBT_OUT_REDEEM_SCRIPT, b"\xff")
        data = (PSBT_MAGIC + global_kv(tx_bytes) + b"\x00" + ikv + b"\x00" +
                okv + b"\x00")
        psbt = parse_psbt(data)
        assert len(psbt.inputs) == 1
        assert len(psbt.outputs) == 1
        assert psbt.inputs[0].unknown == {b"\x09": b"x"}

    def test_two_inputs_two_outputs(self):
        """Multiple non-empty input/output maps with matching counts."""
        tx_bytes = build_raw_tx(num_inputs=2, num_outputs=2)
        ikv1 = input_kv(0x09, b"a")
        ikv2 = input_kv(0x09, b"b")
        okv1 = output_kv(PSBT_OUT_REDEEM_SCRIPT, b"\xdd")
        okv2 = output_kv(PSBT_OUT_WITNESS_SCRIPT, b"\xee")
        data = (PSBT_MAGIC + global_kv(tx_bytes) + b"\x00" + ikv1 + b"\x00" +
                ikv2 + b"\x00" + okv1 + b"\x00" + okv2 + b"\x00")
        psbt = parse_psbt(data)
        assert len(psbt.inputs) == 2
        assert len(psbt.outputs) == 2
        assert psbt.inputs[0].unknown.get(b"\x09") == b"a"
        assert psbt.inputs[1].unknown.get(b"\x09") == b"b"
        assert psbt.outputs[0].redeem_script == b"\xdd"
        assert psbt.outputs[1].witness_script == b"\xee"

    def test_parse_psbt_rejects_mismatched_counts(self):
        tx_bytes = build_raw_tx(num_inputs=2, num_outputs=1)
        ikv1 = input_kv(0x09, b"x")
        ikv2 = input_kv(0x09, b"y")
        okv = output_kv(PSBT_OUT_REDEEM_SCRIPT, b"\xff")
        data = (PSBT_MAGIC + global_kv(tx_bytes) + b"\x00" + ikv1 + b"\x00" +
                ikv2 + b"\x00" + b"\x00" + okv + b"\x00")
        with pytest.raises(ValueError, match="Mismatched"):
            parse_psbt(data)


# ── serialize_psbt ─────────────────────────────────────────────────────────


class TestSerializePsbt:

    def test_roundtrip_empty(self):
        tx_bytes = build_raw_tx()
        psbt = Psbt(tx=tx_bytes, inputs=(), outputs=())
        raw = serialize_psbt(psbt)
        parsed = parse_psbt(raw)
        assert parsed.tx == tx_bytes
        assert len(parsed.inputs) == 0
        assert len(parsed.outputs) == 0

    def test_serialize_preserves_fields(self):
        tx_bytes = build_raw_tx(num_inputs=1, num_outputs=1)
        inp = PsbtInput(
            non_witness_utxo=b"\x01",
            witness_utxo=b"\x02",
            sighash_type=1,
            redeem_script=b"\x03",
            witness_script=b"\x04",
            final_script_sig=b"\x05",
        )
        out = PsbtOutput(
            redeem_script=b"\x06",
            witness_script=b"\x07",
        )
        psbt = Psbt(tx=tx_bytes, inputs=(inp,), outputs=(out,))
        raw = serialize_psbt(psbt)
        assert PSBT_MAGIC in raw
        assert tx_bytes in raw
        assert b"\x01" in raw
        assert b"\x02" in raw
        assert (1).to_bytes(4, "little") in raw
        assert b"\x03" in raw
        assert b"\x04" in raw
        assert b"\x05" in raw
        assert b"\x06" in raw
        assert b"\x07" in raw

    def test_roundtrip_with_partial_sigs_and_bip32(self):
        """Round-trip PSBT with partial_sigs, bip32_derivations, unknown."""
        tx_bytes = build_raw_tx(num_inputs=1, num_outputs=1)
        pubkey = b"\x02" + b"\xaa" * 32
        sig = b"\x30\x06\x02\x01\x01\x02\x01\x01" + bytes([0x01])
        inp = PsbtInput(
            partial_sigs={pubkey: sig},
            bip32_derivations={
                pubkey:
                    b"\x01\x02\x03\x04\x02\x00\x00\x00\x00\x01\x00\x00\x00\x00"
            },
            unknown={b"\x0f": b"custom"},
        )
        out = PsbtOutput(
            bip32_derivations={pubkey: b"\x01\x02\x03\x04\x01\x00\x00\x00\x00"},
            unknown={b"\x0f": b"out_custom"},
        )
        psbt = Psbt(tx=tx_bytes, inputs=(inp,), outputs=(out,))
        raw = serialize_psbt(psbt)

        parsed = parse_psbt(raw)
        assert len(parsed.inputs) == 1
        assert len(parsed.outputs) == 1
        assert parsed.inputs[0].partial_sigs == {pubkey: sig}
        assert parsed.inputs[0].bip32_derivations == inp.bip32_derivations
        assert parsed.inputs[0].unknown == {b"\x0f": b"custom"}
        assert parsed.outputs[0].bip32_derivations == out.bip32_derivations
        assert parsed.outputs[0].unknown == {b"\x0f": b"out_custom"}

    def test_roundtrip_with_final_script_witness(self):
        """Round-trip PSBT with final_script_witness set."""
        tx_bytes = build_raw_tx(num_inputs=1, num_outputs=1)
        inp = PsbtInput(final_script_witness=(b"\x01\x02", b"\x03"),)
        psbt = Psbt(tx=tx_bytes, inputs=(inp,), outputs=(PsbtOutput(),))
        raw = serialize_psbt(psbt)

        parsed = parse_psbt(raw)
        assert len(parsed.inputs) == 1
        assert parsed.inputs[0].final_script_witness == (b"\x01\x02", b"\x03")

    def test_serialize_global_map_structure(self):
        tx_bytes = build_raw_tx()
        psbt = Psbt(tx=tx_bytes, inputs=(), outputs=())
        raw = serialize_psbt(psbt)
        # Verify: magic + global_kv + 00 + 00 + 00
        assert raw[:5] == PSBT_MAGIC
        # The serialization ends with 00 00 (input terminator + output terminator)
        assert raw[-2:] == b"\x00\x00"
        assert len(raw) == 20


# ── parse_psbt_hex ─────────────────────────────────────────────────────────


class TestParsePsbtHex:

    def test_valid(self):
        tx_bytes = build_raw_tx()
        data = PSBT_MAGIC + global_kv(tx_bytes) + b"\x00"
        psbt = parse_psbt_hex(data.hex())
        assert psbt.tx == tx_bytes

    def test_invalid_hex(self):
        with pytest.raises(ValueError):
            parse_psbt_hex("zzzz")


# ── parse_keypath_value ────────────────────────────────────────────────────


class TestParseKeypathValue:

    def test_normal(self):
        fingerprint = b"\x01\x02\x03\x04"
        count = 2
        path = (1).to_bytes(4, "little") + (2).to_bytes(4, "little")
        value = fingerprint + bytes([count]) + path
        fpr, p = parse_keypath_value(value)
        assert fpr == "01020304"
        assert p == ("1", "2")

    def test_zero_count(self):
        fingerprint = b"\xaa\xbb\xcc\xdd"
        value = fingerprint + b"\x00"
        fpr, p = parse_keypath_value(value)
        assert fpr == "aabbccdd"
        assert p == ()

    def test_many_elements(self):
        fingerprint = b"\x11\x22\x33\x44"
        count = 5
        path = b"".join(i.to_bytes(4, "little") for i in range(1, 6))
        value = fingerprint + bytes([count]) + path
        fpr, p = parse_keypath_value(value)
        assert fpr == "11223344"
        assert p == ("1", "2", "3", "4", "5")


# ── psbt_extract_signatures ────────────────────────────────────────────────

VALID_PUBKEY = bytes.fromhex(
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
VALID_DER = bytes.fromhex(
    "3044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    "022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")


class TestPsbtExtractSignatures:

    def __rx(self, num: int) -> bytes:
        return build_raw_tx(num_inputs=num, num_outputs=num)

    def test_no_sigs(self):
        tx_bytes = self.__rx(1)
        psbt = Psbt(tx=tx_bytes, inputs=(PsbtInput(),), outputs=(PsbtOutput(),))
        coll = psbt_extract_signatures(psbt)
        assert isinstance(coll, SignatureCollection)
        assert len(coll) == 0

    def test_valid_partial_sig(self):
        tx_bytes = self.__rx(1)
        sig = VALID_DER + bytes([0x01])
        inp = PsbtInput(partial_sigs={VALID_PUBKEY: sig})
        psbt = Psbt(tx=tx_bytes, inputs=(inp,), outputs=(PsbtOutput(),))
        coll = psbt_extract_signatures(psbt)
        assert len(coll) == 1
        rec = coll[0]
        assert rec.sig == VALID_DER
        assert rec.sighash_flag == 0x01
        assert rec.script_type == "psbt_partial"
        assert rec.amount == 0

    def test_invalid_pubkey_skipped(self):
        tx_bytes = self.__rx(1)
        sig = VALID_DER + bytes([0x01])
        inp = PsbtInput(partial_sigs={b"\x00" * 10: sig})
        psbt = Psbt(tx=tx_bytes, inputs=(inp,), outputs=(PsbtOutput(),))
        coll = psbt_extract_signatures(psbt)
        assert len(coll) == 0

    def test_short_sig_skipped(self):
        tx_bytes = self.__rx(1)
        inp = PsbtInput(partial_sigs={VALID_PUBKEY: b"\x00"})
        psbt = Psbt(tx=tx_bytes, inputs=(inp,), outputs=(PsbtOutput(),))
        coll = psbt_extract_signatures(psbt)
        assert len(coll) == 0

    def test_invalid_der_skipped(self):
        tx_bytes = self.__rx(1)
        sig = b"\x30\x02\x02\x01\x00" + bytes([0x01])
        inp = PsbtInput(partial_sigs={VALID_PUBKEY: sig})
        psbt = Psbt(tx=tx_bytes, inputs=(inp,), outputs=(PsbtOutput(),))
        coll = psbt_extract_signatures(psbt)
        assert len(coll) == 0

    def test_with_input_values(self):
        tx_bytes = self.__rx(2)
        sig = VALID_DER + bytes([0x01])
        inp0 = PsbtInput(partial_sigs={VALID_PUBKEY: sig})
        inp1 = PsbtInput(partial_sigs={VALID_PUBKEY: sig})
        psbt = Psbt(
            tx=tx_bytes,
            inputs=(inp0, inp1),
            outputs=(PsbtOutput(), PsbtOutput()),
        )
        coll = psbt_extract_signatures(psbt, input_values=[100, 200])
        assert len(coll) == 2
        assert coll[0].amount == 100
        assert coll[1].amount == 200

    def test_finalized_script_sig(self):
        tx_bytes = self.__rx(1)
        sig_element = VALID_DER + bytes([0x01])
        from bitcoin.script.parser import serialize_script
        from bitcoin.encoding.sec import serialize_sec

        pubkey_point = parse_public_key(VALID_PUBKEY)
        pubkey_element = serialize_sec(pubkey_point, compressed=True)
        script_sig = serialize_script([sig_element, pubkey_element])
        inp = PsbtInput(final_script_sig=script_sig)
        psbt = Psbt(tx=tx_bytes, inputs=(inp,), outputs=(PsbtOutput(),))
        coll = psbt_extract_signatures(psbt)
        assert len(coll) == 1
        assert coll[0].script_type == "finalized"
        assert coll[0].sig == VALID_DER
        assert coll[0].public_key == pubkey_point

    def test_finalized_no_bytes_elements(self):
        tx_bytes = self.__rx(1)
        from bitcoin.script.parser import serialize_script

        script_sig = serialize_script([0x00, 0x51])
        inp = PsbtInput(final_script_sig=script_sig)
        psbt = Psbt(tx=tx_bytes, inputs=(inp,), outputs=(PsbtOutput(),))
        coll = psbt_extract_signatures(psbt)
        assert len(coll) == 0

    def test_finalized_invalid_der_in_script(self):
        tx_bytes = self.__rx(1)
        from bitcoin.script.parser import serialize_script

        script_sig = serialize_script([b"\x00\x01"])
        inp = PsbtInput(final_script_sig=script_sig)
        psbt = Psbt(tx=tx_bytes, inputs=(inp,), outputs=(PsbtOutput(),))
        coll = psbt_extract_signatures(psbt)
        assert len(coll) == 0

    def test_multiple_partial_sigs_same_input(self):
        tx_bytes = self.__rx(1)
        sig = VALID_DER + bytes([0x01])
        pubkey2 = bytes.fromhex(
            "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        )
        inp = PsbtInput(partial_sigs={
            VALID_PUBKEY: sig,
            pubkey2: sig,
        })
        psbt = Psbt(tx=tx_bytes, inputs=(inp,), outputs=(PsbtOutput(),))
        coll = psbt_extract_signatures(psbt)
        assert len(coll) == 2

    def test_no_sigs_with_input_values_fallback(self):
        tx_bytes = self.__rx(1)
        psbt = Psbt(tx=tx_bytes, inputs=(PsbtInput(),), outputs=(PsbtOutput(),))
        coll = psbt_extract_signatures(psbt, input_values=[500])
        assert len(coll) == 0

    def testextract_pubkey_from_elements_valid(self):
        from bitcoin.psbt.parser import extract_pubkey_from_elements
        from bitcoin.encoding.sec import serialize_sec

        pubkey_point = parse_public_key(VALID_PUBKEY)
        pubkey_element = serialize_sec(pubkey_point, compressed=True)
        result = extract_pubkey_from_elements([pubkey_element])
        assert result == pubkey_point
        assert not result.infinity

    def testextract_pubkey_from_elements_uncompressed(self):
        from bitcoin.psbt.parser import extract_pubkey_from_elements
        from bitcoin.encoding.sec import serialize_sec

        pubkey_point = parse_public_key(VALID_PUBKEY)
        pubkey_element = serialize_sec(pubkey_point, compressed=False)
        result = extract_pubkey_from_elements([pubkey_element])
        assert result == pubkey_point

    def testextract_pubkey_from_elements_no_pubkey(self):
        from bitcoin.psbt.parser import extract_pubkey_from_elements

        result = extract_pubkey_from_elements([b"\x00", b"\x01"])
        assert result is None

    def testextract_pubkey_from_elements_invalid_length(self):
        from bitcoin.psbt.parser import extract_pubkey_from_elements

        result = extract_pubkey_from_elements([b"\x02" + b"\x00" * 16])
        assert result is None

    def testextract_pubkey_from_elements_off_curve(self):
        from bitcoin.psbt.parser import extract_pubkey_from_elements

        # 65-byte uncompressed SEC with x=0, y=1 — not on curve
        off_curve = b"\x04" + b"\x00" * 32 + b"\x01" * 32
        result = extract_pubkey_from_elements([off_curve])
        assert result is None


# ── _parse_key_value_map ───────────────────────────────────────────────────

# ── parse_key_value_map ───────────────────────────────────────────────────


def test_parse_key_value_map_empty():
    data = b"\x00"
    result, offset = parse_key_value_map(data, 0)
    assert result == {}
    assert offset == 1


def test_parse_key_value_map_single_entry():
    key = encode_varint(1) + bytes([0x01])
    val = encode_varint(5) + b"hello"
    data = key + val + b"\x00"
    result, offset = parse_key_value_map(data, 0)
    assert result == {0x01: b"hello"}
    assert offset == len(data)


def test_parse_key_value_map_multiple_entries():
    kv1 = encode_varint(1) + bytes([0x01]) + encode_varint(3) + b"abc"
    kv2 = encode_varint(1) + bytes([0x02]) + encode_varint(2) + b"de"
    data = kv1 + kv2 + b"\x00"
    result, offset = parse_key_value_map(data, 0)
    assert result == {0x01: b"abc", 0x02: b"de"}
    assert offset == len(data)


def test_parse_key_value_map_entry_with_key_data():
    key = encode_varint(3) + bytes([0x01]) + b"\xaa\xbb"
    val = encode_varint(2) + b"zz"
    data = key + val + b"\x00"
    result, offset = parse_key_value_map(data, 0)
    assert result == {0x01: b"zz"}
    assert offset == len(data)


# ── serialize_key_value ───────────────────────────────────────────────────


def test_serialize_key_value_with_key_data():
    result = serialize_key_value(0x01, b"abc", [b"\x00"])
    expected = encode_varint(2) + bytes([0x01, 0x00
                                        ]) + encode_varint(3) + b"abc"
    assert result == expected


def test_serialize_key_value_empty_key_data():
    result = serialize_key_value(0x01, b"abc", [])
    expected = encode_varint(1) + bytes([0x01]) + encode_varint(3) + b"abc"
    assert result == expected


def test_serialize_key_value_empty_value():
    result = serialize_key_value(0x05, b"", [b"\x00"])
    expected = encode_varint(2) + bytes([0x05, 0x00]) + encode_varint(0) + b""
    assert result == expected


def test_serialize_key_value_multiple_key_data():
    result = serialize_key_value(0x01, b"v", [b"\xaa", b"\xbb"])
    expected = (encode_varint(3) + bytes([0x01, 0xaa, 0xbb]) +
                encode_varint(1) + b"v")
    assert result == expected


# ── parse_input_map ───────────────────────────────────────────────────────


def test_parse_input_map_all_key_types():
    entries = bytearray()
    entries.extend(input_kv(PSBT_IN_NON_WITNESS_UTXO, b"\x00" * 10))
    entries.extend(input_kv(PSBT_IN_WITNESS_UTXO, b"\x01" * 40))
    entries.extend(
        input_kv(PSBT_IN_PARTIAL_SIG, b"\x05" * 10, key_data=b"\x02" * 33))
    entries.extend(input_kv(PSBT_IN_SIGHASH_TYPE, (1).to_bytes(4, "little")))
    entries.extend(input_kv(PSBT_IN_REDEEM_SCRIPT, b"\x06" * 5))
    entries.extend(input_kv(PSBT_IN_WITNESS_SCRIPT, b"\x07" * 5))
    entries.extend(
        input_kv(PSBT_IN_BIP32_DERIVATION, b"\x09" * 8, key_data=b"\x0a" * 33))
    entries.extend(input_kv(PSBT_IN_FINAL_SCRIPTSIG, b"\x0b" * 3))
    entries.extend(
        input_kv(
            PSBT_IN_FINAL_SCRIPTWITNESS,
            build_witness_stack([b"\x0c", b"\x0d\x0e"]),
        ))
    entries.extend(input_kv(0x09, b"\x0f"))
    entries.append(0x00)

    inp, offset = parse_input_map(bytes(entries), 0)
    assert inp.non_witness_utxo == b"\x00" * 10
    assert inp.witness_utxo == b"\x01" * 40
    assert inp.partial_sigs == {b"\x02" * 33: b"\x05" * 10}
    assert inp.sighash_type == 1
    assert inp.redeem_script == b"\x06" * 5
    assert inp.witness_script == b"\x07" * 5
    assert inp.bip32_derivations == {b"\x0a" * 33: b"\x09" * 8}
    assert inp.final_script_sig == b"\x0b" * 3
    assert inp.final_script_witness == (b"\x0c", b"\x0d\x0e")
    assert inp.unknown == {b"\x09": b"\x0f"}
    assert offset == len(entries)


def test_parse_input_map_empty():
    inp, offset = parse_input_map(b"\x00", 0)
    assert inp.non_witness_utxo is None
    assert inp.sighash_type is None
    assert len(inp.partial_sigs) == 0
    assert offset == 1


def test_parse_input_map_unknown_keys():
    entries = bytearray()
    entries.extend(input_kv(0x0a, b"v1"))
    entries.extend(input_kv(0x0b, b"v2", key_data=b"\x01"))
    entries.append(0x00)
    inp, offset = parse_input_map(bytes(entries), 0)
    assert inp.unknown == {b"\x0a": b"v1", b"\x0b\x01": b"v2"}
    assert offset == len(entries)


# ── serialize_input_map ───────────────────────────────────────────────────


def test_serialize_input_map_all_fields():
    inp = PsbtInput(
        non_witness_utxo=b"\x01",
        witness_utxo=b"\x02",
        sighash_type=1,
        redeem_script=b"\x03",
        witness_script=b"\x04",
        final_script_sig=b"\x05",
    )
    result = serialize_input_map(inp)
    assert b"\x01" in result
    assert b"\x02" in result
    assert (1).to_bytes(4, "little") in result
    assert b"\x03" in result
    assert b"\x04" in result
    assert b"\x05" in result


def test_serialize_input_map_empty():
    inp = PsbtInput()
    result = serialize_input_map(inp)
    assert result == b""


def test_serialize_input_map_roundtrip():
    inp = PsbtInput(redeem_script=b"\xaa\xbb")
    ser = serialize_input_map(inp)
    data = ser + b"\x00"
    inp2, _ = parse_input_map(data, 0)
    assert inp2.redeem_script == b"\xaa\xbb"


def test_serialize_input_map_partial_sigs():
    """partial_sigs is written by serialize_input_map and round-trips."""
    pubkey = b"\x02" * 33
    sig = b"\x05"
    inp = PsbtInput(partial_sigs={pubkey: sig})
    result = serialize_input_map(inp)
    # varint key_len(1) + type(1) + 33B pubkey + varint val_len(1) + 1B sig
    assert len(result) == 37
    inp2, _ = parse_input_map(result + b"\x00", 0)
    assert inp2.partial_sigs == {pubkey: sig}


# ── parse_output_map ──────────────────────────────────────────────────────


def test_parse_output_map_all_key_types():
    entries = bytearray()
    entries.extend(output_kv(PSBT_OUT_REDEEM_SCRIPT, b"\x01"))
    entries.extend(output_kv(PSBT_OUT_WITNESS_SCRIPT, b"\x02"))
    entries.extend(
        output_kv(PSBT_OUT_BIP32_DERIVATION, b"\x04" * 8,
                  key_data=b"\x05" * 33))
    entries.extend(output_kv(0x03, b"\x06"))
    entries.append(0x00)

    out, offset = parse_output_map(bytes(entries), 0)
    assert out.redeem_script == b"\x01"
    assert out.witness_script == b"\x02"
    assert out.bip32_derivations == {b"\x05" * 33: b"\x04" * 8}
    assert out.unknown == {b"\x03": b"\x06"}
    assert offset == len(entries)


def test_parse_output_map_empty():
    out, offset = parse_output_map(b"\x00", 0)
    assert out.redeem_script is None
    assert out.witness_script is None
    assert offset == 1


# ── serialize_output_map ──────────────────────────────────────────────────


def test_serialize_output_map_all_fields():
    out = PsbtOutput(redeem_script=b"\x01", witness_script=b"\x02")
    result = serialize_output_map(out)
    assert b"\x01" in result
    assert b"\x02" in result


def test_serialize_output_map_empty():
    out = PsbtOutput()
    result = serialize_output_map(out)
    assert result == b""


def test_serialize_output_map_roundtrip():
    out = PsbtOutput(redeem_script=b"\xaa", witness_script=b"\xbb")
    ser = serialize_output_map(out)
    data = ser + b"\x00"
    out2, _ = parse_output_map(data, 0)
    assert out2.redeem_script == b"\xaa"
    assert out2.witness_script == b"\xbb"


# ── parse_witness_stack ───────────────────────────────────────────────────


def test_parse_witness_stack_empty():
    result = parse_witness_stack(b"")
    assert result == ()


def test_parse_witness_stack_single_item():
    result = parse_witness_stack(encode_varint(3) + b"abc")
    assert result == (b"abc",)


def test_parse_witness_stack_multiple_items():
    data = (encode_varint(1) + b"a" + encode_varint(2) + b"bc" +
            encode_varint(3) + b"def")
    result = parse_witness_stack(data)
    assert result == (b"a", b"bc", b"def")


def test_parse_witness_stack_integration():
    ws = build_witness_stack([b"\x01\x02", b"\x03"])
    kv = input_kv(PSBT_IN_FINAL_SCRIPTWITNESS, ws)
    data = kv + b"\x00"
    inp, _ = parse_input_map(data, 0)
    assert inp.final_script_witness == (b"\x01\x02", b"\x03")
