from __future__ import annotations

import json

import pytest

from bitcoin.cli import main as cli_main
from bitcoin.der import parse_der_signature
from bitcoin.ecc import SECP256K1_ORDER, is_on_curve
from bitcoin.exceptions import (
    InvalidDerSignatureError,
    InvalidHexError,
    InvalidSecPublicKeyError,
    InvalidSighashFlagError,
    MalformedVarintError,
    MissingInputValueError,
    ScriptParseError,
    TruncatedTransactionError,
    UnsupportedScriptPathError,
)
from bitcoin.script import (
    ScriptChunk,
    is_witness_program,
    parse_multisig_redeem_script,
    parse_script,
    remove_code_separators,
    witness_program_hash_size,
)
from bitcoin.signature import SignatureCollection
from bitcoin.transaction import Transaction


def encode_varint(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def push(data: bytes) -> bytes:
    if len(data) < 0x4C:
        return bytes([len(data)]) + data
    if len(data) <= 0xFF:
        return b"\x4c" + bytes([len(data)]) + data
    if len(data) <= 0xFFFF:
        return b"\x4d" + len(data).to_bytes(2, "little") + data
    return b"\x4e" + len(data).to_bytes(4, "little") + data


def build_der_signature(r: bytes, s: bytes, sighash_flag: int) -> bytes:
    if r and r[0] & 0x80:
        r = b"\x00" + r
    if s and s[0] & 0x80:
        s = b"\x00" + s
    der = bytearray()
    der.append(0x30)
    body = bytearray()
    body.extend([0x02, len(r)])
    body.extend(r)
    body.extend([0x02, len(s)])
    body.extend(s)
    der.append(len(body))
    der.extend(body)
    der.append(sighash_flag)
    return bytes(der)


def build_p2pkh_transaction() -> tuple[str, str, str]:
    prevout_hash = bytes.fromhex("11" * 32)
    pubkey = bytes.fromhex(
        "02c0ded4b6f919c7d4317a7ce0d2db2aab7b4d79b0f1b9ab2d5b8e86e7b0d1c6c5")
    signature = build_der_signature(bytes.fromhex("7f" * 32),
                                    bytes.fromhex("55" * 32), 0x01)
    script_sig = push(signature) + push(pubkey)
    outputs = [
        (12345, bytes.fromhex("76a914" + "22" * 20 + "88ac")),
    ]
    raw = bytearray()
    raw.extend((2).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend(prevout_hash)
    raw.extend((1).to_bytes(4, "little"))
    raw.extend(encode_varint(len(script_sig)))
    raw.extend(script_sig)
    raw.extend((0xFFFFFFFE).to_bytes(4, "little"))
    raw.extend(encode_varint(len(outputs)))
    for value, script in outputs:
        raw.extend(value.to_bytes(8, "little"))
        raw.extend(encode_varint(len(script)))
        raw.extend(script)
    raw.extend((0).to_bytes(4, "little"))
    return raw.hex(), pubkey.hex(), signature.hex()


def build_p2sh_multisig_transaction() -> tuple[str, list[str]]:
    prevout_hash = bytes.fromhex("22" * 32)
    pubkey1 = bytes.fromhex(
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    pubkey2 = bytes.fromhex(
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
    redeem_script = b"\x52" + push(pubkey1) + push(pubkey2) + b"\x52\xae"
    signature1 = build_der_signature(bytes.fromhex("11" * 32),
                                     bytes.fromhex("22" * 32), 0x01)
    signature2 = build_der_signature(bytes.fromhex("33" * 32),
                                     bytes.fromhex("44" * 32), 0x01)
    script_sig = b"\x00" + push(signature1) + push(signature2) + push(
        redeem_script)
    raw = bytearray()
    raw.extend((1).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend(prevout_hash)
    raw.extend((2).to_bytes(4, "little"))
    raw.extend(encode_varint(len(script_sig)))
    raw.extend(script_sig)
    raw.extend((0xFFFFFFFF).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend((50000).to_bytes(8, "little"))
    raw.extend(encode_varint(25))
    raw.extend(bytes.fromhex("76a914" + "33" * 20 + "88ac"))
    raw.extend((0).to_bytes(4, "little"))
    return raw.hex(), [pubkey1.hex(), pubkey2.hex()]


def build_p2wpkh_transaction() -> tuple[str, int, str, str]:
    prevout_hash = bytes.fromhex("33" * 32)
    pubkey = bytes.fromhex(
        "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357")
    signature = build_der_signature(
        bytes.fromhex(
            "0b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be"),
        bytes.fromhex(
            "40529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed"),
        0x01,
    )
    raw = bytearray()
    raw.extend((1).to_bytes(4, "little"))
    raw.extend(b"\x00\x01")
    raw.extend(encode_varint(1))
    raw.extend(prevout_hash)
    raw.extend((0).to_bytes(4, "little"))
    raw.extend(encode_varint(0))
    raw.extend((0xFFFFFFFF).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend((1000).to_bytes(8, "little"))
    raw.extend(encode_varint(25))
    raw.extend(bytes.fromhex("76a914" + "44" * 20 + "88ac"))
    raw.extend(encode_varint(2))
    raw.extend(encode_varint(len(signature)))
    raw.extend(signature)
    raw.extend(encode_varint(len(pubkey)))
    raw.extend(pubkey)
    raw.extend((0).to_bytes(4, "little"))
    return raw.hex(), 200000000, pubkey.hex(), signature.hex()


def build_p2sh_p2wpkh_transaction() -> tuple[str, int, str, str]:
    prevout_hash = bytes.fromhex("44" * 32)
    pubkey = bytes.fromhex(
        "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873")
    redeem_script = bytes.fromhex(
        "001479091972186c449eb1ded22b78e40d009bdf0089")
    signature = build_der_signature(
        bytes.fromhex(
            "68c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d90"),
        bytes.fromhex(
            "5b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce2715"),
        0x02,
    )
    raw = bytearray()
    raw.extend((1).to_bytes(4, "little"))
    raw.extend(b"\x00\x01")
    raw.extend(encode_varint(1))
    raw.extend(prevout_hash)
    raw.extend((1).to_bytes(4, "little"))
    raw.extend(encode_varint(len(push(redeem_script))))
    raw.extend(push(redeem_script))
    raw.extend((0xFFFFFFFE).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend((1000).to_bytes(8, "little"))
    raw.extend(encode_varint(25))
    raw.extend(bytes.fromhex("76a914" + "55" * 20 + "88ac"))
    raw.extend(encode_varint(2))
    raw.extend(encode_varint(len(signature)))
    raw.extend(signature)
    raw.extend(encode_varint(len(pubkey)))
    raw.extend(pubkey)
    raw.extend((0).to_bytes(4, "little"))
    return raw.hex(), 1000000000, pubkey.hex(), signature.hex()


def build_p2wsh_multisig_transaction() -> tuple[str, list[int]]:
    prevout_hash = bytes.fromhex("55" * 32)
    pubkey1 = bytes.fromhex(
        "0307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3")
    pubkey2 = bytes.fromhex(
        "03b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b")
    witness_script = b"\x52" + push(pubkey1) + push(pubkey2) + b"\x52\xae"
    signature1 = build_der_signature(
        bytes.fromhex(
            "08c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d90"),
        bytes.fromhex(
            "5b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce2715"),
        0x01,
    )
    signature2 = build_der_signature(
        bytes.fromhex(
            "19ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e"),
        bytes.fromhex(
            "07cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c767954"),
        0x03,
    )
    raw = bytearray()
    raw.extend((2).to_bytes(4, "little"))
    raw.extend(b"\x00\x01")
    raw.extend(encode_varint(1))
    raw.extend(prevout_hash)
    raw.extend((0).to_bytes(4, "little"))
    raw.extend(encode_varint(0))
    raw.extend((0xFFFFFFFF).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend((500000).to_bytes(8, "little"))
    raw.extend(encode_varint(25))
    raw.extend(bytes.fromhex("76a914" + "66" * 20 + "88ac"))
    raw.extend(encode_varint(4))
    raw.extend(encode_varint(0))
    raw.extend(encode_varint(len(signature1)))
    raw.extend(signature1)
    raw.extend(encode_varint(len(signature2)))
    raw.extend(signature2)
    raw.extend(encode_varint(len(witness_script)))
    raw.extend(witness_script)
    raw.extend((0).to_bytes(4, "little"))
    return raw.hex(), [50000000]


def test_parse_legacy_transaction() -> None:
    raw_hex, pubkey_hex, signature_hex = build_p2pkh_transaction()
    transaction = Transaction.parse_hex(raw_hex)
    collection = transaction.extract()
    assert collection.r == ["7f" * 32]
    assert collection.s == ["55" * 32]
    assert len(collection.z) == 1
    assert collection.signatures[0].public_key == pubkey_hex
    assert collection.signatures[0].script_type == "legacy-p2pkh"


def test_parse_p2sh_multisig_transaction() -> None:
    raw_hex, pubkeys = build_p2sh_multisig_transaction()
    transaction = Transaction.parse_hex(raw_hex)
    collection = transaction.extract()
    assert len(collection.signatures) == 2
    assert collection.signatures[0].public_key == pubkeys[0]
    assert collection.signatures[1].public_key == pubkeys[1]
    assert collection.signatures[0].script_type == "legacy-p2sh-multisig"


def test_parse_native_segwit_transaction() -> None:
    raw_hex, amount, pubkey_hex, signature_hex = build_p2wpkh_transaction()
    transaction = Transaction.parse_hex(raw_hex).with_input_values([amount])
    collection = transaction.extract()
    assert collection.signatures[0].public_key == pubkey_hex
    assert collection.signatures[0].script_type == "segwit-v0-p2wpkh"
    assert collection.signatures[0].sighash_flag == 0x01


def test_parse_nested_segwit_multisig_transaction() -> None:
    raw_hex, values = build_p2wsh_multisig_transaction()
    transaction = Transaction.parse_hex(raw_hex).with_input_values(values)
    collection = transaction.extract()
    assert len(collection.signatures) == 2
    assert collection.signatures[0].script_type == "segwit-v0-p2wsh"
    assert collection.signatures[1].sighash_flag == 0x03


def test_invalid_hex_rejected() -> None:
    with pytest.raises(InvalidHexError):
        Transaction.parse_hex("zz")


def test_malformed_varint_rejected() -> None:
    raw = bytes.fromhex("01000000fdfc00")
    with pytest.raises(MalformedVarintError):
        Transaction.parse_hex(raw.hex())


def test_truncated_transaction_rejected() -> None:
    raw_hex, _, _ = build_p2pkh_transaction()
    with pytest.raises(TruncatedTransactionError):
        Transaction.parse_hex(raw_hex[:-4])


def test_missing_segwit_input_value_rejected() -> None:
    raw_hex, _, _, _ = build_p2wpkh_transaction()
    transaction = Transaction.parse_hex(raw_hex)
    with pytest.raises(MissingInputValueError):
        transaction.extract()


def test_bad_sighash_flag_rejected() -> None:
    prevout_hash = bytes.fromhex("11" * 32)
    pubkey = bytes.fromhex(
        "02c0ded4b6f919c7d4317a7ce0d2db2aab7b4d79b0f1b9ab2d5b8e86e7b0d1c6c5")
    signature = build_der_signature(bytes.fromhex("7f" * 32),
                                    bytes.fromhex("55" * 32), 0x05)
    script_sig = push(signature) + push(pubkey)
    raw = bytearray()
    raw.extend((2).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend(prevout_hash)
    raw.extend((1).to_bytes(4, "little"))
    raw.extend(encode_varint(len(script_sig)))
    raw.extend(script_sig)
    raw.extend((0xFFFFFFFE).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend((12345).to_bytes(8, "little"))
    raw.extend(encode_varint(25))
    raw.extend(bytes.fromhex("76a914" + "22" * 20 + "88ac"))
    raw.extend((0).to_bytes(4, "little"))
    transaction = Transaction.parse_hex(raw.hex())
    with pytest.raises(InvalidSighashFlagError):
        transaction.extract()


def test_invalid_der_signature_rejected() -> None:
    prevout_hash = bytes.fromhex("11" * 32)
    pubkey = bytes.fromhex(
        "02c0ded4b6f919c7d4317a7ce0d2db2aab7b4d79b0f1b9ab2d5b8e86e7b0d1c6c5")
    signature = b"\x31\x06\x02\x01\x01\x02\x01\x01\x01"
    script_sig = push(signature) + push(pubkey)
    raw = bytearray()
    raw.extend((2).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend(prevout_hash)
    raw.extend((1).to_bytes(4, "little"))
    raw.extend(encode_varint(len(script_sig)))
    raw.extend(script_sig)
    raw.extend((0xFFFFFFFE).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend((12345).to_bytes(8, "little"))
    raw.extend(encode_varint(25))
    raw.extend(bytes.fromhex("76a914" + "22" * 20 + "88ac"))
    raw.extend((0).to_bytes(4, "little"))
    transaction = Transaction.parse_hex(raw.hex())
    with pytest.raises(InvalidDerSignatureError):
        transaction.extract()


def test_der_signature_too_short_rejected() -> None:
    with pytest.raises(InvalidDerSignatureError):
        parse_der_signature(b"")


def test_der_signature_too_long_rejected() -> None:
    with pytest.raises(InvalidDerSignatureError):
        parse_der_signature(b"\x30" + b"\x4a" + b"\x00" * 74 + b"\x01")


def test_der_signature_missing_sequence_tag_rejected() -> None:
    with pytest.raises(InvalidDerSignatureError):
        parse_der_signature(b"\x31\x06\x02\x01\x01\x02\x01\x01\x01")


def test_script_parse_pushdata_exceeds_script() -> None:
    with pytest.raises(ScriptParseError):
        parse_script(bytes([0x01]))


def test_script_parse_pushdata1_truncated_length() -> None:
    script = bytes([0x4C])
    with pytest.raises(ScriptParseError):
        parse_script(script)


def test_script_parse_pushdata1_exceeds_script() -> None:
    script = bytes([0x4C, 0x05])
    with pytest.raises(ScriptParseError):
        parse_script(script)


def test_script_parse_pushdata2_truncated_length() -> None:
    script = bytes([0x4D, 0x01])
    with pytest.raises(ScriptParseError):
        parse_script(script)


def test_script_parse_pushdata4_truncated_length() -> None:
    script = bytes([0x4E, 0x01, 0x00, 0x00])
    with pytest.raises(ScriptParseError):
        parse_script(script)


def test_parse_all_zero_bytes_rejected() -> None:
    raw = bytes(100)
    with pytest.raises((TruncatedTransactionError, MalformedVarintError)):
        Transaction.parse_hex(raw.hex())


def test_parse_empty_hex_rejected() -> None:
    with pytest.raises(InvalidHexError):
        Transaction.parse_hex("")


def test_parse_hex_only_whitespace() -> None:
    with pytest.raises(InvalidHexError):
        Transaction.parse_hex("   ")


def test_parse_odd_length_hex_rejected() -> None:
    with pytest.raises(InvalidHexError):
        Transaction.parse_hex("abc")


def test_parse_with_0x_prefix_rejected() -> None:
    with pytest.raises(InvalidHexError):
        Transaction.parse_hex("0x01000000")


def test_cli_unknown_command_rejected() -> None:
    exit_code = cli_main(["unknown"])
    assert exit_code in (1, 2)


def test_unsupported_script_path_rejected() -> None:
    prevout_hash = bytes.fromhex("11" * 32)
    signature = build_der_signature(bytes.fromhex("7f" * 32),
                                    bytes.fromhex("55" * 32), 0x01)
    script_sig = push(signature) + push(b"\x51")
    raw = bytearray()
    raw.extend((1).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend(prevout_hash)
    raw.extend((0).to_bytes(4, "little"))
    raw.extend(encode_varint(len(script_sig)))
    raw.extend(script_sig)
    raw.extend((0xFFFFFFFF).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend((0).to_bytes(8, "little"))
    raw.extend(encode_varint(0))
    raw.extend((0).to_bytes(4, "little"))
    transaction = Transaction.parse_hex(raw.hex())
    with pytest.raises(UnsupportedScriptPathError):
        transaction.extract()


def test_cli_pretty_prints_parse_output(
        capsys: pytest.CaptureFixture[str]) -> None:
    raw_hex, _, _ = build_p2pkh_transaction()
    exit_code = cli_main(["parse", "--tx", raw_hex])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out.startswith('{\n  "inputs": [\n')
    assert '"version": 2' in captured.out


def test_cli_pretty_prints_extract_output(
        capsys: pytest.CaptureFixture[str]) -> None:
    raw_hex, _, _ = build_p2pkh_transaction()
    exit_code = cli_main(["extract", "--tx", raw_hex])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out.startswith('{\n  "count": 1,\n')
    assert '"script_type": "legacy-p2pkh"' in captured.out


def test_cli_rejects_invalid_input_values(
        capsys: pytest.CaptureFixture[str]) -> None:
    raw_hex, _, _ = build_p2pkh_transaction()
    exit_code = cli_main(["extract", "--tx", raw_hex, "--input-values", "abc"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Invalid input value: 'abc'" in captured.err


def test_cli_rejects_input_value_count_mismatch(
    capsys: pytest.CaptureFixture[str],) -> None:
    raw_hex, _, _ = build_p2pkh_transaction()
    exit_code = cli_main(
        ["extract", "--tx", raw_hex, "--input-values", "100,200"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "input value count must match" in captured.err


def test_cli_captures_bitcoin_error(capsys: pytest.CaptureFixture[str]) -> None:
    raw_hex, _, _ = build_p2pkh_transaction()
    exit_code = cli_main(["extract", "--tx", raw_hex[:-4]])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Transaction ended unexpectedly" in captured.err


def test_cli_captures_parse_error(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli_main(["extract", "--tx", "zz"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "contains non-hex characters" in captured.err


def test_parse_p2sh_p2wpkh_transaction() -> None:
    raw_hex, amount, pubkey_hex, signature_hex = build_p2sh_p2wpkh_transaction()
    transaction = Transaction.parse_hex(raw_hex).with_input_values([amount])
    collection = transaction.extract()
    assert collection.signatures[0].public_key == pubkey_hex
    assert collection.signatures[0].script_type == "segwit-v0-p2sh-p2wpkh"
    assert collection.signatures[0].sighash_flag == 0x02


def test_parse_nested_segwit_p2sh_p2wpkh_transaction() -> None:
    raw_hex, amount, pubkey_hex, signature_hex = build_p2sh_p2wpkh_transaction()
    transaction = Transaction.parse_hex(raw_hex).with_input_values([amount])
    collection = transaction.extract()
    assert len(collection.signatures) == 1
    assert collection.signatures[0].r is not None
    assert collection.signatures[0].z is not None


def test_cli_with_input_values_single(
        capsys: pytest.CaptureFixture[str]) -> None:
    raw_hex, amount, _, _ = build_p2wpkh_transaction()
    exit_code = cli_main(
        ["extract", "--tx", raw_hex, "--input-values",
         str(amount)])
    captured = capsys.readouterr()
    assert exit_code == 0
    payload = json.loads(captured.out)
    assert payload["count"] == 1
    assert payload["records"][0]["script_type"] == "segwit-v0-p2wpkh"


# ── DER validation branches ──────────────────────────────────────────────


def test_der_r_integer_empty() -> None:
    sig = build_der_signature(b"", bytes([1]), 0x01)
    with pytest.raises(InvalidDerSignatureError):
        parse_der_signature(sig)


def test_der_r_integer_negative() -> None:
    der = bytes([0x30, 6, 0x02, 2, 0x80, 0x01, 0x02, 1, 0x01, 0x01])
    with pytest.raises(InvalidDerSignatureError):
        parse_der_signature(der)


def test_der_r_integer_excessive_leading_zero() -> None:
    sig = build_der_signature(bytes([0x00, 0x01]), bytes([1]), 0x01)
    with pytest.raises(InvalidDerSignatureError):
        parse_der_signature(sig)


def test_der_s_integer_empty() -> None:
    der = bytes([0x30, 5, 0x02, 1, 0x01, 0x02, 0, 0x01])
    with pytest.raises(InvalidDerSignatureError):
        parse_der_signature(der)


def test_der_s_integer_negative() -> None:
    der = bytes([0x30, 6, 0x02, 1, 0x01, 0x02, 2, 0x80, 0x01, 0x01])
    with pytest.raises(InvalidDerSignatureError):
        parse_der_signature(der)


def test_der_missing_s_tag() -> None:
    der = bytearray()
    der.append(0x30)
    body = bytearray()
    body.extend([0x02, 1, 0x01])
    der.append(len(body))
    der.extend(body)
    der.append(0x01)
    sig = bytes(der)
    with pytest.raises(InvalidDerSignatureError):
        parse_der_signature(sig)


def test_der_truncated_rejects() -> None:
    sig = build_der_signature(bytes([1]), bytes([1]), 0x01)[:-3]
    with pytest.raises(InvalidDerSignatureError):
        parse_der_signature(sig)


# ── DER remaining branches ──────────────────────────────────────────────


def test_der_s_tag_missing_value() -> None:
    r_data = bytes([0x01])
    body = bytearray([0x02, len(r_data)])
    body.extend(r_data)
    body.extend([0x99, 1, 0x01])
    der = bytearray([0x30, len(body)])
    der.extend(body)
    sig = bytes(der) + b"\x01"
    with pytest.raises(InvalidDerSignatureError, match="S integer tag"):
        parse_der_signature(sig)


def test_der_r_empty_integer() -> None:
    # r_len=0, s_len=2 → validates _validate_der_integer(b"", "R") → empty
    der = bytes([0x30, 6, 0x02, 0, 0x02, 2, 0x01, 0x02])
    sig = der + b"\x01"
    with pytest.raises(InvalidDerSignatureError, match="R integer is empty"):
        parse_der_signature(sig)


def test_der_r_negative_integer() -> None:
    r_bytes = bytes([0x80, 0x00, 0x01])
    body = bytes([0x02, len(r_bytes)]) + r_bytes + bytes([0x02, 2, 0x01, 0x02])
    der = bytes([0x30, len(body)]) + body
    sig = der + b"\x01"
    with pytest.raises(InvalidDerSignatureError, match="R integer is negative"):
        parse_der_signature(sig)


def test_der_r_excessive_leading_zero() -> None:
    sig = build_der_signature(bytes([0x00, 0x01]), bytes([0x01, 0x02]), 0x01)
    with pytest.raises(InvalidDerSignatureError,
                       match="R integer has a leading zero"):
        parse_der_signature(sig)


def test_der_s_valid_leading_zero_allowed() -> None:
    r_bytes = bytes([0x01])
    s_bytes = bytes([0x00, 0x80])
    sig = build_der_signature(r_bytes, s_bytes, 0x01)
    parsed = parse_der_signature(sig)
    assert parsed.s == s_bytes


def test_der_length_inconsistent() -> None:
    # der[1] != len(der) - 2
    der = bytes([0x30, 8, 0x02, 1, 0x01, 0x02, 1, 0x01])
    sig = der + b"\x01"
    with pytest.raises(InvalidDerSignatureError,
                       match="DER length is inconsistent"):
        parse_der_signature(sig)


# ── Sighash flag parsing ────────────────────────────────────────────────


def test_sighash_flag_bad_base_type_rejected_direct() -> None:
    from bitcoin.sighash import parse_sighash_flag

    with pytest.raises(InvalidSighashFlagError,
                       match="Unsupported sighash base type"):
        parse_sighash_flag(0x00)


def test_sighash_legacy_anyonecanpay_path() -> None:
    from bitcoin.sighash import legacy_sighash

    raw_hex, _, _ = build_p2pkh_transaction()
    tx = Transaction.parse_hex(raw_hex)
    script_code = bytes.fromhex("76a914" + "22" * 20 + "88ac")
    digest = legacy_sighash(tx, 0, script_code, 0x81)
    assert isinstance(digest, bytes) and len(digest) == 32


def test_sighash_legacy_none_path() -> None:
    from bitcoin.sighash import legacy_sighash

    raw_hex, _, _ = build_p2pkh_transaction()
    tx = Transaction.parse_hex(raw_hex)
    script_code = bytes.fromhex("76a914" + "22" * 20 + "88ac")
    digest = legacy_sighash(tx, 0, script_code, 0x02)
    assert isinstance(digest, bytes) and len(digest) == 32


def test_sighash_legacy_single_path() -> None:
    from bitcoin.sighash import legacy_sighash

    raw_hex, _, _ = build_p2pkh_transaction()
    tx = Transaction.parse_hex(raw_hex)
    script_code = bytes.fromhex("76a914" + "22" * 20 + "88ac")
    digest = legacy_sighash(tx, 0, script_code, 0x03)
    assert isinstance(digest, bytes) and len(digest) == 32


def test_sighash_legacy_single_no_output() -> None:
    from bitcoin.sighash import legacy_sighash

    raw_hex, _, _ = build_p2pkh_transaction()
    tx = Transaction.parse_hex(raw_hex)
    script_code = bytes.fromhex("76a914" + "22" * 20 + "88ac")
    digest = legacy_sighash(tx, 1, script_code, 0x03)
    # SINGLE with input_index >= len(outputs) → hash of int_to_bytes(1, 32)
    assert isinstance(digest, bytes) and len(digest) == 32


def test_sighash_segwit_anyonecanpay_path() -> None:
    raw_hex, amount, _, _ = build_p2wpkh_transaction()
    tx = Transaction.parse_hex(raw_hex).with_input_values([amount])
    collection = tx.extract()
    assert len(collection.signatures) == 1
    first = collection.signatures[0]
    # sighash_flag=0x01, base_type=SIGHASH_ALL → not anyone_can_pay
    assert first.sighash_flag == 0x01


# ── Script parsing branches ─────────────────────────────────────────────


def test_script_pushdata1_success() -> None:
    data = bytes(range(10))
    script = bytes([0x4C, 10]) + data
    chunks = parse_script(script)
    assert len(chunks) == 1
    assert chunks[0].data == data


def test_script_pushdata2_success() -> None:
    data = bytes([1]) * 300
    script = bytes([0x4D]) + (300).to_bytes(2, "little") + data
    chunks = parse_script(script)
    assert len(chunks) == 1
    assert chunks[0].data == data


def test_script_pushdata2_exceeds_script() -> None:
    script = bytes([0x4D, 0x10, 0x00]) + b"\x01"
    with pytest.raises(ScriptParseError, match="PUSHDATA2 exceeds"):
        parse_script(script)


def test_script_pushdata4_success() -> None:
    data = bytes([1]) * 70000
    script = bytes([0x4E]) + (70000).to_bytes(4, "little") + data
    chunks = parse_script(script)
    assert len(chunks) == 1
    assert chunks[0].data == data


def test_script_pushdata4_exceeds_script() -> None:
    script = bytes([0x4E, 0x00, 0x01, 0x00, 0x00]) + b"\x01"
    with pytest.raises(ScriptParseError, match="PUSHDATA4 exceeds"):
        parse_script(script)


def test_script_code_separator_rejected() -> None:
    with pytest.raises(UnsupportedScriptPathError, match="OP_CODESEPARATOR"):
        remove_code_separators(bytes([0xAB]))


def test_script_chunk_is_push_true() -> None:
    chunk = ScriptChunk(opcode=1, data=b"\x01")
    assert chunk.is_push is True


def test_script_chunk_is_push_false() -> None:
    chunk = ScriptChunk(opcode=0xAB, data=None)
    assert chunk.is_push is False


def test_is_witness_program_false_wrong_length() -> None:
    assert is_witness_program(b"\x00\x14") is False  # len=2 not in {22, 34}


def test_is_witness_program_false_wrong_version() -> None:
    assert is_witness_program(b"\x01" + b"\x14" + b"\x00" * 20) is False


def test_is_witness_program_true_v0_p2wpkh() -> None:
    assert is_witness_program(b"\x00\x14" + b"\x00" * 20) is True


def test_is_witness_program_true_v0_p2wsh() -> None:
    assert is_witness_program(b"\x00\x20" + b"\x00" * 32) is True


def test_witness_program_hash_size_invalid() -> None:
    assert witness_program_hash_size(b"\x00\x14") is None


def test_witness_program_hash_size_valid() -> None:
    result = witness_program_hash_size(b"\x00\x20" + b"\x00" * 32)
    assert result == 32


def test_parse_multisig_redeem_script_missing_checkmultisig() -> None:
    script = bytes([0x51, 0x21] + [0x00] * 33 + [0x51])
    with pytest.raises(UnsupportedScriptPathError, match="CHECKMULTISIG"):
        parse_multisig_redeem_script(script)


def test_parse_multisig_redeem_script_invalid_structure() -> None:
    # First chunk is a push (data is not None) instead of m-value opcode
    script = push(b"\x51") + push(b"\x00" * 33) + bytes([0x51, 0xAE])
    with pytest.raises(UnsupportedScriptPathError, match="invalid structure"):
        parse_multisig_redeem_script(script)


def test_parse_multisig_redeem_script_bad_m() -> None:
    # m opcode 0x50 (80, not a push) is not in 0x51-0x60 range
    script = bytes([0x50]) + push(b"\x00" * 33) + bytes([0x52, 0xAE])
    with pytest.raises(UnsupportedScriptPathError, match="m value"):
        parse_multisig_redeem_script(script)


def test_parse_multisig_redeem_script_bad_n() -> None:
    # n opcode 0x50 (80, not a push) is not in 0x51-0x60 range
    script = bytes([0x52]) + push(b"\x00" * 33) + bytes([0x50, 0xAE])
    with pytest.raises(UnsupportedScriptPathError, match="n value"):
        parse_multisig_redeem_script(script)


def test_parse_multisig_redeem_script_inconsistent_pubkey_count() -> None:
    # n=3 (0x53) but only 1 pubkey provided
    script = bytes([0x52]) + push(b"\x00" * 33) + bytes([0x53, 0xAE])
    with pytest.raises(UnsupportedScriptPathError, match="pubkey count"):
        parse_multisig_redeem_script(script)


def test_parse_multisig_redeem_script_bad_pubkey_length() -> None:
    pubkey_33 = b"\x00" * 33
    pubkey_bad = b"\x00" * 20
    script = bytes([0x52]) + push(pubkey_33) + push(pubkey_bad) + bytes(
        [0x52, 0xAE])
    with pytest.raises(UnsupportedScriptPathError, match="public key length"):
        parse_multisig_redeem_script(script)


def test_parse_multisig_redeem_script_invalid_threshold() -> None:
    pubkey1 = b"\x00" * 33
    pubkey2 = b"\x00" * 33
    # m=0 (opcode 0x50, but 0x50 is NOT 0x51-0x60) — wait, bad m catches this first
    # Let's use valid m=1, n=2 but m > n case: m=3, n=2
    script = bytes([0x53]) + push(pubkey1) + push(pubkey2) + bytes([0x52, 0xAE])
    with pytest.raises(UnsupportedScriptPathError, match="threshold"):
        parse_multisig_redeem_script(script)


# ── Extractor unsupported paths ─────────────────────────────────────────


def test_unsupported_non_segwit_script_path() -> None:
    # script_sig with OP_0 (empty push) — not P2PKH, not P2SH multisig
    prevout_hash = bytes.fromhex("11" * 32)
    script_sig = bytes([0x00])
    raw = bytearray()
    raw.extend((1).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend(prevout_hash)
    raw.extend((0).to_bytes(4, "little"))
    raw.extend(encode_varint(len(script_sig)))
    raw.extend(script_sig)
    raw.extend((0xFFFFFFFF).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend((0).to_bytes(8, "little"))
    raw.extend(encode_varint(0))
    raw.extend((0).to_bytes(4, "little"))
    transaction = Transaction.parse_hex(raw.hex())
    with pytest.raises(UnsupportedScriptPathError, match="non-SegWit"):
        transaction.extract()


def test_unsupported_segwit_script_path() -> None:
    prevout_hash = bytes.fromhex("11" * 32)
    signature = build_der_signature(bytes.fromhex("7f" * 32),
                                    bytes.fromhex("55" * 32), 0x01)
    raw = bytearray()
    raw.extend((1).to_bytes(4, "little"))
    raw.extend(b"\x00\x01")
    raw.extend(encode_varint(1))
    raw.extend(prevout_hash)
    raw.extend((0).to_bytes(4, "little"))
    raw.extend(encode_varint(0))
    raw.extend((0xFFFFFFFF).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend((1000).to_bytes(8, "little"))
    raw.extend(encode_varint(25))
    raw.extend(bytes.fromhex("76a914" + "44" * 20 + "88ac"))
    raw.extend(encode_varint(1))
    raw.extend(encode_varint(len(signature)))
    raw.extend(signature)
    raw.extend((0).to_bytes(4, "little"))
    transaction = Transaction.parse_hex(raw.hex()).with_input_values([1000])
    with pytest.raises(UnsupportedScriptPathError, match="SegWit"):
        transaction.extract()


def test_unsupported_general_script_path() -> None:
    prevout_hash = bytes.fromhex("11" * 32)
    raw = bytearray()
    raw.extend((1).to_bytes(4, "little"))
    raw.extend(b"\x00\x01")
    raw.extend(encode_varint(1))
    raw.extend(prevout_hash)
    raw.extend((0).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend(bytes([0x00]))
    raw.extend((0xFFFFFFFF).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend((1000).to_bytes(8, "little"))
    raw.extend(encode_varint(25))
    raw.extend(bytes.fromhex("76a914" + "44" * 20 + "88ac"))
    raw.extend(encode_varint(1))
    raw.extend(encode_varint(0))
    raw.extend((0).to_bytes(4, "little"))
    transaction = Transaction.parse_hex(raw.hex())
    with pytest.raises(UnsupportedScriptPathError,
                       match="Unsupported script path"):
        transaction.extract()


def test_p2sh_multisig_too_short() -> None:
    prevout_hash = bytes.fromhex("11" * 32)
    # Single push (not a redeem script) — fewer than 2 pushes
    script_sig = push(b"\x01")
    raw = bytearray()
    raw.extend((1).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend(prevout_hash)
    raw.extend((0).to_bytes(4, "little"))
    raw.extend(encode_varint(len(script_sig)))
    raw.extend(script_sig)
    raw.extend((0xFFFFFFFF).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend((0).to_bytes(8, "little"))
    raw.extend(encode_varint(0))
    raw.extend((0).to_bytes(4, "little"))
    transaction = Transaction.parse_hex(raw.hex())
    with pytest.raises(UnsupportedScriptPathError, match="too short"):
        transaction.extract()


def test_p2sh_p2wpkh_invalid_witness() -> None:
    prevout_hash = bytes.fromhex("44" * 32)
    redeem_script = bytes.fromhex(
        "001479091972186c449eb1ded22b78e40d009bdf0089")
    signature = build_der_signature(bytes.fromhex("7f" * 32),
                                    bytes.fromhex("55" * 32), 0x01)
    raw = bytearray()
    raw.extend((1).to_bytes(4, "little"))
    raw.extend(b"\x00\x01")
    raw.extend(encode_varint(1))
    raw.extend(prevout_hash)
    raw.extend((1).to_bytes(4, "little"))
    raw.extend(encode_varint(len(push(redeem_script))))
    raw.extend(push(redeem_script))
    raw.extend((0xFFFFFFFE).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend((1000).to_bytes(8, "little"))
    raw.extend(encode_varint(25))
    raw.extend(bytes.fromhex("76a914" + "55" * 20 + "88ac"))
    raw.extend(encode_varint(3))
    raw.extend(encode_varint(len(signature)))
    raw.extend(signature)
    raw.extend(encode_varint(0))
    raw.extend(encode_varint(1))
    raw.extend(bytes([1]))
    raw.extend((0).to_bytes(4, "little"))
    transaction = Transaction.parse_hex(raw.hex()).with_input_values([1000])
    with pytest.raises(UnsupportedScriptPathError, match="P2SH-P2WPKH"):
        transaction.extract()


def test_script_parse_too_short() -> None:
    with pytest.raises(UnsupportedScriptPathError, match="too short"):
        parse_multisig_redeem_script(bytes([0x51]))


# ── CLI edge cases ──────────────────────────────────────────────────────


def test_cli_parse_bad_hex(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli_main(["parse", "--tx", "zz"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "non-hex characters" in captured.err


def test_cli_unknown_command_exits_two(
        capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli_main(["unknown"])
    assert exit_code == 2


# ── ByteReader tests ────────────────────────────────────────────────────


def test_bytereader_negative_length() -> None:
    from bitcoin.utils import ByteReader

    reader = ByteReader(b"")
    with pytest.raises(ValueError, match="non-negative"):
        reader.read(-1)


def test_bytereader_uint8() -> None:
    from bitcoin.utils import ByteReader

    reader = ByteReader(b"\x2a\xff")
    assert reader.read_uint8() == 0x2A
    assert reader.read_uint8() == 0xFF


def test_bytereader_uint16() -> None:
    from bitcoin.utils import ByteReader

    reader = ByteReader(b"\x01\x02")
    assert reader.read_uint16() == 0x0201  # little-endian


def test_bytereader_uint32() -> None:
    from bitcoin.utils import ByteReader

    reader = ByteReader(b"\xef\xcd\xab\x89")
    assert reader.read_uint32() == 0x89ABCDEF  # little-endian


def test_bytereader_uint64() -> None:
    from bitcoin.utils import ByteReader

    reader = ByteReader(b"\x08\x07\x06\x05\x04\x03\x02\x01")
    assert reader.read_uint64() == 0x0102030405060708  # little-endian


def test_bytereader_varint_fd() -> None:
    from bitcoin.utils import ByteReader

    # 0x100 >= 0xFD, minimal for 2-byte prefix
    data = b"\xfd\x00\x01"
    reader = ByteReader(data)
    assert reader.read_varint() == 0x100


def test_bytereader_varint_fe() -> None:
    from bitcoin.utils import ByteReader

    # 0x10000 >= 0x10000, minimal for 4-byte prefix
    data = b"\xfe\x00\x00\x01\x00"
    reader = ByteReader(data)
    assert reader.read_varint() == 65536


def test_bytereader_varint_ff() -> None:
    from bitcoin.utils import ByteReader

    data = b"\xff" + (0x100000000).to_bytes(8, "little")
    reader = ByteReader(data)
    assert reader.read_varint() == 0x100000000


def test_bytereader_varint_non_minimal_fd() -> None:
    from bitcoin.exceptions import MalformedVarintError
    from bitcoin.utils import ByteReader

    # 0x0001 = 1 < 0xFD, should use 1-byte prefix
    data = b"\xfd\x01\x00"
    reader = ByteReader(data)
    with pytest.raises(MalformedVarintError, match="Non-minimal"):
        reader.read_varint()


def test_bytereader_varint_non_minimal_fe() -> None:
    from bitcoin.utils import ByteReader

    # 0x100 <= 0xFFFF, should use 0xFD prefix, not 0xFE
    data = b"\xfe\x00\x01\x00\x00"
    reader = ByteReader(data)
    with pytest.raises(MalformedVarintError, match="Non-minimal"):
        reader.read_varint()


def test_bytereader_varint_non_minimal_ff() -> None:
    from bitcoin.exceptions import MalformedVarintError
    from bitcoin.utils import ByteReader

    # 0x10000 <= 0xFFFFFFFF, should use 0xFE prefix, not 0xFF
    data = b"\xff" + (0x10000).to_bytes(8, "little")
    reader = ByteReader(data)
    with pytest.raises(MalformedVarintError, match="Non-minimal"):
        reader.read_varint()


# ── int_to_hex and int_to_little_endian_bytes ────────────────────────────


def test_int_to_hex_zero() -> None:
    from bitcoin.utils import int_to_hex

    assert int_to_hex(0) == "0"


def test_int_to_hex_negative() -> None:
    from bitcoin.utils import int_to_hex

    with pytest.raises(ValueError, match="non-negative"):
        int_to_hex(-1)


def test_int_to_little_endian_bytes_negative() -> None:
    from bitcoin.utils import int_to_little_endian_bytes

    with pytest.raises(ValueError, match="non-negative"):
        int_to_little_endian_bytes(-1, 4)


def test_validate_hex_string_non_hex_chars() -> None:
    from bitcoin.utils import validate_hex_string

    with pytest.raises(InvalidHexError, match="non-hex"):
        validate_hex_string("0x0100")


# ── Serializer infinity path ────────────────────────────────────────────


def test_serializer_point_relation_collection_to_dict() -> None:
    from bitcoin.ecc import (
        SECP256K1_ORDER,
        G,
        LinearPointRelationCollection,
        derive_point_relation,
        scalar_multiply,
    )
    from bitcoin.models import SignatureRecord
    from bitcoin.serializer import point_relation_collection_to_dict

    d = 19
    k = 29
    r = 7
    s = 11
    z = (s * k - d * r) % SECP256K1_ORDER

    def _hex(val: int) -> str:
        return val.to_bytes(max(1, (val.bit_length() + 7) // 8), "big").hex()

    sig_record = SignatureRecord(
        r=_hex(r),
        s=_hex(s),
        z=_hex(z),
        sighash_flag=1,
        input_index=0,
        public_key=None,
        script_type="legacy-p2pkh",
    )
    pk = scalar_multiply(d, G)
    rel = derive_point_relation(sig_record, pk)
    coll = LinearPointRelationCollection(records=(rel,))
    result = point_relation_collection_to_dict(coll)
    assert isinstance(result, dict)
    records = result.get("records", [])
    assert isinstance(records, list)
    first = records[0]
    assert isinstance(first, dict)
    assert first.get("equation") == "D + \u03b2G = \u03b1K"


# ── Signature module edge cases ──────────────────────────────────────────


def test_signature_collection_linear_empty() -> None:
    raw_hex, _, _ = build_p2pkh_transaction()
    tx = Transaction.parse_hex(raw_hex)
    linear = tx.extract().linear()
    assert linear.alpha == [linear.records[0].alpha]
    assert linear.beta == [linear.records[0].beta]


# ── P2SH-P2WSH multisig extraction path ──────────────────────────────────


def test_sighash_flag_bad_bits_rejected() -> None:
    sig = build_der_signature(bytes.fromhex("7f" * 32),
                              bytes.fromhex("55" * 32), 0x84)
    prevout_hash = bytes.fromhex("11" * 32)
    pubkey = bytes.fromhex(
        "02c0ded4b6f919c7d4317a7ce0d2db2aab7b4d79b0f1b9ab2d5b8e86e7b0d1c6c5")
    script_sig = push(sig) + push(pubkey)
    raw = bytearray()
    raw.extend((2).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend(prevout_hash)
    raw.extend((1).to_bytes(4, "little"))
    raw.extend(encode_varint(len(script_sig)))
    raw.extend(script_sig)
    raw.extend((0xFFFFFFFE).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend((12345).to_bytes(8, "little"))
    raw.extend(encode_varint(25))
    raw.extend(bytes.fromhex("76a914" + "22" * 20 + "88ac"))
    raw.extend((0).to_bytes(4, "little"))
    transaction = Transaction.parse_hex(raw.hex())
    with pytest.raises(InvalidSighashFlagError):
        transaction.extract()


# ── resolve_input_value out-of-bounds ────────────────────────────────────


def test_resolve_input_value_out_of_bounds() -> None:
    from bitcoin.extractor import resolve_input_value
    from bitcoin.models import TransactionContext

    ctx = TransactionContext(input_values=(100, 200))
    with pytest.raises(MissingInputValueError):
        resolve_input_value(ctx, 5)


# ── validate_hex_string edge cases ──────────────────────────────────────


def test_validate_hex_string_empty() -> None:
    from bitcoin.utils import validate_hex_string

    with pytest.raises(InvalidHexError):
        validate_hex_string("")


def test_validate_hex_string_whitespace() -> None:
    from bitcoin.utils import validate_hex_string

    with pytest.raises(InvalidHexError):
        validate_hex_string("  ")


# ── P2SH-P2WSH multisig extraction path ──────────────────────────────────


def build_p2sh_p2wsh_multisig_transaction() -> tuple[str, list[int]]:
    prevout_hash = bytes.fromhex("66" * 32)
    pubkey1 = bytes.fromhex(
        "0307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3")
    pubkey2 = bytes.fromhex(
        "03b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b")
    witness_script = b"\x52" + push(pubkey1) + push(pubkey2) + b"\x52\xae"
    redeem_script = bytes.fromhex("0020" + "55" * 32)
    signature1 = build_der_signature(bytes.fromhex("11" * 32),
                                     bytes.fromhex("22" * 32), 0x01)
    signature2 = build_der_signature(bytes.fromhex("33" * 32),
                                     bytes.fromhex("44" * 32), 0x03)
    raw = bytearray()
    raw.extend((1).to_bytes(4, "little"))
    raw.extend(b"\x00\x01")
    raw.extend(encode_varint(1))
    raw.extend(prevout_hash)
    raw.extend((0).to_bytes(4, "little"))
    raw.extend(encode_varint(len(push(redeem_script))))
    raw.extend(push(redeem_script))
    raw.extend((0xFFFFFFFF).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend((100000).to_bytes(8, "little"))
    raw.extend(encode_varint(25))
    raw.extend(bytes.fromhex("76a914" + "77" * 20 + "88ac"))
    raw.extend(encode_varint(4))
    raw.extend(encode_varint(0))
    raw.extend(encode_varint(len(signature1)))
    raw.extend(signature1)
    raw.extend(encode_varint(len(signature2)))
    raw.extend(signature2)
    raw.extend(encode_varint(len(witness_script)))
    raw.extend(witness_script)
    raw.extend((0).to_bytes(4, "little"))
    return raw.hex(), [100000]


def test_parse_p2sh_p2wsh_multisig_transaction() -> None:
    raw_hex, values = build_p2sh_p2wsh_multisig_transaction()
    transaction = Transaction.parse_hex(raw_hex).with_input_values(values)
    collection = transaction.extract()
    assert len(collection.signatures) == 2
    assert collection.signatures[0].script_type == "segwit-v0-p2sh-p2wsh"
    assert collection.signatures[0].sighash_flag == 0x01
    assert collection.signatures[1].sighash_flag == 0x03


# ── Final edge-case coverage ────────────────────────────────────────────


def test_der_r_tag_missing() -> None:
    body = bytes([0x99, 1, 0x01, 0x02, 1, 0x01])
    der = bytes([0x30, len(body)]) + body
    sig = der + b"\x01"
    with pytest.raises(InvalidDerSignatureError, match="R integer tag"):
        parse_der_signature(sig)


def test_p2sh_p2wsh_short_witness() -> None:
    prevout_hash = bytes.fromhex("66" * 32)
    redeem_script = bytes.fromhex("0020" + "55" * 32)
    raw = bytearray()
    raw.extend((1).to_bytes(4, "little"))
    raw.extend(b"\x00\x01")
    raw.extend(encode_varint(1))
    raw.extend(prevout_hash)
    raw.extend((0).to_bytes(4, "little"))
    raw.extend(encode_varint(len(push(redeem_script))))
    raw.extend(push(redeem_script))
    raw.extend((0xFFFFFFFF).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend((100000).to_bytes(8, "little"))
    raw.extend(encode_varint(25))
    raw.extend(bytes.fromhex("76a914" + "77" * 20 + "88ac"))
    raw.extend(encode_varint(1))
    raw.extend(encode_varint(0))
    raw.extend((0).to_bytes(4, "little"))
    transaction = Transaction.parse_hex(raw.hex()).with_input_values([100000])
    with pytest.raises(UnsupportedScriptPathError, match="P2SH-P2WSH"):
        transaction.extract()


def test_with_input_values_count_mismatch() -> None:
    raw_hex, _, _ = build_p2pkh_transaction()
    tx = Transaction.parse_hex(raw_hex)
    with pytest.raises(ValueError, match="count must match"):
        tx.with_input_values([1, 2])


def test_linear_points_rejects_missing_pubkey() -> None:
    from bitcoin.models import SignatureRecord

    record = SignatureRecord(
        r="01",
        s="01",
        z="01",
        sighash_flag=1,
        input_index=0,
        public_key=None,
        script_type="legacy-p2pkh",
    )
    from bitcoin.signature import SignatureCollection

    coll = SignatureCollection(records=(record,))
    with pytest.raises(InvalidSecPublicKeyError, match="requires a public key"):
        coll.linear_points()


def test_linear_points_rejects_invalid_pubkey_hex() -> None:
    from bitcoin.models import SignatureRecord

    record = SignatureRecord(
        r="01",
        s="01",
        z="01",
        sighash_flag=1,
        input_index=0,
        public_key="zz",
        script_type="legacy-p2pkh",
    )
    from bitcoin.signature import SignatureCollection

    coll = SignatureCollection(records=(record,))
    with pytest.raises(InvalidSecPublicKeyError, match="not valid hex"):
        coll.linear_points()


def test_sighash_legacy_none_multi_input() -> None:
    from bitcoin.sighash import legacy_sighash

    raw_hex, _, _ = build_p2pkh_transaction()
    tx = Transaction.parse_hex(raw_hex)
    import dataclasses

    with_inputs = list(tx.inputs)
    with_inputs.append(dataclasses.replace(with_inputs[0], sequence=0xFFFFFFFE))
    tx_multi = dataclasses.replace(tx, inputs=tuple(with_inputs))
    script_code = bytes.fromhex("76a914" + "22" * 20 + "88ac")
    digest = legacy_sighash(tx_multi, 0, script_code, 0x02)
    assert isinstance(digest, bytes) and len(digest) == 32


def test_sighash_legacy_single_multi_input() -> None:
    from bitcoin.sighash import legacy_sighash

    prevout_hash = bytes(32)
    script_code = bytes.fromhex("76a914" + "22" * 20 + "88ac")
    output_script = bytes.fromhex("76a914" + "33" * 20 + "88ac")
    raw = bytearray()
    raw.extend((1).to_bytes(4, "little"))
    raw.extend(encode_varint(2))
    for _ in range(2):
        raw.extend(prevout_hash)
        raw.extend((0).to_bytes(4, "little"))
        raw.extend(encode_varint(0))
        raw.extend((0xFFFFFFFE).to_bytes(4, "little"))
    raw.extend(encode_varint(2))
    for _ in range(2):
        raw.extend((1000).to_bytes(8, "little"))
        raw.extend(encode_varint(len(output_script)))
        raw.extend(output_script)
    raw.extend((0).to_bytes(4, "little"))
    tx = Transaction.parse_hex(raw.hex())
    digest = legacy_sighash(tx, 1, script_code, 0x03)
    assert isinstance(digest, bytes) and len(digest) == 32


def test_sighash_segwit_anyonecanpay() -> None:
    from bitcoin.sighash import segwit_sighash

    raw_hex, _, _ = build_p2pkh_transaction()
    tx = Transaction.parse_hex(raw_hex)
    script_code = bytes.fromhex("76a914" + "22" * 20 + "88ac")
    digest = segwit_sighash(tx, 0, script_code, 50000, 0x81)
    assert isinstance(digest, bytes) and len(digest) == 32


def test_serialize_varint_large_values() -> None:
    from bitcoin.sighash import serialize_varint
    from bitcoin.utils import little_endian_bytes_to_int

    result = serialize_varint(0x10000)
    assert result[0] == 0xFE
    assert little_endian_bytes_to_int(result[1:5]) == 0x10000

    result = serialize_varint(0x100000000)
    assert result[0] == 0xFF
    assert little_endian_bytes_to_int(result[1:9]) == 0x100000000


def test_serialize_varint_0xFD() -> None:
    from bitcoin.sighash import serialize_varint
    from bitcoin.utils import little_endian_bytes_to_int

    result = serialize_varint(0x100)
    assert result[0] == 0xFD
    assert little_endian_bytes_to_int(result[1:3]) == 0x100


# ── Point double with y=0 (tangent vertical → infinity) ─────────────────


def test_point_double_y_zero() -> None:
    from bitcoin.ecc import (
        SECP256K1_INFINITY,
        Secp256k1Point,
        point_double,
    )

    pt = object.__new__(Secp256k1Point)
    pt.x = 0
    pt.y = 0
    pt.infinity = False
    result = point_double(pt)
    assert result == SECP256K1_INFINITY


# ── CLI edge cases ──────────────────────────────────────────────────────


def test_cli_points_non_compact() -> None:
    raw_hex, _ = build_p2sh_multisig_transaction()
    rc = cli_main(["points", "--tx", raw_hex])
    assert rc == 0


def test_cli_parse_bad_hex_returns_one() -> None:
    rc = cli_main(["parse", "--tx", "nothex"])
    assert rc == 1


def test_cli_parse_invalid_tx_returns_one() -> None:
    rc = cli_main(["parse", "--tx", "aabb"])
    assert rc == 1


def test_cli_extract_bad_sighash_returns_one() -> None:
    sig = build_der_signature(bytes.fromhex("7f" * 32),
                              bytes.fromhex("55" * 32), 0x84)
    prevout_hash = bytes.fromhex("11" * 32)
    script_sig = push(sig) + push(
        bytes.fromhex(
            "02c0ded4b6f919c7d4317a7ce0d2db2aab7b4d79b0f1b9ab2d5b8e86e7b0d1c6c5"
        ))
    raw = bytearray()
    raw.extend((2).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend(prevout_hash)
    raw.extend((1).to_bytes(4, "little"))
    raw.extend(encode_varint(len(script_sig)))
    raw.extend(script_sig)
    raw.extend((0xFFFFFFFE).to_bytes(4, "little"))
    raw.extend(encode_varint(1))
    raw.extend((12345).to_bytes(8, "little"))
    raw.extend(encode_varint(25))
    raw.extend(bytes.fromhex("76a914" + "22" * 20 + "88ac"))
    raw.extend((0).to_bytes(4, "little"))
    rc = cli_main(["extract", "--tx", raw.hex()])
    assert rc == 1


def test_cli_generic_exception_handler() -> None:
    from unittest.mock import patch

    def broken(*args: object, **kwargs: object) -> object:
        raise RuntimeError("unexpected error")

    with patch("bitcoin.cli.parse", broken):
        rc = cli_main(["parse", "--tx", "aa"])
        assert rc == 1


# ── serializer._hex branches ────────────────────────────────────────────


def test_hex_non_none() -> None:
    from bitcoin.serializer import to_hex

    result = to_hex(42)
    assert result is not None


def test_hex_none() -> None:
    from bitcoin.serializer import to_hex

    result = to_hex(None)
    assert result is None


# ── hash160 branches ────────────────────────────────────────────────────

# ── transform_points ───────────────────────────────────────────────────


def test_transform_points_p2pkh() -> None:
    raw_hex, _, _ = build_p2pkh_transaction()
    tx = Transaction.parse_hex(raw_hex)
    collection = tx.extract().transform_points()
    assert len(collection.records) == 1
    record = collection.records[0]
    assert record.input_index == 0
    assert 0 <= record.alpha < SECP256K1_ORDER
    assert 0 <= record.beta < SECP256K1_ORDER
    assert not record.new_d_point.infinity
    assert is_on_curve(record.new_d_point.x, record.new_d_point.y)


def test_transform_points_p2sh_multisig() -> None:
    raw_hex, _ = build_p2sh_multisig_transaction()
    tx = Transaction.parse_hex(raw_hex)
    collection = tx.extract().transform_points()
    assert len(collection.records) == 2
    for record in collection.records:
        assert is_on_curve(record.new_d_point.x, record.new_d_point.y)


def test_transform_points_p2wpkh() -> None:
    raw_hex, amount, _, _ = build_p2wpkh_transaction()
    tx = Transaction.parse_hex(raw_hex).with_input_values([amount])
    collection = tx.extract().transform_points()
    assert len(collection.records) == 1
    assert is_on_curve(collection.records[0].new_d_point.x,
                       collection.records[0].new_d_point.y)


def test_transform_points_p2sh_p2wpkh() -> None:
    raw_hex, amount, _, _ = build_p2sh_p2wpkh_transaction()
    tx = Transaction.parse_hex(raw_hex).with_input_values([amount])
    collection = tx.extract().transform_points()
    assert len(collection.records) == 1
    assert is_on_curve(collection.records[0].new_d_point.x,
                       collection.records[0].new_d_point.y)


def test_transform_points_p2wsh_multisig() -> None:
    raw_hex, amounts = build_p2wsh_multisig_transaction()
    tx = Transaction.parse_hex(raw_hex).with_input_values(amounts)
    collection = tx.extract().transform_points()
    assert len(collection.records) == 2
    for record in collection.records:
        assert is_on_curve(record.new_d_point.x, record.new_d_point.y)


def test_transform_points_cli_json() -> None:
    from bitcoin.serializer import transformed_point_collection_to_dict

    raw_hex, _, _ = build_p2pkh_transaction()
    tx = Transaction.parse_hex(raw_hex)
    transformed = tx.extract().transform_points()
    result = transformed_point_collection_to_dict(transformed)
    assert len(result) == 1
    entry = result[0]
    assert entry["curve"] == "secp256k1"
    assert entry["new_d_point"]["on_curve"] is True
    assert entry["new_d_point"]["encoding"] == "affine"
    assert entry["new_d_point"]["x"] is not None
    assert entry["new_d_point"]["y"] is not None
    assert entry["validation"]["point_on_curve"] is True
    assert entry["equations"]["scalar"] == "d' ≡ αk (mod n)"
    assert entry["equations"]["point"] == "D' = d'G"


def test_transform_via_cli() -> None:
    raw_hex, _, _ = build_p2pkh_transaction()
    exit_code = cli_main(["transform", "--tx", raw_hex])
    assert exit_code == 0


def test_transform_points_rejects_missing_pubkey() -> None:
    from bitcoin.models import SignatureRecord

    record = SignatureRecord(
        r="7f" * 32,
        s="55" * 32,
        z="aa" * 32,
        sighash_flag=0x01,
        input_index=0,
        public_key=None,
        script_type="legacy-p2pkh",
    )
    collection = SignatureCollection(records=(record,))
    with pytest.raises(InvalidSecPublicKeyError, match="requires a public key"):
        collection.transform_points()


def test_hash160_normal() -> None:
    from bitcoin.utils import hash160

    result = hash160(b"test")
    assert isinstance(result, bytes) and len(result) == 20


def test_hash160_missing_ripemd160() -> None:
    from unittest.mock import patch

    with patch("bitcoin.utils.hashlib.new") as mock_new:
        mock_new.side_effect = ValueError("RIPEMD160 not available")
        from bitcoin.utils import hash160

        with pytest.raises(RuntimeError, match="RIPEMD160 is not available"):
            hash160(b"test")
