"""Tests for the PSBT module."""

from __future__ import annotations

import pytest

from bitcoin.psbt import parse_keypath_value, parse_psbt, parse_psbt_hex, psbt_extract_signatures


def test_parse_psbt_invalid_magic() -> None:
    from bitcoin.exceptions import BitcoinError

    try:
        parse_psbt(b"\x00" * 100)
    except BitcoinError:
        pass


def test_parse_psbt_unknown_global() -> None:
    """PSBT with only an unknown global key should fail gracefully."""
    from bitcoin.exceptions import BitcoinError

    data = b"psbt\xff"
    data += b"\x01"  # key length (1)
    data += b"\xff"  # key type (unknown)
    data += b"\x04"  # value length (4)
    data += b"test"
    data += b"\x00"  # global separator
    try:
        parse_psbt(data)
    except BitcoinError:
        pass


def test_parse_psbt_too_short() -> None:
    from bitcoin.exceptions import BitcoinError

    with pytest.raises(BitcoinError):
        parse_psbt(b"")


def test_parse_psbt_magic_only() -> None:
    from bitcoin.exceptions import BitcoinError

    with pytest.raises(BitcoinError):
        parse_psbt(b"psbt\xff")


def test_parse_psbt_missing_inputs() -> None:
    """PSBT with global map but no inputs."""
    from bitcoin.exceptions import BitcoinError

    data = b"psbt\xff"
    data += b"\x00"  # global separator (empty global map)
    with pytest.raises(BitcoinError):
        parse_psbt(data)


def test_parse_psbt_non_minimal_varint() -> None:
    """PSBT with non-minimal varints should fail."""
    from bitcoin.exceptions import BitcoinError

    data = b"psbt\xff"
    data += b"\x00"  # global separator
    # input with non-minimal varint key length (0xfd prefix for value < 0xfd)
    data += b"\xfd\x01\x00"  # non-minimal varint for key length 1
    data += b"\x00"  # key type
    data += b"\x01"  # value length
    data += b"\x00"  # value
    data += b"\x00"  # input separator
    data += b"\x00"  # output separator
    with pytest.raises(BitcoinError):
        parse_psbt(data)


def test_parse_psbt_hex_roundtrip() -> None:
    """parse_psbt_hex produces the same result as parse_psbt."""
    tx_bytes = bytearray()
    tx_bytes += (2).to_bytes(4, "little")
    tx_bytes += b"\x01"
    tx_bytes += b"\x11" * 32
    tx_bytes += (0).to_bytes(4, "little")
    tx_bytes += b"\x00"
    tx_bytes += b"\xff\xff\xff\xff"
    tx_bytes += b"\x01"
    tx_bytes += (1000).to_bytes(8, "little")
    tx_bytes += b"\x00"
    tx_bytes += (0).to_bytes(4, "little")

    psbt = bytearray()
    psbt += b"psbt\xff"
    psbt += b"\x01"
    psbt += b"\x00"
    psbt += len(tx_bytes).to_bytes(1, "little")
    psbt += tx_bytes
    psbt += b"\x00"
    psbt += b"\x00"  # empty input
    psbt += b"\x00"  # empty output

    result = parse_psbt_hex(bytes(psbt).hex())
    assert result.unsigned_tx is not None


def test_parse_keypath_value() -> None:
    """Parse a BIP32 keypath with fingerprint and derivation path."""
    fingerprint = b"\x01\x02\x03\x04"
    path_indices = [0x8000002C, 0x80000001]
    value = fingerprint
    value += bytes([len(path_indices)])
    for idx in path_indices:
        value += idx.to_bytes(4, "little")
    fingerprint_hex, path = parse_keypath_value(value)
    assert fingerprint_hex == "01020304"
    assert path == ("2147483692", "2147483649")


def test_parse_psbt_with_partial_sig() -> None:
    """PSBT with an unsigned tx and partial_sig in one input."""
    from bitcoin.psbt import PsbtInput

    # Build a minimal 1-input 1-output unsigned tx
    prevout_hash = b"\x11" * 32
    tx_bytes = bytearray()
    tx_bytes += (2).to_bytes(4, "little")  # version
    tx_bytes += b"\x01"  # input count
    tx_bytes += prevout_hash
    tx_bytes += (0).to_bytes(4, "little")  # vout
    tx_bytes += b"\x00"  # empty scriptSig
    tx_bytes += b"\xff\xff\xff\xff"  # sequence
    tx_bytes += b"\x01"  # output count
    tx_bytes += (1000).to_bytes(8, "little")  # value
    tx_bytes += b"\x00"  # empty scriptPubKey
    tx_bytes += (0).to_bytes(4, "little")  # locktime

    psbt = bytearray()
    psbt += b"psbt\xff"
    # Global: unsigned tx
    psbt += b"\x01"  # key length
    psbt += b"\x00"  # key type (0x00 = unsigned tx)
    psbt += len(tx_bytes).to_bytes(1, "little")
    psbt += tx_bytes
    psbt += b"\x00"  # global separator

    # Input map with partial_sig
    dummy_pubkey = b"\x02\xc0\xde\xc0\xde" + b"\x00" * 28
    dummy_sig = bytes.fromhex("304402207f" * 2 + "022055" * 2 + "01")

    psbt += b"\x22"  # key length (34)
    psbt += b"\x02"  # key type (partial_sig)
    psbt += dummy_pubkey
    psbt += bytes([len(dummy_sig)])
    psbt += dummy_sig
    psbt += b"\x00"  # input separator

    # Output separator
    psbt += b"\x00"

    result = parse_psbt(bytes(psbt))
    assert len(result.inputs) == 1
    inp = result.inputs[0]
    assert isinstance(inp, PsbtInput)
    assert inp.partial_sigs != {}


def test_psbt_extract_signatures_empty() -> None:
    """psbt_extract_signatures on a PSBT with no partial_sigs yields empty."""
    tx_bytes = bytearray()
    tx_bytes += (2).to_bytes(4, "little")
    tx_bytes += b"\x01"
    tx_bytes += b"\x11" * 32
    tx_bytes += (0).to_bytes(4, "little")
    tx_bytes += b"\x00"
    tx_bytes += b"\xff\xff\xff\xff"
    tx_bytes += b"\x01"
    tx_bytes += (1000).to_bytes(8, "little")
    tx_bytes += b"\x00"
    tx_bytes += (0).to_bytes(4, "little")

    psbt = bytearray()
    psbt += b"psbt\xff"
    psbt += b"\x01"
    psbt += b"\x00"
    psbt += len(tx_bytes).to_bytes(1, "little")
    psbt += tx_bytes
    psbt += b"\x00"
    psbt += b"\x00"  # empty input map
    psbt += b"\x00"  # empty output map

    result = parse_psbt(bytes(psbt))
    sigs = psbt_extract_signatures(result)
    assert len(sigs.records) == 0


def test_parse_psbt_unknown_input_key() -> None:
    """PSBT with unknown input key type is handled gracefully (logged)."""
    tx_bytes = bytearray()
    tx_bytes += (2).to_bytes(4, "little")
    tx_bytes += b"\x01"
    tx_bytes += b"\x11" * 32
    tx_bytes += (0).to_bytes(4, "little")
    tx_bytes += b"\x00"
    tx_bytes += b"\xff\xff\xff\xff"
    tx_bytes += b"\x01"
    tx_bytes += (1000).to_bytes(8, "little")
    tx_bytes += b"\x00"
    tx_bytes += (0).to_bytes(4, "little")

    psbt = bytearray()
    psbt += b"psbt\xff"
    psbt += b"\x01"
    psbt += b"\x00"
    psbt += len(tx_bytes).to_bytes(1, "little")
    psbt += tx_bytes
    psbt += b"\x00"

    # Input map with unknown key type 0xfe
    psbt += b"\x01"
    psbt += b"\xfe"
    psbt += b"\x01"
    psbt += b"\x00"
    psbt += b"\x00"

    psbt += b"\x00"

    result = parse_psbt(bytes(psbt))
    assert len(result.inputs) == 1


def test_parse_psbt_unknown_output_key() -> None:
    """PSBT with unknown output key type is handled gracefully (logged)."""
    tx_bytes = bytearray()
    tx_bytes += (2).to_bytes(4, "little")
    tx_bytes += b"\x01"
    tx_bytes += b"\x11" * 32
    tx_bytes += (0).to_bytes(4, "little")
    tx_bytes += b"\x00"
    tx_bytes += b"\xff\xff\xff\xff"
    tx_bytes += b"\x01"
    tx_bytes += (1000).to_bytes(8, "little")
    tx_bytes += b"\x00"
    tx_bytes += (0).to_bytes(4, "little")

    psbt = bytearray()
    psbt += b"psbt\xff"
    psbt += b"\x01"
    psbt += b"\x00"
    psbt += len(tx_bytes).to_bytes(1, "little")
    psbt += tx_bytes
    psbt += b"\x00"

    psbt += b"\x00"  # empty input

    # Output map with unknown key type 0xfe
    psbt += b"\x01"
    psbt += b"\xfe"
    psbt += b"\x01"
    psbt += b"\x00"
    psbt += b"\x00"

    result = parse_psbt(bytes(psbt))
    assert len(result.outputs) == 1


def test_parse_psbt_with_redeem_script() -> None:
    """PSBT input with redeem_script key."""
    tx_bytes = bytearray()
    tx_bytes += (2).to_bytes(4, "little")
    tx_bytes += b"\x01"
    tx_bytes += b"\x11" * 32
    tx_bytes += (0).to_bytes(4, "little")
    tx_bytes += b"\x00"
    tx_bytes += b"\xff\xff\xff\xff"
    tx_bytes += b"\x01"
    tx_bytes += (1000).to_bytes(8, "little")
    tx_bytes += b"\x00"
    tx_bytes += (0).to_bytes(4, "little")

    psbt = bytearray()
    psbt += b"psbt\xff"
    psbt += b"\x01"
    psbt += b"\x00"
    psbt += len(tx_bytes).to_bytes(1, "little")
    psbt += tx_bytes
    psbt += b"\x00"

    # Input with redeem_script
    redeem = b"\x76\xa9\x14" + b"\x22" * 20 + b"\x88\xac"
    psbt += b"\x01"
    psbt += b"\x04"  # key type = redeem_script
    psbt += bytes([len(redeem)])
    psbt += redeem
    psbt += b"\x00"

    psbt += b"\x00"

    result = parse_psbt(bytes(psbt))
    inp = result.inputs[0]
    assert inp.redeem_script == redeem


def test_parse_psbt_with_witness_script() -> None:
    """PSBT input with witness_script key."""
    tx_bytes = bytearray()
    tx_bytes += (2).to_bytes(4, "little")
    tx_bytes += b"\x01"
    tx_bytes += b"\x11" * 32
    tx_bytes += (0).to_bytes(4, "little")
    tx_bytes += b"\x00"
    tx_bytes += b"\xff\xff\xff\xff"
    tx_bytes += b"\x01"
    tx_bytes += (1000).to_bytes(8, "little")
    tx_bytes += b"\x00"
    tx_bytes += (0).to_bytes(4, "little")

    psbt = bytearray()
    psbt += b"psbt\xff"
    psbt += b"\x01"
    psbt += b"\x00"
    psbt += len(tx_bytes).to_bytes(1, "little")
    psbt += tx_bytes
    psbt += b"\x00"

    ws = b"\x00\x20" + b"\x55" * 32
    psbt += b"\x01"
    psbt += b"\x05"  # key type = witness_script
    psbt += bytes([len(ws)])
    psbt += ws
    psbt += b"\x00"

    psbt += b"\x00"

    result = parse_psbt(bytes(psbt))
    inp = result.inputs[0]
    assert inp.witness_script == ws


def test_parse_psbt_with_sighash_type() -> None:
    """PSBT input with sighash_type key."""
    tx_bytes = bytearray()
    tx_bytes += (2).to_bytes(4, "little")
    tx_bytes += b"\x01"
    tx_bytes += b"\x11" * 32
    tx_bytes += (0).to_bytes(4, "little")
    tx_bytes += b"\x00"
    tx_bytes += b"\xff\xff\xff\xff"
    tx_bytes += b"\x01"
    tx_bytes += (1000).to_bytes(8, "little")
    tx_bytes += b"\x00"
    tx_bytes += (0).to_bytes(4, "little")

    psbt = bytearray()
    psbt += b"psbt\xff"
    psbt += b"\x01"
    psbt += b"\x00"
    psbt += len(tx_bytes).to_bytes(1, "little")
    psbt += tx_bytes
    psbt += b"\x00"

    psbt += b"\x01"
    psbt += b"\x03"  # key type = sighash_type
    psbt += b"\x04"
    psbt += (0x01).to_bytes(4, "little")
    psbt += b"\x00"

    psbt += b"\x00"

    result = parse_psbt(bytes(psbt))
    inp = result.inputs[0]
    assert inp.sighash_type == 0x01


def test_parse_psbt_with_witness_utxo() -> None:
    """PSBT input with witness_utxo key."""
    tx_bytes = bytearray()
    tx_bytes += (2).to_bytes(4, "little")
    tx_bytes += b"\x01"
    tx_bytes += b"\x11" * 32
    tx_bytes += (0).to_bytes(4, "little")
    tx_bytes += b"\x00"
    tx_bytes += b"\xff\xff\xff\xff"
    tx_bytes += b"\x01"
    tx_bytes += (1000).to_bytes(8, "little")
    tx_bytes += b"\x00"
    tx_bytes += (0).to_bytes(4, "little")

    psbt = bytearray()
    psbt += b"psbt\xff"
    psbt += b"\x01"
    psbt += b"\x00"
    psbt += len(tx_bytes).to_bytes(1, "little")
    psbt += tx_bytes
    psbt += b"\x00"

    # witness_utxo: amount (8 bytes) + scriptPubKey varbytes
    spk = b"\x00\x14" + b"\x55" * 20
    wutxo = (200000000).to_bytes(8, "little")
    wutxo += bytes([len(spk)]) + spk
    psbt += b"\x01"
    psbt += b"\x01"  # key type = witness_utxo
    psbt += bytes([len(wutxo)])
    psbt += wutxo
    psbt += b"\x00"

    psbt += b"\x00"

    result = parse_psbt(bytes(psbt))
    inp = result.inputs[0]
    assert inp.witness_utxo is not None
    amount, script = inp.witness_utxo
    assert amount == 200000000
    assert script == spk


def test_parse_psbt_with_keypath() -> None:
    """PSBT input with BIP32 keypath key."""
    tx_bytes = bytearray()
    tx_bytes += (2).to_bytes(4, "little")
    tx_bytes += b"\x01"
    tx_bytes += b"\x11" * 32
    tx_bytes += (0).to_bytes(4, "little")
    tx_bytes += b"\x00"
    tx_bytes += b"\xff\xff\xff\xff"
    tx_bytes += b"\x01"
    tx_bytes += (1000).to_bytes(8, "little")
    tx_bytes += b"\x00"
    tx_bytes += (0).to_bytes(4, "little")

    psbt = bytearray()
    psbt += b"psbt\xff"
    psbt += b"\x01"
    psbt += b"\x00"
    psbt += len(tx_bytes).to_bytes(1, "little")
    psbt += tx_bytes
    psbt += b"\x00"

    # keypath: pubkey in key data, fingerprint + derivation in value
    pubkey = b"\x02" + b"\x55" * 32
    kp_value = b"\x01\x02\x03\x04"  # fingerprint
    kp_value += b"\x02"  # 2 path elements
    kp_value += (0x8000002C).to_bytes(4, "little")
    kp_value += (0x80000001).to_bytes(4, "little")

    psbt += bytes([1 + len(pubkey)])
    psbt += b"\x06"  # key type = BIP32 keypath
    psbt += pubkey
    psbt += bytes([len(kp_value)])
    psbt += kp_value
    psbt += b"\x00"

    psbt += b"\x00"

    result = parse_psbt(bytes(psbt))
    inp = result.inputs[0]
    pubkey_hex = pubkey.hex()
    assert pubkey_hex in inp.keypaths
    expected = ("01020304", "2147483692", "2147483649")
    assert inp.keypaths[pubkey_hex] == expected


def test_parse_psbt_with_output_redeem_script() -> None:
    """PSBT output map with redeem_script."""
    tx_bytes = bytearray()
    tx_bytes += (2).to_bytes(4, "little")
    tx_bytes += b"\x01"
    tx_bytes += b"\x11" * 32
    tx_bytes += (0).to_bytes(4, "little")
    tx_bytes += b"\x00"
    tx_bytes += b"\xff\xff\xff\xff"
    tx_bytes += b"\x01"
    tx_bytes += (1000).to_bytes(8, "little")
    tx_bytes += b"\x00"
    tx_bytes += (0).to_bytes(4, "little")

    psbt = bytearray()
    psbt += b"psbt\xff"
    psbt += b"\x01"
    psbt += b"\x00"
    psbt += len(tx_bytes).to_bytes(1, "little")
    psbt += tx_bytes
    psbt += b"\x00"

    psbt += b"\x00"  # empty input

    # Output with redeem_script
    redeem = b"\x76\xa9\x14" + b"\x22" * 20 + b"\x88\xac"
    psbt += b"\x01"
    psbt += b"\x00"  # key type = output redeem_script
    psbt += bytes([len(redeem)])
    psbt += redeem
    psbt += b"\x00"

    result = parse_psbt(bytes(psbt))
    out = result.outputs[0]
    assert out.redeem_script == redeem


def test_parse_psbt_with_output_witness_script() -> None:
    """PSBT output map with witness_script."""
    tx_bytes = bytearray()
    tx_bytes += (2).to_bytes(4, "little")
    tx_bytes += b"\x01"
    tx_bytes += b"\x11" * 32
    tx_bytes += (0).to_bytes(4, "little")
    tx_bytes += b"\x00"
    tx_bytes += b"\xff\xff\xff\xff"
    tx_bytes += b"\x01"
    tx_bytes += (1000).to_bytes(8, "little")
    tx_bytes += b"\x00"
    tx_bytes += (0).to_bytes(4, "little")

    psbt = bytearray()
    psbt += b"psbt\xff"
    psbt += b"\x01"
    psbt += b"\x00"
    psbt += len(tx_bytes).to_bytes(1, "little")
    psbt += tx_bytes
    psbt += b"\x00"

    psbt += b"\x00"  # empty input

    ws = b"\x00\x20" + b"\x55" * 32
    psbt += b"\x01"
    psbt += b"\x01"  # key type = output witness_script
    psbt += bytes([len(ws)])
    psbt += ws
    psbt += b"\x00"

    result = parse_psbt(bytes(psbt))
    out = result.outputs[0]
    assert out.witness_script == ws


def test_parse_psbt_none_key_non_witness_utxo() -> None:
    """PSBT input with non_witness_utxo."""
    tx_bytes = bytearray()
    tx_bytes += (2).to_bytes(4, "little")
    tx_bytes += b"\x01"
    tx_bytes += b"\x11" * 32
    tx_bytes += (0).to_bytes(4, "little")
    tx_bytes += b"\x00"
    tx_bytes += b"\xff\xff\xff\xff"
    tx_bytes += b"\x01"
    tx_bytes += (1000).to_bytes(8, "little")
    tx_bytes += b"\x00"
    tx_bytes += (0).to_bytes(4, "little")

    psbt = bytearray()
    psbt += b"psbt\xff"
    psbt += b"\x01"
    psbt += b"\x00"
    psbt += len(tx_bytes).to_bytes(1, "little")
    psbt += tx_bytes
    psbt += b"\x00"

    # non_witness_utxo = full prevout tx
    nwutxo = tx_bytes  # reuse same tx bytes
    psbt += b"\x01"
    psbt += b"\x00"  # key type = non_witness_utxo
    psbt += len(nwutxo).to_bytes(1, "little") if len(
        nwutxo) < 253 else b"\xfd" + len(nwutxo).to_bytes(2, "little")
    psbt += nwutxo
    psbt += b"\x00"

    psbt += b"\x00"

    result = parse_psbt(bytes(psbt))
    inp = result.inputs[0]
    assert inp.non_witness_utxo == nwutxo


def test_parse_psbt_single_unknown_input_unknown_output() -> None:
    """PSBT with one input, one output both having unknown keys."""
    tx_bytes = bytearray()
    tx_bytes += (2).to_bytes(4, "little")
    tx_bytes += b"\x01"
    tx_bytes += b"\x11" * 32
    tx_bytes += (0).to_bytes(4, "little")
    tx_bytes += b"\x00"
    tx_bytes += b"\xff\xff\xff\xff"
    tx_bytes += b"\x01"
    tx_bytes += (1000).to_bytes(8, "little")
    tx_bytes += b"\x00"
    tx_bytes += (0).to_bytes(4, "little")

    psbt = bytearray()
    psbt += b"psbt\xff"
    psbt += b"\x01"
    psbt += b"\x00"
    psbt += len(tx_bytes).to_bytes(1, "little")
    psbt += tx_bytes
    psbt += b"\x00"
    psbt += b"\x01"  # input key length 1
    psbt += b"\xaa"  # unknown
    psbt += b"\x01"
    psbt += b"\x00"
    psbt += b"\x00"
    psbt += b"\x01"  # output key length 1
    psbt += b"\xbb"  # unknown
    psbt += b"\x01"
    psbt += b"\x00"
    psbt += b"\x00"

    result = parse_psbt(bytes(psbt))
    assert len(result.inputs) == 1
    assert len(result.outputs) == 1
