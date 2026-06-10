# mypy: ignore-errors
"""Fuzz tests for binary parsers using Hypothesis."""

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from bitcoin.curve import GENERATOR
from bitcoin.curve.params import CURVE_ORDER
from bitcoin.encoding.der import decode_der, encode_der
from bitcoin.encoding.sec import parse_sec, serialize_sec
from bitcoin.encoding.varint import decode_varint, encode_varint
from bitcoin.psbt.models import Psbt, PsbtInput, PsbtOutput
from bitcoin.psbt.parser import parse_psbt, serialize_psbt
from bitcoin.services.serializer import serialize_legacy_tx, serialize_tx
from bitcoin.transaction.models import OutPoint, Tx, TxIn, TxOut, Witness
from bitcoin.transaction.parser import parse_tx

# ── Transaction parser ─────────────────────────────────────────────


@settings(max_examples=200)
@given(st.binary())
def test_parse_tx_crash(data):
    try:
        parse_tx(data)
    except ValueError:
        pass


@settings(max_examples=200)
@given(st.binary())
def test_parse_tx_roundtrip(data):
    try:
        tx, _ = parse_tx(data)
        serialized = serialize_tx(tx)
        tx2, _ = parse_tx(serialized)
        assert tx == tx2
    except ValueError:
        pass


# ── DER encoder/decoder ────────────────────────────────────────────


@settings(max_examples=200)
@given(
    st.integers(min_value=1, max_value=CURVE_ORDER - 1),
    st.integers(min_value=1, max_value=CURVE_ORDER - 1),
)
def test_der_roundtrip(r, s):
    sig = encode_der(r, s, s_high_ok=True)
    r2, s2 = decode_der(sig)
    assert r == r2
    assert s == s2


@settings(max_examples=200)
@given(st.binary())
def test_decode_der_crash(data):
    try:
        decode_der(data)
    except ValueError:
        pass


@pytest.mark.parametrize("r,s", [(0, 1), (1, 0), (-1, 1), (1, -1)])
def test_der_invalid_inputs(r, s):
    with pytest.raises((ValueError, OverflowError, IndexError)):
        encode_der(r, s)


# ── SEC parser ─────────────────────────────────────────────────────


@settings(max_examples=200)
@given(st.binary())
def test_parse_sec_crash(data):
    try:
        parse_sec(data)
    except ValueError:
        pass


def test_sec_roundtrip_compressed():
    data = serialize_sec(GENERATOR, compressed=True)
    point = parse_sec(data)
    assert point == GENERATOR


def test_sec_roundtrip_uncompressed():
    data = serialize_sec(GENERATOR, compressed=False)
    point = parse_sec(data)
    assert point == GENERATOR


# ── Varint encoder/decoder ─────────────────────────────────────────


@settings(max_examples=200)
@given(st.binary())
def test_decode_varint_crash(data):
    try:
        decode_varint(data, 0)
    except ValueError:
        pass


@settings(max_examples=200)
@given(st.integers(min_value=0, max_value=2**64 - 1))
def test_varint_roundtrip(n):
    encoded = encode_varint(n)
    decoded, _ = decode_varint(encoded, 0)
    assert decoded == n


@pytest.mark.parametrize("n", [-1, -100])
def test_varint_negative(n):
    with pytest.raises(ValueError):
        encode_varint(n)


# ── PSBT parser ────────────────────────────────────────────────────


@settings(max_examples=200)
@given(st.binary())
def test_parse_psbt_crash(data):
    try:
        parse_psbt(data)
    except ValueError:
        pass


def test_psbt_roundtrip():
    txin = TxIn(
        previous_output=OutPoint(txid=b"\x00" * 32, vout=0),
        script_sig=b"",
        sequence=0xFFFFFFFF,
        witness=Witness(()),
    )
    txout = TxOut(value=1000, script_pubkey=b"\x6a")
    tx = Tx(version=2, inputs=(txin,), outputs=(txout,), lock_time=0)
    raw_tx = serialize_legacy_tx(tx)

    inp = PsbtInput()
    out = PsbtOutput()
    psbt = Psbt(
        tx=raw_tx,
        inputs=(inp,),
        outputs=(out,),
    )

    serialized = serialize_psbt(psbt)
    psbt2 = parse_psbt(serialized)
    assert psbt.tx == psbt2.tx
    assert len(psbt.inputs) == len(psbt2.inputs)
    assert len(psbt.outputs) == len(psbt2.outputs)
