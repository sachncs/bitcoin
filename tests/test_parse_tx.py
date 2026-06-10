"""Tests for transaction parsing (parse_tx) with real and synthetic transactions."""
from __future__ import annotations

import pytest

from bitcoin import OutPoint, ParsingError, Tx, TxIn, TxOut, Witness, make_tx, parse_tx
from bitcoin.services.serializer import serialize_legacy_tx, serialize_tx


class TestParseTx:

    def test_parse_legacy_no_inputs(self) -> None:
        """Minimal legacy transaction: version 1, 0 inputs, 0 outputs, locktime 0."""
        tx = Tx(version=1, inputs=(), outputs=(), lock_time=0)
        raw = serialize_legacy_tx(tx)
        parsed, consumed = parse_tx(raw)
        assert parsed.version == 1
        assert len(parsed.inputs) == 0
        assert len(parsed.outputs) == 0
        assert parsed.lock_time == 0
        assert not parsed.is_segwit()
        assert consumed == len(raw)

    def test_parse_legacy_one_output(self) -> None:
        """Transaction with one input and one output."""
        txin = TxIn(
            previous_output=OutPoint(txid=b"\x00" * 32, vout=0),
            script_sig=b"",
            sequence=0xFFFFFFFF,
            witness=Witness(()),
        )
        txout = TxOut(value=1000, script_pubkey=b"")
        tx = Tx(version=1, inputs=(txin,), outputs=(txout,), lock_time=0)
        raw = serialize_legacy_tx(tx)
        parsed, consumed = parse_tx(raw)
        assert parsed.version == 1
        assert len(parsed.inputs) == 1
        assert len(parsed.outputs) == 1
        assert parsed.outputs[0].value == 1000
        assert not parsed.is_segwit()
        assert consumed == len(raw)

    def test_parse_roundtrip_legacy(self) -> None:
        """Parsing a serialized legacy tx gives the same result."""
        tx_in = TxIn(
            previous_output=OutPoint(txid=b"\x00" * 31 + b"\x01", vout=0),
            script_sig=b"\x00",
            sequence=0xFFFFFFFF,
            witness=Witness(()),
        )
        tx_out = TxOut(
            value=50000,
            script_pubkey=b"\x76\xa9\x14" + b"\x00" * 20 + b"\x88\xac",
        )
        original = Tx(version=2,
                      inputs=(tx_in,),
                      outputs=(tx_out,),
                      lock_time=0)
        raw = serialize_tx(original)
        parsed, consumed = parse_tx(raw)
        assert consumed == len(raw)
        assert parsed.version == original.version
        assert len(parsed.inputs) == len(original.inputs)
        assert len(parsed.outputs) == len(original.outputs)
        assert parsed.outputs[0].value == original.outputs[0].value
        assert not parsed.is_segwit()

    def test_parse_roundtrip_segwit(self) -> None:
        """Parsing a serialized segwit tx gives the same result."""
        tx_in = TxIn(
            previous_output=OutPoint(txid=b"\x00" * 31 + b"\x01", vout=0),
            script_sig=b"",
            sequence=0xFFFFFFFF,
            witness=Witness((b"\x30\x45\x02\x21\x00", b"\x02" * 33)),
        )
        tx_out = TxOut(value=10000, script_pubkey=b"\x00\x14" + b"\x00" * 20)
        original = Tx(version=2,
                      inputs=(tx_in,),
                      outputs=(tx_out,),
                      lock_time=0)
        raw = serialize_tx(original)
        parsed, consumed = parse_tx(raw)
        assert consumed == len(raw)
        assert parsed.is_segwit()
        assert len(parsed.inputs[0].witness) == 2

    def test_parse_roundtrip_multiple_inputs(self) -> None:
        """Transaction with multiple inputs and outputs round-trips."""
        inputs = tuple(
            TxIn(
                previous_output=OutPoint(txid=i.to_bytes(32, "big"), vout=i),
                script_sig=b"",
                sequence=0xFFFFFFFF,
                witness=Witness(()),
            ) for i in range(3))
        outputs = tuple(
            TxOut(value=i * 1000, script_pubkey=b"\x6a") for i in range(2))
        original = Tx(version=1, inputs=inputs, outputs=outputs, lock_time=0)
        raw = serialize_tx(original)
        parsed, consumed = parse_tx(raw)
        assert consumed == len(raw)
        assert len(parsed.inputs) == 3
        assert len(parsed.outputs) == 2

    def test_parse_txid(self) -> None:
        """txid() returns double-SHA256 of legacy serialization."""
        tx = make_tx(version=1, inputs=[], outputs=[])
        txid = tx.txid()
        assert len(txid) == 32

    def test_parse_make_tx(self) -> None:
        """make_tx convenience builder works."""
        tx = make_tx(
            version=2,
            inputs=[{
                "txid": b"\x01" * 32,
                "vout": 0
            }],
            outputs=[{
                "value": 1,
                "script_pubkey": b"\x6a"
            }],
        )
        assert tx.version == 2
        assert len(tx.inputs) == 1
        assert tx.inputs[0].previous_output.txid == b"\x01" * 32

    def test_parse_negative_version(self) -> None:
        """Version can be negative (BIP-68)."""
        tx = make_tx(version=-1, inputs=[], outputs=[])
        assert tx.version == -1

    def test_parse_high_locktime(self) -> None:
        """Locktime can be high."""
        tx = make_tx(version=2, inputs=[], outputs=[], lock_time=500000000)
        raw = serialize_tx(tx)
        parsed, _ = parse_tx(raw)
        assert parsed.lock_time == 500000000

    def test_truncated_bytes(self) -> None:
        """Incomplete transaction raises ParsingError."""
        with pytest.raises((ParsingError, ValueError)):
            parse_tx(b"\x01\x00\x00\x00")

    def test_make_tx_empty_fields(self) -> None:
        """make_tx with no inputs or outputs."""
        tx = make_tx(version=1, inputs=[], outputs=[])
        assert len(tx.inputs) == 0
        assert len(tx.outputs) == 0

    def test_parse_witness_data_preserved(self) -> None:
        """Witness items are preserved through parse roundtrip."""
        items = (b"\x30\x45", b"\x02" * 33, b"\x01")
        txin = TxIn(
            previous_output=OutPoint(txid=b"\x00" * 32, vout=0),
            script_sig=b"",
            sequence=0xFFFFFFFF,
            witness=Witness(items),
        )
        tx = Tx(version=2, inputs=(txin,), outputs=(), lock_time=0)
        raw = serialize_tx(tx)
        parsed, _ = parse_tx(raw)
        assert parsed.inputs[0].witness.items == items
