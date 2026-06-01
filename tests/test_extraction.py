"""Tests for signature extraction and sighash computation."""
from __future__ import annotations

import pytest

from bitcoin import (
    parse_tx, extract_signatures, linearize_signatures, Record,
    sighash_legacy, sighash_segwit, sighash_taproot,
    SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY,
    Tx, TxIn, TxOut, OutPoint, Witness,
    encode_der, hash256,
)
from bitcoin.curve import GENERATOR, CURVE_ORDER, multiply
from bitcoin.encoding import decode_hex, encode_hex, int_to_bytes


class TestExtractSignatures:
    def test_extract_empty_tx(self) -> None:
        """Empty transaction has no signatures."""
        tx = Tx(version=1, inputs=(), outputs=(), lock_time=0)
        records = extract_signatures(tx)
        assert records == []

    def test_extract_no_utxo_data(self) -> None:
        """Transaction without utxo data returns records with minimal info."""
        tx_in = TxIn(
            previous_output=OutPoint(txid=b"\x00" * 32, vout=0),
            script_sig=b"\x30\x06\x02\x01\x01\x02\x01\x01",
            sequence=0xFFFFFFFF,
            witness=Witness(()),
        )
        tx_out = TxOut(value=0, script_pubkey=b"\x6a")
        tx = Tx(version=2, inputs=(tx_in,), outputs=(tx_out,), lock_time=0)
        records = extract_signatures(tx)
        assert isinstance(records, list)

    def test_extract_returns_records(self) -> None:
        """extract_signatures returns a list of Record objects."""
        tx = Tx(version=1, inputs=(), outputs=(), lock_time=0)
        records = extract_signatures(tx)
        for rec in records:
            assert isinstance(rec, Record)


class TestSighashFlags:
    def test_sighash_all_value(self) -> None:
        assert SIGHASH_ALL == 0x01

    def test_sighash_none_value(self) -> None:
        assert SIGHASH_NONE == 0x02

    def test_sighash_single_value(self) -> None:
        assert SIGHASH_SINGLE == 0x03

    def test_sighash_anyonecanpay_value(self) -> None:
        assert SIGHASH_ANYONECANPAY == 0x80


class TestSighashLegacy:
    def __make_tx(self) -> Tx:
        txin = TxIn(previous_output=OutPoint(txid=b"\x00" * 32, vout=0),
                     script_sig=b"", sequence=0xFFFFFFFF, witness=Witness(()))
        return Tx(version=1, inputs=(txin,), outputs=(), lock_time=0)

    def test_sighash_legacy_returns_32_bytes(self) -> None:
        result = sighash_legacy(self.__make_tx(), 0, b"\x00", SIGHASH_ALL)
        assert len(result) == 32

    def test_sighash_legacy_deterministic(self) -> None:
        tx = self.__make_tx()
        a = sighash_legacy(tx, 0, b"\x00", SIGHASH_ALL)
        b = sighash_legacy(tx, 0, b"\x00", SIGHASH_ALL)
        assert a == b

    def test_sighash_legacy_different_script(self) -> None:
        tx = self.__make_tx()
        a = sighash_legacy(tx, 0, b"\x00", SIGHASH_ALL)
        b = sighash_legacy(tx, 0, b"\x01", SIGHASH_ALL)
        assert a != b

    def test_sighash_legacy_single_no_output(self) -> None:
        """SINGLE with no matching output raises ValueError."""
        txin = TxIn(OutPoint(b"\x00" * 32, 0), b"", 0, Witness(()))
        tx = Tx(version=1, inputs=(txin,), outputs=(), lock_time=0)
        with pytest.raises(ValueError, match="out of bounds"):
            sighash_legacy(tx, 0, b"\x00", SIGHASH_SINGLE)


class TestSighashSegwit:
    def __make_tx(self) -> Tx:
        txin = TxIn(previous_output=OutPoint(txid=b"\x00" * 32, vout=0),
                     script_sig=b"", sequence=0xFFFFFFFF, witness=Witness(()))
        return Tx(version=1, inputs=(txin,), outputs=(), lock_time=0)

    def test_sighash_segwit_returns_32_bytes(self) -> None:
        result = sighash_segwit(self.__make_tx(), 0, b"\x00", 0, SIGHASH_ALL)
        assert len(result) == 32

    def test_sighash_segwit_deterministic(self) -> None:
        tx = self.__make_tx()
        a = sighash_segwit(tx, 0, b"\x00", 0, SIGHASH_ALL)
        b = sighash_segwit(tx, 0, b"\x00", 0, SIGHASH_ALL)
        assert a == b

    def test_sighash_segwit_different_amount(self) -> None:
        tx = self.__make_tx()
        a = sighash_segwit(tx, 0, b"\x00", 100, SIGHASH_ALL)
        b = sighash_segwit(tx, 0, b"\x00", 200, SIGHASH_ALL)
        assert a != b


class TestSighashTaproot:
    def __make_tx(self) -> Tx:
        txin = TxIn(previous_output=OutPoint(txid=b"\x00" * 32, vout=0),
                     script_sig=b"", sequence=0xFFFFFFFF, witness=Witness(()))
        txout = TxOut(value=1000, script_pubkey=b"\x51")
        return Tx(version=1, inputs=(txin,), outputs=(txout,), lock_time=0)

    def test_sighash_taproot_returns_32_bytes(self) -> None:
        tx = self.__make_tx()
        result = sighash_taproot(tx, 0, None, SIGHASH_ALL)
        assert len(result) == 32

    def test_sighash_taproot_deterministic(self) -> None:
        tx = self.__make_tx()
        a = sighash_taproot(tx, 0, None, SIGHASH_ALL)
        b = sighash_taproot(tx, 0, None, SIGHASH_ALL)
        assert a == b


class TestExtractTaproot:
    def __p2tr_script_pubkey(self) -> bytes:
        """Build a minimal P2TR scriptPubKey."""
        pubkey = b"\x00" * 32  # 32-byte x-only pubkey
        return bytes([0x51, 0x20]) + pubkey

    def __make_tx_with_witness(
        self, witness_items: tuple[bytes, ...], script_pubkey: bytes | None = None,
    ) -> Tx:
        txin = TxIn(
            previous_output=OutPoint(txid=b"\x00" * 32, vout=0),
            script_sig=b"",
            sequence=0xFFFFFFFF,
            witness=Witness(witness_items),
        )
        if script_pubkey is None:
            script_pubkey = self.__p2tr_script_pubkey()
        txout = TxOut(value=1000, script_pubkey=script_pubkey)
        return Tx(version=1, inputs=(txin,), outputs=(txout,), lock_time=0)

    def test_taproot_key_path_spend(self) -> None:
        """Key-path spend with 64-byte Schnorr sig."""
        sig = b"\x01" * 64
        tx = self.__make_tx_with_witness((sig,))
        records = extract_signatures(
            tx, utxo_script_pubkeys=[self.__p2tr_script_pubkey()],
        )
        assert len(records) == 1
        assert records[0].script_type == "p2tr"
        assert records[0].sighash_flag == 0x01  # SIGHASH_ALL default

    def test_taproot_key_path_with_sighash(self) -> None:
        """Key-path spend with 65-byte sig containing explicit sighash."""
        sig = b"\x01" * 64 + b"\x03"  # 64-byte sig + SIGHASH_SINGLE
        tx = self.__make_tx_with_witness((sig,))
        records = extract_signatures(
            tx, utxo_script_pubkeys=[self.__p2tr_script_pubkey()],
        )
        assert len(records) == 1
        assert records[0].sighash_flag == 0x03

    def test_taproot_script_path_spend(self) -> None:
        """Script-path spend with multiple witness items."""
        sig = b"\x01" * 64
        leaf_script = b"\x20\x00" * 16  # 32-byte script
        control_block = b"\xc0" + b"\x00" * 32
        tx = self.__make_tx_with_witness((sig, leaf_script, control_block))
        records = extract_signatures(
            tx, utxo_script_pubkeys=[self.__p2tr_script_pubkey()],
        )
        assert len(records) == 1
        assert records[0].script_type == "p2tr"

    def test_taproot_empty_witness(self) -> None:
        """Empty witness yields no records."""
        tx = self.__make_tx_with_witness(())
        records = extract_signatures(
            tx, utxo_script_pubkeys=[self.__p2tr_script_pubkey()],
        )
        assert records == []


class TestLinearizeSignatures:
    def test_linearize_empty(self) -> None:
        assert linearize_signatures([]) == []

    def test_linearize_preserves_single(self) -> None:
        rec = Record(
            txid=b"\x00" * 32, vin=0,
            sig=b"\x30\x06\x02\x01\x01\x02\x01\x01",
            public_key=GENERATOR, script_type="p2pkh",
            sighash_flag=0x01, amount=0,
        )
        result = linearize_signatures([rec])
        assert len(result) == 1
        assert result[0] is rec

    def test_linearize_sorts_by_txid(self) -> None:
        rec_a = Record(
            txid=b"\x00" * 32, vin=0,
            sig=b"\x30\x06\x02\x01\x01\x02\x01\x01",
            public_key=GENERATOR, script_type="p2pkh",
            sighash_flag=0x01, amount=0,
        )
        rec_b = Record(
            txid=b"\x01" * 32, vin=0,
            sig=b"\x30\x06\x02\x01\x01\x02\x01\x01",
            public_key=GENERATOR, script_type="p2pkh",
            sighash_flag=0x01, amount=0,
        )
        result = linearize_signatures([rec_b, rec_a])
        assert result[0].txid == b"\x00" * 32
        assert result[1].txid == b"\x01" * 32
