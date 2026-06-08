"""Tests covering remaining uncovered branches in models, records, collections."""
from __future__ import annotations

import pytest

from bitcoin.curve import GENERATOR
from bitcoin.signature import Record, SignatureCollection, linearize_signatures
from bitcoin.signature.linearization.coefficients import (
    LinearCoefficientCollection,
    derive_linear_coefficients,
)
from bitcoin.transaction.models import (
    OutPoint,
    Tx,
    TxIn,
    Witness,
)


class TestRecordCoverage:

    def test_empty_sig(self) -> None:
        with pytest.raises(ValueError, match="signature must be non-empty"):
            Record(
                txid=b"\x00" * 32,
                input_index=0,
                signature=b"",
                public_key=GENERATOR,
                script_type="p2pkh",
                sighash_flag=0x01,
                amount=0,
            )

    def test_non_bytes_sig(self) -> None:
        with pytest.raises(ValueError, match="signature must be non-empty"):
            Record(
                txid=b"\x00" * 32,
                input_index=0,
                signature=123,  # type: ignore[arg-type]
                public_key=GENERATOR,
                script_type="p2pkh",
                sighash_flag=0x01,
                amount=0,
            )

    def test_negative_amount(self) -> None:
        with pytest.raises(ValueError, match="amount must be non-negative"):
            Record(
                txid=b"\x00" * 32,
                input_index=0,
                signature=b"\x30\x06\x02\x01\x01\x02\x01\x01",
                public_key=GENERATOR,
                script_type="p2pkh",
                sighash_flag=0x01,
                amount=-1,
            )


class TestCollectionCoverage:

    def test_iter(self) -> None:
        rec = Record(
            txid=b"\x00" * 32,
            input_index=0,
            signature=b"\x30\x06\x02\x01\x01\x02\x01\x01",
            public_key=GENERATOR,
            script_type="p2pkh",
            sighash_flag=0x01,
            amount=0,
        )
        coll = SignatureCollection(records=(rec,))
        count = 0
        for _ in coll:
            count += 1
        assert count == 1

    def test_getitem(self) -> None:
        rec = Record(
            txid=b"\x00" * 32,
            input_index=0,
            signature=b"\x30\x06\x02\x01\x01\x02\x01\x01",
            public_key=GENERATOR,
            script_type="p2pkh",
            sighash_flag=0x01,
            amount=0,
        )
        coll = SignatureCollection(records=(rec,))
        assert coll[0] == rec

    def test_linearize_with_collection(self) -> None:
        recs = [
            Record(
                txid=b"\x01" * 32,
                input_index=1,
                signature=b"\x30\x06\x02\x01\x01\x02\x01\x01",
                public_key=GENERATOR,
                script_type="p2pkh",
                sighash_flag=0x01,
                amount=0,
            ),
        ]
        coll = SignatureCollection(records=tuple(recs))
        result = linearize_signatures(list(coll))
        assert len(result) == 1


class TestCoefficientsCoverage:

    def test_alpha_beta_properties(self) -> None:
        rec = derive_linear_coefficients(7, 11, 42, input_index=5)
        col = LinearCoefficientCollection(records=(rec,))
        assert col.alpha == [rec.alpha]
        assert col.beta == [rec.beta]

    def test_mixed_records(self) -> None:
        rec1 = derive_linear_coefficients(1, 2, 3, input_index=0)
        rec2 = derive_linear_coefficients(4, 5, 6, input_index=1)
        col = LinearCoefficientCollection(records=(rec1, rec2))
        assert len(col.alpha) == 2
        assert len(col.beta) == 2

    def test_empty_collection(self) -> None:
        col = LinearCoefficientCollection(records=())
        assert col.alpha == []
        assert col.beta == []


class TestWtxidCoverage:

    def test_wtxid(self) -> None:
        txin = TxIn(
            previous_output=OutPoint(txid=b"\x00" * 32, vout=0),
            script_sig=b"",
            sequence=0xFFFFFFFF,
            witness=Witness((b"\x30\x06\x02\x01\x01\x02\x01\x01",)),
        )
        tx = Tx(version=2, inputs=(txin,), outputs=(), lock_time=0)
        result = tx.wtxid()
        assert len(result) == 32

    def test_wtxid_non_segwit(self) -> None:
        txin = TxIn(
            previous_output=OutPoint(txid=b"\x00" * 32, vout=0),
            script_sig=b"",
            sequence=0xFFFFFFFF,
            witness=Witness(()),
        )
        tx = Tx(version=2, inputs=(txin,), outputs=(), lock_time=0)
        assert tx.wtxid() == tx.txid()

    def test_txid(self) -> None:
        txin = TxIn(
            previous_output=OutPoint(txid=b"\x00" * 32, vout=0),
            script_sig=b"",
            sequence=0xFFFFFFFF,
            witness=Witness(()),
        )
        tx = Tx(version=2, inputs=(txin,), outputs=(), lock_time=0)
        assert len(tx.txid()) == 32
