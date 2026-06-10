"""Tests for the new signature/ package (Record, extraction, linearization)."""

import pytest

from bitcoin.curve import GENERATOR, multiply
from bitcoin.encoding.hasher import hash256
from bitcoin.signature import Record, linearize_signatures
from bitcoin.signature.check import verify_sig


class TestRecord:

    def test_creation(self) -> None:
        rec = Record(
            txid=b"\x00" * 32,
            input_index=0,
            signature=b"\x30\x06\x02\x01\x01\x02\x01\x01",
            public_key=GENERATOR,
            script_type="p2pkh",
            sighash_flag=0x01,
            amount=10000,
        )
        assert rec.vin == 0
        assert rec.script_type == "p2pkh"

    def test_invalid_txid_length(self) -> None:
        with pytest.raises(ValueError, match="txid must be 32 bytes"):
            Record(
                txid=b"\x00" * 31,
                input_index=0,
                signature=b"\x30\x06\x02\x01\x01\x02\x01\x01",
                public_key=GENERATOR,
                script_type="p2pkh",
                sighash_flag=0x01,
                amount=0,
            )

    def test_r_value(self) -> None:
        # DER encoding of r=1, s=1
        sig = b"\x30\x06\x02\x01\x01\x02\x01\x01"
        rec = Record(
            txid=b"\x00" * 32,
            input_index=0,
            signature=sig,
            public_key=GENERATOR,
            script_type="p2pkh",
            sighash_flag=0x01,
            amount=0,
        )
        assert rec.r_value == 1

    def test_r_value_bad_der(self) -> None:
        with pytest.raises(ValueError):
            Record(
                txid=b"\x00" * 32,
                input_index=0,
                signature=b"\x00\x01\x02",
                public_key=GENERATOR,
                script_type="p2pkh",
                sighash_flag=0x01,
                amount=0,
            ).r_value

    def test_negative_vin(self) -> None:
        with pytest.raises(ValueError,
                           match="input_index must be non-negative"):
            Record(
                txid=b"\x00" * 32,
                input_index=-1,
                signature=b"\x30\x06\x02\x01\x01\x02\x01\x01",
                public_key=GENERATOR,
                script_type="p2pkh",
                sighash_flag=0x01,
                amount=0,
            )

    def test_frozen(self) -> None:
        rec = Record(
            txid=b"\x00" * 32,
            input_index=0,
            signature=b"\x30\x06\x02\x01\x01\x02\x01\x01",
            public_key=GENERATOR,
            script_type="p2pkh",
            sighash_flag=0x01,
            amount=0,
        )
        with pytest.raises(Exception):
            rec.vin = 1  # type: ignore[misc]


class TestVerifySig:

    def test_verify_valid(self) -> None:
        msg = hash256(b"test message")
        from bitcoin.signature.signer import sign
        private_key = 1
        sig = sign(msg, private_key)
        public_key = multiply(private_key, GENERATOR)
        assert verify_sig(msg, sig, public_key)

    def test_verify_invalid_sig_format(self) -> None:
        result = verify_sig(b"\x00" * 32, b"\x00\x01\x02", GENERATOR)
        assert not result

    def test_verify_bad_r_s_range(self) -> None:
        result = verify_sig(b"\x00" * 32, b"\x30\x06\x02\x01\x00\x02\x01\x01",
                            GENERATOR)
        assert not result


class TestLinearization:

    def test_linearize_empty(self) -> None:
        result = linearize_signatures([])
        assert result == []

    def test_linearize_orders_by_txid_then_vin(self) -> None:
        records = [
            Record(
                txid=b"\x01" * 32,
                input_index=1,
                signature=b"\x30\x06\x02\x01\x01\x02\x01\x01",
                public_key=GENERATOR,
                script_type="p2pkh",
                sighash_flag=0x01,
                amount=0,
            ),
            Record(
                txid=b"\x00" * 32,
                input_index=0,
                signature=b"\x30\x06\x02\x01\x01\x02\x01\x01",
                public_key=GENERATOR,
                script_type="p2pkh",
                sighash_flag=0x01,
                amount=0,
            ),
        ]
        sorted_recs = linearize_signatures(records)
        assert sorted_recs[0].txid == b"\x00" * 32
        assert sorted_recs[1].txid == b"\x01" * 32
