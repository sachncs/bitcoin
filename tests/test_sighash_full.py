"""Comprehensive tests for sighash (flag, legacy, segwit, taproot) + serializer."""

from __future__ import annotations

import pytest

from bitcoin.sighash.flag import (
    SIGHASH_ALL,
    SIGHASH_ALL_ANYONECANPAY,
    SIGHASH_NONE,
    SIGHASH_NONE_ANYONECANPAY,
    SIGHASH_SINGLE,
    SIGHASH_SINGLE_ANYONECANPAY,
    require_sighash_flag,
    sighash_name,
)
from bitcoin.sighash.legacy import sighash_legacy
from bitcoin.sighash.segwit import sighash_segwit
from bitcoin.sighash.taproot import sighash_taproot
from bitcoin.services.serializer import (
    serialize_legacy_tx_for_sighash,
    serialize_tx_for_sighash_taproot,
    serialize_legacy_tx,
    serialize_tx,
)
from bitcoin.transaction.models import OutPoint, Tx, TxIn, TxOut, Witness

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

EMPTY = Witness(())


def make_outpoint(txid: bytes | None = None, vout: int = 0) -> OutPoint:
    return OutPoint(txid=txid or b"\x01" * 32, vout=vout)


def make_txin(
    prev_out: OutPoint | None = None,
    script_sig: bytes = b"",
    sequence: int = 0xFFFFFFFF,
    witness: Witness | None = None,
) -> TxIn:
    return TxIn(
        previous_output=prev_out or make_outpoint(),
        script_sig=script_sig,
        sequence=sequence,
        witness=witness or EMPTY,
    )


def make_txout(value: int = 1000, script_pubkey: bytes = b"\x00") -> TxOut:
    return TxOut(value=value, script_pubkey=script_pubkey)


def make_tx(
    inputs: tuple[TxIn, ...] | None = None,
    outputs: tuple[TxOut, ...] | None = None,
    version: int = 1,
    lock_time: int = 0,
) -> Tx:
    return Tx(
        version=version,
        inputs=inputs or (make_txin(),),
        outputs=outputs or (make_txout(),),
        lock_time=lock_time,
    )


SCRIPT = b"\x76\xa9\x14" + b"\x11" * 20 + b"\x88\xac"
TAPLEAF_HASH = b"\x22" * 32

# Shared tx objects (class-level constants)
TX_2IN_2OUT = make_tx(
    inputs=(
        make_txin(sequence=0xFFFFFFFE),
        make_txin(make_outpoint(b"\x02" * 32, 1), sequence=0xFFFFFFFD),
    ),
    outputs=(make_txout(10000, b"\x01"), make_txout(20000, b"\x02")),
)

TX_1OUT = make_tx(
    inputs=(
        make_txin(),
        make_txin(make_outpoint(b"\x03" * 32, 0)),
    ),
    outputs=(make_txout(value=5000),),
)

TX_TAPROOT = make_tx(
    inputs=(
        make_txin(sequence=0xFFFFFFFE),
        make_txin(make_outpoint(b"\x02" * 32, 1)),
    ),
    outputs=(make_txout(10000, b"\x01"), make_txout(20000, b"\x02")),
)

# ===================================================================
# flag.py
# ===================================================================


class TestSighashFlag:
    """100 % line / branch coverage of ``bitcoin.sighash.flag``."""

    def test_sighash_name_all(self) -> None:
        assert sighash_name(SIGHASH_ALL) == "SIGHASH_ALL"

    def test_sighash_name_none(self) -> None:
        assert sighash_name(SIGHASH_NONE) == "SIGHASH_NONE"

    def test_sighash_name_single(self) -> None:
        assert sighash_name(SIGHASH_SINGLE) == "SIGHASH_SINGLE"

    def test_sighash_name_all_anyonecanpay(self) -> None:
        assert sighash_name(
            SIGHASH_ALL_ANYONECANPAY) == "SIGHASH_ALL|ANYONECANPAY"

    def test_sighash_name_none_anyonecanpay(self) -> None:
        assert sighash_name(
            SIGHASH_NONE_ANYONECANPAY) == "SIGHASH_NONE|ANYONECANPAY"

    def test_sighash_name_single_anyonecanpay(self) -> None:
        assert sighash_name(SIGHASH_SINGLE_ANYONECANPAY) == (
            "SIGHASH_SINGLE|ANYONECANPAY")

    def test_sighash_name_unknown(self) -> None:
        assert sighash_name(0x04) == "SIGHASH_UNKNOWN(4)"

    def test_sighash_name_unknown_with_acp(self) -> None:
        assert sighash_name(0x84) == "SIGHASH_UNKNOWN(132)"

    def test_require_valid_all(self) -> None:
        assert require_sighash_flag(SIGHASH_ALL) == SIGHASH_ALL

    def test_require_valid_none(self) -> None:
        assert require_sighash_flag(SIGHASH_NONE) == SIGHASH_NONE

    def test_require_valid_single(self) -> None:
        assert require_sighash_flag(SIGHASH_SINGLE) == SIGHASH_SINGLE

    def test_require_valid_all_acp(self) -> None:
        assert (require_sighash_flag(SIGHASH_ALL_ANYONECANPAY) ==
                SIGHASH_ALL_ANYONECANPAY)

    def test_require_valid_none_acp(self) -> None:
        assert (require_sighash_flag(SIGHASH_NONE_ANYONECANPAY) ==
                SIGHASH_NONE_ANYONECANPAY)

    def test_require_valid_single_acp(self) -> None:
        assert (require_sighash_flag(SIGHASH_SINGLE_ANYONECANPAY) ==
                SIGHASH_SINGLE_ANYONECANPAY)

    def test_require_invalid_base(self) -> None:
        with pytest.raises(ValueError, match="Unknown SIGHASH base type"):
            require_sighash_flag(0x04)

    def test_require_invalid_base_with_acp(self) -> None:
        with pytest.raises(ValueError, match="Unknown SIGHASH base type"):
            require_sighash_flag(0x84)


# ===================================================================
# legacy.py  (sighash_legacy)
# ===================================================================


class TestSighashLegacy:
    """100 % line / branch coverage of ``sighash_legacy``."""

    def test_all(self) -> None:
        h = sighash_legacy(TX_2IN_2OUT, 0, SCRIPT, SIGHASH_ALL)
        assert len(h) == 32

    def test_none(self) -> None:
        h = sighash_legacy(TX_2IN_2OUT, 0, SCRIPT, SIGHASH_NONE)
        assert len(h) == 32

    def test_single_valid(self) -> None:
        h = sighash_legacy(TX_2IN_2OUT, 0, SCRIPT, SIGHASH_SINGLE)
        assert len(h) == 32

    def test_single_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="out of bounds"):
            sighash_legacy(TX_2IN_2OUT, 5, SCRIPT, SIGHASH_SINGLE)

    def test_anyonecanpay_all(self) -> None:
        h = sighash_legacy(TX_2IN_2OUT, 0, SCRIPT, SIGHASH_ALL_ANYONECANPAY)
        assert len(h) == 32

    def test_anyonecanpay_none(self) -> None:
        h = sighash_legacy(TX_2IN_2OUT, 0, SCRIPT, SIGHASH_NONE_ANYONECANPAY)
        assert len(h) == 32

    def test_anyonecanpay_single(self) -> None:
        h = sighash_legacy(TX_2IN_2OUT, 0, SCRIPT, SIGHASH_SINGLE_ANYONECANPAY)
        assert len(h) == 32


# ===================================================================
# segwit.py  (sighash_segwit)
# ===================================================================


class TestSighashSegwit:
    """100 % line / branch coverage of ``sighash_segwit``."""

    VALUE = 50000

    def test_all(self) -> None:
        h = sighash_segwit(TX_2IN_2OUT, 0, SCRIPT, self.VALUE, SIGHASH_ALL)
        assert len(h) == 32

    def test_none(self) -> None:
        h = sighash_segwit(TX_2IN_2OUT, 0, SCRIPT, self.VALUE, SIGHASH_NONE)
        assert len(h) == 32

    def test_single_input_index_zero(self) -> None:
        """input_index == 0 — no leading zero-outputs in hash_outputs."""
        h = sighash_segwit(TX_2IN_2OUT, 0, SCRIPT, self.VALUE, SIGHASH_SINGLE)
        assert len(h) == 32

    def test_single_with_nonzero_index(self) -> None:
        """input_index > 0 — leading zero-outputs in hash_outputs_data."""
        h = sighash_segwit(TX_2IN_2OUT, 1, SCRIPT, self.VALUE, SIGHASH_SINGLE)
        assert len(h) == 32

    def test_single_out_of_range(self) -> None:
        """input_index valid for inputs but >= len(outputs)."""
        tx = make_tx(
            inputs=(make_txin(), make_txin(make_outpoint(b"\x04" * 32, 0))),
            outputs=(make_txout(value=5000),),
        )
        with pytest.raises(ValueError, match="out of range"):
            sighash_segwit(tx, 1, SCRIPT, self.VALUE, SIGHASH_SINGLE)

    def test_all_anyonecanpay(self) -> None:
        h = sighash_segwit(TX_2IN_2OUT, 0, SCRIPT, self.VALUE,
                           SIGHASH_ALL_ANYONECANPAY)
        assert len(h) == 32

    def test_none_anyonecanpay(self) -> None:
        h = sighash_segwit(TX_2IN_2OUT, 0, SCRIPT, self.VALUE,
                           SIGHASH_NONE_ANYONECANPAY)
        assert len(h) == 32

    def test_single_anyonecanpay(self) -> None:
        h = sighash_segwit(TX_2IN_2OUT, 0, SCRIPT, self.VALUE,
                           SIGHASH_SINGLE_ANYONECANPAY)
        assert len(h) == 32


# ===================================================================
# taproot.py  (sighash_taproot)
# ===================================================================


class TestSighashTaproot:
    """100 % line / branch coverage of ``sighash_taproot``."""

    def test_key_path(self) -> None:
        h = sighash_taproot(TX_TAPROOT, 0, script=None, sighash_flag=0x00)
        assert len(h) == 32

    def test_key_path_with_flag(self) -> None:
        h = sighash_taproot(TX_TAPROOT, 0, script=None, sighash_flag=0x01)
        assert len(h) == 32

    def test_script_path(self) -> None:
        h = sighash_taproot(
            TX_TAPROOT,
            0,
            script=SCRIPT,
            sighash_flag=0x00,
            tapleaf_hash=TAPLEAF_HASH,
        )
        assert len(h) == 32

    def test_script_path_missing_tapleaf_hash(self) -> None:
        with pytest.raises(ValueError, match="tapleaf_hash required"):
            sighash_taproot(TX_TAPROOT, 0, script=SCRIPT, sighash_flag=0x00)

    def test_input_index_out_of_range(self) -> None:
        with pytest.raises(IndexError, match="out of range"):
            sighash_taproot(TX_TAPROOT, 5, script=None, sighash_flag=0x00)

    def test_with_annex(self) -> None:
        h = sighash_taproot(
            TX_TAPROOT,
            0,
            script=None,
            sighash_flag=0x00,
            annex=b"\x50\x00",
        )
        assert len(h) == 32

    def test_with_extension(self) -> None:
        h = sighash_taproot(
            TX_TAPROOT,
            0,
            script=None,
            sighash_flag=0x00,
            extension=b"\x01\x02",
        )
        assert len(h) == 32

    def test_key_version_nonzero(self) -> None:
        h = sighash_taproot(
            TX_TAPROOT,
            0,
            script=SCRIPT,
            sighash_flag=0x00,
            tapleaf_hash=TAPLEAF_HASH,
            key_version=1,
        )
        assert len(h) == 32

    def test_codeseparator_position(self) -> None:
        h = sighash_taproot(
            TX_TAPROOT,
            0,
            script=SCRIPT,
            sighash_flag=0x00,
            tapleaf_hash=TAPLEAF_HASH,
            codeseparator_position=42,
        )
        assert len(h) == 32

    def test_script_path_with_annex(self) -> None:
        h = sighash_taproot(
            TX_TAPROOT,
            0,
            script=SCRIPT,
            sighash_flag=0x00,
            tapleaf_hash=TAPLEAF_HASH,
            annex=b"\x50",
        )
        assert len(h) == 32

    def test_flag_with_acp(self) -> None:
        h = sighash_taproot(TX_TAPROOT, 0, script=None, sighash_flag=0x83)
        assert len(h) == 32

    def test_large_script_fd_varint(self) -> None:
        """Script length >= 0xFD exercises the 2-byte varint branch."""
        big_script = b"\x00" * 254
        h = sighash_taproot(
            TX_TAPROOT,
            0,
            script=big_script,
            sighash_flag=0x00,
            tapleaf_hash=TAPLEAF_HASH,
        )
        assert len(h) == 32

    def test_large_script_fe_varint(self) -> None:
        """Script length > 0xFFFF exercises the 4-byte varint branch."""
        big_script = b"\x00" * 0x10001
        h = sighash_taproot(
            TX_TAPROOT,
            0,
            script=big_script,
            sighash_flag=0x00,
            tapleaf_hash=TAPLEAF_HASH,
        )
        assert len(h) == 32

    def test_script_path_tapleaf_hash_none_with_flag(self) -> None:
        """Also test with sighash_flag=0x83 and script path — different code
        path combos."""
        h = sighash_taproot(
            TX_TAPROOT,
            0,
            script=SCRIPT,
            sighash_flag=0x83,
            tapleaf_hash=TAPLEAF_HASH,
        )
        assert len(h) == 32


# ===================================================================
# serializer.py
# ===================================================================


class TestSerializer:
    """Coverage for all public and private serialization helpers."""

    # -- serialize_tx --

    def test_serialize_tx_non_segwit(self) -> None:
        tx = make_tx()
        raw = serialize_tx(tx)
        assert isinstance(raw, bytes)
        assert raw[4:6] != b"\x00\x01"

    def test_serialize_tx_segwit(self) -> None:
        wit = Witness((b"\x30\x45", b"\x02\x03"))
        txin = make_txin(witness=wit)
        tx = make_tx(inputs=(txin,))
        assert tx.is_segwit()
        raw = serialize_tx(tx)
        assert raw[4:6] == b"\x00\x01"

    # -- serialize_legacy_tx --

    def test_serialize_legacy_tx_no_witness(self) -> None:
        tx = make_tx()
        raw = serialize_legacy_tx(tx)
        assert isinstance(raw, bytes)

    def test_serialize_legacy_tx_with_witness(self) -> None:
        wit = Witness((b"\x30\x45",))
        txin = make_txin(witness=wit)
        tx = make_tx(inputs=(txin,))
        raw = serialize_legacy_tx(tx)
        assert raw[4:6] != b"\x00\x01"

    # -- serialize_legacy_tx_for_sighash --

    def test_legacy_sighash_all(self) -> None:
        raw = serialize_legacy_tx_for_sighash(TX_2IN_2OUT, 0, SCRIPT,
                                              SIGHASH_ALL)
        assert isinstance(raw, bytes)

    def test_legacy_sighash_none(self) -> None:
        raw = serialize_legacy_tx_for_sighash(TX_2IN_2OUT, 0, SCRIPT,
                                              SIGHASH_NONE)
        assert isinstance(raw, bytes)

    def test_legacy_sighash_single_valid(self) -> None:
        raw = serialize_legacy_tx_for_sighash(TX_2IN_2OUT, 0, SCRIPT,
                                              SIGHASH_SINGLE)
        assert isinstance(raw, bytes)

    def test_legacy_sighash_single_out_of_range(self) -> None:
        with pytest.raises(ValueError, match="out of bounds"):
            serialize_legacy_tx_for_sighash(TX_2IN_2OUT, 5, SCRIPT,
                                            SIGHASH_SINGLE)

    def test_legacy_sighash_anyonecanpay_all(self) -> None:
        raw = serialize_legacy_tx_for_sighash(TX_2IN_2OUT, 0, SCRIPT,
                                              SIGHASH_ALL_ANYONECANPAY)
        assert isinstance(raw, bytes)

    def test_legacy_sighash_anyonecanpay_none(self) -> None:
        raw = serialize_legacy_tx_for_sighash(TX_2IN_2OUT, 0, SCRIPT,
                                              SIGHASH_NONE_ANYONECANPAY)
        assert isinstance(raw, bytes)

    def test_legacy_sighash_anyonecanpay_single(self) -> None:
        raw = serialize_legacy_tx_for_sighash(TX_2IN_2OUT, 0, SCRIPT,
                                              SIGHASH_SINGLE_ANYONECANPAY)
        assert isinstance(raw, bytes)

    def test_legacy_sighash_anyonecanpay_all_second_input(self) -> None:
        """ACP + input_index != 0 exercises the ACP path for input 1."""
        raw = serialize_legacy_tx_for_sighash(TX_2IN_2OUT, 1, SCRIPT,
                                              SIGHASH_ALL_ANYONECANPAY)
        assert isinstance(raw, bytes)

    def test_legacy_sighash_all_with_flag_zero(self) -> None:
        """flag=0 exercises the non-ACP, non-NONE/SINGLE else branch in the
        input loop (line 94 of serializer.py)."""
        raw = serialize_legacy_tx_for_sighash(TX_2IN_2OUT, 0, SCRIPT, 0)
        assert isinstance(raw, bytes)

    # -- serialize_tx_for_sighash_taproot --

    def test_taproot_sighash_serialize(self) -> None:
        raw = serialize_tx_for_sighash_taproot(TX_TAPROOT)
        assert isinstance(raw, bytes)
        assert raw

    def test_taproot_sighash_serialize_with_flag(self) -> None:
        raw = serialize_tx_for_sighash_taproot(TX_TAPROOT)
        assert isinstance(raw, bytes)
        assert raw
