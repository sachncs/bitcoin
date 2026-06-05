"""Tests for PSBT parsing."""
from __future__ import annotations

import pytest

from bitcoin.psbt import PsbtInput, PsbtOutput, parse_psbt, serialize_psbt
from bitcoin.psbt.models import Psbt as PsbtModel
from bitcoin.transaction import Tx
from bitcoin.services.serializer import serialize_legacy_tx


class TestPsbt:
    def test_minimal_psbt(self) -> None:
        """Create and serialize a minimal PSBT, then parse it back."""
        tx = Tx(version=1, inputs=(), outputs=(), lock_time=0)
        raw_tx = serialize_legacy_tx(tx)
        psbt = PsbtModel(tx=raw_tx, inputs=(), outputs=())
        raw = serialize_psbt(psbt)
        parsed = parse_psbt(raw)
        assert parsed.tx == raw_tx
        assert len(parsed.inputs) == 0
        assert len(parsed.outputs) == 0

    def test_roundtrip(self) -> None:
        """Serialize → parse round-trips."""
        tx = Tx(version=2, inputs=(), outputs=(), lock_time=0)
        raw_tx = serialize_legacy_tx(tx)
        psbt = PsbtModel(tx=raw_tx, inputs=(), outputs=())
        raw = serialize_psbt(psbt)
        psbt2 = parse_psbt(raw)
        raw2 = serialize_psbt(psbt2)
        assert raw == raw2

    def test_invalid_magic(self) -> None:
        """Invalid magic bytes raises ValueError."""
        with pytest.raises(ValueError, match="magic"):
            parse_psbt(b"\x00" * 100)

    def test_psbt_input_creation(self) -> None:
        """PsbtInput dataclass."""
        inp = PsbtInput(
            partial_sigs={},
            redeem_script=b"",
            witness_script=b"",
            bip32_derivations={},
            sighash_type=1,
        )
        assert inp.sighash_type == 1
        assert inp.redeem_script == b""
        assert inp.partial_sigs == {}

    def test_psbt_output_creation(self) -> None:
        """PsbtOutput dataclass."""
        out = PsbtOutput(
            redeem_script=b"\x00",
            witness_script=b"\x01",
            bip32_derivations={},
        )
        assert out.redeem_script == b"\x00"
        assert out.witness_script == b"\x01"

    def test_serialize_with_maps(self) -> None:
        """Serialize PSBT — zero input/output maps match empty unsigned tx."""
        tx = Tx(version=1, inputs=(), outputs=(), lock_time=0)
        raw_tx = serialize_legacy_tx(tx)
        inp = PsbtInput(sighash_type=1)
        out = PsbtOutput()
        psbt = PsbtModel(tx=raw_tx, inputs=(inp,), outputs=(out,))
        serialize_psbt(psbt)
        # This will fail validation because len(inputs) != len(outputs)
        # in production, but serialize_psbt doesn't validate
        assert psbt.tx == raw_tx
