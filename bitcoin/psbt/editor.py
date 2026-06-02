"""Fluent builder for constructing and editing PSBTs (BIP-174).

Provides ``PsbtEditor`` for programmatic creation and modification of
``Psbt`` instances.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Self

from bitcoin.psbt.models import Psbt, PsbtInput, PsbtOutput
from bitcoin.transaction.parser import parse_tx


@dataclass
class MutableInput:
    """Mutable analogue of ``PsbtInput`` for incremental construction."""

    non_witness_utxo: bytes | None = None
    witness_utxo: bytes | None = None
    partial_sigs: dict[bytes, bytes] = field(default_factory=dict)
    sighash_type: int | None = None
    redeem_script: bytes | None = None
    witness_script: bytes | None = None
    bip32_derivations: dict[bytes, bytes] = field(default_factory=dict)
    final_script_sig: bytes | None = None
    final_script_witness: tuple[bytes, ...] | None = None


@dataclass
class MutableOutput:
    """Mutable analogue of ``PsbtOutput`` for incremental construction."""

    redeem_script: bytes | None = None
    witness_script: bytes | None = None
    bip32_derivations: dict[bytes, bytes] = field(default_factory=dict)


class PsbtEditor:
    """Fluent builder for constructing and editing PSBTs.

    Use :meth:`from_tx` to create an editor from an unsigned transaction,
    or construct directly from an existing ``Psbt``.
    """

    def __init__(self, psbt: Psbt) -> None:
        """Initialize the editor from an existing ``Psbt``.

        Args:
            psbt: A ``Psbt`` instance to edit.
        """
        self.tx: bytes = psbt.tx
        self.unknown: dict[bytes, bytes] = dict(psbt.unknown)
        self.inputs: list[MutableInput] = [
            MutableInput(
                non_witness_utxo=inp.non_witness_utxo,
                witness_utxo=inp.witness_utxo,
                partial_sigs=dict(inp.partial_sigs),
                sighash_type=inp.sighash_type,
                redeem_script=inp.redeem_script,
                witness_script=inp.witness_script,
                bip32_derivations=dict(inp.bip32_derivations),
                final_script_sig=inp.final_script_sig,
                final_script_witness=inp.final_script_witness,
            ) for inp in psbt.inputs
        ]
        self.outputs: list[MutableOutput] = [
            MutableOutput(
                redeem_script=out.redeem_script,
                witness_script=out.witness_script,
                bip32_derivations=dict(out.bip32_derivations),
            ) for out in psbt.outputs
        ]

    @staticmethod
    def from_tx(tx: bytes) -> PsbtEditor:
        """Create a ``PsbtEditor`` from an unsigned transaction.

        Args:
            tx: Raw unsigned transaction bytes.

        Returns:
            A new ``PsbtEditor`` initialised with empty input/output maps.
        """
        parsed_tx, _ = parse_tx(tx)
        num_inputs = len(parsed_tx.inputs)
        num_outputs = len(parsed_tx.outputs)

        psbt = Psbt(
            tx=tx,
            inputs=tuple(PsbtInput() for _ in range(num_inputs)),
            outputs=tuple(PsbtOutput() for _ in range(num_outputs)),
        )
        return PsbtEditor(psbt)

    def set_input_utxo(
        self,
        vin: int,
        *,
        non_witness_utxo: bytes | None = None,
        witness_utxo: bytes | None = None,
    ) -> Self:
        """Set the UTXO data for a given input.

        Args:
            vin: Input index.
            non_witness_utxo: Raw non-witness UTXO (full previous tx).
            witness_utxo: Raw witness UTXO (value + scriptPubKey).

        Returns:
            ``self`` for chaining.
        """
        inp = self.inputs[vin]
        if non_witness_utxo is not None:
            inp.non_witness_utxo = non_witness_utxo
        if witness_utxo is not None:
            inp.witness_utxo = witness_utxo
        return self

    def set_input_redeem_script(self, vin: int, script: bytes) -> Self:
        """Set the redeem script for a PSBT input.

        Args:
            vin: Input index.
            script: Redeem script bytes.

        Returns:
            ``self`` for chaining.
        """
        self.inputs[vin].redeem_script = script
        return self

    def set_input_witness_script(self, vin: int, script: bytes) -> Self:
        """Set the witness script for a PSBT input.

        Args:
            vin: Input index.
            script: Witness script bytes.

        Returns:
            ``self`` for chaining.
        """
        self.inputs[vin].witness_script = script
        return self

    def set_input_sighash_type(self, vin: int, flag: int) -> Self:
        """Set the sighash type for a PSBT input.

        Args:
            vin: Input index.
            flag: Sighash flag integer.

        Returns:
            ``self`` for chaining.
        """
        self.inputs[vin].sighash_type = flag
        return self

    def add_input_partial_sig(self, vin: int, pubkey: bytes,
                              sig: bytes) -> Self:
        """Add a partial signature for a PSBT input.

        Args:
            vin: Input index.
            pubkey: Public key bytes.
            sig: Signature bytes (DER + sighash byte).

        Returns:
            ``self`` for chaining.
        """
        self.inputs[vin].partial_sigs[pubkey] = sig
        return self

    def set_output_redeem_script(self, vout: int, script: bytes) -> Self:
        """Set the redeem script for a PSBT output.

        Args:
            vout: Output index.
            script: Redeem script bytes.

        Returns:
            ``self`` for chaining.
        """
        self.outputs[vout].redeem_script = script
        return self

    def set_output_witness_script(self, vout: int, script: bytes) -> Self:
        """Set the witness script for a PSBT output.

        Args:
            vout: Output index.
            script: Witness script bytes.

        Returns:
            ``self`` for chaining.
        """
        self.outputs[vout].witness_script = script
        return self

    def finalize_input(
        self,
        vin: int,
        *,
        final_script_sig: bytes | None = None,
        final_witness: tuple[bytes, ...] | None = None,
    ) -> Self:
        """Finalize a PSBT input with concrete script/witness data.

        Args:
            vin: Input index.
            final_script_sig: Final ``scriptSig`` bytes.
            final_witness: Final witness stack items.

        Returns:
            ``self`` for chaining.
        """
        inp = self.inputs[vin]
        if final_script_sig is not None:
            inp.final_script_sig = final_script_sig
        if final_witness is not None:
            inp.final_script_witness = final_witness
        return self

    def build(self) -> Psbt:
        """Construct and return the final ``Psbt``.

        Returns:
            A new frozen ``Psbt`` instance reflecting all edits.
        """
        inputs = tuple(
            PsbtInput(
                non_witness_utxo=inp.non_witness_utxo,
                witness_utxo=inp.witness_utxo,
                partial_sigs=dict(inp.partial_sigs),
                sighash_type=inp.sighash_type,
                redeem_script=inp.redeem_script,
                witness_script=inp.witness_script,
                bip32_derivations=dict(inp.bip32_derivations),
                final_script_sig=inp.final_script_sig,
                final_script_witness=inp.final_script_witness,
            ) for inp in self.inputs)
        outputs = tuple(
            PsbtOutput(
                redeem_script=out.redeem_script,
                witness_script=out.witness_script,
                bip32_derivations=dict(out.bip32_derivations),
            ) for out in self.outputs)
        return Psbt(
            tx=self.tx,
            inputs=inputs,
            outputs=outputs,
            unknown=dict(self.unknown),
        )
