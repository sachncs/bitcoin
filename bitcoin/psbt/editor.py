"""Fluent builder for constructing and editing PSBTs (BIP-174).

Provides ``PsbtEditor`` for programmatic creation, signing, and
finalization of ``Psbt`` instances.
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

    def add_input_partial_sig(self, vin: int, pubkey: bytes, sig: bytes) -> Self:
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

    def sign_input(
        self,
        vin: int,
        private_key: int,
        *,
        pubkey: bytes | None = None,
        sighash_flag: int | None = None,
    ) -> Self:
        """Sign a PSBT input with a private key.

        Parses the unsigned transaction, determines the script code and
        value from the PSBT input data, signs the input, and stores the
        resulting signature in ``partial_sigs``.

        Args:
            vin: Input index to sign.
            private_key: Private key as an integer.
            pubkey: Public key bytes.  If ``None``, derived from
                *private_key* via multiplication with GENERATOR.
            sighash_flag: Sighash flag.  If ``None``, uses the input's
                ``sighash_type`` or defaults to ``SIGHASH_ALL``.

        Returns:
            ``self`` for chaining.
        """
        from bitcoin.curve import GENERATOR, multiply
        from bitcoin.sighash.flag import SIGHASH_ALL
        from bitcoin.signature.signer import sign_tx_input

        tx, _ = parse_tx(self.tx)
        inp = self.inputs[vin]

        flag = sighash_flag if sighash_flag is not None else (
            inp.sighash_type if inp.sighash_type is not None else SIGHASH_ALL)

        # Determine the script code from the PSBT input data.
        script_code = b""
        value = 0

        if inp.witness_script is not None:
            script_code = inp.witness_script
        elif inp.redeem_script is not None:
            script_code = inp.redeem_script
        else:
            # Derive the script code from the witness_utxo scriptPubKey
            if inp.witness_utxo is not None:
                from bitcoin.encoding.varint import decode_varint
                offset = 0
                value, offset = decode_varint(inp.witness_utxo, offset)
                script_pubkey_len, offset = decode_varint(inp.witness_utxo, offset)
                script_pubkey = inp.witness_utxo[offset:offset + script_pubkey_len]
                from bitcoin.script.classifier import classify_script_pubkey
                st = classify_script_pubkey(script_pubkey)
                if st in ("p2wpkh", "p2sh"):
                    from bitcoin.script.builder import build_p2pkh
                    script_code = build_p2pkh(script_pubkey[-20:])
                else:
                    script_code = script_pubkey

        if pubkey is None:
            pubkey_point = multiply(private_key, GENERATOR)
            from bitcoin.curve import serialize_public_key
            pubkey = serialize_public_key(pubkey_point)

        sig = sign_tx_input(tx, vin, private_key, script=script_code,
                            value=value, sighash_flag=flag)
        inp.partial_sigs[pubkey] = sig
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
