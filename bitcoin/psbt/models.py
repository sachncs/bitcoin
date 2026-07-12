# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Frozen dataclass models for PSBT (BIP-174) structures.

Defines :class:`Psbt`, :class:`PsbtInput`, and :class:`PsbtOutput`
— the in-memory representation of a BIP-174 Partially Signed Bitcoin
Transaction.

Design notes:

- ``frozen=True, slots=True`` everywhere: PSBTs are routinely
  compared and hashed, and the slot optimisation matters when
  parsing large files.
- All fields are stored as raw ``bytes`` (not parsed structures), so
  round-tripping is bit-exact and unknown fields are preserved in
  the ``unknown`` dicts for forward compatibility with new BIP-174
  extensions (Taproot, etc.).
- :meth:`Psbt.__post_init__` validates that the input and output
  counts match (a structural BIP-174 invariant that prevents the
  silent data loss that would result from truncating one side).
- The :meth:`PsbtInput.serialize` / :meth:`PsbtOutput.serialize` /
  :meth:`Psbt.serialize` methods are thin convenience wrappers
  around the parser module's serialisation functions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bitcoin.signature.collection import SignatureCollection


@dataclass(frozen=True, slots=True)
class PsbtInput:
    """Per-input map in a PSBT (BIP-174).

    Attributes:
        non_witness_utxo: Raw non-witness UTXO (full previous tx).
        witness_utxo: Raw witness UTXO (txid, vout, value, scriptPubKey).
        partial_sigs: Mapping of ``{pubkey_bytes: sig_bytes}``.
        sighash_type: Sighash flag integer.
        redeem_script: Redeem script for P2SH.
        witness_script: Witness script for P2WSH.
        bip32_derivations: Mapping of ``{pubkey_bytes: keypath_bytes}``.
        final_script_sig: Finalized ``scriptSig``.
        final_script_witness: Finalized witness stack items.
        proprietary: Proprietary key-value pairs.
        unknown: Unknown key-value pairs.
    """

    non_witness_utxo: bytes | None = None
    witness_utxo: bytes | None = None
    partial_sigs: dict[bytes, bytes] = field(default_factory=dict)
    sighash_type: int | None = None
    redeem_script: bytes | None = None
    witness_script: bytes | None = None
    bip32_derivations: dict[bytes, bytes] = field(default_factory=dict)
    final_script_sig: bytes | None = None
    final_script_witness: tuple[bytes, ...] | None = None
    proprietary: dict[bytes, bytes] = field(default_factory=dict)
    unknown: dict[bytes, bytes] = field(default_factory=dict)

    def serialize(self) -> bytes:
        """Serialize this input map to its PSBT wire format.

        Returns:
            The serialized input map bytes.
        """
        from bitcoin.psbt.parser import serialize_input_map

        return serialize_input_map(self)


@dataclass(frozen=True, slots=True)
class PsbtOutput:
    """Per-output map in a PSBT (BIP-174).

    Attributes:
        redeem_script: Redeem script for P2SH.
        witness_script: Witness script for P2WSH.
        bip32_derivations: Mapping of ``{pubkey_bytes: keypath_bytes}``.
        proprietary: Proprietary key-value pairs.
        unknown: Unknown key-value pairs.
    """

    redeem_script: bytes | None = None
    witness_script: bytes | None = None
    bip32_derivations: dict[bytes, bytes] = field(default_factory=dict)
    proprietary: dict[bytes, bytes] = field(default_factory=dict)
    unknown: dict[bytes, bytes] = field(default_factory=dict)

    def serialize(self) -> bytes:
        """Serialize this output map to its PSBT wire format.

        Returns:
            The serialized output map bytes.
        """
        from bitcoin.psbt.parser import serialize_output_map

        return serialize_output_map(self)


@dataclass(frozen=True, slots=True)
class Psbt:
    """A Partially Signed Bitcoin Transaction (BIP-174).

    Attributes:
        tx: Raw unsigned transaction bytes.
        inputs: Tuple of per-input maps.
        outputs: Tuple of per-output maps.
        unknown: Unknown global key-value pairs.
    """

    tx: bytes
    inputs: tuple[PsbtInput, ...]
    outputs: tuple[PsbtOutput, ...]
    unknown: dict[bytes, bytes] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate that input and output counts match.

        Raises:
            ValueError: If ``len(inputs) != len(outputs)``.
        """
        if len(self.inputs) != len(self.outputs):
            raise ValueError(
                f"Mismatched input/output count in PSBT: "
                f"{len(self.inputs)} inputs vs {len(self.outputs)} outputs."
            )

    def serialize(self) -> bytes:
        """Serialize this PSBT to its binary wire format (BIP-174).

        Returns:
            The serialized PSBT bytes.
        """
        from bitcoin.psbt.parser import serialize_psbt

        return serialize_psbt(self)

    def extract_signatures(
        self,
        *,
        input_values: list[int] | None = None,
    ) -> SignatureCollection:
        """Extract ECDSA signatures from PSBT partial signatures.

        Args:
            input_values: Optional per-input UTXO values in satoshis.

        Returns:
            A ``SignatureCollection`` containing all extracted records.
        """
        from bitcoin.psbt.parser import psbt_extract_signatures

        return psbt_extract_signatures(self, input_values=input_values)
