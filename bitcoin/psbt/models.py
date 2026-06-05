"""Frozen dataclass models for PSBT (BIP-174) structures."""

from __future__ import annotations

from dataclasses import dataclass, field


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
                f"{len(self.inputs)} inputs vs {len(self.outputs)} outputs.")
