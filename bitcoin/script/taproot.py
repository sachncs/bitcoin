"""Taproot script-path support for parsing and extracting script spends.

Provides structured parsing of Taproot witness stacks and helpers for
extracting x-only public keys from P2TR scriptPubKeys.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bitcoin.signature.record import Record


@dataclass(frozen=True, slots=True)
class TaprootScriptPath:
    """A parsed Taproot script path spend.

    Attributes:
        script: The leaf script being executed.
        control_block: The control block that proves inclusion in the
            taproot tree.
        sigs: Schnorr signatures in the witness stack for this leaf.
    """

    script: bytes
    control_block: bytes
    sigs: tuple[bytes, ...]


def parse_taproot_witness_stack(
    witness_items: tuple[bytes, ...],) -> list[TaprootScriptPath] | None:
    """Parse a Taproot witness stack into script path spends.

    The last witness item is the control block.  The second-to-last item
    is the leaf script.  All items before the leaf script that are 64 or
    65 bytes long are treated as signatures for that leaf.

    Args:
        witness_items: The witness stack items from a Taproot input.

    Returns:
        A list of ``TaprootScriptPath`` for a script-path spend, or
        ``None`` if this is a key-path spend (single witness item).
    """
    if not witness_items or len(witness_items) < 2:
        return None

    # Single item = key-path spend
    if len(witness_items) == 1:
        return None

    control_block = witness_items[-1]
    leaf_script = witness_items[-2]

    sigs: list[bytes] = []
    for i in range(len(witness_items) - 2):
        item = witness_items[i]
        if len(item) in (64, 65):
            sigs.append(item[:64])

    return [
        TaprootScriptPath(
            script=leaf_script,
            control_block=control_block,
            sigs=tuple(sigs),
        )
    ]


def extract_taproot_scripts(records: list[Record]) -> list[Record]:
    """Post-process Taproot records to expand script-path sigs.

    This is a placeholder that returns *records* unchanged.  To obtain
    structured script-path information from raw witness data, use
    ``parse_taproot_witness_stack``.

    Args:
        records: A list of ``Record`` instances from
            ``extract_signatures``.

    Returns:
        The same list of *records* (identity transform).
    """
    return list(records)


P2TR_SCRIPT_LENGTH = 34
P2TR_OP_1_BYTE = 0x51
P2TR_PUSH_32_BYTE = 0x20


def get_x_only_pubkey(script_pubkey: bytes) -> bytes | None:
    """Extract the 32-byte x-only public key from a P2TR output.

    A standard P2TR scriptPubKey is 34 bytes:
    ``0x51 0x20 <32-byte-xonly>``.

    Args:
        script_pubkey: The P2TR ``scriptPubKey``.

    Returns:
        The 32-byte x-only public key, or ``None`` if the script does
        not match the P2TR format.
    """
    if (len(script_pubkey) == P2TR_SCRIPT_LENGTH and
            script_pubkey[0] == P2TR_OP_1_BYTE and
            script_pubkey[1] == P2TR_PUSH_32_BYTE):
        return script_pubkey[2:P2TR_SCRIPT_LENGTH]
    return None
