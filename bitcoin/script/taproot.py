# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Taproot script-path support for parsing and extracting script spends.

Provides structured parsing of Taproot witness stacks, control block
parsing, and helpers for extracting x-only public keys from P2TR
scriptPubKeys.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from bitcoin.encoding.hasher import tagged_hash

if TYPE_CHECKING:
    from bitcoin.signature.record import Record


# Control block structure: parity byte (1) + internal key (32) + merkle path (n * 32)
CONTROL_BLOCK_MIN_SIZE = 33  # 1 + 32
CONTROL_BLOCK_LEAF_MARKER = 0xC0  # bit 1 set for leaf version


@dataclass(frozen=True, slots=True)
class TaprootScriptPath:
    """A parsed Taproot script path spend.

    Attributes:
        script: The leaf script being executed.
        control_block: The control block that proves inclusion in the
            taproot tree.
        sigs: Schnorr signatures in the witness stack for this leaf.
        leaf_version: The leaf version byte from the control block.
        internal_key: The 32-byte x-only internal public key.
        merkle_path: The merkle proof (list of 32-byte hashes).
    """

    script: bytes
    control_block: bytes
    sigs: tuple[bytes, ...]
    leaf_version: int = 0
    internal_key: bytes = b""
    merkle_path: tuple[bytes, ...] = ()


@dataclass(frozen=True, slots=True)
class TaprootControlBlock:
    """Parsed Taproot control block.

    Attributes:
        parity: The parity byte (0x00 or 0x01).
        internal_key: The 32-byte x-only internal public key.
        merkle_path: The merkle proof hashes.
        leaf_version: The leaf version (extracted from parity byte).
        is_leaf: Whether this control block is for a leaf spend.
    """

    parity: int
    internal_key: bytes
    merkle_path: tuple[bytes, ...]
    leaf_version: int
    is_leaf: bool


def parse_control_block(control_block: bytes) -> TaprootControlBlock | None:
    """Parse a Taproot control block into its components.

    A control block has the structure:
    - 1 byte: parity (bit 0) + leaf version (bits 1-7)
    - 32 bytes: internal key
    - n * 32 bytes: merkle path

    Args:
        control_block: The raw control block bytes.

    Returns:
        A ``TaprootControlBlock`` or ``None`` if the control block
        is too small.
    """
    if len(control_block) < CONTROL_BLOCK_MIN_SIZE:
        return None

    parity = control_block[0] & 0x01
    leaf_version = control_block[0] & 0xFE
    is_leaf = (
        (control_block[0] & CONTROL_BLOCK_LEAF_MARKER) == CONTROL_BLOCK_LEAF_MARKER
    )
    internal_key = control_block[1:33]

    merkle_path = []
    offset = 33
    while offset + 32 <= len(control_block):
        merkle_path.append(control_block[offset : offset + 32])
        offset += 32

    return TaprootControlBlock(
        parity=parity,
        internal_key=internal_key,
        merkle_path=tuple(merkle_path),
        leaf_version=leaf_version,
        is_leaf=is_leaf,
    )


def compute_tapleaf_hash(script: bytes, leaf_version: int = 0xC0) -> bytes:
    """Compute the tapleaf hash for a script.

    The tapleaf hash is ``tagged_hash("TapLeaf", version || len || script)``.

    Args:
        script: The leaf script.
        leaf_version: The leaf version byte (default 0xC0).

    Returns:
        The 32-byte tapleaf hash.
    """
    script_len = len(script)
    if script_len < 0xFD:
        compact_len = bytes([script_len])
    elif script_len <= 0xFFFF:
        compact_len = bytes([0xFD]) + script_len.to_bytes(2, "little")
    else:
        compact_len = bytes([0xFE]) + script_len.to_bytes(4, "little")

    leaf_data = bytes([leaf_version]) + compact_len + script
    return tagged_hash("TapLeaf", leaf_data)


def compute_tweak(internal_key: bytes, merkle_root: bytes) -> bytes:
    """Compute the Taproot output key tweak.

    The tweak is ``tagged_hash("TapTweak", internal_key || merkle_root)``.

    Args:
        internal_key: The 32-byte x-only internal public key.
        merkle_root: The 32-byte merkle root (or empty for key-path only).

    Returns:
        The 32-byte tweak value.
    """
    data = internal_key + merkle_root
    return tagged_hash("TapTweak", data)


def is_valid_leaf_version(version: int) -> bool:
    """Check if a byte is a valid taproot leaf version.

    Valid leaf versions have bit 0 set (odd) and the remaining bits
    specify the leaf version. The current standard is 0xC0.

    Args:
        version: The leaf version byte.

    Returns:
        True if the version is valid.
    """
    return (version & 0x01) == 0x00


def parse_taproot_witness_stack(
    witness_items: tuple[bytes, ...],
) -> list[TaprootScriptPath] | None:
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

    # Parse control block for additional info
    cb = parse_control_block(control_block)
    leaf_version = cb.leaf_version if cb else 0
    internal_key = cb.internal_key if cb else b""
    merkle_path = cb.merkle_path if cb else ()

    return [
        TaprootScriptPath(
            script=leaf_script,
            control_block=control_block,
            sigs=tuple(sigs),
            leaf_version=leaf_version,
            internal_key=internal_key,
            merkle_path=merkle_path,
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
    if (
        len(script_pubkey) == P2TR_SCRIPT_LENGTH
        and script_pubkey[0] == P2TR_OP_1_BYTE
        and script_pubkey[1] == P2TR_PUSH_32_BYTE
    ):
        return script_pubkey[2:P2TR_SCRIPT_LENGTH]
    return None


def is_key_path_spend(witness_items: tuple[bytes, ...]) -> bool:
    """Check if a witness stack represents a key-path spend.

    Key-path spends have a single witness item containing the 64-byte
    Schnorr signature.

    Args:
        witness_items: The witness stack items.

    Returns:
        True if this is a key-path spend.
    """
    return len(witness_items) == 1


def get_key_path_signature(witness_items: tuple[bytes, ...]) -> bytes | None:
    """Extract the Schnorr signature from a key-path spend.

    Args:
        witness_items: The witness stack items.

    Returns:
        The 64-byte Schnorr signature, or ``None`` if not a key-path
        spend.
    """
    if not is_key_path_spend(witness_items):
        return None
    sig = witness_items[0]
    if len(sig) in (64, 65):
        return sig[:64]
    return None
