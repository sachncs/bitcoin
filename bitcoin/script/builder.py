"""Script building helpers."""

from __future__ import annotations

from bitcoin.script.opcodes import (
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_0,
    OP_1,
)

from bitcoin.script.parser import serialize_script
from bitcoin.encoding.hasher import hash160


def build_p2pk(public_key_bytes: bytes) -> bytes:
    """Build a Pay-to-Public-Key (P2PK) output script.

    Args:
        public_key_bytes: The raw public key bytes.

    Returns:
        The serialized P2PK script.
    """
    return serialize_script([public_key_bytes, OP_CHECKSIG])


def build_p2pkh(hash160_bytes: bytes) -> bytes:
    """Build a Pay-to-Public-Key-Hash (P2PKH) output script.

    Args:
        hash160_bytes: The 20-byte HASH160 digest of a public key.

    Returns:
        The serialized P2PKH script.

    Raises:
        ValueError: If the hash is not exactly 20 bytes.
    """
    if len(hash160_bytes) != 20:
        raise ValueError("P2PKH requires a 20-byte hash.")
    return serialize_script(
        [OP_DUP, OP_HASH160, hash160_bytes, OP_EQUALVERIFY, OP_CHECKSIG])


def make_p2pkh_script(public_key: bytes) -> bytes:
    """Build a P2PKH scriptPubKey from a full public key (convenience).

    Hashes the public key with HASH160 and returns the serialized script.

    Args:
        public_key: The full public key bytes (33 or 65 bytes).

    Returns:
        The serialized P2PKH script.
    """
    return build_p2pkh(hash160(public_key))
