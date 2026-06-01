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


def build_p2pk(pubkey_bytes: bytes) -> bytes:
    """Build a Pay-to-Public-Key (P2PK) output script.

    Args:
        pubkey_bytes: The raw public key bytes.

    Returns:
        The serialized P2PK script.
    """
    return serialize_script([pubkey_bytes, OP_CHECKSIG])


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


def build_p2wpkh(hash160_bytes: bytes) -> bytes:
    """Build a Pay-to-Witness-Public-Key-Hash (P2WPKH) witness program.

    Args:
        hash160_bytes: The 20-byte HASH160 digest of a public key.

    Returns:
        The serialized P2WPKH script (OP_0 <hash>).

    Raises:
        ValueError: If the hash is not exactly 20 bytes.
    """
    if len(hash160_bytes) != 20:
        raise ValueError("P2WPKH requires a 20-byte hash.")
    return serialize_script([OP_0, hash160_bytes])


def build_p2wsh(sha256_bytes: bytes) -> bytes:
    """Build a Pay-to-Witness-Script-Hash (P2WSH) witness program.

    Args:
        sha256_bytes: The 32-byte SHA256 hash of a witness script.

    Returns:
        The serialized P2WSH script (OP_0 <hash>).

    Raises:
        ValueError: If the hash is not exactly 32 bytes.
    """
    if len(sha256_bytes) != 32:
        raise ValueError("P2WSH requires a 32-byte hash.")
    return serialize_script([OP_0, sha256_bytes])


def build_p2sh(script_bytes: bytes) -> bytes:
    """Build a Pay-to-Script-Hash (P2SH) output script.

    Args:
        script_bytes: The redeem script bytes (will be HASH160'd).

    Returns:
        The serialized P2SH script (OP_HASH160 <20-byte hash> OP_EQUAL).
    """
    digest = hash160(script_bytes)
    return serialize_script([OP_HASH160, digest, OP_EQUAL])


def build_p2tr(x_only_bytes: bytes) -> bytes:
    """Build a Pay-to-Taproot (P2TR) output script.

    Args:
        x_only_bytes: The 32-byte x-only public key.

    Returns:
        The serialized P2TR script (OP_1 <key>).

    Raises:
        ValueError: If the key is not exactly 32 bytes.
    """
    if len(x_only_bytes) != 32:
        raise ValueError("P2TR requires a 32-byte x-only public key.")
    return serialize_script([OP_1, x_only_bytes])


def make_p2pkh_script(pubkey: bytes) -> bytes:
    """Build a P2PKH scriptPubKey from a full public key.

    Hashes the public key with HASH160 and returns the serialized script
    using raw opcode bytes (OP_DUP OP_HASH160 <20 bytes>
    OP_EQUALVERIFY OP_CHECKSIG).

    Args:
        pubkey: The full public key bytes.

    Returns:
        The serialized P2PKH script.
    """
    digest = hash160(pubkey)
    return b"\x76\xa9\x14" + digest + b"\x88\xac"
