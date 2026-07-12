# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Hash-function wrappers used throughout Bitcoin.

Thin convenience wrappers around ``hashlib`` for the four hash
functions that appear in every Bitcoin protocol:

- :func:`sha256` – plain SHA-256.
- :func:`hash256` – double SHA-256, used for transaction IDs (txid /
  wtxid) and block headers.
- :func:`hash160` – SHA-256 followed by RIPEMD-160, used wherever
  Bitcoin wants a 20-byte address-style digest (legacy address hashes,
  P2SH script hashes, witness program hashes).
- :func:`tagged_hash` – the BIP-340 domain-separated hash used by
  Taproot and Schnorr.

All functions return raw ``bytes`` rather than hex strings so they can
be used directly as inputs to further hashing or as message digests.
"""

import hashlib


def sha256(data: bytes) -> bytes:
    """Return the SHA-256 digest of *data*.

    Args:
        data: Input bytes to hash.

    Returns:
        32-byte SHA-256 digest.
    """
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    """Return the double-SHA-256 digest of *data* (SHA-256 applied twice).

    This is used for transaction hashing (txid, wtxid).

    Args:
        data: Input bytes to hash.

    Returns:
        32-byte double-SHA-256 digest.
    """
    return sha256(sha256(data))


def hash160(data: bytes) -> bytes:
    """Return the HASH-160 digest (SHA-256 followed by RIPEMD-160).

    Args:
        data: Input bytes to hash.

    Returns:
        20-byte HASH-160 digest.
    """
    return hashlib.new("ripemd160", sha256(data)).digest()


def tagged_hash(tag: str, data: bytes) -> bytes:
    """Return the BIP-340 tagged hash.

    Computes ``SHA256(SHA256(tag) || SHA256(tag) || data)``.
    Used for Taproot signing.

    Args:
        tag: Domain-separation tag string.
        data: Input bytes to hash.

    Returns:
        32-byte tagged hash.
    """
    tag_hash = sha256(tag.encode())
    return sha256(tag_hash + tag_hash + data)
