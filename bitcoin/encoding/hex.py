# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Hexadecimal encoding/decoding helpers.

The two functions here simply wrap the ``bytes.hex()`` /
``bytes.fromhex()`` methods so the rest of the codebase can refer to a
single, project-wide entry point.  Centralising these calls makes it
easy to swap in a faster hex codec (e.g. ``binascii.hexlify`` or a
third-party library) if profiling demands it.
"""


def encode_hex(data: bytes) -> str:
    """Encode bytes as a hexadecimal string.

    Args:
        data: The bytes to encode.

    Returns:
        The hex-encoded string.

    Raises:
        AttributeError: If *data* is not bytes (delegates to ``data.hex()``).
    """
    return data.hex()


def decode_hex(hex_str: str) -> bytes:
    """Decode a hex string to bytes.

    Args:
        hex_str: Hex-encoded string.

    Returns:
        Decoded bytes.

    Raises:
        TypeError: If *hex_str* is not ``str``.
        ValueError: If the string has an odd length or contains
            non-hex characters.
    """
    return bytes.fromhex(hex_str)
