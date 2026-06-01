"""Bitcoin variable-length integer (``varint``) encoding."""

from typing import Tuple


def encode_varint(value: int) -> bytes:
    """Encode an integer as a Bitcoin variable-length integer.

    Uses 1, 3, 5, or 9 bytes depending on *value*'s magnitude.

    Args:
        value: Non-negative integer to encode.

    Returns:
        Varint-encoded bytes (little-endian multi-byte segments).

    Raises:
        TypeError: If *value* is not ``int``.
        ValueError: If *value* is negative.
    """
    if value < 0:
        raise ValueError(f"Cannot encode negative varint: {value}.")
    if value < 0xFD:
        return value.to_bytes(1, "little")
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def decode_varint(stream: bytes, offset: int = 0) -> Tuple[int, int]:
    """Decode a Bitcoin variable-length integer from a byte stream.

    Args:
        stream: Source byte string.
        offset: Starting position of the varint.

    Returns:
        Tuple of ``(value, new_offset)`` where *new_offset* points
        past the decoded varint.

    Raises:
        ValueError: If the stream is truncated before the varint
            can be fully read.
    """
    if offset >= len(stream):
        raise ValueError("Truncated varint stream.")
    prefix = stream[offset]
    if prefix < 0xFD:
        return prefix, offset + 1
    if prefix == 0xFD:
        needed = offset + 3
        if len(stream) < needed:
            raise ValueError("Truncated varint stream.")
        n = int.from_bytes(stream[offset + 1:needed], "little")
        return n, needed
    if prefix == 0xFE:
        needed = offset + 5
        if len(stream) < needed:
            raise ValueError("Truncated varint stream.")
        n = int.from_bytes(stream[offset + 1:needed], "little")
        return n, needed
    needed = offset + 9
    if len(stream) < needed:
        raise ValueError("Truncated varint stream.")
    n = int.from_bytes(stream[offset + 1:needed], "little")
    return n, needed
