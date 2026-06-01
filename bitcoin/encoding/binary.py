"""Binary serialization helpers for byte-level encoding and decoding."""
from __future__ import annotations

from typing import Iterator, Literal


def bytes_to_int(data: bytes,
                 byteorder: Literal["big", "little"] = "big") -> int:
    """Convert bytes to an integer.

    Args:
        data: Bytes to convert.
        byteorder: Byte order of *data* (``"big"`` or ``"little"``).

    Returns:
        Integer representation of *data*.
    """
    return int.from_bytes(data, byteorder)


def int_to_bytes(value: int,
                 length: int,
                 byteorder: Literal["big", "little"] = "big") -> bytes:
    """Convert an integer to a fixed-length byte string.

    Args:
        value: Integer to convert.
        length: Length of the output in bytes.
        byteorder: Byte order (``"big"`` or ``"little"``).

    Returns:
        Fixed-length byte string of *length* bytes.
    """
    return value.to_bytes(length, byteorder)


def read_exactly(stream: bytes, n: int, offset: int = 0) -> tuple[bytes, int]:
    """Read exactly *n* bytes from a stream at a given offset.

    Args:
        stream: Source byte string.
        n: Number of bytes to read.
        offset: Starting position within *stream*.

    Returns:
        Tuple of ``(chunk, new_offset)`` where *chunk* is the
        requested *n* bytes and *new_offset* = *offset* + *n*.

    Raises:
        ValueError: If *stream* does not contain *n* bytes starting
            at *offset*.
    """
    if offset + n > len(stream):
        raise ValueError(
            f"Requested {n} bytes at offset {offset} but stream only "
            f"has {len(stream)} bytes.")
    return stream[offset:offset + n], offset + n


def iter_bytes(data: bytes, chunk_size: int) -> Iterator[bytes]:
    """Yield fixed-size slices of a byte string.

    Args:
        data: Byte string to slice.
        chunk_size: Size of each yielded slice.

    Yields:
        Consecutive non-overlapping slices of *data*, each
        *chunk_size* bytes long. The last slice may be shorter.
    """
    for i in range(0, len(data), chunk_size):
        yield data[i:i + chunk_size]
