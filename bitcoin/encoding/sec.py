# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""SEC-format public-key parsing and serialization.

Implements the SEC-1 compact binary encodings for elliptic-curve
public keys:

- **Compressed** (33 bytes): a single header byte (``0x02`` for even
  ``y``, ``0x03`` for odd ``y``) followed by the big-endian
  ``x``-coordinate.  The ``y`` coordinate is recovered on parse by
  solving the curve equation and selecting the appropriate root.
- **Uncompressed** (65 bytes): a single ``0x04`` header byte followed
  by the full ``(x, y)`` pair, both big-endian.

Both parse helpers validate that the decoded point satisfies the
curve equation, rejecting malformed or off-curve encodings early.
Both are also LRU-cached, because the same public key is frequently
looked up many times during signature extraction.
"""

from functools import lru_cache
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bitcoin.curve.point import Point


@lru_cache(maxsize=1024)
def parse_sec(data: bytes) -> "Point":
    """Parse a SEC-encoded public key into a ``Point``.

    Supports both compressed (33-byte, prefix ``0x02`` or ``0x03``)
    and uncompressed (65-byte, prefix ``0x04``) formats.

    Args:
        data: SEC-encoded public key bytes.

    Returns:
        ``Point`` instance on the secp256k1 curve.

    Raises:
        ValueError: If the data length is invalid, the prefix byte is
            unrecognized, or the decoded point is not on the curve.
    """
    from bitcoin.curve.point import Point

    if len(data) == 33 and data[0] in (0x02, 0x03):
        point = Point.from_sec_compressed(data)
    elif len(data) == 65 and data[0] == 0x04:
        point = Point.from_sec_uncompressed(data)
    else:
        raise ValueError(
            f"Invalid SEC key length {len(data)} (expected 33 or 65 bytes)."
        )

    from bitcoin.curve.operations import is_on_curve

    if not is_on_curve(point):
        raise ValueError("Decoded point is not on the secp256k1 curve.")
    return point


@lru_cache(maxsize=1024)
def serialize_sec(point: "Point", compressed: bool = True) -> bytes:
    """Serialize a ``Point`` to SEC format.

    Args:
        point: Point on the secp256k1 curve.
        compressed: If ``True``, produce 33-byte compressed encoding;
            otherwise produce 65-byte uncompressed encoding.

    Returns:
        SEC-encoded public key bytes.

    Raises:
        ValueError: If *point* is the point at infinity.
    """
    if point.infinity:
        raise ValueError("Cannot serialize point at infinity.")
    if compressed:
        return point.to_sec_compressed()
    return point.to_sec_uncompressed()
