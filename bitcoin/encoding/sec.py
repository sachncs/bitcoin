"""SEC-format public-key parsing and serialization."""

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
            f"Invalid SEC key length {len(data)} (expected 33 or 65 bytes).")

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
