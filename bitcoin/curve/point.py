"""The ``Point`` value type — a point on the secp256k1 curve."""

from __future__ import annotations

from bitcoin.curve.params import CURVE_B, FIELD_PRIME


class Point:
    """An affine point on secp256k1, or the point at infinity.

    Slots are used for a compact memory layout.  The point is guaranteed
    to lie on the curve when *infinity* is ``False``.
    """

    __slots__ = ("__x", "__y", "__infinity")

    def __init__(self,
                 x: int | None = None,
                 y: int | None = None,
                 *,
                 infinity: bool = False) -> None:
        """Initialize a Point on the secp256k1 curve.

        Args:
            x: The affine x-coordinate.
            y: The affine y-coordinate.
            infinity: If True, create the point at infinity (ignores x, y).

        Raises:
            ValueError: If not infinity and x or y is missing or out of range.
        """
        if infinity:
            self.__x: int | None = None
            self.__y: int | None = None
            self.__infinity: bool = True
            return
        if x is None or y is None:
            raise ValueError("Affine point requires both x and y.")
        if not (0 <= x < FIELD_PRIME):
            raise ValueError(f"x coordinate out of field: {x}")
        if not (0 <= y < FIELD_PRIME):
            raise ValueError(f"y coordinate out of field: {y}")
        self.__x = x
        self.__y = y
        self.__infinity = False

    # -- read-only properties ------------------------------------------------

    @property
    def x(self) -> int | None:
        """The affine x-coordinate, or ``None`` for the point at infinity."""
        return self.__x

    @property
    def y(self) -> int | None:
        """The affine y-coordinate, or ``None`` for the point at infinity."""
        return self.__y

    @property
    def infinity(self) -> bool:
        """``True`` if this is the point at infinity."""
        return self.__infinity

    # -- equality / hashing --------------------------------------------------

    def __eq__(self, other: object) -> bool:
        """Return True if *other* is a Point with identical coordinates."""
        if not isinstance(other, Point):
            return NotImplemented
        if self.__infinity and other.__infinity:
            return True
        if self.__infinity != other.__infinity:
            return False
        return self.__x == other.__x and self.__y == other.__y

    def __hash__(self) -> int:
        """Return a hash based on the point's coordinates."""
        if self.__infinity:
            return hash((True,))
        return hash((False, self.__x, self.__y))

    def __repr__(self) -> str:
        """Return a developer-friendly string representation."""
        if self.__infinity:
            return "Point(infinity=True)"
        return f"Point(x=0x{self.__x:064x}, y=0x{self.__y:064x})"

    # -- constructors --------------------------------------------------------

    @classmethod
    def from_sec_compressed(cls, data: bytes) -> Point:
        """Parse a 33-byte compressed SEC-encoded public key.

        Args:
            data: A 33-byte SEC-compressed key.

        Returns:
            A new Point parsed from the encoding.

        Raises:
            ValueError: If *data* is not a valid compressed SEC key.
        """
        if len(data) != 33 or data[0] not in (0x02, 0x03):
            raise ValueError("Invalid compressed SEC key.")
        x = int.from_bytes(data[1:33], "big")
        y_sq = (pow(x, 3, FIELD_PRIME) + CURVE_B) % FIELD_PRIME
        y = pow(y_sq, (FIELD_PRIME + 1) // 4, FIELD_PRIME)
        if (y & 1) != (data[0] & 1):
            y = FIELD_PRIME - y
        return cls(x=x, y=y)

    @classmethod
    def from_sec_uncompressed(cls, data: bytes) -> Point:
        """Parse a 65-byte uncompressed SEC-encoded public key.

        Args:
            data: A 65-byte SEC-uncompressed key.

        Returns:
            A new Point parsed from the encoding.

        Raises:
            ValueError: If *data* is not a valid uncompressed SEC key.
        """
        if len(data) != 65 or data[0] != 0x04:
            raise ValueError("Invalid uncompressed SEC key.")
        x = int.from_bytes(data[1:33], "big")
        y = int.from_bytes(data[33:], "big")
        return cls(x=x, y=y)

    # -- serialization -------------------------------------------------------

    def to_sec_compressed(self) -> bytes:
        """Encode this point as a 33-byte compressed SEC key.

        Returns:
            The 33-byte SEC-compressed encoding.

        Raises:
            ValueError: If this is the point at infinity.
        """
        y = self.__y
        x = self.__x
        if y is None or x is None:
            raise ValueError("Cannot serialize infinity point.")
        prefix = bytes([0x02 | (y & 1)])
        return prefix + x.to_bytes(32, "big")

    def to_sec_uncompressed(self) -> bytes:
        """Encode this point as a 65-byte uncompressed SEC key.

        Returns:
            The 65-byte SEC-uncompressed encoding.

        Raises:
            ValueError: If this is the point at infinity.
        """
        x = self.__x
        y = self.__y
        if x is None or y is None:
            raise ValueError("Cannot serialize infinity point.")
        return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")
