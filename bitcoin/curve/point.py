"""The ``Point`` value type — a point on the secp256k1 curve.

Domain-driven composed engine exposed via ``Point.arithmetic`` for
arithmetic operations (negate, add, double, multiply, is_on_curve).
"""

from __future__ import annotations

from bitcoin.curve.params import CURVE_B, FIELD_PRIME


class PointArithmetic:
    """Composed arithmetic engine for point operations.

    Accessed via ``point.arithmetic``.  Provides domain-chain access to
    curve arithmetic without exposing the underlying operations module.

    Args:
        point: The Point instance this engine is bound to.
    """

    __slots__ = ("__point",)

    def __init__(self, point: Point) -> None:
        self.__point: Point = point

    def negate(self) -> Point:
        """Return the additive inverse of the bound point.

        Returns:
            The negated Point, or the point at infinity unchanged.
        """
        from bitcoin.curve.operations import negate
        return negate(self.__point)

    def add(self, other: Point) -> Point:
        """Return the sum of the bound point and *other*.

        Args:
            other: The point to add.

        Returns:
            The sum Point.
        """
        from bitcoin.curve.operations import add
        return add(self.__point, other)

    def double(self) -> Point:
        """Return the bound point doubled (2 * point).

        Returns:
            The doubled Point.
        """
        from bitcoin.curve.operations import double
        return double(self.__point)

    def multiply(self, scalar: int) -> Point:
        """Return scalar multiplication scalar * point.

        Args:
            scalar: The scalar multiplier (non-negative).

        Returns:
            The resulting Point.

        Raises:
            ValueError: If *scalar* is negative.
        """
        from bitcoin.curve.operations import multiply
        return multiply(scalar, self.__point)

    def is_on_curve(self) -> bool:
        """Check whether the bound point lies on the secp256k1 curve.

        Returns:
            True if the point is on the curve.  The point at infinity
            is always considered on the curve.
        """
        from bitcoin.curve.operations import is_on_curve
        return is_on_curve(self.__point)

    def serialize(self, compressed: bool = True) -> bytes:
        """Serialize the bound point to SEC-encoded bytes.

        Args:
            compressed: Whether to use compressed encoding (default True).

        Returns:
            SEC-encoded bytes.

        Raises:
            ValueError: If the point is at infinity.
        """
        if compressed:
            return self.__point.to_sec_compressed()
        return self.__point.to_sec_uncompressed()


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

    # -- composed engine access ---------------------------------------------

    @property
    def arithmetic(self) -> PointArithmetic:
        """Access point arithmetic via a composed engine.

        Returns:
            A ``PointArithmetic`` instance bound to this point.
        """
        return PointArithmetic(self)

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

        Validates that the decompressed y-coordinate satisfies the curve
        equation ``y^2 = x^3 + b (mod p)``, rejecting invalid encodings.

        Args:
            data: A 33-byte SEC-compressed key.

        Returns:
            A new Point parsed from the encoding.

        Raises:
            ValueError: If *data* is not a valid compressed SEC key or
                the decompressed point is not on the curve.
        """
        if len(data) != 33 or data[0] not in (0x02, 0x03):
            raise ValueError("Invalid compressed SEC key.")
        x = int.from_bytes(data[1:33], "big")
        y_sq = (pow(x, 3, FIELD_PRIME) + CURVE_B) % FIELD_PRIME
        y = pow(y_sq, (FIELD_PRIME + 1) // 4, FIELD_PRIME)
        if (y & 1) != (data[0] & 1):
            y = FIELD_PRIME - y
        # Validate that the decompressed y satisfies the curve equation.
        if (y * y) % FIELD_PRIME != y_sq:
            raise ValueError(
                "Decompressed point is not on the secp256k1 curve.")
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
