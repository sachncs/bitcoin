"""Native pure-Python secp256k1 backend."""

from __future__ import annotations

from typing import TYPE_CHECKING

from bitcoin.curve import operations as ops
from bitcoin.curve.backend.base import CurveBackend
from bitcoin.encoding.sec import parse_sec, serialize_sec
from bitcoin.field.sqrt import sqrt as field_sqrt

if TYPE_CHECKING:
    from bitcoin.curve.point import Point


class NativeBackend(CurveBackend):
    """Backend that delegates to the pure-Python ``operations`` module."""

    def negate(self, point: Point) -> Point:
        """Return the additive inverse of *point*.

        Args:
            point: The point to negate.

        Returns:
            The negated point.
        """
        return ops.negate(point)

    def add(self, left: Point, right: Point) -> Point:
        """Return the sum of two points.

        Args:
            left: The first point.
            right: The second point.

        Returns:
            The sum point.
        """
        return ops.add(left, right)

    def double(self, point: Point) -> Point:
        """Return the point doubled (``2 * point``).

        Args:
            point: The point to double.

        Returns:
            The doubled point.
        """
        return ops.double(point)

    def multiply(self, scalar: int, point: Point) -> Point:
        """Return scalar multiplication ``scalar * point``.

        Args:
            scalar: The scalar multiplier.
            point: The point to multiply.

        Returns:
            The resulting point.
        """
        return ops.multiply(scalar, point)

    def is_on_curve(self, point: Point) -> bool:
        """Return True if *point* lies on the secp256k1 curve.

        Args:
            point: The point to verify.

        Returns:
            True if the point is on the curve.
        """
        return ops.is_on_curve(point)

    def sqrt(self, value: int) -> int:
        """Compute the square root of *value* modulo FIELD_PRIME.

        Args:
            value: The value to compute the square root of.

        Returns:
            The square root modulo FIELD_PRIME.
        """
        from bitcoin.curve.params import FIELD_PRIME
        return field_sqrt(value, FIELD_PRIME)

    def parse_sec(self, data: bytes) -> Point:
        """Parse a SEC-encoded public key into a Point.

        Args:
            data: The SEC-encoded public key bytes.

        Returns:
            The parsed Point.
        """
        return parse_sec(data)

    def serialize_sec(self, point: Point, compressed: bool = True) -> bytes:
        """Serialize a Point to SEC-encoded bytes.

        Args:
            point: The point to serialize.
            compressed: Whether to use compressed encoding (default True).

        Returns:
            The SEC-encoded bytes.
        """
        return serialize_sec(point, compressed)
