"""Abstract interface for pluggable secp256k1 backends."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bitcoin.curve.point import Point


class CurveBackend(ABC):
    """Abstract base class for pluggable secp256k1 backends.

    Subclasses must implement all eight abstract methods to provide
    curve arithmetic, serialization, and square-root computation.
    """

    @abstractmethod
    def negate(self, point: Point) -> Point:
        """Return the additive inverse of *point*.

        Args:
            point: The point to negate.

        Returns:
            The negated point.
        """

    @abstractmethod
    def add(self, left: Point, right: Point) -> Point:
        """Return the sum of two points.

        Args:
            left: The first point.
            right: The second point.

        Returns:
            The sum point.
        """

    @abstractmethod
    def double(self, point: Point) -> Point:
        """Return the point doubled (``2 * point``).

        Args:
            point: The point to double.

        Returns:
            The doubled point.
        """

    @abstractmethod
    def multiply(self, scalar: int, point: Point) -> Point:
        """Return scalar multiplication ``scalar * point``.

        Args:
            scalar: The scalar multiplier.
            point: The point to multiply.

        Returns:
            The resulting point.
        """

    @abstractmethod
    def is_on_curve(self, point: Point) -> bool:
        """Return True if *point* lies on the secp256k1 curve.

        Args:
            point: The point to verify.

        Returns:
            True if the point is on the curve.
        """

    @abstractmethod
    def sqrt(self, value: int) -> int:
        """Compute the square root of *value* modulo FIELD_PRIME.

        Args:
            value: The value to compute the square root of.

        Returns:
            The square root modulo FIELD_PRIME.
        """

    @abstractmethod
    def parse_sec(self, data: bytes) -> Point:
        """Parse a SEC-encoded public key into a Point.

        Args:
            data: The SEC-encoded public key bytes.

        Returns:
            The parsed Point.
        """

    @abstractmethod
    def serialize_sec(self, point: Point, compressed: bool = True) -> bytes:
        """Serialize a Point to SEC-encoded bytes.

        Args:
            point: The point to serialize.
            compressed: Whether to use compressed encoding (default True).

        Returns:
            The SEC-encoded bytes.
        """
