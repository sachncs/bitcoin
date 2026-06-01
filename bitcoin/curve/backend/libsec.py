"""libsecp256k1-backed secp256k1 backend via the ``coincurve`` package."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from bitcoin.curve.backend.base import CurveBackend
from bitcoin.curve.libsecp256k1 import check as check_libsecp256k1

if TYPE_CHECKING:
    from bitcoin.curve.point import Point

logger = logging.getLogger(__name__)


class LibsecpBackend(CurveBackend):
    """Backend using ``coincurve`` (libsecp256k1 C bindings).

    Falls back to the pure-Python implementation for operations the C
    library does not expose (negate, add, double).
    """

    def __init__(self) -> None:
        check_libsecp256k1()
        logger.debug(
            "LibsecpBackend initialised; negate/add/double fall back to "
            "pure Python because coincurve does not expose them.")

    def negate(self, point: Point) -> Point:
        """Return the additive inverse of *point* (pure-Python fallback).

        ``coincurve`` does not expose a negate operation, so this
        delegates to the pure-Python implementation.

        Args:
            point: The point to negate.

        Returns:
            The negated point.
        """
        from bitcoin.curve.operations import negate
        return negate(point)

    def add(self, left: Point, right: Point) -> Point:
        """Return the sum of two points (pure-Python fallback).

        ``coincurve`` does not expose point addition, so this
        delegates to the pure-Python implementation.

        Args:
            left: The first point.
            right: The second point.

        Returns:
            The sum point.
        """
        from bitcoin.curve.operations import add
        return add(left, right)

    def double(self, point: Point) -> Point:
        """Return the point doubled (pure-Python fallback).

        ``coincurve`` does not expose point doubling, so this
        delegates to the pure-Python implementation.

        Args:
            point: The point to double.

        Returns:
            The doubled point.
        """
        from bitcoin.curve.operations import double
        return double(point)

    def multiply(self, scalar: int, point: Point) -> Point:
        """Return scalar multiplication ``scalar * point`` via coincurve.

        Uses the ``coincurve`` C extension for the multiplication,
        then parses the resulting compressed public key back into a
        Point.

        Args:
            scalar: The scalar multiplier.
            point: The point to multiply.

        Returns:
            The resulting point.
        """
        import coincurve

        px = coincurve.PublicKey(point.to_sec_compressed())
        tweak = scalar.to_bytes(32, "big")
        new_pub = px.multiply(tweak)
        raw = new_pub.format()  # 33-byte compressed
        from bitcoin.encoding.sec import parse_sec
        return parse_sec(raw)

    def is_on_curve(self, point: Point) -> bool:
        """Return True if *point* lies on the secp256k1 curve.

        Verifies by attempting to construct a coincurve PublicKey
        from the point's compressed SEC encoding.

        Args:
            point: The point to verify.

        Returns:
            True if the point is on the curve, False otherwise.
        """
        import coincurve

        try:
            coincurve.PublicKey(point.to_sec_compressed())
            return True
        except ValueError:
            return False

    def sqrt(self, value: int) -> int:
        """Compute the square root of *value* modulo FIELD_PRIME.

        Args:
            value: The value to compute the square root of.

        Returns:
            The square root modulo FIELD_PRIME.
        """
        from bitcoin.curve.params import FIELD_PRIME
        from bitcoin.field.sqrt import sqrt
        return sqrt(value, FIELD_PRIME)

    def parse_sec(self, data: bytes) -> Point:
        """Parse a SEC-encoded public key into a Point.

        Args:
            data: The SEC-encoded public key bytes.

        Returns:
            The parsed Point.
        """
        from bitcoin.encoding.sec import parse_sec
        return parse_sec(data)

    def serialize_sec(self, point: Point, compressed: bool = True) -> bytes:
        """Serialize a Point to SEC-encoded bytes.

        Args:
            point: The point to serialize.
            compressed: Whether to use compressed encoding (default True).

        Returns:
            The SEC-encoded bytes.
        """
        from bitcoin.encoding.sec import serialize_sec
        return serialize_sec(point, compressed)
