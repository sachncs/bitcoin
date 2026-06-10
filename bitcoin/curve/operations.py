"""Pure-Python secp256k1 point arithmetic."""

from __future__ import annotations

from bitcoin.curve.params import CURVE_A, CURVE_B, CURVE_ORDER, FIELD_PRIME
from bitcoin.curve.point import Point
from bitcoin.field import inverse


def negate(point: Point) -> Point:
    """Return the additive inverse of *point*.

    Args:
        point: The point to negate.

    Returns:
        The negated point, or the point at infinity unchanged.
    """
    if point.infinity:
        return point
    y = point.y
    if y is None:
        return point
    return Point(x=point.x, y=FIELD_PRIME - y)


def add(left: Point, right: Point) -> Point:
    """Return the sum of two points on the secp256k1 curve.

    Args:
        left: The first point.
        right: The second point.

    Returns:
        The point resulting from point addition.
    """
    if left.infinity:
        return right
    if right.infinity:
        return left
    if left.x == right.x:
        if left.y != right.y:
            return Point(infinity=True)
        return double(left)

    x1, y1 = left.x, left.y
    x2, y2 = right.x, right.y
    if x1 is None or y1 is None or x2 is None or y2 is None:
        return Point(infinity=True)
    slope = ((y2 - y1) * inverse((x2 - x1) % FIELD_PRIME, FIELD_PRIME)) % FIELD_PRIME
    x3 = (slope * slope - x1 - x2) % FIELD_PRIME
    y3 = (slope * (x1 - x3) - y1) % FIELD_PRIME
    return Point(x=x3, y=y3)


def double(point: Point) -> Point:
    """Return the point doubled (``2 * point``).

    Args:
        point: The point to double.

    Returns:
        The doubled point, or the point at infinity if *point* is
        infinity or has y = 0.
    """
    if point.infinity or point.y == 0:
        return Point(infinity=True)
    x1, y1 = point.x, point.y
    if x1 is None or y1 is None:
        return Point(infinity=True)
    slope = ((3 * x1 * x1 + CURVE_A) * inverse(
        (2 * y1) % FIELD_PRIME, FIELD_PRIME)) % FIELD_PRIME
    x3 = (slope * slope - 2 * x1) % FIELD_PRIME
    y3 = (slope * (x1 - x3) - y1) % FIELD_PRIME
    return Point(x=x3, y=y3)


def multiply(scalar: int, point: Point) -> Point:
    """Return scalar multiplication ``scalar * point`` via the Montgomery ladder.

    Args:
        scalar: The scalar multiplier.
        point: The point to multiply.

    Returns:
        The resulting point, or the point at infinity if *scalar* is
        zero or *point* is infinity.
    """
    if scalar == 0 or point.infinity:
        return Point(infinity=True)
    scalar = scalar % CURVE_ORDER
    if scalar == 0:
        return Point(infinity=True)

    r0 = Point(infinity=True)
    r1 = point
    for bit in bits(scalar):
        if bit == 0:
            r1 = add(r0, r1)
            r0 = double(r0)
        else:
            r0 = add(r0, r1)
            r1 = double(r1)
    return r0


def is_on_curve(point: Point) -> bool:
    """Return True if *point* lies on the secp256k1 curve.

    Args:
        point: The point to verify.

    Returns:
        True if the point is on the curve, False otherwise.
        The point at infinity is always considered on the curve.
    """
    if point.infinity:
        return True
    x, y = point.x, point.y
    if x is None or y is None:
        return False
    return (y * y - (pow(x, 3, FIELD_PRIME) + CURVE_B)) % FIELD_PRIME == 0


# -- helpers --------------------------------------------------------------


def bits(scalar: int) -> list[int]:
    """Return the binary representation of *scalar* (MSB-first).

    Args:
        scalar: The integer to convert.

    Returns:
        A list of bits (0 or 1) from most significant to least
        significant.
    """
    if scalar == 0:
        return [0]
    return [int(b) for b in bin(scalar)[2:]]
