"""Backend selection and dispatch for curve operations."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from bitcoin.curve.backend.base import CurveBackend
from bitcoin.curve.backend.native import NativeBackend

if TYPE_CHECKING:
    from bitcoin.curve.point import Point

logger = logging.getLogger(__name__)

backend: CurveBackend | None = None


def get_backend() -> CurveBackend | None:
    """Return the current backend, or ``None`` to use the native default."""
    return backend


def set_backend(value: CurveBackend) -> None:
    """Set the active curve backend.

    Args:
        value: A ``CurveBackend`` instance.

    Raises:
        TypeError: If *value* is not a ``CurveBackend`` instance.

    Note:
        This function is **not thread-safe** when called concurrently with
        dispatch functions.  Set the backend once at startup before
        creating any worker threads.
    """
    if not isinstance(value, CurveBackend):
        raise TypeError(
            f"Expected CurveBackend instance, got {type(value).__name__}.")
    global backend
    backend = value


def resolve_backend() -> CurveBackend:
    """Return the active backend or the default native backend."""
    if backend is not None:
        return backend
    from bitcoin.settings import settings
    backend_name = settings.default_backend
    if backend_name == "libsecp":
        libsecp_backend = _try_load_libsecp()
        if libsecp_backend is not None:
            return libsecp_backend
    return NativeBackend()


def _try_load_libsecp() -> CurveBackend | None:
    """Attempt to load the ``coincurve``-based libsecp backend.

    Returns:
        A ``LibsecpBackend`` instance, or ``None`` if the optional
        dependency is not installed.
    """
    try:
        from bitcoin.curve.backend.libsec import LibsecpBackend  # noqa: PLC0415
        return LibsecpBackend()
    except ImportError:
        logger.warning(
            "libsecp backend requested but not available; "
            "falling back to NativeBackend.")
        return None


# ── Public dispatch functions ──────────────────────────────────────────


def negate(point: Point) -> Point:
    """Return the additive inverse of *point*.

    Args:
        point: The point to negate.

    Returns:
        The negated point.
    """
    return resolve_backend().negate(point)


def add(left: Point, right: Point) -> Point:
    """Return the sum of two points.

    Args:
        left: The first point.
        right: The second point.

    Returns:
        The sum point.
    """
    return resolve_backend().add(left, right)


def double(point: Point) -> Point:
    """Return the point doubled (``2 * point``).

    Args:
        point: The point to double.

    Returns:
        The doubled point.
    """
    return resolve_backend().double(point)


def multiply(scalar: int, point: Point) -> Point:
    """Return scalar multiplication ``scalar * point``.

    Args:
        scalar: The scalar multiplier.
        point: The point to multiply.

    Returns:
        The resulting point.
    """
    return resolve_backend().multiply(scalar, point)


def is_on_curve(point: Point) -> bool:
    """Return True if *point* lies on the secp256k1 curve.

    Args:
        point: The point to verify.

    Returns:
        True if the point is on the curve.
    """
    return resolve_backend().is_on_curve(point)


def sqrt_field(value: int) -> int:
    """Compute the square root of *value* modulo FIELD_PRIME.

    Args:
        value: The value to compute the square root of.

    Returns:
        The square root modulo FIELD_PRIME.
    """
    from bitcoin.curve.params import FIELD_PRIME
    return resolve_backend().sqrt(value)


def parse_public_key(data: bytes) -> Point:
    """Parse a SEC-encoded public key into a Point.

    Args:
        data: The SEC-encoded public key bytes (compressed or
            uncompressed).

    Returns:
        The parsed Point.
    """
    return resolve_backend().parse_sec(data)


def serialize_public_key(point: Point, compressed: bool = True) -> bytes:
    """Serialize a Point to SEC-encoded bytes.

    Args:
        point: The point to serialize.
        compressed: Whether to use compressed encoding (default True).

    Returns:
        The SEC-encoded bytes.
    """
    return resolve_backend().serialize_sec(point, compressed)


def normalize(value: int) -> int:
    """Return *value* reduced to the range ``[0, FIELD_PRIME)``."""
    from bitcoin.curve.params import FIELD_PRIME
    return value % FIELD_PRIME


def normalize_non_negative(value: int, label: str = "value") -> int:
    """Thin wrapper over ``field.modular.validate_non_negative``."""
    from bitcoin.field import validate_non_negative
    return validate_non_negative(value, label)
