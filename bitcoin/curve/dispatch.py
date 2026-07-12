# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Backend selection and public dispatch for curve operations.

This module owns the module-level :data:`backend` singleton and routes
every public curve operation (``add``, ``double``, ``multiply``,
``negate``, ``is_on_curve``, ``sqrt``, SEC encode/decode, ``normalize``)
through it.  It also implements a thread-safe lazy-initialised
4-bit window table for the generator point, used by :func:`multiply`
when the operand is ``G`` to avoid a full scalar multiplication.

Dispatch flow:

1. :func:`set_backend` (or :func:`resolve_backend` on first use) chooses
   either the pure-Python :class:`NativeBackend` or, when ``coincurve``
   is available and the ``default_backend`` setting requests it, the
   :class:`LibsecpBackend`.
2. Public helpers (``add``, ``multiply``, ...) forward to the active
   backend's methods.
3. :func:`multiply` short-circuits to the fixed-base table when the
   operand is the generator.

Thread-safety: backend selection and the generator table are protected
by :data:`backend_lock` and :data:`g_table_lock` respectively, so
concurrent first-time callers will see a fully initialised table.
"""

from __future__ import annotations

import functools
import logging
import threading

from bitcoin.curve.backend.base import CurveBackend
from bitcoin.curve.backend.native import NativeBackend
from bitcoin.curve.params import CURVE_ORDER
from bitcoin.curve.point import Point

logger = logging.getLogger(__name__)

backend_lock = threading.Lock()
backend: CurveBackend | None = None

# Pre-computation table for fixed-base multiplication with the generator.
# G_TABLE[i] == GENERATOR * i  for i in 0..15, using 4-bit windows.
# Protected by g_table_lock for thread-safe lazy initialization.
G_TABLE: list[Point] = []
g_table_initialized = False
g_table_lock = threading.Lock()


def build_g_table() -> list[Point]:
    """Build the fixed-base multiplication table for the generator point.

    Constructs a 16-entry lookup table containing ``i * G`` for
    ``i = 0..15`` using successive point addition.  Used internally by
    :func:`multiply_fixed_base` to accelerate generator-point
    multiplication via 4-bit windowing.

    Returns:
        A list of 16 ``Point`` instances: ``[0*G, 1*G, 2*G, ..., 15*G]``.
    """
    from bitcoin.curve.operations import add
    from bitcoin.curve.params import GENERATOR_X, GENERATOR_Y

    G = Point(x=GENERATOR_X, y=GENERATOR_Y)
    table: list[Point] = [Point(infinity=True), G]
    for i in range(2, 16):
        table.append(add(table[i - 1], G))
    return table


def get_g_table() -> list[Point]:
    """Return the generator-point lookup table, initialising on first use.

    Implements double-checked locking for thread-safe lazy initialisation.
    The table is built once by :func:`build_g_table` and cached for all
    subsequent calls.

    Returns:
        The cached 16-entry lookup table for ``i * G``.
    """
    global G_TABLE, g_table_initialized
    if not g_table_initialized:
        with g_table_lock:
            if not g_table_initialized:
                G_TABLE = build_g_table()
                g_table_initialized = True
    return G_TABLE


def is_generator(point: Point) -> bool:
    """Return ``True`` if *point* equals the secp256k1 generator point ``G``.

    The comparison is structural (coordinates), so callers should ensure
    the point is already known to be on the curve if strictness matters.

    Args:
        point: The point to test.

    Returns:
        ``True`` if *point* is the generator ``G``, else ``False``.
        The point at infinity is never the generator.
    """
    from bitcoin.curve.params import GENERATOR_X, GENERATOR_Y

    if point.infinity:
        return False
    return point.x == GENERATOR_X and point.y == GENERATOR_Y


def multiply_fixed_base(scalar: int) -> Point:
    """Multiply the generator point by *scalar* using 4-bit windowing.

    Falls back to the public ``multiply`` dispatch for non-generator
    points, but accepts the optimised table-lookup path when the
    caller can guarantee the point is ``G``.

    The algorithm scans the scalar four bits at a time from MSB to LSB,
    doubling the accumulator four times per window and adding the
    pre-computed table entry for the window value (when non-zero).

    Args:
        scalar: Non-negative integer multiplier.

    Returns:
        ``scalar * G`` as a ``Point``.
    """
    table = get_g_table()
    result = Point(infinity=True)
    num_windows = (scalar.bit_length() + 3) // 4
    for i in range(num_windows - 1, -1, -1):
        for _ in range(4):
            result = double(result)
        window = (scalar >> (i * 4)) & 0xF
        if window:
            result = add(result, table[window])
    return result


def get_backend() -> CurveBackend | None:
    """Return the current backend, or ``None`` to use the native default."""
    return backend


def set_backend(value: CurveBackend) -> None:
    """Set the active curve backend (thread-safe).

    Args:
        value: A ``CurveBackend`` instance.

    Raises:
        TypeError: If *value* is not a ``CurveBackend`` instance.
    """
    if not isinstance(value, CurveBackend):
        raise TypeError(f"Expected CurveBackend instance, got {type(value).__name__}.")
    global backend
    with backend_lock:
        backend = value


def resolve_backend() -> CurveBackend:
    """Return the active backend or the default native backend."""
    global backend
    with backend_lock:
        if backend is not None:
            return backend
    from bitcoin.settings import settings

    backend_name = settings.default_backend
    if backend_name == "libsecp":
        libsecp_backend = try_load_libsecp()
        if libsecp_backend is not None:
            return libsecp_backend
    return NativeBackend()


def try_load_libsecp() -> CurveBackend | None:
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
            "falling back to NativeBackend."
        )
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

    The scalar is reduced modulo ``CURVE_ORDER`` to ensure consistent
    results across backends and to reject negative values.

    Args:
        scalar: The scalar multiplier (must be non-negative).
        point: The point to multiply.

    Returns:
        The resulting point.

    Raises:
        ValueError: If *scalar* is negative.
    """
    if scalar < 0:
        raise ValueError("scalar must be non-negative.")
    scalar = scalar % CURVE_ORDER
    if scalar == 0:
        return Point(infinity=True)
    if is_generator(point):
        return multiply_fixed_base(scalar)
    return resolve_backend().multiply(scalar, point)


@functools.lru_cache(maxsize=4096)
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
    return resolve_backend().sqrt(value)


@functools.lru_cache(maxsize=4096)
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
    """Validate that *value* is a non-negative integer and return it.

    Convenience re-export of :func:`bitcoin.field.validate_non_negative`
    so callers working with curve operations can validate inputs without
    importing from ``bitcoin.field`` directly.

    Args:
        value: Integer to validate.
        label: Name used in error messages (default ``"value"``).

    Returns:
        *value* unchanged on success.

    Raises:
        TypeError: If *value* is not an ``int``.
        ValueError: If *value* is negative.
    """
    from bitcoin.field import validate_non_negative

    return validate_non_negative(value, label)


__all__ = [
    "add",
    "double",
    "get_backend",
    "is_on_curve",
    "multiply",
    "negate",
    "normalize",
    "normalize_non_negative",
    "parse_public_key",
    "resolve_backend",
    "serialize_public_key",
    "set_backend",
    "sqrt_field",
]
