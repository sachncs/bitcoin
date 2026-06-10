"""Secp256k1 curve arithmetic, backends, and the ``Point`` type.

Everything in this package is independent of Bitcoin transactions,
scripts, and signatures.
"""

from bitcoin.curve import libsecp256k1
from bitcoin.curve.backend.base import CurveBackend
from bitcoin.curve.backend.libsec import LibsecpBackend
from bitcoin.curve.backend.native import NativeBackend
from bitcoin.curve.dispatch import (
    add,
    double,
    get_backend,
    is_on_curve,
    multiply,
    negate,
    normalize,
    normalize_non_negative,
    parse_public_key,
    serialize_public_key,
    set_backend,
    sqrt_field,
)
from bitcoin.curve.params import (
    CURVE_A,
    CURVE_B,
    CURVE_ORDER,
    FIELD_PRIME,
    GENERATOR_X,
    GENERATOR_Y,
)
from bitcoin.curve.point import Point

# Singleton points
GENERATOR = Point(x=GENERATOR_X, y=GENERATOR_Y)  # The secp256k1 generator point
INFINITY = Point(infinity=True)  # The point at infinity

__all__ = [
    "CURVE_A",
    "CURVE_B",
    "CURVE_ORDER",
    "CurveBackend",
    "FIELD_PRIME",
    "GENERATOR",
    "GENERATOR_X",
    "GENERATOR_Y",
    "INFINITY",
    "LibsecpBackend",
    "NativeBackend",
    "Point",
    "add",
    "double",
    "get_backend",
    "is_on_curve",
    "libsecp256k1",
    "multiply",
    "negate",
    "normalize",
    "normalize_non_negative",
    "parse_public_key",
    "serialize_public_key",
    "set_backend",
    "sqrt_field",
]
