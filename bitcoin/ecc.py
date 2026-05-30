"""Manual secp256k1 affine point arithmetic and SEC public key handling.

This module implements the elliptic-curve point operations needed to move from
the scalar relation

    d' \u2261 \u03b1k (mod n)

to point-space relations on secp256k1:

    D + \u03b2G = \u03b1K

The implementation is intentionally explicit:

- affine coordinates only
- no external ECC dependencies
- modular inversion via extended Euclidean algorithm
- deterministic double-and-add scalar multiplication
- strict point validation after every construction
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from bitcoin.arithmetic import inverse_mod as arithmetic_inverse
from bitcoin.arithmetic import normalize_non_negative as arithmetic_normalize
from bitcoin.ecc_backend import get_backend
from bitcoin.exceptions import InvalidSecp256k1PointError, InvalidSecPublicKeyError
from bitcoin.linear import derive_linear_coefficients
from bitcoin.models import SignatureRecord
from bitcoin.utils import int_to_hex

logger = logging.getLogger(__name__)

SECP256K1_FIELD_PRIME = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_A = 0
SECP256K1_B = 7
SECP256K1_GX = (
    55066263022277343669578718895168534326250603453777594175500187360389116729240
)
SECP256K1_GY = (
    32670510020758816978083085130507043184471273380659243275938904335757337482424
)


def normalize_non_negative(value: int, label: str) -> int:
    """Normalize a value to a non-negative integer."""
    try:
        return arithmetic_normalize(value, label)
    except (TypeError, ValueError) as exc:
        raise InvalidSecp256k1PointError(str(exc)) from exc


def normalize_field_element(value: int, label: str) -> int:
    """Normalize and validate a field element is below the secp256k1 prime."""
    value = normalize_non_negative(value, label)
    if value >= SECP256K1_FIELD_PRIME:
        raise InvalidSecp256k1PointError(f"{label} must be smaller than p.")
    return value


def inverse_mod(value: int, modulus: int) -> int:
    """Return the modular inverse of value modulo modulus."""
    try:
        return arithmetic_inverse(value, modulus)
    except (TypeError, ValueError) as exc:
        raise InvalidSecp256k1PointError(str(exc)) from exc


def field_pow(value: int, exponent: int) -> int:
    return pow(value, exponent, SECP256K1_FIELD_PRIME)


def is_on_curve(x: int, y: int) -> bool:
    """Return whether (x, y) satisfies the secp256k1 curve equation."""
    backend = get_backend()
    if backend is not None:
        return backend.is_on_curve(x, y)
    logger.debug("No ECC backend active; using pure Python for is_on_curve")
    return is_on_curve_py(x, y)


def field_sqrt(value: int) -> int:
    """Return the square root of a field element modulo p."""
    backend = get_backend()
    if backend is not None:
        return backend.field_sqrt(value)
    logger.debug("No ECC backend active; using pure Python for field_sqrt")
    return field_sqrt_py(value)


def int_to_bytes(value: int) -> bytes:
    return value.to_bytes(32, "big")


class Secp256k1Point:
    """Represents an affine secp256k1 point on the curve y\u00b2 = x\u00b3 + 7."""

    __slots__ = ("x", "y", "infinity")

    def __init__(self,
                 x: int | None = None,
                 y: int | None = None,
                 infinity: bool = False) -> None:
        if not isinstance(infinity, bool):
            raise InvalidSecp256k1PointError("infinity must be a boolean.")
        if infinity:
            if x is not None or y is not None:
                raise InvalidSecp256k1PointError(
                    "Infinity must not carry affine coordinates.")
            self.x: int | None = None
            self.y: int | None = None
            self.infinity = True
            return
        if x is None or y is None:
            raise InvalidSecp256k1PointError(
                "Affine points require x and y coordinates.")
        self.x = normalize_field_element(x, "x")
        self.y = normalize_field_element(y, "y")
        if not is_on_curve(self.x, self.y):
            raise InvalidSecp256k1PointError("Point is not on secp256k1.")
        self.infinity = False

    def to_sec_compressed(self) -> bytes:
        if self.infinity:
            raise InvalidSecPublicKeyError(
                "Infinity cannot be serialized as SEC.")
        assert self.x is not None and self.y is not None
        prefix = 0x02 if self.y % 2 == 0 else 0x03
        return bytes([prefix]) + int_to_bytes(self.x)

    def to_sec_uncompressed(self) -> bytes:
        if self.infinity:
            raise InvalidSecPublicKeyError(
                "Infinity cannot be serialized as SEC.")
        assert self.x is not None and self.y is not None
        return b"\x04" + int_to_bytes(self.x) + int_to_bytes(self.y)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Secp256k1Point):
            return NotImplemented
        return (self.x == other.x and self.y == other.y and
                self.infinity == other.infinity)

    def __hash__(self) -> int:
        return hash((self.x, self.y, self.infinity))

    def __repr__(self) -> str:
        if self.infinity:
            return "Secp256k1Point(infinity=True)"
        assert self.x is not None and self.y is not None
        return (f"Secp256k1Point(x=0x{int_to_hex(self.x)}, "
                f"y=0x{int_to_hex(self.y)}, infinity=False)")


def point_negate_py(point: Secp256k1Point) -> Secp256k1Point:
    """Pure-Python negation: P -> -P."""
    if point.infinity:
        return point
    assert point.x is not None and point.y is not None
    return Secp256k1Point(x=point.x,
                          y=(-point.y) % SECP256K1_FIELD_PRIME,
                          infinity=False)


def point_add_py(left: Secp256k1Point, right: Secp256k1Point) -> Secp256k1Point:
    """Pure-Python point addition."""
    if left.infinity:
        return right
    if right.infinity:
        return left

    assert left.x is not None and left.y is not None
    assert right.x is not None and right.y is not None

    if left.x == right.x:
        if (left.y + right.y) % SECP256K1_FIELD_PRIME == 0:
            return SECP256K1_INFINITY
        return point_double_py(left)

    slope = ((right.y - left.y) * inverse_mod(
        (right.x - left.x) % SECP256K1_FIELD_PRIME,
        SECP256K1_FIELD_PRIME)) % SECP256K1_FIELD_PRIME
    x3 = (slope * slope - left.x - right.x) % SECP256K1_FIELD_PRIME
    y3 = (slope * (left.x - x3) - left.y) % SECP256K1_FIELD_PRIME
    return Secp256k1Point(x=x3, y=y3, infinity=False)


def point_double_py(point: Secp256k1Point) -> Secp256k1Point:
    """Pure-Python point doubling."""
    if point.infinity:
        return point
    assert point.x is not None and point.y is not None
    if point.y % SECP256K1_FIELD_PRIME == 0:
        return SECP256K1_INFINITY

    slope = ((3 * point.x * point.x + SECP256K1_A) * inverse_mod(
        (2 * point.y) % SECP256K1_FIELD_PRIME,
        SECP256K1_FIELD_PRIME)) % SECP256K1_FIELD_PRIME
    x3 = (slope * slope - 2 * point.x) % SECP256K1_FIELD_PRIME
    y3 = (slope * (point.x - x3) - point.y) % SECP256K1_FIELD_PRIME
    return Secp256k1Point(x=x3, y=y3, infinity=False)


def scalar_multiply_py(scalar: int, point: Secp256k1Point) -> Secp256k1Point:
    """Pure-Python Montgomery ladder scalar multiplication."""
    scalar %= SECP256K1_ORDER
    if scalar == 0 or point.infinity:
        return SECP256K1_INFINITY

    r0: Secp256k1Point = SECP256K1_INFINITY
    r1: Secp256k1Point = point
    bits = scalar.bit_length()
    for i in range(bits - 1, -1, -1):
        bit = (scalar >> i) & 1
        if bit == 0:
            r1 = point_add_py(r0, r1)
            r0 = point_double_py(r0)
        else:
            r0 = point_add_py(r0, r1)
            r1 = point_double_py(r1)
    return r0


def is_on_curve_py(x: int, y: int) -> bool:
    """Pure-Python curve equation check."""
    left = (y * y) % SECP256K1_FIELD_PRIME
    right = (pow(x, 3, SECP256K1_FIELD_PRIME) +
             SECP256K1_B) % SECP256K1_FIELD_PRIME
    return left == right


def field_sqrt_py(value: int) -> int:
    """Pure-Python field square root via Tonelli-Shanks for p ≡ 3 (mod 4)."""
    root = field_pow(value, (SECP256K1_FIELD_PRIME + 1) // 4)
    if (root * root) % SECP256K1_FIELD_PRIME != value % SECP256K1_FIELD_PRIME:
        raise InvalidSecp256k1PointError("Field element has no square root.")
    return root


def parse_sec_py(data: bytes) -> Secp256k1Point:
    """Pure-Python SEC public key parsing."""
    if isinstance(data, bytearray):
        data = bytes(data)
    if not isinstance(data, bytes):
        raise InvalidSecPublicKeyError("SEC public key must be bytes.")
    if len(data) == 33 and data[0] in {0x02, 0x03}:
        x = int.from_bytes(data[1:], "big")
        if x >= SECP256K1_FIELD_PRIME:
            raise InvalidSecPublicKeyError(
                "Compressed SEC x-coordinate is invalid.")
        rhs = (pow(x, 3, SECP256K1_FIELD_PRIME) +
               SECP256K1_B) % SECP256K1_FIELD_PRIME
        y = field_sqrt_py(rhs)
        if (y % 2 == 1) != (data[0] == 0x03):
            y = (-y) % SECP256K1_FIELD_PRIME
        point = Secp256k1Point(x=x, y=y, infinity=False)
        return point
    if len(data) == 65 and data[0] == 0x04:
        x = int.from_bytes(data[1:33], "big")
        y = int.from_bytes(data[33:], "big")
        return Secp256k1Point(x=x, y=y, infinity=False)
    raise InvalidSecPublicKeyError("Unsupported SEC public key encoding.")


# ── Public API (checks for active backend, falls back to _py_*) ──────────


def point_negate(point: Secp256k1Point) -> Secp256k1Point:
    """Return the negation of a secp256k1 point."""
    backend = get_backend()
    if backend is not None:
        return backend.point_negate(point)
    logger.debug("No ECC backend active; using pure Python for point_negate")
    return point_negate_py(point)


def point_add(left: Secp256k1Point, right: Secp256k1Point) -> Secp256k1Point:
    """Add two secp256k1 affine points."""
    backend = get_backend()
    if backend is not None:
        return backend.point_add(left, right)
    logger.debug("No ECC backend active; using pure Python for point_add")
    return point_add_py(left, right)


def point_double(point: Secp256k1Point) -> Secp256k1Point:
    """Double a secp256k1 affine point."""
    backend = get_backend()
    if backend is not None:
        return backend.point_double(point)
    logger.debug("No ECC backend active; using pure Python for point_double")
    return point_double_py(point)


def scalar_multiply(scalar: int, point: Secp256k1Point) -> Secp256k1Point:
    """Multiply a secp256k1 point by a scalar via constant-time Montgomery ladder."""
    backend = get_backend()
    if backend is not None:
        return backend.scalar_multiply(scalar, point)
    logger.debug("No ECC backend active; using pure Python for scalar_multiply")
    return scalar_multiply_py(scalar, point)


def serialize_sec_py(point: Secp256k1Point, compressed: bool = True) -> bytes:
    """Pure-Python SEC serialization."""
    if compressed:
        return point.to_sec_compressed()
    return point.to_sec_uncompressed()


def parse_sec_public_key(data: bytes) -> Secp256k1Point:
    """Parse a compressed or uncompressed SEC-encoded public key."""
    backend = get_backend()
    if backend is not None:
        return backend.parse_sec_public_key(data)
    return parse_sec_py(data)


def serialize_sec_public_key(point: Secp256k1Point,
                             compressed: bool = True) -> bytes:
    """Serialize a secp256k1 point to compressed or uncompressed SEC format."""
    backend = get_backend()
    if backend is not None:
        return backend.serialize_sec_public_key(point, compressed=compressed)
    return serialize_sec_py(point, compressed=compressed)


G = Secp256k1Point(x=SECP256K1_GX, y=SECP256K1_GY, infinity=False)
SECP256K1_INFINITY = Secp256k1Point(infinity=True)


@dataclass(frozen=True, slots=True)
class LinearPointRelation:
    """Represents a point-space ECDSA linearization."""

    input_index: int
    alpha: int
    beta: int
    point_b: Secp256k1Point
    transformed_public_key: Secp256k1Point
    equation: str

    def verify(self, nonce_point: Secp256k1Point) -> bool:
        if nonce_point.infinity:
            raise InvalidSecp256k1PointError("Nonce point cannot be infinity.")
        original_public_key = point_add(self.transformed_public_key,
                                        point_negate(self.point_b))
        left = point_add(original_public_key, self.point_b)
        right = scalar_multiply(self.alpha, nonce_point)
        return left == right


@dataclass(frozen=True, slots=True)
class LinearPointRelationCollection:
    """Immutable collection of point-space relations."""

    records: tuple[LinearPointRelation, ...]

    @property
    def alpha(self) -> list[int]:
        return [record.alpha for record in self.records]

    @property
    def beta(self) -> list[int]:
        return [record.beta for record in self.records]


def derive_point_relation(
    signature_record: SignatureRecord,
    public_key_point: Secp256k1Point,
) -> LinearPointRelation:
    """Derive D + beta*G = alpha*K relation from a signature and public key."""
    if public_key_point.infinity:
        raise InvalidSecp256k1PointError("Public key point cannot be infinity.")

    coefficient_record = derive_linear_coefficients(signature_record)
    point_b = scalar_multiply(coefficient_record.beta, G)
    transformed_public_key = point_add(public_key_point, point_b)
    return LinearPointRelation(
        input_index=coefficient_record.input_index,
        alpha=coefficient_record.alpha,
        beta=coefficient_record.beta,
        point_b=point_b,
        transformed_public_key=transformed_public_key,
        equation="D + \u03b2G = \u03b1K",
    )


@dataclass(frozen=True, slots=True)
class TransformedPointRecord:
    """The result of transforming a signature into D' = d'G."""

    input_index: int
    alpha: int
    beta: int
    new_d_point: Secp256k1Point

    def __post_init__(self) -> None:
        if not 0 <= self.alpha < SECP256K1_ORDER:
            raise InvalidSecp256k1PointError("alpha must be in [0, n-1].")
        if not 0 <= self.beta < SECP256K1_ORDER:
            raise InvalidSecp256k1PointError("beta must be in [0, n-1].")

    def validate(self) -> dict[str, bool]:
        """Validate alpha, beta ranges and point-on-curve.

        Returns:
            Dictionary with ``alpha_in_range``, ``beta_in_range``,
            and ``point_on_curve`` boolean keys.
        """
        if self.new_d_point.infinity:
            on_curve = False
        else:
            p = self.new_d_point
            assert isinstance(p.x, int) and isinstance(p.y, int)
            on_curve = is_on_curve(p.x, p.y)
        return {
            "alpha_in_range": 0 <= self.alpha < SECP256K1_ORDER,
            "beta_in_range": 0 <= self.beta < SECP256K1_ORDER,
            "point_on_curve": on_curve,
        }


@dataclass(frozen=True, slots=True)
class TransformedPointCollection:
    """Immutable collection of transformed point records."""

    records: tuple[TransformedPointRecord, ...]


def derive_transformed_point(
    signature_record: SignatureRecord,
    public_key_point: Secp256k1Point,
) -> TransformedPointRecord:
    """Derive the transformed point D' = d'*G from a signature and public key."""
    if public_key_point.infinity:
        raise InvalidSecp256k1PointError("Public key point cannot be infinity.")

    coefficient_record = derive_linear_coefficients(signature_record)
    point_b = scalar_multiply(coefficient_record.beta, G)
    new_d_point = point_add(public_key_point, point_b)

    return TransformedPointRecord(
        input_index=coefficient_record.input_index,
        alpha=coefficient_record.alpha,
        beta=coefficient_record.beta,
        new_d_point=new_d_point,
    )


__all__ = [
    "G",
    "InvalidSecPublicKeyError",
    "InvalidSecp256k1PointError",
    "LinearPointRelation",
    "LinearPointRelationCollection",
    "SECP256K1_A",
    "SECP256K1_B",
    "SECP256K1_FIELD_PRIME",
    "SECP256K1_GX",
    "SECP256K1_GY",
    "SECP256K1_INFINITY",
    "SECP256K1_ORDER",
    "Secp256k1Point",
    "TransformedPointCollection",
    "TransformedPointRecord",
    "derive_point_relation",
    "derive_transformed_point",
    "field_pow",
    "field_sqrt",
    "field_sqrt_py",
    "int_to_bytes",
    "inverse_mod",
    "is_on_curve",
    "is_on_curve_py",
    "normalize_field_element",
    "normalize_non_negative",
    "parse_sec_public_key",
    "parse_sec_py",
    "point_add",
    "point_add_py",
    "point_double",
    "point_double_py",
    "point_negate",
    "point_negate_py",
    "scalar_multiply",
    "scalar_multiply_py",
    "serialize_sec_public_key",
    "serialize_sec_py",
]
