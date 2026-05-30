"""Deterministic linearization of extracted Bitcoin ECDSA signature data.

This module derives the transformed relation

    d' \u2261 \u03b1k (mod n)

from extracted signature values by starting with the standard ECDSA identity

    d \u2261 (sk - z)r^{-1} (mod n)

and expanding it into the linear form

    d + \u03b2 \u2261 \u03b1k (mod n)

where:

    \u03b1 \u2261 sr^{-1} (mod n)
    \u03b2 \u2261 zr^{-1} (mod n)

The arithmetic is performed exactly over secp256k1's curve order. No external
number theory or elliptic curve libraries are used.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from bitcoin.arithmetic import (
    NotInvertibleError,)
from bitcoin.arithmetic import (
    inverse_mod as arithmetic_inverse,)
from bitcoin.arithmetic import (
    normalize_non_negative as arithmetic_normalize,)
from bitcoin.exceptions import (
    InvalidLinearCoefficientError,
    NonInvertibleLinearCoefficientError,
)
from bitcoin.models import SignatureRecord
from bitcoin.utils import int_to_hex

logger = logging.getLogger(__name__)

SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def normalize_non_negative(value: int, label: str) -> int:
    """Normalize a value to a non-negative integer for scalar arithmetic."""
    try:
        return arithmetic_normalize(value, label)
    except (TypeError, ValueError) as exc:
        raise InvalidLinearCoefficientError(str(exc)) from exc


def normalize_scalar(value: int, label: str) -> int:
    """Normalize and validate a scalar is non-zero and below the curve order."""
    value = normalize_non_negative(value, label)
    if value == 0:
        raise InvalidLinearCoefficientError(f"{label} must be non-zero.")
    if value >= SECP256K1_ORDER:
        raise InvalidLinearCoefficientError(
            f"{label} must be smaller than the curve order.")
    return value


def inverse_mod(value: int, modulus: int) -> int:
    """Return the modular inverse of value modulo the given modulus."""
    try:
        return arithmetic_inverse(value, modulus)
    except NotInvertibleError as exc:
        raise NonInvertibleLinearCoefficientError(str(exc)) from exc
    except (TypeError, ValueError) as exc:
        raise InvalidLinearCoefficientError(str(exc)) from exc


def parse_signature_scalar(value: str, label: str) -> int:
    """Parse a hexadecimal string into an integer scalar."""
    if not isinstance(value, str):
        raise InvalidLinearCoefficientError(
            f"{label} must be a hexadecimal string.")
    stripped = value.strip().lower()
    if stripped.startswith("0x"):
        stripped = stripped[2:]
    if not stripped:
        raise InvalidLinearCoefficientError(f"{label} cannot be empty.")
    try:
        parsed = int(stripped, 16)
    except ValueError as error:
        raise InvalidLinearCoefficientError(
            f"{label} is not valid hex.") from error
    return parsed


@dataclass(frozen=True, slots=True)
class LinearCoefficientRecord:
    """Represents one linearized signature relation."""

    input_index: int
    r: int
    s: int
    z: int
    alpha: int
    beta: int
    sighash_flag: int
    script_type: str

    def __post_init__(self) -> None:
        if not isinstance(self.input_index, int) or self.input_index < 0:
            raise InvalidLinearCoefficientError(
                "input_index must be a non-negative int.")
        normalize_scalar(self.r, "r")
        normalize_scalar(self.s, "s")
        normalize_non_negative(self.z, "z")
        if not isinstance(self.alpha,
                          int) or not 0 <= self.alpha < SECP256K1_ORDER:
            raise InvalidLinearCoefficientError(
                "alpha must be reduced modulo n.")
        if not isinstance(self.beta,
                          int) or not 0 <= self.beta < SECP256K1_ORDER:
            raise InvalidLinearCoefficientError(
                "beta must be reduced modulo n.")
        if (not isinstance(self.sighash_flag, int) or
                not 0 <= self.sighash_flag <= 0xFFFFFFFF):
            raise InvalidLinearCoefficientError(
                "sighash_flag must be non-negative.")
        if not isinstance(self.script_type,
                          str) or not self.script_type.strip():
            raise InvalidLinearCoefficientError(
                "script_type must be a non-empty string.")

    def equation(self) -> str:
        return "d' \u2261 \u03b1k (mod n)"

    def expanded_equation(self) -> str:
        return (f"d + 0x{int_to_hex(self.beta)} \u2261 "
                f"0x{int_to_hex(self.alpha)} * k (mod n)")

    def verify_linear_relation(self, k: int, d: int) -> bool:
        if not isinstance(k, int) or not isinstance(d, int):
            raise InvalidLinearCoefficientError("k and d must be integers.")
        k = normalize_non_negative(k, "k")
        d = normalize_non_negative(d, "d")
        left = (d + self.beta) % SECP256K1_ORDER
        right = (self.alpha * k) % SECP256K1_ORDER
        return left == right


@dataclass(frozen=True, slots=True)
class LinearCoefficientCollection:
    """Immutable collection of linearized signature relations."""

    records: tuple[LinearCoefficientRecord, ...]

    @property
    def alpha(self) -> list[int]:
        return [record.alpha for record in self.records]

    @property
    def beta(self) -> list[int]:
        return [record.beta for record in self.records]


def derive_linear_coefficients(
    signature_record: SignatureRecord,) -> LinearCoefficientRecord:
    """Derive alpha and beta coefficients from an ECDSA signature record."""
    r = parse_signature_scalar(signature_record.r, "r")
    s = parse_signature_scalar(signature_record.s, "s")
    z = parse_signature_scalar(signature_record.z, "z")

    try:
        r = normalize_scalar(r, "r")
        s = normalize_scalar(s, "s")
    except InvalidLinearCoefficientError:
        logger.error(
            "Invalid scalar in signature at input %d (r=%s, s=%s)",
            signature_record.input_index,
            signature_record.r,
            signature_record.s,
        )
        raise

    r_inverse = inverse_mod(r, SECP256K1_ORDER)
    alpha = (s * r_inverse) % SECP256K1_ORDER
    beta = (z % SECP256K1_ORDER) * r_inverse % SECP256K1_ORDER

    return LinearCoefficientRecord(
        input_index=signature_record.input_index,
        r=r,
        s=s,
        z=z,
        alpha=alpha,
        beta=beta,
        sighash_flag=signature_record.sighash_flag,
        script_type=signature_record.script_type,
    )


__all__ = [
    "LinearCoefficientCollection",
    "LinearCoefficientRecord",
    "NotInvertibleError",
    "SECP256K1_ORDER",
    "derive_linear_coefficients",
    "inverse_mod",
    "normalize_non_negative",
    "normalize_scalar",
    "parse_signature_scalar",
]
