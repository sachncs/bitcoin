"""Shared modular arithmetic for secp256k1 operations."""

from __future__ import annotations

__all__ = [
    "NotInvertibleError",
    "inverse_mod",
    "normalize_non_negative",
]


class NotInvertibleError(ValueError):
    """Raised when a value has no modular inverse."""


def normalize_non_negative(value: int, label: str) -> int:
    """Validate that *value* is a non-negative integer.

    Raises:
        TypeError: If *value* is not an ``int``.
        ValueError: If *value* is negative.
    """
    if type(value) is not int:
        raise TypeError(f"{label} must be an integer.")
    if value < 0:
        raise ValueError(f"{label} must be non-negative.")
    return value


def inverse_mod(value: int, modulus: int) -> int:
    """Return the modular inverse of *value* modulo *modulus*.

    The algorithm uses the extended Euclidean algorithm and validates all
    inputs before computation.

    Raises:
        TypeError: If either argument is not an ``int``.
        ValueError: If *value* is negative or *modulus* <= 1.
        NotInvertibleError: If *value* is zero or shares a factor with
            *modulus*.
    """
    if not isinstance(modulus, int):
        raise TypeError("Modulus must be an integer.")
    if modulus <= 1:
        raise ValueError("Modulus must be greater than one.")
    value = normalize_non_negative(value, "value")
    if value == 0:
        raise NotInvertibleError("Zero is not invertible.")
    value %= modulus
    if value == 0:
        raise NotInvertibleError("Value is not invertible.")

    old_r, r = modulus, value
    old_t, t = 0, 1
    while r:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_t, t = t, old_t - quotient * t

    if old_r != 1:
        raise NotInvertibleError("Value is not invertible modulo modulus.")
    return old_t % modulus
