"""Modular arithmetic over finite fields: inversion and validation."""

from bitcoin.exceptions import NotInvertible


def inverse(value: int, modulus: int) -> int:
    """Return the modular inverse of *value* modulo *modulus*.

    Uses the extended Euclidean algorithm.

    Args:
        value: Integer whose inverse is sought. Must be non-negative.
        modulus: Modulus. Must be greater than 1.

    Returns:
        Integer *x* such that ``(value * x) % modulus == 1``.

    Raises:
        TypeError: If either argument is not an ``int``.
        ValueError: If *modulus* is ≤ 1 or *value* is negative.
        NotInvertible: If *value* and *modulus* are not coprime
            (including when *value* is zero).
    """
    if not isinstance(value, int):
        raise TypeError(f"Value must be int, got {type(value).__name__}.")
    if not isinstance(modulus, int):
        raise TypeError(f"Modulus must be int, got {type(modulus).__name__}.")
    if modulus <= 1:
        raise ValueError(f"Modulus must be > 1, got {modulus}.")
    if value < 0:
        raise ValueError(f"Value must be non-negative, got {value}.")
    if value == 0:
        raise NotInvertible("Zero has no modular inverse.")

    old_r, r = modulus, value
    old_t, t = 0, 1
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_t, t = t, old_t - quotient * t

    if old_r != 1:
        raise NotInvertible(
            f"Value {value} is not invertible modulo {modulus}.")
    return old_t % modulus


def validate_non_negative(value: int, label: str = "value") -> int:
    """Validate that *value* is a non-negative integer and return it.

    Args:
        value: Integer to validate.
        label: Name used in error messages (default ``"value"``).

    Returns:
        *value* unchanged on success.

    Raises:
        TypeError: If *value* is not an ``int``.
        ValueError: If *value* is negative.
    """
    if not isinstance(value, int):
        raise TypeError(f"{label} must be an int, got {type(value).__name__}.")
    if value < 0:
        raise ValueError(f"{label} must be non-negative, got {value}.")
    return value
