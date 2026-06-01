"""Field square root via Tonelli-Shanks for p ≡ 3 (mod 4)."""

from bitcoin.exceptions import PointError


def pow_mod(value: int, exponent: int, modulus: int) -> int:
    """Return ``pow(value, exponent, modulus)``.

    Exists as a named wrapper so callers can mock or trace modular
    exponentiation independently of the builtin.

    Args:
        value: Base integer.
        exponent: Exponent integer.
        modulus: Modulus integer.

    Returns:
        ``(value ** exponent) % modulus``.
    """
    return pow(value, exponent, modulus)


def sqrt(value: int, field_prime: int) -> int:
    """Return a square root of *value* in the field GF(*field_prime*).

    Implements the Tonelli-Shanks algorithm for the special case
    *field_prime* ≡ 3 (mod 4), which secp256k1 satisfies.

    Args:
        value: Integer whose square root is sought.
        field_prime: Prime modulus of the field.

    Returns:
        Integer *root* such that ``(root * root) % field_prime == value``.

    Raises:
        PointError: If *value* is not a quadratic residue modulo
            *field_prime*.
    """
    root = pow_mod(value, (field_prime + 1) // 4, field_prime)
    if (root * root) % field_prime != value % field_prime:
        raise PointError(f"No square root for value modulo {field_prime}.")
    return root
