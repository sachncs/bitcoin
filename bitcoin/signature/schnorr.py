"""Schnorr signature verification (BIP-340) for Taproot inputs."""

from __future__ import annotations

from bitcoin.curve import GENERATOR
from bitcoin.curve.dispatch import add, multiply, negate
from bitcoin.curve.params import CURVE_ORDER, FIELD_PRIME
from bitcoin.encoding.hasher import tagged_hash


def lift_x(x: int) -> tuple[int, int] | None:
    """Lift an x-coordinate to a point with even y (BIP-340).

    Args:
        x: The x-coordinate (0 <= x < p).

    Returns:
        ``(x, y)`` where y is even, or ``None`` if no such point exists.
    """
    if x >= FIELD_PRIME:
        return None
    y_sq = (pow(x, 3, FIELD_PRIME) + 7) % FIELD_PRIME
    y = pow(y_sq, (FIELD_PRIME + 1) // 4, FIELD_PRIME)
    if (y * y) % FIELD_PRIME != y_sq:
        return None
    if y & 1:
        y = FIELD_PRIME - y
    return (x, y)


def verify_schnorr_signature(
    public_key_bytes: bytes,
    signature_bytes: bytes,
    message_hash: bytes,
) -> bool:
    """Verify a BIP-340 Schnorr signature.

    Args:
        public_key_bytes: 32-byte x-only public key.
        signature_bytes: 64-byte signature ``(r || s)``.
        message_hash: 32-byte message hash.

    Returns:
        ``True`` if the signature is valid.
    """
    if (len(public_key_bytes) != 32 or len(signature_bytes) != 64 or
            len(message_hash) != 32):
        return False

    p = lift_x(int.from_bytes(public_key_bytes, "big"))
    if p is None:
        return False

    r = int.from_bytes(signature_bytes[:32], "big")
    s = int.from_bytes(signature_bytes[32:], "big")

    if r >= FIELD_PRIME or s >= CURVE_ORDER:
        return False

    from bitcoin.curve.point import Point
    pubkey_point = Point(x=p[0], y=p[1])

    e = tagged_hash("BIP0340/challenge",
                    signature_bytes[:32] + public_key_bytes + message_hash)
    e_int = int.from_bytes(e, "big") % CURVE_ORDER

    sG = multiply(s, GENERATOR)
    eP = multiply(e_int, pubkey_point)
    R = add(sG, negate(eP))

    if R.infinity or R.x is None or R.y is None or (R.y & 1) != 0:
        return False

    return R.x == r


verify_schnorr_sig = verify_schnorr_signature

__all__ = [
    "lift_x",
    "verify_schnorr_signature",
    "verify_schnorr_sig",
]
