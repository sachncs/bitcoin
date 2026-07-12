# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""ECDSA public-key recovery and signature verification.

Three primitives used throughout the rest of the signature pipeline:

- :func:`recover_public_key` – recover the public key ``Q`` from a
  signature ``(r, s)``, the message hash, and a 2-bit recovery ID
  (``rec_id``) using the standard ECDSA public-key recovery formula
  ``Q = r⁻¹ · (s · R − e · G)``.  Returns a :class:`Point`; raises
  :exc:`ValueError` if the recovered point is not on the curve or is
  the point at infinity.
- :func:`verify_signature` (re-exported as :func:`verify_sig`) –
  verify a signature against a public key using the standard ECDSA
  verification equation, with constant-time byte comparison via
  :func:`hmac.compare_digest`.
- :func:`constant_time_eq` – a constant-time bytes-equality helper,
  useful for tests and for callers building their own verification
  paths.

Security notes
--------------

:func:`verify_signature` uses :func:`hmac.compare_digest` for the
final ``r == R.x`` comparison, so the verification time does not
depend on the value of ``r``.  This is a defence against timing-
side-channel attacks when verification is performed on attacker-
supplied signatures.
"""

from __future__ import annotations

import hmac
import logging
from typing import TYPE_CHECKING

from bitcoin.curve import GENERATOR
from bitcoin.curve.dispatch import add, is_on_curve, multiply
from bitcoin.curve.params import CURVE_ORDER, FIELD_PRIME
from bitcoin.encoding.der import decode_der

if TYPE_CHECKING:
    from bitcoin.curve.point import Point

logger = logging.getLogger(__name__)

PUBKEY_RECOVERY_OFFSET = 27
HASH_BYTE_LENGTH = 32


def recover_public_key(
    message_hash: bytes, der_signature: bytes, recovery_flag: int
) -> Point:
    """Recover the ECDSA public key from a signature and recovery ID.

    Uses the standard ECDSA public-key recovery formula:
    ``Q = r^(-1) * (s * R - e * G)``.

    Args:
        message_hash: The 32-byte message hash.
        der_signature: The DER-encoded signature.
        recovery_flag: The recovery flag byte (``27..34`` for compressed,
            ``35..42`` for uncompressed).

    Returns:
        The recovered ``Point``.

    Raises:
        ValueError: If the recovered point is not on the curve or is infinity.
    """
    r, s = decode_der(der_signature)
    rec_id = (recovery_flag - PUBKEY_RECOVERY_OFFSET) & 0x03

    # Recover R point from r (x-coordinate)
    r_y_sq = (pow(r, 3, FIELD_PRIME) + 7) % FIELD_PRIME
    r_y = pow(r_y_sq, (FIELD_PRIME + 1) // 4, FIELD_PRIME)
    if (r_y & 1) != (rec_id & 1):
        r_y = FIELD_PRIME - r_y

    from bitcoin.curve.point import Point

    r_point = Point(x=r, y=r_y)

    if not is_on_curve(r_point):
        raise ValueError("Recovered R point is not on the curve.")

    # Negate message hash modulo CURVE_ORDER: e' = -e mod n
    e = int.from_bytes(message_hash, "big")
    e_inv = CURVE_ORDER - (e % CURVE_ORDER) if e % CURVE_ORDER != 0 else 0

    # Q = r^(-1) * (s * R - e * G) = s * r^(-1) * R + (-e) * r^(-1) * G
    from bitcoin.field import inverse

    r_inv = inverse(r, CURVE_ORDER)

    r1 = multiply((s * r_inv) % CURVE_ORDER, r_point)
    r2 = multiply((r_inv * e_inv) % CURVE_ORDER, GENERATOR)
    public_key = add(r1, r2)

    if public_key.infinity:
        raise ValueError("Recovered point is infinity.")

    return public_key


def constant_time_eq(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time."""
    return hmac.compare_digest(a, b)


def verify_signature(
    message_hash: bytes, der_signature: bytes, public_key: Point
) -> bool:
    """Verify an ECDSA signature against a public key.

    Args:
        message_hash: The 32-byte message hash.
        der_signature: The DER-encoded signature.
        public_key: The public key ``Point``.

    Returns:
        ``True`` if the signature is valid, ``False`` otherwise.
    """
    try:
        r, s = decode_der(der_signature)
    except ValueError:
        logger.debug("verify_signature: DER decoding failed")
        return False

    if r < 1 or r >= CURVE_ORDER or s < 1 or s >= CURVE_ORDER:
        logger.debug("verify_signature: r/s out of range")
        return False

    if not is_on_curve(public_key) or public_key.infinity:
        logger.debug("verify_signature: invalid public key")
        return False

    e = int.from_bytes(message_hash, "big") % CURVE_ORDER
    if e == 0:
        logger.debug("verify_signature: message hash is zero")
        return False

    from bitcoin.field import inverse

    s_inv = inverse(s, CURVE_ORDER)
    u1 = (e * s_inv) % CURVE_ORDER
    u2 = (r * s_inv) % CURVE_ORDER

    u1_g = multiply(u1, GENERATOR)
    u2_p = multiply(u2, public_key)
    point = add(u1_g, u2_p)

    if point.infinity:
        logger.debug("verify_signature: resulting point is infinity")
        return False

    px = point.x
    if px is None:
        logger.debug("verify_signature: point x is None")
        return False
    r_bytes = r.to_bytes(HASH_BYTE_LENGTH, "big")
    px_bytes = (px % CURVE_ORDER).to_bytes(HASH_BYTE_LENGTH, "big")
    return constant_time_eq(px_bytes, r_bytes)


# Backward-compatible alias — verify_signature is the canonical name.
verify_sig = verify_signature
