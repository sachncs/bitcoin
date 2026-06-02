"""Batch ECDSA signature verification.

Verifies each signature individually for correctness.  This gives the
same security level as single verification while providing a convenient
API for verifying multiple signatures at once.
"""

from __future__ import annotations

from bitcoin.curve.point import Point
from bitcoin.signature.check import verify_sig


def batch_verify(
    messages: list[bytes],
    sigs: list[bytes],
    public_keys: list[Point],
) -> bool:
    """Verify a batch of ECDSA signatures.

    All signatures must be valid for the batch to return ``True``.
    A single invalid signature makes the entire batch fail.

    Args:
        messages: 32-byte message hashes, one per signature.
        sigs: DER-encoded signatures, one per message.
        public_keys: Public-key ``Point`` instances, one per message.

    Returns:
        ``True`` iff **all** signatures are valid.

    Raises:
        ValueError: If the three lists differ in length.
    """
    n = len(messages)
    if len(sigs) != n or len(public_keys) != n:
        raise ValueError(
            f"Length mismatch: {len(messages)} messages, "
            f"{len(sigs)} sigs, {len(public_keys)} keys."
        )

    return all(verify_sig(m, s, pk) for m, s, pk in zip(messages, sigs, public_keys))


__all__ = [
    "batch_verify",
]
