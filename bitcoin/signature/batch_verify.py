"""Sequential ECDSA signature verification for multiple signatures.

Verifies each signature individually for correctness.  This gives the
same security level as single verification while providing a convenient
API for verifying multiple signatures at once.
"""

from __future__ import annotations

from bitcoin.curve.point import Point
from bitcoin.signature.check import verify_sig


def verify_all(
    message_hashes: list[bytes],
    der_signatures: list[bytes],
    public_keys: list[Point],
) -> bool:
    """Verify a sequence of ECDSA signatures.

    All signatures must be valid for the function to return ``True``.
    A single invalid signature makes the entire batch fail.

    Args:
        message_hashes: 32-byte message hashes, one per signature.
        der_signatures: DER-encoded signatures, one per message.
        public_keys: Public-key ``Point`` instances, one per message.

    Returns:
        ``True`` iff **all** signatures are valid.

    Raises:
        ValueError: If the three lists differ in length.
    """
    n = len(message_hashes)
    if len(der_signatures) != n or len(public_keys) != n:
        raise ValueError(
            f"Length mismatch: {len(message_hashes)} messages, "
            f"{len(der_signatures)} signatures, {len(public_keys)} keys."
        )

    zipped = zip(message_hashes, der_signatures, public_keys, strict=True)
    return all(verify_sig(m, s, pk) for m, s, pk in zipped)


batch_verify = verify_all

__all__ = [
    "verify_all",
    "batch_verify",
]
