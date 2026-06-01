"""SIGHASH flag constants, validation, and human-readable names.

Constants
---------
SIGHASH_ALL
SIGHASH_NONE
SIGHASH_SINGLE
SIGHASH_ANYONECANPAY
SIGHASH_MASK
SIGHASH_ALL_ANYONECANPAY
SIGHASH_NONE_ANYONECANPAY
SIGHASH_SINGLE_ANYONECANPAY
SIGHASH_NAMES

Functions
---------
sighash_name
require_sighash_flag
"""

from __future__ import annotations

SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80
SIGHASH_MASK = 0x1F
SIGHASH_ALL_ANYONECANPAY = SIGHASH_ALL | SIGHASH_ANYONECANPAY
SIGHASH_NONE_ANYONECANPAY = SIGHASH_NONE | SIGHASH_ANYONECANPAY
SIGHASH_SINGLE_ANYONECANPAY = SIGHASH_SINGLE | SIGHASH_ANYONECANPAY

SIGHASH_NAMES: dict[int, str] = {
    SIGHASH_ALL: "SIGHASH_ALL",
    SIGHASH_NONE: "SIGHASH_NONE",
    SIGHASH_SINGLE: "SIGHASH_SINGLE",
    SIGHASH_ALL_ANYONECANPAY: "SIGHASH_ALL|ANYONECANPAY",
    SIGHASH_NONE_ANYONECANPAY: "SIGHASH_NONE|ANYONECANPAY",
    SIGHASH_SINGLE_ANYONECANPAY: "SIGHASH_SINGLE|ANYONECANPAY",
}


def sighash_name(flag: int) -> str:
    """Return a human-readable name for *flag*.

    Args:
        flag: A SIGHASH flag integer.

    Returns:
        The corresponding name string (e.g. ``"SIGHASH_ALL"``) or
        ``"SIGHASH_UNKNOWN(...)"`` if the base flag is not recognised.
    """
    base = flag & SIGHASH_MASK
    has_acp = bool(flag & SIGHASH_ANYONECANPAY)
    if has_acp:
        base |= SIGHASH_ANYONECANPAY
    return SIGHASH_NAMES.get(base, f"SIGHASH_UNKNOWN({flag})")


def require_sighash_flag(flag: int) -> int:
    """Validate a SIGHASH flag and return it unchanged.

    Args:
        flag: SIGHASH flag to validate.

    Returns:
        The input *flag* unchanged on success.

    Raises:
        ValueError: If the base flag (``flag & SIGHASH_MASK``) is not one of
            ``SIGHASH_ALL``, ``SIGHASH_NONE``, or ``SIGHASH_SINGLE``.
    """
    base = flag & SIGHASH_MASK
    if base not in (SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE):
        raise ValueError(f"Unknown SIGHASH base type: {base}.")
    return flag
