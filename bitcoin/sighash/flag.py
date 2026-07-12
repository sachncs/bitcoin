# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""SIGHASH flag constants, validation, and human-readable names.

Defines the eight standard SIGHASH combinations, where the *base flag*
determines which outputs are committed to (``ALL``, ``NONE``,
``SINGLE``) and the ``ANYONECANPAY`` modifier (ORed into the high bit)
restricts commitment to a single input.

Constants
---------

- :data:`SIGHASH_ALL` (0x01), :data:`SIGHASH_NONE` (0x02),
  :data:`SIGHASH_SINGLE` (0x03) – base flags.
- :data:`SIGHASH_ANYONECANPAY` (0x80) – input modifier.
- :data:`SIGHASH_ALL_ANYONECANPAY`, :data:`SIGHASH_NONE_ANYONECANPAY`,
  :data:`SIGHASH_SINGLE_ANYONECANPAY` – pre-composed combinations.
- :data:`SIGHASH_MASK` (0x1F) – mask isolating the base flag bits.
- :data:`SIGHASH_NAMES` – mapping from flag value to human-readable
  name.

Functions
---------

- :func:`sighash_name` – return the human-readable name for a flag.
- :func:`require_sighash_flag` – validate a flag's base component
  and raise :exc:`ValueError` if it is not a known base flag.
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
    return SIGHASH_NAMES.get(flag, f"SIGHASH_UNKNOWN({flag})")


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
