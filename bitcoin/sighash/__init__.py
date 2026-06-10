"""Sighash computation for legacy, SegWit v0, and Taproot transactions.

This module re-exports all sighash functions and SIGHASH flag constants
from the submodules:

  - ``flag``: SIGHASH constants and validation helpers.
  - ``legacy``:  Pre-SegWit (legacy) sighash.
  - ``segwit``:  BIP-143 SegWit v0 sighash.
  - ``taproot``: BIP-341 Taproot sighash.
"""

from bitcoin.sighash.flag import (
    SIGHASH_ALL,
    SIGHASH_ALL_ANYONECANPAY,
    SIGHASH_ANYONECANPAY,
    SIGHASH_MASK,
    SIGHASH_NAMES,
    SIGHASH_NONE,
    SIGHASH_NONE_ANYONECANPAY,
    SIGHASH_SINGLE,
    SIGHASH_SINGLE_ANYONECANPAY,
    require_sighash_flag,
    sighash_name,
)
from bitcoin.sighash.legacy import sighash_legacy
from bitcoin.sighash.segwit import sighash_segwit
from bitcoin.sighash.taproot import sighash_taproot

__all__ = [
    "SIGHASH_ALL",
    "SIGHASH_ALL_ANYONECANPAY",
    "SIGHASH_ANYONECANPAY",
    "SIGHASH_MASK",
    "SIGHASH_NAMES",
    "SIGHASH_NONE",
    "SIGHASH_NONE_ANYONECANPAY",
    "SIGHASH_SINGLE",
    "SIGHASH_SINGLE_ANYONECANPAY",
    "require_sighash_flag",
    "sighash_legacy",
    "sighash_name",
    "sighash_segwit",
    "sighash_taproot",
]
