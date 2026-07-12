# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Signature-hash computation for legacy, SegWit v0, and Taproot inputs.

Three sighash algorithms are supported, each implementing a different
Bitcoin specification:

- :mod:`bitcoin.sighash.flag` – SIGHASH flag constants and validation.
- :mod:`bitcoin.sighash.legacy` – pre-SegWit sighash (hash of full
  transaction with input scripts and selected outputs modified per
  the flag).
- :mod:`bitcoin.sighash.segwit` – BIP-143 SegWit v0 sighash (commits
  to amounts and uses amortised hashes of prevouts and sequences for
  a factor-of-~3 speedup over the legacy algorithm).
- :mod:`bitcoin.sighash.taproot` – BIP-341 Taproot sighash (tagged
  hash over an extensible, script/key-path-aware digest).

The legacy and SegWit sighashes are LRU-cached because they are
typically computed repeatedly for the same transaction during
extraction and signing pipelines.  The Taproot algorithm is not
cached because it carries a much larger set of parameters.

References
----------

- Bitcoin developer guide: "Signature hash modification"
- BIP-143: "Transaction Signature Verification for SegWit v0"
- BIP-341: "Taproot: SegWit version 1 spending rules"
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
