# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Top-level signature-extraction API.

Re-exports :func:`extract_signatures` from
:mod:`bitcoin.signature.extraction.engine`.  This is the entry point
used by callers that just want to pull every ECDSA/Schnorr signature
out of a transaction; the more granular per-script-type extractors
and the plugin registry live in the ``engine`` and ``plugins``
modules.

For PSBTs, see :func:`bitcoin.psbt.psbt_extract_signatures`.
"""

from bitcoin.signature.extraction.engine import extract_signatures

__all__ = [
    "extract_signatures",
]
