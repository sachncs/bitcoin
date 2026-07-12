# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Top-level linearisation API.

Re-exports :func:`linearize_signatures` from
:mod:`bitcoin.signature.linearization.engine`.  Linearisation sorts
extracted signature records by ``(txid, input_index)`` so they can be
compared, serialised, or analysed in a deterministic order across
runs.

The companion :class:`LinearCoefficientCollection` and
:func:`derive_linear_coefficients` API (in
:mod:`bitcoin.signature.linearization.coefficients`) compute the
``(α, β)`` linearisation coefficients that the nonce-reuse attack in
:mod:`bitcoin.signature.attack` requires.
"""

from bitcoin.signature.linearization.engine import linearize_signatures

__all__ = [
    "linearize_signatures",
]
