# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Bitcoin transaction types, parsing, construction, and analysis.

This subpackage owns every aspect of the Bitcoin transaction model:

- :mod:`bitcoin.transaction.models` – immutable ``frozen=True,
  slots=True`` dataclasses: :class:`OutPoint`, :class:`TxIn`,
  :class:`TxOut`, :class:`Witness`, :class:`Tx`, plus the
  :class:`TxSerializer` / :class:`TxRbf` / :class:`TxSighash` composed
  engines bound to ``Tx`` for fluent domain-chain access.
- :mod:`bitcoin.transaction.parser` – wire-format deserialisation
  (legacy + SegWit) with explicit limits (max tx size, input/output
  counts, witness item count and size).
- :mod:`bitcoin.transaction.tx` – :func:`make_tx` /
  :func:`build_transaction` convenience builder.
- :mod:`bitcoin.transaction.builder` – :class:`TransactionBuilder`
  fluent API and :func:`tx_from_dict` validating factory.
- :mod:`bitcoin.transaction.fee` – vsize, fee estimation, and
  output-value summation.
- :mod:`bitcoin.transaction.rbf` – opt-in RBF (BIP-125) detection
  and relative-sequence-lock (BIP-68) inspection.

Hard-coded invariants enforced by the models' ``__post_init__``
hooks:

- ``txid`` is always 32 bytes; ``vout``, ``sequence``, ``value``, and
  ``lock_time`` are non-negative.
- ``value`` is capped at ``21_000_000 * 100_000_000`` satoshis (the
  Bitcoin supply ceiling).
"""

from bitcoin.transaction.builder import TransactionBuilder, tx_from_dict
from bitcoin.transaction.fee import (
    estimate_minimum_fee,
    estimate_optimal_fee,
    estimate_vsize,
    total_output_value,
)
from bitcoin.transaction.models import EMPTY_WITNESS, OutPoint, Tx, TxIn, TxOut, Witness
from bitcoin.transaction.parser import parse_tx
from bitcoin.transaction.rbf import has_sequence_lock, is_opt_in_rbf
from bitcoin.transaction.tx import make_tx

__all__ = [
    "EMPTY_WITNESS",
    "OutPoint",
    "TransactionBuilder",
    "Tx",
    "TxIn",
    "TxOut",
    "Witness",
    "estimate_minimum_fee",
    "estimate_optimal_fee",
    "estimate_vsize",
    "has_sequence_lock",
    "is_opt_in_rbf",
    "make_tx",
    "parse_tx",
    "total_output_value",
    "tx_from_dict",
]
