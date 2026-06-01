"""Bitcoin transaction types, parsing, and construction.

This module re-exports the core transaction model classes and utility
functions from its submodules:

  - ``models``:    ``OutPoint``, ``TxIn``, ``TxOut``, ``Witness``, ``Tx``.
  - ``parser``:    ``parse_tx`` for deserialising transactions from wire format.
  - ``tx``:        ``make_tx`` convenience builder.
  - ``builder``:   ``TransactionBuilder`` fluent API and ``tx_from_dict``.
"""

from bitcoin.transaction.builder import TransactionBuilder, tx_from_dict
from bitcoin.transaction.models import EMPTY_WITNESS, OutPoint, Tx, TxIn, TxOut, Witness
from bitcoin.transaction.parser import parse_tx
from bitcoin.transaction.rbf import is_opt_in_rbf, has_sequence_lock
from bitcoin.transaction.tx import make_tx

__all__ = [
    "EMPTY_WITNESS",
    "OutPoint",
    "TransactionBuilder",
    "Tx",
    "TxIn",
    "TxOut",
    "Witness",
    "has_sequence_lock",
    "is_opt_in_rbf",
    "make_tx",
    "parse_tx",
    "tx_from_dict",
]
