"""Replace-By-Fee (RBF) detection for Bitcoin transactions.

Provides utilities to detect opt-in RBF (BIP-125) and extract
sequence-number information relevant to fee bumping.
"""

from __future__ import annotations

from bitcoin.transaction.models import Tx

# BIP-125: any input with sequence <= 0xFFFFFFFD signals opt-in RBF.
RBF_SEQUENCE_THRESHOLD = 0xFFFFFFFD


def is_opt_in_rbf(tx: Tx) -> bool:
    """Check whether *tx* signals opt-in Replace-By-Fee (BIP-125).

    A transaction opts into RBF when **any** input has a sequence number
    less than or equal to ``0xFFFFFFFD``.

    Args:
        tx: The transaction to inspect.

    Returns:
        ``True`` if at least one input has a BIP-125 signalling sequence.
    """
    return any(txin.sequence <= RBF_SEQUENCE_THRESHOLD for txin in tx.inputs)


def has_sequence_lock(tx: Tx) -> bool:
    """Check whether *tx* uses relative sequence locks (BIP-68).

    A sequence lock is active when **any** input has a sequence number
    less than ``0xFFFFFFFE`` (the disable flag).  The lower 16 bits of
    the sequence encode the lock value.

    Args:
        tx: The transaction to inspect.

    Returns:
        ``True`` if at least one input has a relative time lock.
    """
    return any(txin.sequence < 0xFFFFFFFE for txin in tx.inputs)


__all__ = [
    "RBF_SEQUENCE_THRESHOLD",
    "is_opt_in_rbf",
    "has_sequence_lock",
]
