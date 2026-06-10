"""Legacy (pre-SegWit) sighash computation.

This is the algorithm used before SegWit, superseded by BIP-143.
"""

from __future__ import annotations

import functools
from typing import TYPE_CHECKING

from bitcoin.encoding.hasher import hash256

if TYPE_CHECKING:
    from bitcoin.transaction.models import Tx


@functools.lru_cache(maxsize=128)
def sighash_legacy(transaction: Tx, input_index: int, script: bytes,
                   sighash_flag: int) -> bytes:
    """Compute the legacy (pre-SegWit) sighash for a transaction input.

    The serialisation depends on the SIGHASH flags: inputs/outputs may be
    omitted or zeroed according to the flag semantics.

    Args:
        transaction: The transaction to sign.
        input_index: Index of the input being signed.
        script: The script to evaluate (usually ``script_pubkey`` or
            ``redeemScript``).
        sighash_flag: SIGHASH flag determining which parts of the transaction
            are committed to.

    Returns:
        The 32-byte sighash digest.

    Raises:
        ValueError: If ``SIGHASH_SINGLE`` is used and *input_index* is out of
            range for the transaction outputs.
    """
    from bitcoin.services.serializer import serialize_legacy_tx_for_sighash

    preimage = serialize_legacy_tx_for_sighash(transaction, input_index, script,
                                               sighash_flag)
    return hash256(preimage)
