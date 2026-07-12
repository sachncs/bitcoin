# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Legacy (pre-SegWit) sighash computation.

Implements the original Bitcoin sighash algorithm — the one that
serialises the entire transaction (with the scriptSig of every input
cleared except for the input being signed, which is replaced with the
*provided script*) and double-SHA256-hashes the result, with output
pruning based on the SIGHASH flag.  Superseded by BIP-143 for SegWit
inputs but still required for legacy P2PKH / P2PK / P2SH spends.

The function is :func:`functools.lru_cache`-decorated because
extraction pipelines typically call it many times for the same
``(tx, input_index, script, sighash_flag)`` tuple.
"""

from __future__ import annotations

import functools
from typing import TYPE_CHECKING

from bitcoin.encoding.hasher import hash256

if TYPE_CHECKING:
    from bitcoin.transaction.models import Tx


@functools.lru_cache(maxsize=128)
def sighash_legacy(
    transaction: Tx, input_index: int, script: bytes, sighash_flag: int
) -> bytes:
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

    preimage = serialize_legacy_tx_for_sighash(
        transaction, input_index, script, sighash_flag
    )
    return hash256(preimage)
