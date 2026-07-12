# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Transaction fee estimation and virtual size calculation.

Computes an estimate of a transaction's virtual size (``vbytes``) and
multiplies it by a fee rate to obtain a fee in satoshis.  The
estimator follows BIP-141's weight-unit model, where witness bytes
count as 1 weight unit each and non-witness bytes count as 4, with
``vbytes = ceil(weight / 4)``.

This is an *estimate*, not an exact measurement.  In particular, the
estimator assumes standard script sizes for the overhead constants
(:data:`BASE_VBYTE_SIZE`, :data:`OVERHEAD_PER_INPUT`,
:data:`OVERHEAD_PER_OUTPUT`); call :func:`serialize_tx` and measure
the result if you need an exact size.

Reference: BIP-141 "Segregated Witness".
"""

from __future__ import annotations

from bitcoin.transaction.models import Tx, TxOut

WITNESS_SCALE_FACTOR = 4
BASE_VBYTE_SIZE = 10  # version (4) + flags (2) + lock_time (4)
OUTPUT_BASE_SIZE = 8  # value (8) + script_len (1+)
OVERHEAD_PER_INPUT = 41  # txid (32) + vout (4) + script_len (1) + sequence (4)
OVERHEAD_PER_OUTPUT = 9  # value (8) + script_len (1)


def estimate_vsize(tx: Tx) -> int:
    """Estimate the virtual size (vbytes) of a transaction.

    Accounts for SegWit discount: witness data counts as 1/4 weight
    vs non-witness data.  Returns a lower-bound estimate suitable for
    fee calculation.

    Args:
        tx: The transaction to measure.

    Returns:
        Estimated virtual size in vbytes.
    """
    base_weight = (
        BASE_VBYTE_SIZE
        + OVERHEAD_PER_INPUT * len(tx.inputs)
        + OVERHEAD_PER_OUTPUT * len(tx.outputs)
        + sum(len(out.script_pubkey) for out in tx.outputs)
    )
    base_weight *= WITNESS_SCALE_FACTOR

    witness_weight = 0
    for txin in tx.inputs:
        witness_weight += 2  # witness count varint
        for item in txin.witness.items:
            witness_weight += len(item) + varint_size(len(item))
        if txin.witness.items:
            witness_weight += len(txin.script_sig)

    total_weight = base_weight + witness_weight
    return (total_weight + WITNESS_SCALE_FACTOR - 1) // WITNESS_SCALE_FACTOR


def varint_size(value: int) -> int:
    """Return the byte size of a Bitcoin varint encoding of *value*."""
    if value < 0xFD:
        return 1
    if value <= 0xFFFF:
        return 3
    if value <= 0xFFFFFFFF:
        return 5
    return 9


def estimate_minimum_fee(tx: Tx, sat_per_vbyte: int = 1) -> int:
    """Estimate the minimum transaction fee in satoshis.

    Uses the estimated virtual size and a user-supplied fee rate.

    Args:
        tx: The transaction to estimate fee for.
        sat_per_vbyte: Fee rate in satoshis per vbyte (default 1).

    Returns:
        Minimum fee in satoshis.
    """
    vsize = estimate_vsize(tx)
    return vsize * sat_per_vbyte


def estimate_optimal_fee(tx: Tx, target_blocks: int = 2) -> int:
    """Estimate a fee that would confirm within *target_blocks*.

    This is a placeholder that uses a simple formula.  In production
    you would call a fee-estimation API (e.g. Mempool.space).

    Args:
        tx: The transaction to estimate fee for.
        target_blocks: Desired confirmation target in blocks.

    Returns:
        Recommended fee in satoshis.
    """
    vsize = estimate_vsize(tx)
    sat_per_vbyte = max(1, 120 // max(target_blocks, 1))
    return vsize * sat_per_vbyte


def total_output_value(outputs: tuple[TxOut, ...]) -> int:
    """Return the sum of all output values in satoshis.

    Args:
        outputs: The transaction outputs.

    Returns:
        Total output value in satoshis.
    """
    return sum(out.value for out in outputs)


__all__ = [
    "estimate_minimum_fee",
    "estimate_optimal_fee",
    "estimate_vsize",
    "total_output_value",
    "varint_size",
]
