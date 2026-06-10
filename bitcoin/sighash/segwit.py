"""SegWit v0 sighash computation (BIP-143).

This module implements the BIP-143 signature hash algorithm used for
SegWit v0 (P2WPKH and P2WSH).
"""

from __future__ import annotations

import functools
from typing import TYPE_CHECKING

from bitcoin.encoding.hasher import hash256
from bitcoin.encoding.varint import encode_varint
from bitcoin.sighash.flag import (
    SIGHASH_ANYONECANPAY,
    SIGHASH_MASK,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
)

if TYPE_CHECKING:
    from bitcoin.transaction.models import Tx

ZERO_HASH_32 = b"\x00" * 32


@functools.lru_cache(maxsize=128)
def sighash_segwit(transaction: Tx, input_index: int, script: bytes, value: int,
                   sighash_flag: int) -> bytes:
    """Compute the BIP-143 SegWit v0 sighash for a transaction input.

    Unlike the legacy algorithm, the amount being spent is committed to
    directly, preventing fee-sniping across input value changes.

    Args:
        transaction: The transaction.
        input_index: Index of the input being signed.
        script: The script code (``redeemScript`` for P2SH-P2WPKH,
            ``witnessScript`` for P2WSH).
        value: The amount (in satoshis) of the UTXO being spent.
        sighash_flag: SIGHASH flag determining which parts of the transaction
            are committed to.

    Returns:
        The 32-byte sighash digest.

    Raises:
        ValueError: If ``SIGHASH_SINGLE`` is used and *input_index* is out of
            range for the transaction outputs.
    """
    data = bytearray()
    data.extend(transaction.version.to_bytes(4, "little"))

    # Hash prevouts
    if sighash_flag & SIGHASH_ANYONECANPAY:
        data.extend(ZERO_HASH_32)
    else:
        hash_prevouts = hash256(b"".join(
            txin.previous_output.txid + txin.previous_output.vout.to_bytes(4, "little")
            for txin in transaction.inputs))
        data.extend(hash_prevouts)

    # Hash sequences
    if (sighash_flag & SIGHASH_ANYONECANPAY or
        (sighash_flag & SIGHASH_MASK) in (SIGHASH_NONE, SIGHASH_SINGLE)):
        data.extend(ZERO_HASH_32)
    else:
        hash_sequence = hash256(b"".join(
            txin.sequence.to_bytes(4, "little") for txin in transaction.inputs))
        data.extend(hash_sequence)

    # Outpoint being spent
    outpoint = transaction.inputs[input_index].previous_output
    data.extend(outpoint.txid)
    data.extend(outpoint.vout.to_bytes(4, "little"))

    # Script code
    data.extend(encode_varint(len(script)))
    data.extend(script)

    # Value of the UTXO being spent
    data.extend(value.to_bytes(8, "little"))

    # Sequence
    data.extend(transaction.inputs[input_index].sequence.to_bytes(4, "little"))

    # Hash outputs — BIP-143 specifies only the single output at
    # input_index for SIGHASH_SINGLE, not preceding zero-padded outputs.
    if (sighash_flag & SIGHASH_MASK) == SIGHASH_NONE:
        data.extend(ZERO_HASH_32)
    elif (sighash_flag & SIGHASH_MASK) == SIGHASH_SINGLE:
        if input_index >= len(transaction.outputs):
            raise ValueError(f"Input {input_index} out of range for SIGHASH_SINGLE "
                             f"(only {len(transaction.outputs)} outputs).")
        out = transaction.outputs[input_index]
        hash_outputs_data = (out.value.to_bytes(8, "little") +
                             encode_varint(len(out.script_pubkey)) + out.script_pubkey)
        data.extend(hash256(hash_outputs_data))
    else:
        hash_outputs = hash256(b"".join(
            out.value.to_bytes(8, "little") + encode_varint(len(out.script_pubkey)) +
            out.script_pubkey for out in transaction.outputs))
        data.extend(hash_outputs)

    data.extend(transaction.lock_time.to_bytes(4, "little"))
    data.extend(sighash_flag.to_bytes(4, "little"))

    return hash256(bytes(data))
