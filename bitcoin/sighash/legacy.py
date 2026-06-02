"""Legacy (pre-SegWit) sighash computation.

This is the algorithm used before SegWit, superseded by BIP-143.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from bitcoin.encoding.hasher import hash256
from bitcoin.encoding.varint import encode_varint
from bitcoin.sighash.flag import SIGHASH_ANYONECANPAY, SIGHASH_MASK, SIGHASH_NONE, SIGHASH_SINGLE

if TYPE_CHECKING:
    from bitcoin.transaction.models import Tx

MAX_UINT64 = 0xFFFFFFFFFFFFFFFF
ZERO_VARINT = b"\x00"


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
    data = bytearray()
    data.extend(transaction.version.to_bytes(4, "little"))

    if sighash_flag & SIGHASH_ANYONECANPAY:
        data.append(0x00)
    else:
        data.extend(encode_varint(len(transaction.inputs)))
        for i, txin in enumerate(transaction.inputs):
            if i == input_index:
                data.extend(txin.previous_output.txid)
                data.extend(txin.previous_output.vout.to_bytes(4, "little"))
                data.extend(encode_varint(len(script)))
                data.extend(script)
                data.extend(txin.sequence.to_bytes(4, "little"))
            else:
                data.extend(txin.previous_output.txid)
                data.extend(txin.previous_output.vout.to_bytes(4, "little"))
                data.append(0x00)
                if (sighash_flag & SIGHASH_MASK) in (SIGHASH_NONE,
                                                     SIGHASH_SINGLE):
                    data.extend(b"\x00\x00\x00\x00")
                else:
                    data.extend(txin.sequence.to_bytes(4, "little"))

    if (sighash_flag & SIGHASH_MASK) == SIGHASH_NONE:
        data.extend(ZERO_VARINT)
    elif (sighash_flag & SIGHASH_MASK) == SIGHASH_SINGLE:
        if input_index >= len(transaction.outputs):
            raise ValueError(
                "Input index out of bounds for SIGHASH_SINGLE.")
        data.extend(encode_varint(input_index + 1))
        for i in range(input_index + 1):
            if i < len(transaction.outputs):
                out = transaction.outputs[i]
                data.extend(out.value.to_bytes(8, "little"))
                data.extend(encode_varint(len(out.script_pubkey)))
                data.extend(out.script_pubkey)
            else:
                data.extend(MAX_UINT64.to_bytes(8, "little"))
                data.append(0x00)
    else:
        data.extend(encode_varint(len(transaction.outputs)))
        for out in transaction.outputs:
            data.extend(out.value.to_bytes(8, "little"))
            data.extend(encode_varint(len(out.script_pubkey)))
            data.extend(out.script_pubkey)

    data.extend(transaction.lock_time.to_bytes(4, "little"))
    data.extend(sighash_flag.to_bytes(4, "little"))

    return hash256(bytes(data))
