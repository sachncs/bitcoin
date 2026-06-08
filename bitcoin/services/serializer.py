"""Transaction serialisation to Bitcoin wire format.

Provides SegWit-aware serialisation (``serialize_tx``), legacy
serialisation (``serialize_legacy_tx``), JSON conversion (``tx_to_json``),
and specialised helpers for sighash computation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from bitcoin.encoding.varint import encode_varint
from bitcoin.encoding.hex import encode_hex

if TYPE_CHECKING:
    from bitcoin.transaction.models import Tx


def serialize_tx(tx: Tx) -> bytes:
    """Serialize a transaction to wire format (SegWit-aware).

    Automatically includes the SegWit marker (``0x00``) and flag
    (``0x01``) when the transaction has any non-empty witness, and
    appends witness data after the outputs.

    Args:
        tx: The transaction to serialise.

    Returns:
        Wire-format bytes.
    """
    data = bytearray()
    data.extend(tx.version.to_bytes(4, "little"))

    if tx.is_segwit():
        data.extend(b"\x00\x01")  # SegWit marker + flag

    data.extend(encode_varint(len(tx.inputs)))
    for txin in tx.inputs:
        data.extend(txin.previous_output.txid)
        data.extend(txin.previous_output.vout.to_bytes(4, "little"))
        data.extend(encode_varint(len(txin.script_sig)))
        data.extend(txin.script_sig)
        data.extend(txin.sequence.to_bytes(4, "little"))

    data.extend(encode_varint(len(tx.outputs)))
    for txout in tx.outputs:
        data.extend(txout.value.to_bytes(8, "little"))
        data.extend(encode_varint(len(txout.script_pubkey)))
        data.extend(txout.script_pubkey)

    if tx.is_segwit():
        for txin in tx.inputs:
            data.extend(encode_varint(len(txin.witness)))
            for item in txin.witness.items:
                data.extend(encode_varint(len(item)))
                data.extend(item)

    data.extend(tx.lock_time.to_bytes(4, "little"))
    return bytes(data)


def tx_to_json(tx: Tx) -> dict[str, Any]:
    """Convert a transaction to a JSON-serializable dict.

    Args:
        tx: The transaction to convert.

    Returns:
        A dict representing the full transaction structure.
    """
    return {
        "txid":
            encode_hex(tx.txid()),
        "version":
            tx.version,
        "lock_time":
            tx.lock_time,
        "inputs": [{
            "txid":
                encode_hex(txin.previous_output.txid),
            "vout":
                txin.previous_output.vout,
            "script_sig":
                encode_hex(txin.script_sig),
            "sequence":
                txin.sequence,
            "witness": [encode_hex(w) for w in txin.witness.items]
                       if txin.witness.items else None,
        } for txin in tx.inputs],
        "outputs": [{
            "value": txout.value,
            "script_pubkey": encode_hex(txout.script_pubkey),
        } for txout in tx.outputs],
    }


def serialize_legacy_tx(tx: Tx) -> bytes:
    """Serialize a transaction in legacy (non-SegWit) format.

    Witness data is omitted entirely, matching the pre-SegWit wire
    format.

    Args:
        tx: The transaction to serialise.

    Returns:
        Legacy wire-format bytes.
    """
    data = bytearray()
    data.extend(tx.version.to_bytes(4, "little"))
    data.extend(encode_varint(len(tx.inputs)))
    for txin in tx.inputs:
        data.extend(txin.previous_output.txid)
        data.extend(txin.previous_output.vout.to_bytes(4, "little"))
        data.extend(encode_varint(len(txin.script_sig)))
        data.extend(txin.script_sig)
        data.extend(txin.sequence.to_bytes(4, "little"))
    data.extend(encode_varint(len(tx.outputs)))
    for txout in tx.outputs:
        data.extend(txout.value.to_bytes(8, "little"))
        data.extend(encode_varint(len(txout.script_pubkey)))
        data.extend(txout.script_pubkey)
    data.extend(tx.lock_time.to_bytes(4, "little"))
    return bytes(data)


def serialize_legacy_tx_for_sighash(tx: Tx, input_index: int, script: bytes,
                                    flag: int) -> bytes:
    """Serialise a transaction for legacy sighash computation.

    Produces the pre-image that is double-SHA256 hashed to produce the
    legacy sighash.  The serialisation varies according to the SIGHASH
    flags (ANYONECANPAY, NONE, SINGLE).

    Args:
        tx: The transaction.
        input_index: Index of the input being signed.
        script: Script to place at the input being signed.
        flag: The SIGHASH flag.

    Returns:
        Serialised sighash pre-image bytes.

    Raises:
        ValueError: If ``SIGHASH_SINGLE`` is used and *input_index* is
            out of bounds for the outputs.
    """
    from bitcoin.sighash.flag import (
        SIGHASH_ANYONECANPAY,
        SIGHASH_MASK,
        SIGHASH_NONE,
        SIGHASH_SINGLE,
    )

    base_flag = flag & SIGHASH_MASK
    data = bytearray()
    data.extend(tx.version.to_bytes(4, "little"))

    if flag & SIGHASH_ANYONECANPAY:
        data.extend(encode_varint(1))
        txin = tx.inputs[input_index]
        data.extend(txin.previous_output.txid)
        data.extend(txin.previous_output.vout.to_bytes(4, "little"))
        data.extend(encode_varint(len(script)))
        data.extend(script)
        data.extend(txin.sequence.to_bytes(4, "little"))
    else:
        data.extend(encode_varint(len(tx.inputs)))
        for i, txin in enumerate(tx.inputs):
            data.extend(txin.previous_output.txid)
            data.extend(txin.previous_output.vout.to_bytes(4, "little"))
            if i == input_index:
                data.extend(encode_varint(len(script)))
                data.extend(script)
                data.extend(txin.sequence.to_bytes(4, "little"))
            else:
                data.append(0x00)  # empty script length
                if base_flag in (SIGHASH_NONE, SIGHASH_SINGLE):
                    data.extend(b"\x00\x00\x00\x00")
                else:
                    data.extend(txin.sequence.to_bytes(4, "little"))

    if base_flag == SIGHASH_NONE:
        data.append(0x00)  # varint 0 — zero outputs
    elif base_flag == SIGHASH_SINGLE:
        if input_index >= len(tx.outputs):
            raise ValueError("Input index out of bounds for SIGHASH_SINGLE.")
        data.extend(encode_varint(input_index + 1))
        for i in range(input_index + 1):
            if i < len(tx.outputs):
                out = tx.outputs[i]
                data.extend(out.value.to_bytes(8, "little"))
                data.extend(encode_varint(len(out.script_pubkey)))
                data.extend(out.script_pubkey)
            else:
                data.extend((0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"))
                data.append(0x00)
    else:
        data.extend(encode_varint(len(tx.outputs)))
        for out in tx.outputs:
            data.extend(out.value.to_bytes(8, "little"))
            data.extend(encode_varint(len(out.script_pubkey)))
            data.extend(out.script_pubkey)

    data.extend(tx.lock_time.to_bytes(4, "little"))
    data.extend(flag.to_bytes(4, "little"))
    return bytes(data)


def serialize_tx_for_sighash_taproot(tx: Tx) -> bytes:
    """Serialise transaction data for BIP-341 Taproot sighash.

    Produces the common transaction data shared across all inputs during
    Taproot sighash computation (inputs and outputs, without witness
    data).  The caller is responsible for output pruning based on the
    sighash flag.

    Args:
        tx: The transaction.

    Returns:
        Serialised bytes of inputs and outputs for the Taproot sighash.
    """
    data = bytearray()
    data.extend(encode_varint(len(tx.inputs)))
    for txin in tx.inputs:
        data.extend(txin.previous_output.txid)
        data.extend(txin.previous_output.vout.to_bytes(4, "little"))
        data.extend(txin.sequence.to_bytes(4, "little"))
    data.extend(encode_varint(len(tx.outputs)))
    for txout in tx.outputs:
        data.extend(txout.value.to_bytes(8, "little"))
        data.extend(encode_varint(len(txout.script_pubkey)))
        data.extend(txout.script_pubkey)
    return bytes(data)
