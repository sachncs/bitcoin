"""Convenience utilities for constructing transaction objects.

Provides ``make_tx`` to build a ``Tx`` from simple Python dictionaries.
"""

from __future__ import annotations

from typing import Sequence

from bitcoin.transaction.models import Tx, TxIn, TxOut, OutPoint, Witness


def build_transaction(
    version: int,
    inputs: Sequence[dict[str, object]],
    outputs: Sequence[dict[str, object]],
    lock_time: int = 0,
) -> Tx:
    """Build a ``Tx`` from dictionaries for convenience.

    Args:
        version: Transaction version.
        inputs: Sequence of input dicts. Each dict may contain:
            ``txid`` (bytes, required), ``vout`` (int, required),
            ``script_sig`` (bytes, default ``b""``), ``sequence`` (int,
            default ``0xFFFFFFFF``), ``witness`` (tuple[bytes, ...],
            default ``()``).
        outputs: Sequence of output dicts. Each dict must contain:
            ``value`` (int), ``script_pubkey`` (bytes).
        lock_time: Transaction lock time (default ``0``).

    Returns:
        A new ``Tx`` instance.
    """
    txins: list[TxIn] = []
    for inp in inputs:
        witness_items = inp.get("witness", ())
        if not isinstance(witness_items, tuple):
            raise TypeError("witness must be a tuple")
        witness = Witness(tuple(witness_items))
        txid = inp["txid"]
        vout = inp["vout"]
        script_sig = inp.get("script_sig", b"")
        sequence = inp.get("sequence", 0xFFFFFFFF)
        if not isinstance(txid, bytes):
            raise TypeError("txid must be bytes")
        if not isinstance(vout, int):
            raise TypeError("vout must be int")
        if not isinstance(script_sig, bytes):
            raise TypeError("script_sig must be bytes")
        if not isinstance(sequence, int):
            raise TypeError("sequence must be int")
        txins.append(
            TxIn(
                previous_output=OutPoint(txid=txid, vout=vout),
                script_sig=script_sig,
                sequence=sequence,
                witness=witness,
            ))
    txouts: list[TxOut] = []
    for out in outputs:
        value = out["value"]
        script_pubkey = out["script_pubkey"]
        if not isinstance(value, int):
            raise TypeError("value must be int")
        if not isinstance(script_pubkey, bytes):
            raise TypeError("script_pubkey must be bytes")
        txouts.append(TxOut(value=value, script_pubkey=script_pubkey))
    return Tx(version=version,
              inputs=tuple(txins),
              outputs=tuple(txouts),
              lock_time=lock_time)


make_tx = build_transaction
