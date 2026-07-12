# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""PSBT signature extraction utilities.

Provides :func:`psbt_extract_signatures`, which pulls every ECDSA
signature out of a :class:`~bitcoin.psbt.models.Psbt` (whether it
lives in ``partial_sigs`` or the final ``final_script_sig`` /
``final_script_witness``) and returns a
:class:`~bitcoin.signature.collection.SignatureCollection`.

Two source paths:

- **Partial signatures** – the canonical BIP-174 ``PSBT_IN_PARTIAL_SIG``
  fields, keyed by pubkey.
- **Finalised scripts** – when ``partial_sigs`` is empty but
  ``final_script_sig`` is populated, the function parses the
  scriptSig and recovers the pubkey via
  :func:`extract_pubkey_from_elements`.

Both paths produce :class:`~bitcoin.signature.record.Record`
instances suitable for the same downstream analysis (nonce-reuse
detection, linearisation, batch verification) as raw-transaction
extraction.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bitcoin.curve.point import Point
    from bitcoin.signature.collection import SignatureCollection

from bitcoin.psbt.models import Psbt

logger = logging.getLogger(__name__)


def psbt_extract_signatures(
    psbt: Psbt,
    *,
    input_values: list[int] | None = None,
) -> SignatureCollection:
    """Extract ECDSA signatures from PSBT partial signatures.

    For each input, extracts ``(pubkey, signature)`` pairs from
    ``partial_sigs`` and creates ``Record`` objects.  Also handles
    finalized inputs (``final_script_sig`` / ``final_script_witness``)
    as a fallback when ``partial_sigs`` is empty.

    Args:
        psbt: A parsed ``Psbt`` instance.
        input_values: Optional per-input UTXO values in satoshis.

    Returns:
        A ``SignatureCollection`` containing all extracted records.
    """
    from bitcoin.curve import parse_public_key
    from bitcoin.encoding.der import decode_der
    from bitcoin.signature.collection import SignatureCollection
    from bitcoin.signature.record import Record
    from bitcoin.transaction.parser import parse_tx

    tx, _ = parse_tx(psbt.tx)
    txid = tx.txid()
    records: list[Record] = []

    for vin, inp in enumerate(psbt.inputs):
        value = input_values[vin] if input_values else 0

        for pubkey_bytes, sig_bytes in inp.partial_sigs.items():
            try:
                public_key = parse_public_key(pubkey_bytes)
            except (ValueError, TypeError):
                continue
            if len(sig_bytes) < 2:
                continue
            sig_der = sig_bytes[:-1]
            flag = sig_bytes[-1]
            try:
                decode_der(sig_der)
            except ValueError:
                continue
            records.append(
                Record(
                    txid=txid,
                    input_index=vin,
                    signature=sig_der,
                    public_key=public_key,
                    script_type="psbt_partial",
                    sighash_flag=flag,
                    amount=value,
                )
            )

        if inp.final_script_sig:
            try:
                from bitcoin.script.parser import parse_script

                parsed = parse_script(inp.final_script_sig)
                for element in parsed:
                    if isinstance(element, bytes) and len(element) > 1:
                        sig_candidate = element[:-1]
                        flag = element[-1]
                        decode_der(sig_candidate)
                        pubkey = extract_pubkey_from_elements(parsed)
                        if pubkey is None or pubkey.infinity:
                            continue
                        records.append(
                            Record(
                                txid=txid,
                                input_index=vin,
                                signature=sig_candidate,
                                public_key=pubkey,
                                script_type="finalized",
                                sighash_flag=flag,
                                amount=value,
                            )
                        )
            except (ValueError, IndexError):
                logger.debug("Failed to parse finalized scriptSig for input %d", vin)

    return SignatureCollection(records=tuple(records))


def extract_pubkey_from_elements(elements: Sequence[object]) -> Point | None:
    """Extract the public key from a list of parsed script elements.

    Searches for a 33- or 65-byte element that is a valid SEC-encoded
    public key on the secp256k1 curve.

    Args:
        elements: Parsed script elements.

    Returns:
        The public key ``Point``, or ``None`` if no valid pubkey found.
    """
    from bitcoin.curve import parse_public_key

    for element in reversed(tuple(elements)):
        if isinstance(element, bytes) and len(element) in (33, 65):
            try:
                point = parse_public_key(element)
                if point is not None and not point.infinity:
                    return point
            except (ValueError, TypeError):
                continue
    return None


__all__ = [
    "extract_pubkey_from_elements",
    "psbt_extract_signatures",
]
