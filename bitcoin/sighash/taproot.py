"""Taproot (BIP-341) sighash computation.

Implements the BIP-341 signature hash algorithm, supporting both key-path
and script-path spending.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from bitcoin.encoding.hasher import tagged_hash
from bitcoin.encoding.varint import encode_varint

if TYPE_CHECKING:
    from bitcoin.transaction.models import Tx

NO_CODESEPARATOR = 0xFFFFFFFF


def sighash_taproot(
    transaction: Tx,
    input_index: int,
    script: Optional[bytes],
    sighash_flag: int,
    *,
    extension: bytes = b"",
    tapleaf_hash: Optional[bytes] = None,
    key_version: int = 0,
    codeseparator_position: int = NO_CODESEPARATOR,
    annex: Optional[bytes] = None,
) -> bytes:
    """Compute the BIP-341 Taproot sighash for a transaction input.

    Supports both key-path (``script=None``) and script-path spending.
    The hash is computed as ``tagged_hash("TapSighash", ...)``.

    Args:
        transaction: The transaction.
        input_index: Index of the input being signed.
        script: The script being executed, or ``None`` for key-path
            spending.
        sighash_flag: SIGHASH flag byte (``0x00`` for default, or standard
            sighash values ``0x01``–``0x83``).
        extension: Extra data for future extensions (default ``b""``).
        tapleaf_hash: The ``tapleaf_hash`` as defined in BIP-341.
            Required when *script* is not ``None``.
        key_version: Key version byte (``0`` for current BIP-341
            specification).
        codeseparator_position: Position of the last
            ``OP_CODESEPARATOR`` executed (default ``0xFFFFFFFF``).
        annex: Optional annex data (BIP-341).

    Returns:
        The 32-byte tagged sighash digest.

    Raises:
        IndexError: If *input_index* is out of range for the
            transaction inputs.
        ValueError: If *script* is provided but *tapleaf_hash* is
            ``None``.
    """
    from bitcoin.services.serializer import serialize_tx_for_sighash_taproot

    data = bytearray()
    data.extend(sighash_flag.to_bytes(1, "little"))
    data.extend(extension)

    data.extend((0).to_bytes(1, "little"))

    if input_index >= len(transaction.inputs):
        raise IndexError("Input index out of range.")
    inp = transaction.inputs[input_index]
    data.extend(inp.previous_output.txid)
    data.extend(inp.previous_output.vout.to_bytes(4, "little"))
    data.extend(inp.sequence.to_bytes(4, "little"))

    if script is not None:
        if tapleaf_hash is None:
            raise ValueError("tapleaf_hash required for script-path signing.")
        data.extend((1).to_bytes(1, "little"))
        data.extend(tapleaf_hash)
        data.extend(key_version.to_bytes(1, "little"))
        data.extend(codeseparator_position.to_bytes(4, "little"))
    else:
        data.extend((0).to_bytes(1, "little"))

    if annex is not None:
        data.extend((1).to_bytes(1, "little"))
        data.extend(annex)
    else:
        data.extend((0).to_bytes(1, "little"))

    data.extend(serialize_tx_for_sighash_taproot(transaction, sighash_flag))

    if script is not None:
        data.extend(encode_varint(len(script)))
        data.extend(script)

    return tagged_hash("TapSighash", bytes(data))
