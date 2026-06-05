"""Deserialise Bitcoin transactions from wire format.

Supports both legacy and SegWit (BIP-144) encoded transactions.
"""

from __future__ import annotations


from bitcoin.encoding.varint import decode_varint
from bitcoin.exceptions import ParsingError
from bitcoin.transaction.models import OutPoint, TxIn, TxOut, Tx, Witness

MAX_TX_SIZE = 4_000_000
MAX_INPUTS = 100000
MAX_OUTPUTS = 100000
MAX_WITNESS_ITEMS = 10000
MAX_WITNESS_ITEM_SIZE = 10_000_000


def parse_tx(data: bytes, offset: int = 0) -> tuple[Tx, int]:
    """Parse a transaction from raw bytes, detecting SegWit.

    Automatically detects the SegWit marker + flag (``0x00 0x01``) and
    deserialises witness data accordingly.

    Args:
        data: Raw transaction bytes.
        offset: Starting offset within *data* (default ``0``).

    Returns:
        A tuple ``(Tx, new_offset)`` where *new_offset* is the position
        immediately after the parsed transaction.

    Raises:
        ParsingError: If *data* exceeds ``MAX_TX_SIZE``.
    """
    if len(data) > MAX_TX_SIZE:
        raise ParsingError(
            f"Transaction size {len(data)} exceeds maximum {MAX_TX_SIZE}")
    version = int.from_bytes(data[offset:offset + 4], "little")
    offset += 4

    is_segwit = data[offset:offset + 2] == b"\x00\x01"
    if is_segwit:
        offset += 2

    inputs_list, offset = parse_inputs(data, offset)
    outputs, offset = parse_outputs(data, offset)
    if is_segwit:
        for i in range(len(inputs_list)):
            witness, offset = parse_witness(data, offset)
            inputs_list[i] = TxIn(
                previous_output=inputs_list[i].previous_output,
                script_sig=inputs_list[i].script_sig,
                sequence=inputs_list[i].sequence,
                witness=witness,
            )

    lock_time = int.from_bytes(data[offset:offset + 4], "little")
    offset += 4

    return Tx(version=version,
              inputs=tuple(inputs_list),
              outputs=tuple(outputs),
              lock_time=lock_time), offset


def parse_inputs(data: bytes, offset: int) -> tuple[list[TxIn], int]:
    """Parse the input list from a serialised transaction.

    Each input consists of a 32-byte txid, 4-byte vout, varint-length
    script_sig, and 4-byte sequence.  Witness is initialised as empty
    and filled later in ``parse_tx`` if the transaction is SegWit.

    Args:
        data: Raw transaction bytes.
        offset: Start of the input count varint.

    Returns:
        A tuple ``(inputs, new_offset)``.
    """
    n, offset = decode_varint(data, offset)
    if n > MAX_INPUTS:
        raise ParsingError(f"Input count {n} exceeds maximum {MAX_INPUTS}")
    inputs: list[TxIn] = []
    for _ in range(n):
        txid = data[offset:offset + 32]
        offset += 32
        vout = int.from_bytes(data[offset:offset + 4], "little")
        offset += 4
        script_len, offset = decode_varint(data, offset)
        script_sig = data[offset:offset + script_len]
        offset += script_len
        sequence = int.from_bytes(data[offset:offset + 4], "little")
        offset += 4
        inputs.append(
            TxIn(
                previous_output=OutPoint(txid=txid, vout=vout),
                script_sig=script_sig,
                sequence=sequence,
                witness=Witness(()),
            ))
    return inputs, offset


def parse_outputs(data: bytes, offset: int) -> tuple[list[TxOut], int]:
    """Parse the output list from a serialised transaction.

    Each output consists of an 8-byte value and a varint-length
    script_pubkey.

    Args:
        data: Raw transaction bytes.
        offset: Start of the output count varint.

    Returns:
        A tuple ``(outputs, new_offset)``.
    """
    n, offset = decode_varint(data, offset)
    if n > MAX_OUTPUTS:
        raise ParsingError(f"Output count {n} exceeds maximum {MAX_OUTPUTS}")
    outputs: list[TxOut] = []
    for _ in range(n):
        value = int.from_bytes(data[offset:offset + 8], "little")
        offset += 8
        script_len, offset = decode_varint(data, offset)
        script_pubkey = data[offset:offset + script_len]
        offset += script_len
        outputs.append(TxOut(value=value, script_pubkey=script_pubkey))
    return outputs, offset


def parse_witness(data: bytes, offset: int) -> tuple[Witness, int]:
    """Parse a witness stack from a serialised transaction.

    The witness is encoded as a varint item count followed by
    varint-length-prefixed items.

    Args:
        data: Raw transaction bytes.
        offset: Start of the witness item count varint.

    Returns:
        A tuple ``(witness, new_offset)``.
    """
    n, offset = decode_varint(data, offset)
    if n > MAX_WITNESS_ITEMS:
        raise ParsingError(
            f"Witness item count {n} exceeds maximum {MAX_WITNESS_ITEMS}")
    items: list[bytes] = []
    for _ in range(n):
        item_len, offset = decode_varint(data, offset)
        if item_len > MAX_WITNESS_ITEM_SIZE:
            raise ParsingError(f"Witness item size {item_len} exceeds maximum "
                               f"{MAX_WITNESS_ITEM_SIZE}")
        item = data[offset:offset + item_len]
        offset += item_len
        items.append(item)
    return Witness(tuple(items)), offset
