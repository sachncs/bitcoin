"""Transaction parsing from raw bytes."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from bitcoin.exceptions import TruncatedTransactionError
from bitcoin.models import TransactionInput, TransactionOutput
from bitcoin.utils import ByteReader

logger = logging.getLogger(__name__)

__all__ = [
    "ParsedTransaction",
    "parse_transaction_bytes",
]


@dataclass(frozen=True, slots=True)
class ParsedTransaction:
    """Represents a parsed raw Bitcoin transaction."""

    version: int
    segwit: bool
    inputs: tuple[TransactionInput, ...]
    outputs: tuple[TransactionOutput, ...]
    locktime: int
    raw_bytes: bytes


def parse_transaction_bytes(raw_bytes: bytes) -> ParsedTransaction:
    """Parses raw Bitcoin transaction bytes."""

    reader = ByteReader(raw_bytes)
    version = reader.read_uint32()
    segwit = False

    marker_position = reader.position
    if reader.remaining() >= 2:
        marker = reader.read_uint8()
        flag = reader.read_uint8()
        if marker == 0 and flag != 0:
            segwit = True
        else:
            reader.position = marker_position

    input_count = reader.read_varint()
    inputs: list[TransactionInput] = []
    for _ in range(input_count):
        prevout_hash = reader.read(32)
        prevout_index = reader.read_uint32()
        script_sig = reader.read_varbytes()
        sequence = reader.read_uint32()
        inputs.append(
            TransactionInput(
                prevout_hash=prevout_hash,
                prevout_index=prevout_index,
                script_sig=script_sig,
                sequence=sequence,
                witness=tuple(),
            ))

    output_count = reader.read_varint()
    outputs: list[TransactionOutput] = []
    for _ in range(output_count):
        value = reader.read_uint64()
        script_pubkey = reader.read_varbytes()
        outputs.append(
            TransactionOutput(value=value, script_pubkey=script_pubkey))

    if segwit:
        parsed_inputs: list[TransactionInput] = []
        for txin in inputs:
            witness_count = reader.read_varint()
            witness_items = tuple(
                reader.read_varbytes() for _ in range(witness_count))
            parsed_inputs.append(
                TransactionInput(
                    prevout_hash=txin.prevout_hash,
                    prevout_index=txin.prevout_index,
                    script_sig=txin.script_sig,
                    sequence=txin.sequence,
                    witness=witness_items,
                ))
        inputs = parsed_inputs

    locktime = reader.read_uint32()
    if reader.remaining() != 0:
        raise TruncatedTransactionError(
            f"Transaction has {reader.remaining()} trailing bytes after parsing."
        )

    return ParsedTransaction(
        version=version,
        segwit=segwit,
        inputs=tuple(inputs),
        outputs=tuple(outputs),
        locktime=locktime,
        raw_bytes=raw_bytes,
    )
