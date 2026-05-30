"""Transaction model and public API."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, replace

from bitcoin.extractor import extract_signatures
from bitcoin.models import TransactionContext, TransactionInput, TransactionOutput
from bitcoin.parser import ParsedTransaction, parse_transaction_bytes
from bitcoin.signature import SignatureCollection
from bitcoin.utils import validate_hex_string

logger = logging.getLogger(__name__)

__all__ = [
    "Transaction",
]


@dataclass(frozen=True, slots=True)
class Transaction:
    """Represents a parsed Bitcoin transaction."""

    raw_bytes: bytes
    version: int
    segwit: bool
    inputs: tuple[TransactionInput, ...]
    outputs: tuple[TransactionOutput, ...]
    locktime: int
    context: TransactionContext | None = None

    @classmethod
    def parse_hex(cls, raw_transaction_hex: str) -> Transaction:
        raw_bytes = validate_hex_string(raw_transaction_hex)
        parsed = parse_transaction_bytes(raw_bytes)
        return cls.from_parsed(parsed)

    @classmethod
    def from_parsed(cls, parsed: ParsedTransaction) -> Transaction:
        return cls(
            raw_bytes=parsed.raw_bytes,
            version=parsed.version,
            segwit=parsed.segwit,
            inputs=parsed.inputs,
            outputs=parsed.outputs,
            locktime=parsed.locktime,
        )

    def with_input_values(self, values: Sequence[int | None]) -> Transaction:
        if len(values) != len(self.inputs):
            raise ValueError("Input value count must match input count.")
        return replace(self, context=TransactionContext.from_sequence(values))

    def extract(
            self,
            script_pubkeys: Sequence[bytes] | None = None
    ) -> SignatureCollection:
        return extract_signatures(self, script_pubkeys)
