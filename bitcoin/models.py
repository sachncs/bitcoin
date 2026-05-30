"""Data models for Bitcoin transactions and signature records."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

__all__ = [
    "SignatureRecord",
    "TransactionContext",
    "TransactionInput",
    "TransactionOutput",
]


@dataclass(frozen=True, slots=True)
class TransactionInput:
    """Represents a parsed transaction input."""

    prevout_hash: bytes
    prevout_index: int
    script_sig: bytes
    sequence: int
    witness: tuple[bytes, ...]


@dataclass(frozen=True, slots=True)
class TransactionOutput:
    """Represents a parsed transaction output."""

    value: int
    script_pubkey: bytes


@dataclass(frozen=True, slots=True)
class TransactionContext:
    """Provides spent output values for SegWit sighash computation."""

    input_values: tuple[int | None, ...]

    @staticmethod
    def from_sequence(values: Sequence[int | None]) -> TransactionContext:
        return TransactionContext(input_values=tuple(values))


@dataclass(frozen=True, slots=True)
class SignatureRecord:
    """Contains extracted r, s, z values and metadata for one ECDSA signature."""

    r: str
    s: str
    z: str
    sighash_flag: int
    input_index: int
    public_key: str | None
    script_type: str
