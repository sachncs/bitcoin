"""Frozen dataclass representing a single extracted ECDSA signature with metadata."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bitcoin.curve.point import Point


@dataclass(frozen=True, slots=True)
class Record:
    """A single extracted ECDSA signature with its associated metadata.

    Attributes:
        txid: Transaction ID (32 bytes, little-endian).
        vin: Input index within the transaction.
        sig: Raw DER-encoded signature (``bytes``).
        public_key: Public key that signed (``Point``; may be ``INFINITY``
            when the key could not be recovered).
        script_type: Script type identifier (e.g. ``"p2pkh"``, ``"p2wpkh"``).
        sighash_flag: SIGHASH flag byte.
        amount: Value of the UTXO being spent in satoshis (``0`` if unknown).
    """

    txid: bytes
    vin: int
    sig: bytes
    public_key: Point
    script_type: str
    sighash_flag: int
    amount: int

    def __post_init__(self) -> None:
        """Validate field invariants after initialization.

        Raises:
            ValueError: If *txid* is not 32 bytes, *vin* or *amount* is
                negative, or *sig* is empty.
        """
        if len(self.txid) != 32:
            raise ValueError(f"txid must be 32 bytes, got {len(self.txid)}.")
        if self.vin < 0:
            raise ValueError(f"vin must be non-negative, got {self.vin}.")
        if not isinstance(self.sig, bytes) or len(self.sig) == 0:
            raise ValueError("sig must be non-empty bytes.")
        if self.amount < 0:
            raise ValueError(f"amount must be non-negative, got {self.amount}.")
