"""Frozen dataclass representing a single extracted ECDSA or Schnorr signature."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bitcoin.curve.point import Point


@dataclass(frozen=True, slots=True)
class Record:
    """A single extracted signature with its associated metadata.

    Attributes:
        txid: Transaction ID (32 bytes, little-endian).
        input_index: Input index within the transaction (alias ``vin``).
        signature: Raw DER-encoded or Schnorr signature bytes (alias ``sig``).
        public_key: Public key that signed (``Point``; may be ``INFINITY``
            when the key could not be recovered).
        script_type: Script type identifier (e.g. ``"p2pkh"``, ``"p2wpkh"``).
        sighash_flag: SIGHASH flag byte.
        amount: Value of the UTXO being spent in satoshis (``0`` if unknown).
    """

    txid: bytes
    input_index: int
    signature: bytes
    public_key: Point
    script_type: str
    sighash_flag: int
    amount: int

    @property
    def vin(self) -> int:
        """Return the input index (alias for :attr:`input_index`)."""
        return self.input_index

    @property
    def sig(self) -> bytes:
        """Return the signature bytes (alias for :attr:`signature`)."""
        return self.signature

    def __post_init__(self) -> None:
        """Validate field invariants after initialization.

        Raises:
            ValueError: If *txid* is not 32 bytes, *input_index* or *amount* is
                negative, or *signature* is empty.
        """
        if len(self.txid) != 32:
            raise ValueError(f"txid must be 32 bytes, got {len(self.txid)}.")
        if self.input_index < 0:
            raise ValueError(
                f"input_index must be non-negative, got {self.input_index}.")
        if not isinstance(self.signature, bytes) or len(self.signature) == 0:
            raise ValueError("signature must be non-empty bytes.")
        if self.amount < 0:
            raise ValueError(
                f"amount must be non-negative, got {self.amount}.")
