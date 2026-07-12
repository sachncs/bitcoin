# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Frozen dataclass representing a single extracted ECDSA or Schnorr signature.

The :class:`Record` dataclass is the primary output type of the
extraction pipeline: every standard script type (legacy P2PKH, SegWit
P2WPKH/P2WSH, P2SH-wrapped SegWit, P2TR key-path and script-path)
produces one ``Record`` per discovered signature.

Invariants enforced in :meth:`Record.__post_init__`:

- ``txid`` is exactly 32 bytes (the little-endian transaction hash).
- ``input_index`` and ``amount`` are non-negative.
- ``signature`` is non-empty.

The class also exposes convenience properties:

- :attr:`Record.vin` – alias for ``input_index``.
- :attr:`Record.sig` – alias for ``signature``.
- :attr:`Record.r_value` – decode the DER signature on demand and
  return the ``r`` component.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from bitcoin.encoding.der import decode_der

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

    @property
    def r_value(self) -> int:
        """Return the R component of the DER-encoded signature.

        Returns:
            The integer R component.

        Raises:
            ValueError: If the signature cannot be decoded as DER.
        """
        r, _ = decode_der(self.signature)
        return r

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
                f"input_index must be non-negative, got {self.input_index}."
            )
        if not isinstance(self.signature, bytes) or len(self.signature) == 0:
            raise ValueError("signature must be non-empty bytes.")
        if self.amount < 0:
            raise ValueError(f"amount must be non-negative, got {self.amount}.")
