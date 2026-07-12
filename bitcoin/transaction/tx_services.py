# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Composed engine classes for ``Tx`` domain operations.

Provides three small engines that bind to a :class:`Tx` instance and
expose its domain operations through a fluent ``tx.<engine>``
property:

- :class:`TxSerializer` – wire-format serialisation (SegWit-aware
  and legacy) and JSON conversion.
- :class:`TxRbf` – opt-in RBF (BIP-125) detection and BIP-68
  relative sequence-lock inspection.
- :class:`TxSighash` – legacy, SegWit, and Taproot sighash
  computation, bound to the parent :class:`Tx`.

Engines are stateless aside from their parent reference and use
``__slots__`` to keep their per-instance memory to a minimum.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from bitcoin.transaction.models import Tx


class TxSerializer:
    """Composed serialisation engine for a bound transaction.

    Accessed via ``tx.serializer``.

    Args:
        tx: The Tx instance this engine is bound to.
    """

    __slots__ = ("__tx",)

    def __init__(self, tx: Tx) -> None:
        self.__tx: Tx = tx

    def serialize(self) -> bytes:
        """Serialize the bound transaction to wire format (SegWit-aware).

        Returns:
            Wire-format bytes.
        """
        from bitcoin.services.serializer import serialize_tx

        return serialize_tx(self.__tx)

    def serialize_legacy(self) -> bytes:
        """Serialize the bound transaction in legacy (non-SegWit) format.

        Returns:
            Legacy wire-format bytes.
        """
        from bitcoin.services.serializer import serialize_legacy_tx

        return serialize_legacy_tx(self.__tx)

    def to_json(self) -> dict[str, Any]:
        """Convert the bound transaction to a JSON-serializable dict.

        Returns:
            A dict representing the full transaction structure.
        """
        from bitcoin.services.serializer import tx_to_json

        return tx_to_json(self.__tx)


class TxRbf:
    """Composed RBF detection engine for a bound transaction.

    Accessed via ``tx.rbf``.

    Args:
        tx: The Tx instance this engine is bound to.
    """

    __slots__ = ("__tx",)

    def __init__(self, tx: Tx) -> None:
        self.__tx: Tx = tx

    def is_opt_in(self) -> bool:
        """Check whether the bound transaction signals opt-in RBF (BIP-125).

        Returns:
            True if at least one input has a BIP-125 signalling sequence.
        """
        from bitcoin.transaction.rbf import is_opt_in_rbf

        return is_opt_in_rbf(self.__tx)

    def has_sequence_lock(self) -> bool:
        """Check whether the bound transaction uses relative sequence locks (BIP-68).

        Returns:
            True if at least one input has a relative time lock.
        """
        from bitcoin.transaction.rbf import has_sequence_lock

        return has_sequence_lock(self.__tx)


class TxSighash:
    """Composed sighash computation engine for a bound transaction.

    Accessed via ``tx.sighash``.

    Args:
        tx: The Tx instance this engine is bound to.
    """

    __slots__ = ("__tx",)

    def __init__(self, tx: Tx) -> None:
        self.__tx: Tx = tx

    def legacy(self, input_index: int, script: bytes, sighash_flag: int) -> bytes:
        """Compute the legacy (pre-SegWit) sighash.

        Args:
            input_index: Index of the input being signed.
            script: The script to evaluate.
            sighash_flag: SIGHASH flag.

        Returns:
            32-byte sighash.
        """
        from bitcoin.sighash.legacy import sighash_legacy

        return sighash_legacy(self.__tx, input_index, script, sighash_flag)

    def segwit(
        self, input_index: int, script: bytes, value: int, sighash_flag: int
    ) -> bytes:
        """Compute the BIP-143 SegWit v0 sighash.

        Args:
            input_index: Index of the input being signed.
            script: The script code.
            value: Amount of the UTXO being spent in satoshis.
            sighash_flag: SIGHASH flag.

        Returns:
            32-byte sighash.
        """
        from bitcoin.sighash.segwit import sighash_segwit

        return sighash_segwit(self.__tx, input_index, script, value, sighash_flag)

    def taproot(
        self,
        input_index: int,
        script: bytes | None,
        sighash_flag: int,
        *,
        extension: bytes = b"",
        tapleaf_hash: bytes | None = None,
        key_version: int = 0,
        codeseparator_position: int = 0xFFFFFFFF,
        annex: bytes | None = None,
        amounts: tuple[int, ...] | None = None,
    ) -> bytes:
        """Compute the BIP-341 Taproot sighash.

        Args:
            input_index: Index of the input being signed.
            script: Script for script-path spending, or None for key-path.
            sighash_flag: SIGHASH flag.
            extension: Extension bytes for the sighash.
            tapleaf_hash: Hash of the tapleaf for script-path spending.
            key_version: Key version (0 or 1).
            codeseparator_position: Position of the last OP_CODESEPARATOR.
            annex: Optional annex data.
            amounts: Tuple of per-input amounts.

        Returns:
            32-byte Taproot sighash.
        """
        from bitcoin.sighash.taproot import sighash_taproot

        return sighash_taproot(
            self.__tx,
            input_index,
            script,
            sighash_flag,
            extension=extension,
            tapleaf_hash=tapleaf_hash,
            key_version=key_version,
            codeseparator_position=codeseparator_position,
            annex=annex,
            amounts=amounts,
        )
