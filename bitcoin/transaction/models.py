"""Immutable data models for Bitcoin transaction components.

Provides ``OutPoint``, ``TxIn``, ``TxOut``, ``Witness``, and ``Tx``
dataclasses with basic validation in ``__post_init__``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class OutPoint:
    """Reference to a specific output of a previous transaction.

    Attributes:
        txid: 32-byte transaction hash (little-endian).
        vout: Output index (non-negative).
    """

    txid: bytes  # 32 bytes, little-endian
    vout: int  # output index

    def __post_init__(self) -> None:
        if len(self.txid) != 32:
            raise ValueError(f"txid must be 32 bytes, got {len(self.txid)}.")
        if self.vout < 0:
            raise ValueError(f"vout must be non-negative, got {self.vout}.")


@dataclass(frozen=True, slots=True)
class TxIn:
    """A transaction input, including witness data.

    Attributes:
        previous_output: The UTXO being spent.
        script_sig: Legacy input script (signature + public key).
        sequence: Sequence number (``0xFFFFFFFF`` by default).
        witness: Witness stack (SegWit); empty for non-SegWit inputs.
    """

    previous_output: OutPoint
    script_sig: bytes
    sequence: int
    witness: Witness

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise ValueError(
                f"Sequence must be non-negative, got {self.sequence}.")


@dataclass(frozen=True, slots=True)
class TxOut:
    """A transaction output (value + script).

    Attributes:
        value: Amount in satoshis (non-negative, capped at 21M BTC).
        script_pubkey: Locking script (``scriptPubKey``).
    """

    value: int  # satoshis
    script_pubkey: bytes

    def __post_init__(self) -> None:
        if self.value < 0:
            raise ValueError(f"Value must be non-negative, got {self.value}.")
        # 21 million BTC max
        if self.value > 21_000_000 * 100_000_000:
            raise ValueError(f"Value exceeds maximum: {self.value}.")


@dataclass(frozen=True, slots=True)
class Witness:
    """A SegWit witness stack (ordered list of byte items).

    Attributes:
        items: Tuple of witness elements, each as raw bytes.
    """

    items: tuple[bytes, ...] = ()

    def __len__(self) -> int:
        return len(self.items)


EMPTY_WITNESS = Witness(())


@dataclass(frozen=True, slots=True)
class Tx:
    """A Bitcoin transaction with optional SegWit support.

    Attributes:
        version: Transaction version (typically ``1`` or ``2``).
        inputs: Tuple of transaction inputs.
        outputs: Tuple of transaction outputs.
        lock_time: Lock time (absolute block height or timestamp).
    """

    version: int
    inputs: tuple[TxIn, ...]
    outputs: tuple[TxOut, ...]
    lock_time: int

    def is_segwit(self) -> bool:
        """Check whether this transaction uses SegWit.

        Returns:
            ``True`` if at least one input has a non-empty witness stack.
        """
        return any(txin.witness.items for txin in self.inputs)

    def txid(self) -> bytes:
        """Compute the transaction ID (hash of legacy serialisation).

        Uses ``double-SHA256`` of the non-witness serialisation.

        Returns:
            32-byte transaction hash.
        """
        from bitcoin.encoding.hasher import hash256
        from bitcoin.services.serializer import serialize_legacy_tx

        return hash256(serialize_legacy_tx(self))

    def wtxid(self) -> bytes:
        """Compute the witness transaction ID (hash of full serialisation).

        Uses ``double-SHA256`` of the SegWit-aware wire serialisation.

        Returns:
            32-byte witness transaction hash.
        """
        from bitcoin.encoding.hasher import hash256
        from bitcoin.services.serializer import serialize_tx

        return hash256(serialize_tx(self))
