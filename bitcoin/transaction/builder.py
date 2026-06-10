"""Fluent builder and dict-based factory for Bitcoin transactions.

Provides ``TransactionBuilder`` for programmatic construction with
validation, and ``tx_from_dict`` as a drop-in replacement for
``make_tx`` with stricter error checking.
"""

from __future__ import annotations

from typing import Self

from bitcoin.transaction.models import OutPoint, Tx, TxIn, TxOut, Witness


class TransactionBuilder:
    """Fluent builder for constructing Bitcoin transactions.

    Accumulates inputs, outputs, and transaction metadata, then
    validates and returns a frozen ``Tx`` via :meth:`build`.

    Attributes:
        version: Transaction version (default ``2``).
        lock_time: Transaction lock time (default ``0``).
    """

    def __init__(self, version: int = 2) -> None:
        """Initialize the builder.

        Args:
            version: Transaction version (default ``2``).

        Raises:
            ValueError: If *version* is negative.
        """
        if version < 0:
            raise ValueError(f"Version must be non-negative, got {version}.")
        self.__version: int = version
        self.__lock_time: int = 0
        self.__inputs: list[dict[str, object]] = []
        self.__outputs: list[dict[str, object]] = []

    def add_input(
            self,
            txid: bytes,
            vout: int,
            script_sig: bytes = b"",
            sequence: int = 0xFFFFFFFF,
            witness: tuple[bytes, ...] = (),
    ) -> Self:
        """Append a transaction input.

        Args:
            txid: 32-byte previous transaction hash (little-endian).
            vout: Output index of the previous transaction.
            script_sig: Input script (default ``b""``).
            sequence: Sequence number (default ``0xFFFFFFFF``).
            witness: Witness stack items (default ``()``).

        Returns:
            ``self`` for chaining.
        """
        self.__inputs.append({
            "txid": txid,
            "vout": vout,
            "script_sig": script_sig,
            "sequence": sequence,
            "witness": witness,
        })
        return self

    def add_output(self, value: int, script_pubkey: bytes) -> Self:
        """Append a transaction output.

        Args:
            value: Amount in satoshis (must be non-negative).
            script_pubkey: Locking script bytes.

        Returns:
            ``self`` for chaining.
        """
        self.__outputs.append({
            "value": value,
            "script_pubkey": script_pubkey,
        })
        return self

    def set_lock_time(self, lock_time: int) -> Self:
        """Set the transaction lock time.

        Args:
            lock_time: Lock time value (non-negative).

        Returns:
            ``self`` for chaining.

        Raises:
            ValueError: If *lock_time* is negative.
        """
        if lock_time < 0:
            raise ValueError(f"Lock time must be non-negative, got {lock_time}.")
        self.__lock_time = lock_time
        return self

    def build(self) -> Tx:
        """Validate accumulated state and return a ``Tx``.

        Returns:
            A new frozen ``Tx`` instance.

        Raises:
            ValueError: If no inputs or no outputs are defined, or if any
                field fails model validation.
        """
        if not self.__inputs:
            raise ValueError("At least one input is required.")
        if not self.__outputs:
            raise ValueError("At least one output is required.")

        txins: list[TxIn] = []
        for inp in self.__inputs:
            txid = inp["txid"]
            vout = inp["vout"]
            script_sig = inp["script_sig"]
            sequence = inp["sequence"]
            witness_items = inp["witness"]

            if not isinstance(txid, bytes):
                raise ValueError("txid must be bytes.")
            if not isinstance(vout, int):
                raise ValueError("vout must be int.")
            if not isinstance(script_sig, bytes):
                raise ValueError("script_sig must be bytes.")
            if not isinstance(sequence, int):
                raise ValueError("sequence must be int.")
            if not isinstance(witness_items, tuple):
                raise ValueError("witness must be a tuple.")
            if not all(isinstance(item, bytes) for item in witness_items):
                raise ValueError("All witness items must be bytes.")

            witness = Witness(tuple(witness_items))
            txins.append(
                TxIn(
                    previous_output=OutPoint(txid=txid, vout=vout),
                    script_sig=script_sig,
                    sequence=sequence,
                    witness=witness,
                ))

        txouts: list[TxOut] = []
        for out_data in self.__outputs:
            value = out_data["value"]
            script_pubkey = out_data["script_pubkey"]
            if not isinstance(value, int):
                raise ValueError("value must be int.")
            if not isinstance(script_pubkey, bytes):
                raise ValueError("script_pubkey must be bytes.")
            txouts.append(TxOut(value=value, script_pubkey=script_pubkey))

        return Tx(
            version=self.__version,
            inputs=tuple(txins),
            outputs=tuple(txouts),
            lock_time=self.__lock_time,
        )


def tx_from_dict(data: dict[str, object]) -> Tx:
    """Build a ``Tx`` from a dictionary (validating factory).

    The dictionary must have the following structure::

        {
            "version": int,
            "inputs": [{"txid": bytes, "vout": int, ...}, ...],
            "outputs": [{"value": int, "script_pubkey": bytes}, ...],
            "lock_time": int,  # optional, default 0
        }

    Each input dict may contain ``script_sig`` (bytes, default ``b""``),
    ``sequence`` (int, default ``0xFFFFFFFF``), and ``witness``
    (tuple[bytes, ...], default ``()``).

    Args:
        data: Dictionary describing the transaction.

    Returns:
        A new ``Tx`` instance.

    Raises:
        ValueError: If any required key is missing, a value has the wrong
            type, or model validation fails.
    """
    if not isinstance(data, dict):
        raise ValueError("data must be a dict.")

    version = data.get("version")
    if not isinstance(version, int):
        raise ValueError("version must be an int.")

    inputs_raw = data.get("inputs")
    if not isinstance(inputs_raw, (list, tuple)):
        raise ValueError("inputs must be a sequence.")

    outputs_raw = data.get("outputs")
    if not isinstance(outputs_raw, (list, tuple)):
        raise ValueError("outputs must be a sequence.")

    lock_time = data.get("lock_time", 0)
    if not isinstance(lock_time, int):
        raise ValueError("lock_time must be an int.")

    builder = TransactionBuilder(version=version)
    if lock_time != 0:
        builder.set_lock_time(lock_time)

    for inp in inputs_raw:
        if not isinstance(inp, dict):
            raise ValueError("Each input must be a dict.")
        txid = inp.get("txid")
        vout = inp.get("vout")
        script_sig = inp.get("script_sig", b"")
        sequence = inp.get("sequence", 0xFFFFFFFF)
        witness = inp.get("witness", ())
        if not isinstance(txid, bytes):
            raise ValueError("Each input must have a bytes txid.")
        if not isinstance(vout, int):
            raise ValueError("Each input must have an int vout.")
        builder.add_input(
            txid=txid,
            vout=vout,
            script_sig=script_sig,
            sequence=sequence,
            witness=witness,
        )

    for out_data in outputs_raw:
        if not isinstance(out_data, dict):
            raise ValueError("Each output must be a dict.")
        value = out_data.get("value")
        script_pubkey = out_data.get("script_pubkey")
        if not isinstance(value, int):
            raise ValueError("Each output must have an int value.")
        if not isinstance(script_pubkey, bytes):
            raise ValueError("Each output must have bytes script_pubkey.")
        builder.add_output(value=value, script_pubkey=script_pubkey)

    return builder.build()
