"""Batch and streaming processing support for signature extraction."""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator, Sequence
from functools import partial
from typing import TypeVar

from bitcoin.exceptions import BitcoinError
from bitcoin.extractor import extract_signatures
from bitcoin.fetcher import fetch_transaction
from bitcoin.models import SignatureRecord
from bitcoin.signature import SignatureCollection
from bitcoin.transaction import Transaction

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

__all__ = [
    "BatchProcessor",
    "SignatureStream",
    "batch_process",
]


class BatchProcessor:
    """Process multiple transactions for signature extraction.

    Args:
        network: Bitcoin network (``"mainnet"``, ``"testnet"``, or ``"signet"``).
        timeout: HTTP request timeout in seconds.
        script_pubkeys: Optional sequence of script pubkeys passed through
            to ``extract_signatures``.
    """

    def __init__(
        self,
        *,
        network: str = "mainnet",
        timeout: int = 30,
        script_pubkeys: Sequence[bytes] | None = None,
    ) -> None:
        self._network = network
        self._timeout = timeout
        self._script_pubkeys = script_pubkeys

    def process_txid(
        self,
        txid: str,
        input_values: Sequence[int] | None = None,
    ) -> SignatureCollection:
        """Fetch, optionally attach input values, and extract signatures.

        Args:
            txid: The transaction ID.
            input_values: Optional spent output values for SegWit sighash
                computation.

        Returns:
            The extracted ``SignatureCollection``.
        """
        tx = fetch_transaction(txid,
                               network=self._network,
                               timeout=self._timeout)
        if input_values is not None:
            tx = tx.with_input_values(input_values)
        return tx.extract(script_pubkeys=self._script_pubkeys)

    def process_txids(
        self,
        txids: Sequence[str],
        input_values: Sequence[Sequence[int] | None] | None = None,
    ) -> list[SignatureCollection]:
        """Process multiple transaction IDs.

        Args:
            txids: Sequence of transaction IDs.
            input_values: Optional sequence of input-value sequences (one per
                txid).  A ``None`` entry means no values for that transaction.

        Returns:
            A list of ``SignatureCollection`` objects, one per txid.
        """
        results: list[SignatureCollection] = []
        for i, txid in enumerate(txids):
            iv = input_values[i] if input_values is not None else None
            try:
                results.append(self.process_txid(txid, input_values=iv))
            except (BitcoinError, ValueError, OSError):
                logger.exception("Failed to process txid %s at index %d", txid,
                                 i)
                raise
        return results

    def process_txids_iter(
        self,
        txids: Sequence[str],
    ) -> Iterator[tuple[str, SignatureCollection]]:
        """Lazily yield ``(txid, SignatureCollection)`` pairs.

        Each transaction is fetched and extracted on demand.

        Args:
            txids: Sequence of transaction IDs.

        Yields:
            ``(txid, collection)`` tuples.
        """
        for txid in txids:
            try:
                yield txid, self.process_txid(txid)
            except (BitcoinError, ValueError, OSError):
                logger.exception("Failed to process txid %s in lazy iterator",
                                 txid)
                raise


class SignatureStream:
    """A lazy stream over signature records extracted from a transaction.

    Supports filtering, mapping, and materialisation.

    Args:
        transaction: A parsed ``Transaction``.
        record_filter: Optional predicate applied at iteration time to
            include only matching records.
    """

    def __init__(
        self,
        transaction: Transaction,
        record_filter: Callable[[SignatureRecord], bool] | None = None,
    ) -> None:
        self._records: tuple[SignatureRecord,
                             ...] = (extract_signatures(transaction).records)
        self._filters: list[Callable[[SignatureRecord], bool]] = []
        if record_filter is not None:
            self._filters.append(record_filter)

    def __iter__(self) -> Iterator[SignatureRecord]:
        for record in self._records:
            if all(f(record) for f in self._filters):
                yield record

    def filter(
        self,
        predicate: Callable[[SignatureRecord], bool],
    ) -> SignatureStream:
        """Return a new stream filtered by *predicate*.

        Multiple filters are composed with AND logic.

        Args:
            predicate: A callable that returns ``True`` for records to keep.

        Returns:
            A new ``SignatureStream`` with the additional filter applied.
        """
        new = SignatureStream.__new__(SignatureStream)
        new._records = self._records
        new._filters = self._filters + [predicate]
        return new

    def map(self, func: Callable[[SignatureRecord], _T]) -> Iterator[_T]:
        """Transform each record using *func*.

        Args:
            func: A callable applied to each ``SignatureRecord``.

        Returns:
            An iterator over transformed values.
        """
        return (func(r) for r in self)

    def collect(self) -> list[SignatureRecord]:
        """Materialise all records into a list.

        Returns:
            A list of ``SignatureRecord`` objects.
        """
        return list(self)

    def to_collection(self) -> SignatureCollection:
        """Materialise as a ``SignatureCollection``.

        Returns:
            A ``SignatureCollection`` containing all records from this stream.
        """
        return SignatureCollection(records=tuple(self))


def extract_one(
    txid: str,
    *,
    network: str,
    timeout: int,
    script_pubkeys: Sequence[bytes] | None,
) -> SignatureCollection:
    tx = fetch_transaction(txid, network=network, timeout=timeout)
    return tx.extract(script_pubkeys=script_pubkeys)


def batch_process(
    *txids: str,
    network: str = "mainnet",
    timeout: int = 30,
    mp: bool = False,
) -> list[SignatureCollection]:
    """Convenience function to process one or more transaction IDs.

    Args:
        *txids: One or more transaction IDs.
        network: Bitcoin network.
        timeout: HTTP request timeout in seconds.
        mp: If ``True``, process txids in parallel using
            ``multiprocessing.Pool`` (one process per txid).

    Returns:
        A list of ``SignatureCollection`` objects, one per txid.
    """
    if mp:
        from multiprocessing import Pool

        worker = partial(
            extract_one,
            network=network,
            timeout=timeout,
            script_pubkeys=None,
        )
        with Pool() as pool:
            total_timeout = timeout * len(txids) if txids else timeout
            try:
                return pool.map_async(worker,
                                      list(txids)).get(timeout=total_timeout)
            except Exception as exc:
                logger.error(
                    "Batch multiprocessing failed for %d txids (timeout=%ds): %s",
                    len(txids),
                    total_timeout,
                    exc,
                )
                raise

    processor = BatchProcessor(network=network, timeout=timeout)
    return processor.process_txids(list(txids))
