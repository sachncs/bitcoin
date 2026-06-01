"""Batch extraction pipeline for multiple transactions.

Supports parallel processing via ``concurrent.futures.ThreadPoolExecutor``,
file-based input, and cross-transaction nonce reuse detection.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from bitcoin.encoding.der import decode_der
from bitcoin.encoding.hex import decode_hex
from bitcoin.signature.attack import NonceReuseGroup
from bitcoin.signature.extraction.engine import extract_signatures
from bitcoin.signature.record import Record
from bitcoin.transaction.parser import parse_tx

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class BatchResult:
    """Result of processing multiple transactions.

    Attributes:
        records: All successfully extracted ``Record`` instances.
        errors: Pairs of ``(txid_or_hex, error_message)`` for each
            failed transaction.
        total_transactions: Total number of transactions submitted.
        successful: Number of transactions that were processed
            without error.
        failed: Number of transactions that raised an exception.
    """

    records: list[Record] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
    total_transactions: int = 0
    successful: int = 0
    failed: int = 0


def __process_single(
    tx_input: str | bytes,
    utxo_scripts: Sequence[bytes] | None,
    utxo_values: Sequence[int] | None,
) -> list[Record]:
    """Extract signatures from a single transaction.

    Args:
        tx_input: A hex string or raw bytes of the transaction.
        utxo_scripts: Optional ``scriptPubKey`` list for each input.
        utxo_values: Optional UTXO value list for each input.

    Returns:
        A list of ``Record`` instances.

    Raises:
        ValueError: If the transaction cannot be parsed.
    """
    if isinstance(tx_input, str):
        raw = decode_hex(tx_input.strip())
    else:
        raw = tx_input
    tx, _ = parse_tx(raw)
    return extract_signatures(
        tx,
        utxo_script_pubkeys=list(utxo_scripts)
        if utxo_scripts is not None else None,
        utxo_values=list(utxo_values) if utxo_values is not None else None,
    )


def batch_extract(
    transactions: Sequence[str | bytes],
    *,
    utxo_scripts: Sequence[Sequence[bytes] | None] | None = None,
    utxo_values: Sequence[Sequence[int] | None] | None = None,
    max_workers: int = 1,
) -> BatchResult:
    """Extract signatures from multiple transactions.

    Processes transactions sequentially when *max_workers* is ``1``,
    or in parallel via a ``ThreadPoolExecutor`` when greater than ``1``.

    Args:
        transactions: A sequence of hex-encoded strings or raw bytes.
        utxo_scripts: Optional per-transaction list of ``scriptPubKey``
            sequences.  If provided, must have the same length as
            *transactions*; elements may be ``None``.
        utxo_values: Optional per-transaction list of UTXO value
            sequences.  If provided, must have the same length as
            *transactions*; elements may be ``None``.
        max_workers: Maximum number of worker threads (``1`` for
            single-threaded).

    Returns:
        A ``BatchResult`` aggregating all extracted records and errors.
    """
    n = len(transactions)
    scripts = utxo_scripts or [None] * n
    values = utxo_values or [None] * n

    if len(scripts) != n or len(values) != n:
        raise ValueError(
            f"utxo_scripts ({len(scripts)}) and utxo_values ({len(values)}) "
            f"must match transactions ({n}).")

    all_records: list[Record] = []
    errors: list[tuple[str, str]] = []
    successful = 0

    if max_workers <= 1:
        for tx_input, tx_scripts, tx_values in zip(transactions,
                                                   scripts,
                                                   values,
                                                   strict=True):
            label = tx_input[:64] if isinstance(tx_input, str) else "<bytes>"
            try:
                records = __process_single(tx_input, tx_scripts, tx_values)
                all_records.extend(records)
                successful += 1
            except Exception as exc:
                logger.debug("Failed to process %s: %s", label, exc)
                errors.append((label, str(exc)))
    else:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {}
            for tx_input, tx_scripts, tx_values in zip(transactions,
                                                       scripts,
                                                       values,
                                                       strict=True):
                label = (tx_input[:64]
                         if isinstance(tx_input, str) else "<bytes>")
                fut = executor.submit(__process_single, tx_input, tx_scripts,
                                      tx_values)
                future_map[fut] = label

            for future in as_completed(future_map):
                label = future_map[future]
                try:
                    records = future.result()
                    all_records.extend(records)
                    successful += 1
                except Exception as exc:
                    logger.debug("Failed to process %s: %s", label, exc)
                    errors.append((label, str(exc)))

    return BatchResult(
        records=all_records,
        errors=errors,
        total_transactions=n,
        successful=successful,
        failed=n - successful,
    )


def batch_extract_from_file(
    file_path: str,
    *,
    delimiter: str = "\n",
    max_workers: int = 1,
) -> BatchResult:
    """Read hex-encoded transactions from a file and extract signatures.

    Each transaction is separated by *delimiter* (default: newline).
    Empty lines and lines starting with ``#`` are ignored.

    Args:
        file_path: Path to the input file.
        delimiter: Line delimiter for splitting transactions
            (default ``"\\n"``).
        max_workers: Maximum number of worker threads.

    Returns:
        A ``BatchResult`` aggregating all extracted records and errors.

    Raises:
        FileNotFoundError: If *file_path* does not exist.
    """
    with open(file_path) as f:
        text = f.read()

    lines: list[str] = text.split(delimiter)
    transactions: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            transactions.append(stripped)

    return batch_extract(transactions, max_workers=max_workers)


def merge_records(results: Sequence[BatchResult]) -> list[Record]:
    """Merge records from multiple batch results into a single sorted list.

    Records are deduplicated by ``(txid, vin)`` — only the first
    occurrence of each ``(txid, vin)`` pair is kept.  The returned list
    is sorted by ``(txid, vin)``.

    Args:
        results: A sequence of ``BatchResult`` instances.

    Returns:
        A merged, sorted, deduplicated list of ``Record`` instances.
    """
    seen: set[tuple[bytes, int]] = set()
    merged: list[Record] = []

    for result in results:
        for rec in result.records:
            key = (rec.txid, rec.vin)
            if key not in seen:
                seen.add(key)
                merged.append(rec)

    merged.sort(key=lambda r: (r.txid, r.vin))
    return merged


def __extract_r_from_record(record: Record) -> int | None:
    """Decode the ``r`` value from a ``Record``'s DER signature.

    Args:
        record: A signature record.

    Returns:
        The integer ``r`` value, or ``None`` if decoding fails.
    """
    try:
        r, _ = decode_der(record.sig)
        return r
    except (ValueError, IndexError):
        return None


def correlate_across_transactions(
    records: list[Record],) -> dict[str, list[NonceReuseGroup]]:
    """Detect nonce reuse across multiple transactions.

    Groups records by *script_type*, then within each group groups
    records sharing the same ``r`` value.  Only groups with two or
    more records are reported.

    Args:
        records: A list of ``Record`` instances from one or more
            transactions.

    Returns:
        A dict mapping each *script_type* to a list of
        ``NonceReuseGroup`` instances, sorted by descending group
        size.  Script types with no reuse are omitted.
    """
    by_script: defaultdict[str, list[Record]] = defaultdict(list)
    for rec in records:
        by_script[rec.script_type].append(rec)

    result: dict[str, list[NonceReuseGroup]] = {}
    for script_type, group_records in by_script.items():
        r_groups: defaultdict[int, list[int]] = defaultdict(list)
        for idx, rec in enumerate(group_records):
            r_val = __extract_r_from_record(rec)
            if r_val is not None:
                r_groups[r_val].append(idx)

        groups: list[NonceReuseGroup] = []
        for r_val, indices in r_groups.items():
            if len(indices) >= 2:
                groups.append(NonceReuseGroup(r=r_val, indices=tuple(indices)))

        groups.sort(key=lambda g: g.count, reverse=True)
        if groups:
            result[script_type] = groups

    return result


__all__ = [
    "BatchResult",
    "batch_extract",
    "batch_extract_from_file",
    "correlate_across_transactions",
    "merge_records",
]
