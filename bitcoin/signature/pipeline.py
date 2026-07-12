# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Batch extraction pipeline for multiple transactions.

The pipeline takes a list of transactions (as hex strings or raw
bytes), runs :func:`extract_signatures` on each, and returns an
aggregated :class:`BatchResult`.  It supports:

- **Sequential or parallel** execution via
  :class:`concurrent.futures.ThreadPoolExecutor` (default) or
  :class:`concurrent.futures.ProcessPoolExecutor` (for CPU-bound
  workloads).
- **File-based input** via :func:`batch_extract_from_file`, which
  reads one transaction per line and ignores blank / ``#``-prefixed
  comment lines.
- **Graceful shutdown**: SIGTERM/SIGINT handlers set a flag that
  worker loops check between tasks, so in-flight tasks complete but
  no new tasks are submitted.  Process pools are exempt because they
  do not honour SIGTERM in worker children.
- **Per-batch logging** with a short request ID (UUID4 first 12 hex
  digits) for log correlation across worker threads.
- **Cross-transaction correlation** via :func:`correlate_across_transactions`,
  which groups records by script type then by ``r`` value and
  returns any ``r`` shared by two or more records (the trigger for
  nonce-reuse analysis).

Error handling
--------------

Failures during extraction are captured into
:attr:`BatchResult.errors` as ``(txid_or_label, error_message)``
pairs; the function returns normally even if some transactions fail,
so a single bad input never aborts a batch.
"""

from __future__ import annotations

import logging
import signal
import uuid
from collections import defaultdict
from collections.abc import Sequence
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from threading import Lock

from bitcoin.encoding.der import decode_der
from bitcoin.encoding.hex import decode_hex
from bitcoin.signature.attack import NonceReuseGroup
from bitcoin.signature.extraction.engine import extract_signatures
from bitcoin.signature.record import Record
from bitcoin.transaction.parser import parse_tx

logger = logging.getLogger(__name__)

# ── Graceful shutdown support ────────────────────────────────────────
# Production lifecycle: SIGTERM/SIGINT set a flag that worker loops
# check between tasks, avoiding abrupt thread termination.

shutdown_requested = False
shutdown_lock = Lock()


def handle_shutdown(signum: int, frame: object) -> None:
    """Signal handler: set the shutdown flag so workers stop gracefully."""
    global shutdown_requested
    with shutdown_lock:
        shutdown_requested = True
    logger.warning(
        "Shutdown requested (signal %d). Completing current tasks...", signum
    )


def is_shutdown_requested() -> bool:
    with shutdown_lock:
        return shutdown_requested


def install_shutdown_handlers() -> None:
    """Install SIGTERM and SIGINT handlers (idempotent, safe in threads)."""
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)


def process_single_worker(
    tx_input: str | bytes,
    utxo_scripts: Sequence[bytes] | None,
    utxo_values: Sequence[int] | None,
) -> list[Record] | tuple[str, str]:
    """Top-level worker function for ``ProcessPoolExecutor``.

    Must live at module scope (not as a nested function) so the
    executor can pickle it for dispatch to worker processes.  Each
    invocation runs :func:`process_single` on one transaction;
    exceptions are captured as ``(label, error_message)`` tuples so
    the parent process can attribute failures without aborting the
    batch.

    Args:
        tx_input: A hex string or raw bytes of the transaction.
        utxo_scripts: Optional ``scriptPubKey`` list for each input.
        utxo_values: Optional UTXO value list for each input.

    Returns:
        The list of extracted records on success, or a
        ``(label, error_message)`` tuple on failure.
    """
    try:
        return process_single(tx_input, utxo_scripts, utxo_values)
    except Exception as exc:
        label = tx_input[:64] if isinstance(tx_input, str) else "<bytes>"
        return (label, str(exc))


def generate_request_id() -> str:
    """Generate a short unique request ID for log correlation."""
    return uuid.uuid4().hex[:12]


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


def process_single(
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
        ValueError: If the transaction cannot be parsed or no signatures
            are found for a non-coinbase transaction.
    """
    if isinstance(tx_input, str):
        raw = decode_hex(tx_input.strip())
    else:
        raw = tx_input
    tx, _ = parse_tx(raw)
    records = extract_signatures(
        tx,
        utxo_script_pubkeys=list(utxo_scripts) if utxo_scripts is not None else None,
        utxo_values=list(utxo_values) if utxo_values is not None else None,
    )
    if not records and any(
        txin.previous_output.txid != b"\x00" * 32 for txin in tx.inputs
    ):
        raise ValueError("No signatures found in transaction")
    return records


def batch_extract(
    transactions: Sequence[str | bytes],
    *,
    utxo_scripts: Sequence[Sequence[bytes] | None] | None = None,
    utxo_values: Sequence[Sequence[int] | None] | None = None,
    max_workers: int = 1,
    use_process_pool: bool = False,
    request_id: str | None = None,
) -> BatchResult:
    """Extract signatures from multiple transactions.

    Processes transactions sequentially when *max_workers* is ``1``,
    or in parallel via a ``ThreadPoolExecutor`` (default) or
    ``ProcessPoolExecutor`` (CPU-bound) when greater than ``1``.

    Graceful shutdown: installs SIGTERM/SIGINT handlers on first call.
    After a signal is received, in-flight tasks complete but no new
    tasks are started.

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
        use_process_pool: If ``True``, use ``ProcessPoolExecutor``
            instead of ``ThreadPoolExecutor`` (recommended for CPU-bound
            extraction).  Not compatible with graceful shutdown
            (process pools ignore SIGTERM/SIGINT handlers).
        request_id: Optional correlation ID for structured logging.
            Auto-generated if not provided.

    Returns:
        A ``BatchResult`` aggregating all extracted records and errors.
    """
    install_shutdown_handlers()

    rid = request_id or generate_request_id()
    logger.info(
        "[%s] Starting batch extract: %d transactions, %d workers",
        rid,
        len(transactions),
        max_workers,
    )

    n = len(transactions)
    scripts = utxo_scripts or [None] * n
    values = utxo_values or [None] * n

    if len(scripts) != n or len(values) != n:
        raise ValueError(
            f"utxo_scripts ({len(scripts)}) and utxo_values ({len(values)}) "
            f"must match transactions ({n})."
        )

    all_records: list[Record] = []
    errors: list[tuple[str, str]] = []
    successful = 0
    lock = Lock()

    def process_one_with_shutdown(
        tx_input: str | bytes,
        tx_scripts: Sequence[bytes] | None,
        tx_values: Sequence[int] | None,
    ) -> list[Record] | tuple[str, str]:
        """Wrapper that checks shutdown flag and returns records or error."""
        if is_shutdown_requested():
            label = tx_input[:64] if isinstance(tx_input, str) else "<bytes>"
            return (label, "Shutdown requested")
        try:
            return process_single(tx_input, tx_scripts, tx_values)
        except Exception as exc:
            label = tx_input[:64] if isinstance(tx_input, str) else "<bytes>"
            logger.warning(
                "[%s] Failed to process %s: %s", rid, label, exc, exc_info=True
            )
            return (label, str(exc))

    if max_workers <= 1:
        for tx_input, tx_scripts, tx_values in zip(
            transactions, scripts, values, strict=True
        ):
            if is_shutdown_requested():
                logger.warning("[%s] Shutdown detected, aborting batch.", rid)
                break
            outcome = process_one_with_shutdown(tx_input, tx_scripts, tx_values)
            if isinstance(outcome, tuple):
                errors.append(outcome)
            else:
                all_records.extend(outcome)
                successful += 1
    elif use_process_pool:
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            future_map = {}
            for tx_input, tx_scripts, tx_values in zip(
                transactions, scripts, values, strict=True
            ):
                label = tx_input[:64] if isinstance(tx_input, str) else "<bytes>"
                fut = executor.submit(
                    process_single_worker, tx_input, tx_scripts, tx_values
                )
                future_map[fut] = label

            for future in as_completed(future_map):
                label = future_map[future]
                try:
                    fut_result = future.result()
                except Exception as exc:
                    logger.warning(
                        "[%s] Unexpected worker exception for %s: %s",
                        rid,
                        label,
                        exc,
                        exc_info=True,
                    )
                    with lock:
                        errors.append((label, str(exc)))
                    continue
                if isinstance(fut_result, tuple):
                    with lock:
                        errors.append(fut_result)
                else:
                    with lock:
                        all_records.extend(fut_result)
                        successful += 1
    else:
        with ThreadPoolExecutor(  # type: ignore[assignment]
            max_workers=max_workers
        ) as executor:
            future_map = {}
            for tx_input, tx_scripts, tx_values in zip(
                transactions, scripts, values, strict=True
            ):
                if is_shutdown_requested():
                    logger.warning(
                        "[%s] Shutdown detected, skipping remaining submissions.", rid
                    )
                    break
                label = tx_input[:64] if isinstance(tx_input, str) else "<bytes>"
                fut = executor.submit(
                    process_one_with_shutdown, tx_input, tx_scripts, tx_values
                )
                future_map[fut] = label

            for future in as_completed(future_map):
                label = future_map[future]
                try:
                    fut_result = future.result()
                except Exception as exc:
                    logger.warning(
                        "[%s] Unexpected worker exception for %s: %s",
                        rid,
                        label,
                        exc,
                        exc_info=True,
                    )
                    with lock:
                        errors.append((label, str(exc)))
                    continue
                if isinstance(fut_result, tuple):
                    with lock:
                        errors.append(fut_result)
                else:
                    with lock:
                        all_records.extend(fut_result)
                        successful += 1

    batch_result = BatchResult(
        records=all_records,
        errors=errors,
        total_transactions=n,
        successful=successful,
        failed=n - successful,
    )
    logger.info(
        "[%s] Batch complete: %d / %d successful, %d errors.",
        rid,
        batch_result.successful,
        batch_result.total_transactions,
        len(batch_result.errors),
    )
    return batch_result


def batch_extract_from_file(
    file_path: str,
    *,
    delimiter: str = "\n",
    max_workers: int = 1,
    request_id: str | None = None,
) -> BatchResult:
    """Read hex-encoded transactions from a file and extract signatures.

    Each transaction is separated by *delimiter* (default: newline).
    Empty lines and lines starting with ``#`` are ignored.

    Args:
        file_path: Path to the input file.
        delimiter: Line delimiter for splitting transactions
            (default ``"\\n"``).
        max_workers: Maximum number of worker threads.
        request_id: Optional correlation ID for logging.

    Returns:
        A ``BatchResult`` aggregating all extracted records and errors.

    Raises:
        FileNotFoundError: If *file_path* does not exist.
    """
    rid = request_id or generate_request_id()
    logger.info("[%s] Reading transactions from %s", rid, file_path)

    with open(file_path, encoding="utf-8") as f:
        text = f.read()

    lines: list[str] = text.split(delimiter)
    transactions: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            transactions.append(stripped)

    logger.info("[%s] Loaded %d transactions from file", rid, len(transactions))
    return batch_extract(transactions, max_workers=max_workers, request_id=rid)


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
            key = (rec.txid, rec.input_index)
            if key not in seen:
                seen.add(key)
                merged.append(rec)

    merged.sort(key=lambda r: (r.txid, r.input_index))
    return merged


def extract_r_from_record(record: Record) -> int | None:
    """Decode the ``r`` value from a ``Record``'s signature.

    Handles both DER-encoded ECDSA signatures and 64-byte Schnorr
    signatures (Taproot).  For Schnorr, the first 32 bytes are ``r``.

    Args:
        record: A signature record.

    Returns:
        The integer ``r`` value, or ``None`` if decoding fails.
    """
    sig = record.signature
    if len(sig) == 64:
        return int.from_bytes(sig[:32], "big")
    try:
        r, _ = decode_der(sig)
        return r
    except (ValueError, IndexError):
        return None


def correlate_across_transactions(
    records: list[Record],
) -> dict[str, list[NonceReuseGroup]]:
    """Detect nonce reuse across multiple transactions.

    Groups records by *script_type*, then within each group groups
    records sharing the same ``r`` value.  Only groups with two or
    more records are reported.

    Handles both DER-encoded ECDSA signatures and 64-byte Schnorr
    (Taproot) signatures.

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
            r_val = extract_r_from_record(rec)
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
    "extract_r_from_record",
    "merge_records",
    "process_single",
]
