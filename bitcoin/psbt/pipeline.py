# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Multi-process PSBT processing pipeline.

Handles batch parsing, validation, and extraction from multiple PSBT
files using ``ProcessPoolExecutor`` for CPU-bound work.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Callable, Sequence
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field

from bitcoin.psbt.models import Psbt
from bitcoin.psbt.parser import parse_psbt_from_file

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class PsbtBatchResult:
    """Result of batch-processing multiple PSBT files.

    Attributes:
        psbts: Successfully parsed ``Psbt`` instances.
        errors: Pairs of ``(path, error_message)`` for each failed file.
        total: Number of files submitted.
        successful: Number successfully parsed.
        failed: Number that raised an exception.
    """

    psbts: list[Psbt] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
    total: int = 0
    successful: int = 0
    failed: int = 0


def __parse_psbt_worker(path: str) -> Psbt | tuple[str, str]:
    """Module-level worker for ``ProcessPoolExecutor``."""
    try:
        return parse_psbt_from_file(path)
    except Exception as exc:
        return (path, str(exc))


def process_psbt_batch(
    paths: Sequence[str],
    *,
    max_workers: int = 1,
    request_id: str | None = None,
) -> PsbtBatchResult:
    """Parse multiple PSBT files, optionally in parallel.

    Args:
        paths: Sequence of file paths to PSBT files.
        max_workers: Maximum number of worker processes (``1`` for
            sequential).
        request_id: Optional correlation ID for logging.

    Returns:
        A ``PsbtBatchResult`` aggregating all parsed PSBTs and errors.
    """
    rid = request_id or uuid.uuid4().hex[:12]
    logger.info("[%s] Processing %d PSBT files (%d workers).", rid, len(paths),
                max_workers)

    all_psbts: list[Psbt] = []
    errors: list[tuple[str, str]] = []

    if max_workers <= 1:
        for path in paths:
            try:
                all_psbts.append(parse_psbt_from_file(path))
            except Exception as exc:
                logger.warning("[%s] Failed to parse %s: %s", rid, path, exc)
                errors.append((path, str(exc)))
        successful = len(all_psbts)
    else:
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            fut_map = {executor.submit(__parse_psbt_worker, p): p for p in paths}
            for future in as_completed(fut_map):
                path = fut_map[future]
                try:
                    worker_result = future.result()
                except Exception as exc:
                    logger.warning("[%s] Worker exception for %s: %s", rid, path, exc)
                    errors.append((path, str(exc)))
                    continue
                if isinstance(worker_result, tuple):
                    errors.append(worker_result)
                else:
                    all_psbts.append(worker_result)
        successful = len(all_psbts)

    batch_result = PsbtBatchResult(
        psbts=all_psbts,
        errors=errors,
        total=len(paths),
        successful=successful,
        failed=len(paths) - successful,
    )
    logger.info(
        "[%s] PSBT batch complete: %d / %d successful.",
        rid,
        batch_result.successful,
        batch_result.total,
    )
    return batch_result


def process_psbt_batch_with(
    paths: Sequence[str],
    transform: Callable[[Psbt], Psbt],
    *,
    max_workers: int = 1,
    request_id: str | None = None,
) -> PsbtBatchResult:
    """Parse and transform multiple PSBTs in parallel.

    *transform* is called on each successfully parsed PSBT and may
    perform operations such as signing or finalization.

    Args:
        paths: Sequence of file paths.
        transform: A callable that receives a ``Psbt`` and returns a
            (possibly modified) ``Psbt``.
        max_workers: Worker process count (``1`` for sequential).
        request_id: Optional correlation ID.

    Returns:
        A ``PsbtBatchResult`` with the transformed Psbts.
    """
    raw = process_psbt_batch(paths, max_workers=max_workers, request_id=request_id)
    transformed: list[Psbt] = []
    for psbt in raw.psbts:
        try:
            transformed.append(transform(psbt))
        except Exception as exc:
            logger.warning("Transform failed for one PSBT: %s", exc)
            raw.errors.append(("<transform>", str(exc)))
    return PsbtBatchResult(
        psbts=transformed,
        errors=raw.errors,
        total=raw.total,
        successful=len(transformed),
        failed=raw.total - len(transformed),
    )


__all__ = [
    "PsbtBatchResult",
    "process_psbt_batch",
    "process_psbt_batch_with",
]
