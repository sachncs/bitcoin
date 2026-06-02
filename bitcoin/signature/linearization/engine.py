"""Engine for canonical sorting of extracted signature records."""

from __future__ import annotations

from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from bitcoin.signature.record import Record


def linearize_signatures(records: list[Record]) -> list[Record]:
    """Sort extracted signatures by ``(txid, vin)`` for deterministic ordering.

    The linearization produces a canonical, reproducible order suitable
    for serialization, comparison, and threshold-based analysis.

    Args:
        records: A list of ``Record`` instances.

    Returns:
        A new list sorted by ``(txid, vin)``.
    """
    return sorted(records, key=record_sort_key)


def record_sort_key(record: Record) -> tuple[bytes, int]:
    """Sort key: ``(txid, vin)``."""
    return (record.txid, record.vin)
