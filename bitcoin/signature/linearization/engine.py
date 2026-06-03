"""Engine for canonical sorting of extracted signature records."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bitcoin.signature.record import Record


def linearize_signatures(records: list[Record]) -> list[Record]:
    """Sort extracted signatures by ``(txid, input_index)`` for deterministic ordering.

    The linearization produces a canonical, reproducible order suitable
    for serialization, comparison, and threshold-based analysis.

    Args:
        records: A list of ``Record`` instances.

    Returns:
        A new list sorted by ``(txid, input_index)``.
    """
    return sorted(records, key=record_sort_key)


def record_sort_key(record: Record) -> tuple[bytes, int]:
    """Sort key: ``(txid, input_index)``.

    Args:
        record: The ``Record`` to derive the key from.

    Returns:
        A ``(txid, input_index)`` tuple for comparison.
    """
    return (record.txid, record.vin)
