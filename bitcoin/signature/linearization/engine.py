# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Engine for canonical sorting of extracted signature records.

Provides :func:`linearize_signatures`, which returns a new list of
:class:`~bitcoin.signature.record.Record` instances sorted by
``(txid, input_index)``.  The sort key is exposed separately as
:func:`record_sort_key` so callers can use the same ordering in their
own code.

Why this ordering?

- ``txid`` is the 32-byte little-endian transaction hash.  Sorting by
  the raw bytes gives a total order that is stable across machines
  (lexicographic byte order, not display order).
- Within a transaction, sorting by ``input_index`` matches the
  in-witness / in-scriptSig order of signatures, which is what most
  downstream consumers (BIP-340 challenge computation, batch
  verification, fingerprinting) expect.
"""

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
