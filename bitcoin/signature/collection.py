"""Immutable collection of extracted signature records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Sequence

from bitcoin.signature.record import Record


@dataclass(frozen=True, slots=True)
class SignatureCollection:
    """An immutable collection of ``Record`` instances.

    Provides sequence-like access: ``len()``, iteration, and integer indexing.

    Attributes:
        records: Tuple of ``Record`` objects in insertion order.
    """

    records: tuple[Record, ...]

    def __init__(self, records: Sequence[Record] = ()) -> None:
        object.__setattr__(self, "records", tuple(records))

    def __len__(self) -> int:
        """Return the number of records in the collection."""
        return len(self.records)

    def __iter__(self) -> Iterator[Record]:
        """Yield records in order."""
        return iter(self.records)

    def __getitem__(self, index: int) -> Record:
        """Return the record at *index*."""
        return self.records[index]
