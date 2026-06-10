"""Immutable collection of extracted signature records."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from bitcoin.signature.record import Record


@dataclass(frozen=True, slots=True)
class SignatureCollection:
    """An immutable collection of ``Record`` instances.

    Provides sequence-like access: ``len()``, iteration, and integer indexing.

    Attributes:
        records: Tuple of ``Record`` objects in insertion order.
    """

    records: tuple[Record, ...]

    def __len__(self) -> int:
        """Return the number of records in the collection."""
        return len(self.records)

    def __iter__(self) -> Iterator[Record]:
        """Yield records in order."""
        return iter(self.records)

    def __getitem__(self, index: int) -> Record:
        """Return the record at *index*."""
        return self.records[index]

    def sort_records(self, *, key: str = "input_index") -> SignatureCollection:
        """Return a new collection sorted by the given attribute.

        Args:
            key: Attribute name to sort by (default: ``"input_index"``).

        Returns:
            A new ``SignatureCollection`` with sorted records.

        Raises:
            ValueError: If *key* is not a valid attribute of ``Record``.
        """
        if not hasattr(self.records[0], key) if self.records else False:
            valid = [a for a in dir(Record) if not a.startswith("_")]
            raise ValueError(
                f"Invalid sort key {key!r}. Valid options: {valid}")
        sorted_records = tuple(
            sorted(self.records, key=lambda r: getattr(r, key)))
        return SignatureCollection(records=sorted_records)
