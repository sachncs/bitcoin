"""Signature collection model and aggregation."""

from __future__ import annotations

import logging
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from bitcoin.ecc import (
    LinearPointRelationCollection,
    Secp256k1Point,
    TransformedPointCollection,
    derive_point_relation,
    derive_transformed_point,
    parse_sec_public_key,
)
from bitcoin.exceptions import InvalidSecPublicKeyError
from bitcoin.linear import LinearCoefficientCollection, derive_linear_coefficients
from bitcoin.models import SignatureRecord

logger = logging.getLogger(__name__)

__all__ = [
    "SignatureCollection",
    "iter_records_with_points",
    "parse_public_key_point",
]


@dataclass(frozen=True, slots=True)
class SignatureCollection:
    """Immutable collection of extracted signatures."""

    records: tuple[SignatureRecord, ...]

    @property
    def signatures(self) -> list[SignatureRecord]:
        return list(self.records)

    @property
    def r(self) -> list[str]:
        return [record.r for record in self.records]

    @property
    def s(self) -> list[str]:
        return [record.s for record in self.records]

    @property
    def z(self) -> list[str]:
        return [record.z for record in self.records]

    def linear(self) -> LinearCoefficientCollection:
        return LinearCoefficientCollection(records=tuple(
            derive_linear_coefficients(record) for record in self.records))

    def transform_points(self) -> TransformedPointCollection:
        derived = tuple(
            derive_transformed_point(record, point)
            for record, point in iter_records_with_points(
                self.records, "Transformation"))
        return TransformedPointCollection(records=derived)

    def linear_points(self) -> LinearPointRelationCollection:
        relations = tuple(
            derive_point_relation(record, point)
            for record, point in iter_records_with_points(
                self.records, "Point-space derivation"))
        return LinearPointRelationCollection(records=relations)


def parse_public_key_point(
        record: SignatureRecord) -> tuple[Secp256k1Point, int]:
    if record.public_key is None:
        raise InvalidSecPublicKeyError(
            f"Cannot parse public key for input {record.input_index}: "
            "public key is None.")
    point = parse_sec_public_key(bytes.fromhex(record.public_key))
    return point, record.input_index


def iter_records_with_points(
    records: Sequence[SignatureRecord],
    context: str = "",
) -> Iterator[tuple[SignatureRecord, Secp256k1Point]]:
    for record in records:
        if record.public_key is None:
            raise InvalidSecPublicKeyError(
                f"{context} at input {record.input_index} "
                "requires a public key but none was found.")
        try:
            pubkey_bytes = bytes.fromhex(record.public_key)
        except ValueError:
            raise InvalidSecPublicKeyError(
                f"Public key '{record.public_key}' at input "
                f"{record.input_index} is not valid hex.") from None
        try:
            point = parse_sec_public_key(pubkey_bytes)
        except InvalidSecPublicKeyError:
            continue
        yield record, point
