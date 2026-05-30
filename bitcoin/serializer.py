"""Serialization of domain objects to JSON-safe dicts and JSON strings.

All I/O formatting is centralized here so that domain classes remain pure
data carriers with no serialization concerns.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

from bitcoin.utils import bytes_to_hex, int_to_hex

if TYPE_CHECKING:
    from bitcoin.ecc import (
        LinearPointRelation,
        LinearPointRelationCollection,
        Secp256k1Point,
        TransformedPointCollection,
        TransformedPointRecord,
    )
    from bitcoin.linear import (
        LinearCoefficientCollection,
        LinearCoefficientRecord,
    )
    from bitcoin.signature import SignatureCollection
    from bitcoin.transaction import Transaction

__all__ = [
    "int_to_hex_0x",
    "linear_collection_to_dict",
    "linear_collection_to_json",
    "linear_record_to_dict",
    "point_relation_collection_to_dict",
    "point_relation_collection_to_json",
    "point_relation_to_dict",
    "point_to_dict",
    "point_to_json",
    "signature_collection_to_dict",
    "signature_collection_to_json",
    "to_hex",
    "to_json_string",
    "to_pretty_json_string",
    "transaction_to_dict",
    "transaction_to_json",
    "transformed_point_collection_to_dict",
    "transformed_point_record_to_dict",
]

# ── low-level helpers ────────────────────────────────────────────────────


def to_json_string(value: Any) -> str:
    return json.dumps(value,
                      sort_keys=True,
                      separators=(",", ":"),
                      ensure_ascii=True)


def to_pretty_json_string(value: Any) -> str:
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False)


# ── Secp256k1Point ───────────────────────────────────────────────────────


def point_to_dict(point: Secp256k1Point) -> dict[str, object]:
    if point.infinity:
        return {"infinity": True, "x": None, "y": None}
    return {"infinity": False, "x": to_hex(point.x), "y": to_hex(point.y)}


def point_to_json(point: Secp256k1Point, pretty: bool = False) -> str:
    payload = point_to_dict(point)
    if pretty:
        return to_pretty_json_string(payload)
    return to_json_string(payload)


def to_hex(value: int | None) -> str | None:
    if value is None:
        return None
    return int_to_hex(value)


# ── LinearCoefficientRecord / Collection ─────────────────────────────────


def linear_record_to_dict(record: LinearCoefficientRecord) -> dict[str, object]:
    return {
        "alpha": int_to_hex(record.alpha),
        "beta": int_to_hex(record.beta),
        "equation": record.equation(),
        "expanded_equation": record.expanded_equation(),
        "input_index": record.input_index,
        "r": int_to_hex(record.r),
        "s": int_to_hex(record.s),
        "script_type": record.script_type,
        "sighash_flag": record.sighash_flag,
        "z": int_to_hex(record.z),
    }


def linear_collection_to_dict(
    collection: LinearCoefficientCollection,) -> dict[str, object]:
    return {
        "alpha": [int_to_hex(r.alpha) for r in collection.records],
        "beta": [int_to_hex(r.beta) for r in collection.records],
        "count": len(collection.records),
        "records": [linear_record_to_dict(r) for r in collection.records],
    }


def linear_collection_to_json(collection: LinearCoefficientCollection,
                              pretty: bool = False) -> str:
    payload = linear_collection_to_dict(collection)
    if pretty:
        return to_pretty_json_string(payload)
    return to_json_string(payload)


# ── LinearPointRelation / Collection ─────────────────────────────────────


def point_relation_to_dict(relation: LinearPointRelation) -> dict[str, object]:
    return {
        "alpha":
            int_to_hex(relation.alpha),
        "beta":
            int_to_hex(relation.beta),
        "equation":
            relation.equation,
        "input_index":
            relation.input_index,
        "point_b":
            point_to_dict(relation.point_b),
        "transformed_public_key":
            point_to_dict(relation.transformed_public_key),
    }


def point_relation_collection_to_dict(
    collection: LinearPointRelationCollection,) -> dict[str, object]:
    return {
        "alpha": [int_to_hex(r.alpha) for r in collection.records],
        "beta": [int_to_hex(r.beta) for r in collection.records],
        "count": len(collection.records),
        "records": [point_relation_to_dict(r) for r in collection.records],
    }


def point_relation_collection_to_json(collection: LinearPointRelationCollection,
                                      pretty: bool = False) -> str:
    payload = point_relation_collection_to_dict(collection)
    if pretty:
        return to_pretty_json_string(payload)
    return to_json_string(payload)


# ── TransformedPointRecord / Collection ──────────────────────────────────


def transformed_point_record_to_dict(
    record: TransformedPointRecord,) -> dict[str, object]:
    x = int_to_hex_0x(
        record.new_d_point.x) if not record.new_d_point.infinity else None
    y = int_to_hex_0x(
        record.new_d_point.y) if not record.new_d_point.infinity else None
    validation = record.validate()
    return {
        "input_index": record.input_index,
        "curve": "secp256k1",
        "alpha": int_to_hex_0x(record.alpha),
        "beta": int_to_hex_0x(record.beta),
        "new_d_point": {
            "x": x,
            "y": y,
            "encoding": "affine",
            "on_curve": validation["point_on_curve"],
        },
        "equations": {
            "scalar": "d' \u2261 \u03b1k (mod n)",
            "point": "D' = d'G",
        },
        "validation": validation,
    }


def transformed_point_collection_to_dict(
    collection: TransformedPointCollection,) -> list[dict[str, object]]:
    return [transformed_point_record_to_dict(r) for r in collection.records]


def int_to_hex_0x(value: int | None) -> str | None:
    if value is None:
        return None
    return "0x" + format(value, "064x")


# ── SignatureCollection ──────────────────────────────────────────────────


def signature_collection_to_dict(
        collection: SignatureCollection) -> dict[str, object]:
    return {
        "count": len(collection.records),
        "r": collection.r,
        "records": [asdict(record) for record in collection.records],
        "s": collection.s,
        "z": collection.z,
    }


def signature_collection_to_json(collection: SignatureCollection,
                                 pretty: bool = False) -> str:
    payload = signature_collection_to_dict(collection)
    if pretty:
        return to_pretty_json_string(payload)
    return to_json_string(payload)


# ── Transaction ──────────────────────────────────────────────────────────


def transaction_to_dict(tx: Transaction) -> dict[str, object]:
    return {
        "inputs": [{
            "prevout_hash": bytes_to_hex(txin.prevout_hash),
            "prevout_index": txin.prevout_index,
            "script_sig": bytes_to_hex(txin.script_sig),
            "sequence": txin.sequence,
            "witness": [bytes_to_hex(item) for item in txin.witness],
        } for txin in tx.inputs],
        "locktime": tx.locktime,
        "outputs": [{
            "script_pubkey": bytes_to_hex(txout.script_pubkey),
            "value": txout.value,
        } for txout in tx.outputs],
        "raw_hex": bytes_to_hex(tx.raw_bytes),
        "segwit": tx.segwit,
        "version": tx.version,
    }


def transaction_to_json(tx: Transaction, pretty: bool = False) -> str:
    payload = transaction_to_dict(tx)
    if pretty:
        return to_pretty_json_string(payload)
    return to_json_string(payload)
