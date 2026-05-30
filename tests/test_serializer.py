"""Tests for the serializer module."""

from __future__ import annotations

from bitcoin.ecc import G, SECP256K1_INFINITY, Secp256k1Point
from bitcoin.linear import LinearCoefficientCollection, LinearCoefficientRecord
from bitcoin.models import SignatureRecord
from bitcoin.serializer import (
    int_to_hex_0x,
    linear_collection_to_dict,
    linear_collection_to_json,
    point_to_dict,
    point_to_json,
    signature_collection_to_dict,
    signature_collection_to_json,
    to_hex,
    to_json_string,
    to_pretty_json_string,
    transformed_point_collection_to_dict,
    transformed_point_record_to_dict,
)
from bitcoin.signature import SignatureCollection
from bitcoin.transaction import Transaction


def test_to_hex_none() -> None:
    assert to_hex(None) is None


def test_to_hex_value() -> None:
    result = to_hex(255)
    assert result == "ff"


def test_int_to_hex_0x_none() -> None:
    assert int_to_hex_0x(None) is None


def test_int_to_hex_0x_value() -> None:
    result = int_to_hex_0x(255)
    assert result == "0x00000000000000000000000000000000000000000000000000000000000000ff"


def test_to_json_string_compact() -> None:
    result = to_json_string({"a": 1})
    assert result == '{"a":1}'
    assert "," not in result  # compact: no spaces


def test_to_pretty_json_string() -> None:
    result = to_pretty_json_string({"a": 1})
    assert '  "a"' in result  # indented


def test_point_to_dict_infinity() -> None:
    d = point_to_dict(SECP256K1_INFINITY)
    assert d["infinity"] is True
    assert d["x"] is None
    assert d["y"] is None


def test_point_to_dict_affine() -> None:
    d = point_to_dict(G)
    assert d["infinity"] is False
    assert isinstance(d["x"], str)
    assert isinstance(d["y"], str)


def test_point_to_json_infinity() -> None:
    result = point_to_json(SECP256K1_INFINITY, pretty=False)
    assert "infinity" in result


def test_point_to_json_pretty() -> None:
    result = point_to_json(G, pretty=True)
    assert "  " in result


def test_signature_collection_to_dict() -> None:
    record = SignatureRecord(
        r="ff",
        s="ee",
        z="dd",
        sighash_flag=1,
        input_index=0,
        public_key="02c0de",
        script_type="legacy-p2pkh",
    )
    col = SignatureCollection(records=(record,))
    d = signature_collection_to_dict(col)
    assert d["count"] == 1
    assert d["r"] == ["ff"]


def test_signature_collection_to_json() -> None:
    record = SignatureRecord(
        r="ff",
        s="ee",
        z="dd",
        sighash_flag=1,
        input_index=0,
        public_key="02c0de",
        script_type="legacy-p2pkh",
    )
    col = SignatureCollection(records=(record,))
    result = signature_collection_to_json(col, pretty=False)
    assert "ff" in result


def test_signature_collection_to_json_pretty() -> None:
    record = SignatureRecord(
        r="ff",
        s="ee",
        z="dd",
        sighash_flag=1,
        input_index=0,
        public_key="02c0de",
        script_type="legacy-p2pkh",
    )
    col = SignatureCollection(records=(record,))
    result = signature_collection_to_json(col, pretty=True)
    assert "  " in result


def test_linear_record_to_dict() -> None:
    from bitcoin.serializer import linear_record_to_dict

    record = LinearCoefficientRecord(
        input_index=0,
        r=1,
        s=2,
        z=3,
        alpha=4,
        beta=5,
        sighash_flag=1,
        script_type="test",
    )
    d = linear_record_to_dict(record)
    assert d["alpha"] == "4"
    assert d["input_index"] == 0


def test_linear_collection_to_dict() -> None:
    record = LinearCoefficientRecord(
        input_index=0,
        r=1,
        s=2,
        z=3,
        alpha=4,
        beta=5,
        sighash_flag=1,
        script_type="test",
    )
    col = LinearCoefficientCollection(records=(record,))
    d = linear_collection_to_dict(col)
    assert d["count"] == 1
    assert d["alpha"] == ["4"]


def test_linear_collection_to_json() -> None:
    record = LinearCoefficientRecord(
        input_index=0,
        r=1,
        s=2,
        z=3,
        alpha=4,
        beta=5,
        sighash_flag=1,
        script_type="test",
    )
    col = LinearCoefficientCollection(records=(record,))
    result = linear_collection_to_json(col, pretty=True)
    assert "alpha" in result


def test_transformed_point_record_to_dict() -> None:
    from bitcoin.ecc import derive_transformed_point

    record = SignatureRecord(
        r="ff",
        s="ee",
        z="dd",
        sighash_flag=1,
        input_index=0,
        public_key=G.to_sec_compressed().hex(),
        script_type="test",
    )
    rec = derive_transformed_point(record, G)
    d = transformed_point_record_to_dict(rec)
    assert d["curve"] == "secp256k1"
    assert d["validation"]["point_on_curve"] is True


def test_transformed_point_collection_to_dict() -> None:
    from bitcoin.ecc import derive_transformed_point

    record = SignatureRecord(
        r="ff",
        s="ee",
        z="dd",
        sighash_flag=1,
        input_index=0,
        public_key=G.to_sec_compressed().hex(),
        script_type="test",
    )
    rec = derive_transformed_point(record, G)
    col = type("Col", (), {"records": (rec,)})()
    result = transformed_point_collection_to_dict(col)
    assert len(result) == 1


def test_to_hex_zero() -> None:
    result = to_hex(0)
    assert result == "0"


def test_int_to_hex_0x_zero() -> None:
    result = int_to_hex_0x(0)
    assert result == "0x" + "00" * 32


def test_signature_collection_empty() -> None:
    col = SignatureCollection(records=())
    d = signature_collection_to_dict(col)
    assert d["count"] == 0
    assert d["r"] == []


def test_signature_collection_json_empty() -> None:
    col = SignatureCollection(records=())
    result = signature_collection_to_json(col)
    assert '"count":0' in result
