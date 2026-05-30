from __future__ import annotations

import json

import pytest

from bitcoin.cli import main as cli_main
from bitcoin.ecc import (
    SECP256K1_FIELD_PRIME,
    SECP256K1_INFINITY,
    SECP256K1_ORDER,
    G,
    LinearPointRelationCollection,
    Secp256k1Point,
    TransformedPointCollection,
    derive_point_relation,
    derive_transformed_point,
    field_sqrt,
    inverse_mod,
    is_on_curve,
    parse_sec_public_key,
    point_add,
    point_double,
    point_negate,
    scalar_multiply,
    serialize_sec_public_key,
)
from bitcoin.exceptions import (
    InvalidLinearCoefficientError,
    InvalidSecp256k1PointError,
    InvalidSecPublicKeyError,
)
from bitcoin.models import SignatureRecord
from bitcoin.serializer import point_relation_collection_to_json, point_to_json
from tests.test_transaction import build_p2pkh_transaction
from bitcoin.transaction import Transaction


def _hex_scalar(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big").hex()


def _make_signature_record(r: int,
                           s: int,
                           z: int,
                           input_index: int = 0) -> SignatureRecord:
    return SignatureRecord(
        r=_hex_scalar(r),
        s=_hex_scalar(s),
        z=_hex_scalar(z),
        sighash_flag=1,
        input_index=input_index,
        public_key=serialize_sec_public_key(G, compressed=True).hex(),
        script_type="legacy-p2pkh",
    )


def test_point_addition_and_doubling() -> None:
    double_via_add = point_add(G, G)
    double_direct = point_double(G)
    triple = point_add(G, double_direct)

    assert double_via_add == double_direct
    assert triple == scalar_multiply(3, G)
    assert point_add(G, SECP256K1_INFINITY) == G
    assert point_add(SECP256K1_INFINITY, G) == G
    assert point_double(SECP256K1_INFINITY) == SECP256K1_INFINITY


def test_scalar_multiplication_wraparound() -> None:
    assert scalar_multiply(0, G) == SECP256K1_INFINITY
    assert scalar_multiply(1, G) == G
    assert scalar_multiply(SECP256K1_ORDER, G) == SECP256K1_INFINITY
    assert scalar_multiply(SECP256K1_ORDER + 1, G) == G


def test_sec_parsing_and_serialization_roundtrip() -> None:
    compressed = G.to_sec_compressed()
    uncompressed = G.to_sec_uncompressed()

    assert parse_sec_public_key(compressed) == G
    assert parse_sec_public_key(uncompressed) == G
    assert (serialize_sec_public_key(parse_sec_public_key(compressed),
                                     True) == compressed)
    assert (serialize_sec_public_key(parse_sec_public_key(uncompressed),
                                     False) == uncompressed)


def test_invalid_points_and_encodings_are_rejected() -> None:
    with pytest.raises(InvalidSecp256k1PointError):
        Secp256k1Point(x=SECP256K1_FIELD_PRIME, y=1, infinity=False)

    with pytest.raises(InvalidSecp256k1PointError):
        Secp256k1Point(x=1, y=1, infinity=False)

    with pytest.raises(InvalidSecPublicKeyError):
        parse_sec_public_key(b"\x05" + b"\x00" * 32)

    with pytest.raises(InvalidSecPublicKeyError):
        SECP256K1_INFINITY.to_sec_compressed()


def test_point_space_relation_verification() -> None:
    d = 19
    k = 29
    r = 7
    s = 11
    z = (s * k - d * r) % SECP256K1_ORDER

    public_key_point = scalar_multiply(d, G)
    nonce_point = scalar_multiply(k, G)
    relation = derive_point_relation(_make_signature_record(r, s, z),
                                     public_key_point)

    assert relation.equation == "D + \u03b2G = \u03b1K"
    assert relation.transformed_public_key == point_add(
        public_key_point, scalar_multiply(relation.beta, G))
    assert relation.verify(nonce_point)


def test_point_relation_collection_integration() -> None:
    raw_hex, _, _ = build_p2pkh_transaction()
    collection = Transaction.parse_hex(raw_hex).extract().linear_points()

    assert len(collection.records) == 1
    assert collection.records[0].equation == "D + \u03b2G = \u03b1K"
    assert collection.records[0].transformed_public_key.infinity is False

    payload = json.loads(
        point_relation_collection_to_json(collection, pretty=True))
    assert payload["count"] == 1
    assert payload["records"][0]["equation"] == "D + \u03b2G = \u03b1K"


def test_cli_points_prints_single_record(
        capsys: pytest.CaptureFixture[str]) -> None:
    raw_hex, _, _ = build_p2pkh_transaction()

    exit_code = cli_main(["points", "--tx", raw_hex])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["input_index"] == 0
    assert payload["equation"] == "D + \u03b2G = \u03b1K"
    assert "transformed_public_key" in payload
    assert "x" in payload["transformed_public_key"]
    assert "y" in payload["transformed_public_key"]


def test_point_negate_infinity() -> None:
    assert point_negate(SECP256K1_INFINITY) == SECP256K1_INFINITY


def test_scalar_multiply_zero() -> None:
    assert scalar_multiply(0, G) == SECP256K1_INFINITY


def test_inverse_mod_rejects_bad_params() -> None:
    with pytest.raises(InvalidSecp256k1PointError):
        inverse_mod(1, 1)


def test_inverse_mod_rejects_zero() -> None:
    with pytest.raises(InvalidSecp256k1PointError):
        inverse_mod(0, SECP256K1_FIELD_PRIME)


def test_field_element_out_of_range_rejected() -> None:
    with pytest.raises(InvalidSecp256k1PointError):
        Secp256k1Point(x=SECP256K1_FIELD_PRIME, y=0, infinity=False)


def test_infinity_with_coordinates_rejected() -> None:
    with pytest.raises(InvalidSecp256k1PointError):
        Secp256k1Point(x=0, y=0, infinity=True)


def test_non_integer_coordinate_rejected() -> None:
    with pytest.raises(InvalidSecp256k1PointError):
        Secp256k1Point(x="1", y=1, infinity=False)  # type: ignore[arg-type]


def test_point_add_self_inverse() -> None:
    result = point_add(G, point_negate(G))
    assert result == SECP256K1_INFINITY


def test_uncompressed_sec_roundtrip() -> None:
    uncompressed = G.to_sec_uncompressed()
    parsed = parse_sec_public_key(uncompressed)
    assert serialize_sec_public_key(parsed, compressed=False) == uncompressed


def test_sec_compressed_invalid_prefix_rejected() -> None:
    with pytest.raises(InvalidSecPublicKeyError):
        parse_sec_public_key(b"\x05" + b"\x00" * 32)


def test_sec_compressed_invalid_x_coordinate_rejected() -> None:
    raw = b"\x02" + (SECP256K1_FIELD_PRIME).to_bytes(32, "big")
    with pytest.raises(InvalidSecPublicKeyError):
        parse_sec_public_key(raw)


def test_sec_invalid_length_rejected() -> None:
    with pytest.raises(InvalidSecPublicKeyError):
        parse_sec_public_key(b"\x02" + b"\x00" * 31)


def test_point_to_json_consistency() -> None:
    d1 = json.loads(point_to_json(G))
    d2 = json.loads(point_to_json(G, pretty=True))
    assert d1 == d2


# ── Property-based point arithmetic tests ────────────────────────────────


def test_point_add_commutes_with_doubling() -> None:
    two_g = point_add(G, G)
    double_g = point_double(G)
    assert two_g == double_g

    three_g = point_add(two_g, G)
    assert three_g == scalar_multiply(3, G)
    assert point_add(G, G) == scalar_multiply(2, G)


def test_scalar_multiply_zero_consistency() -> None:
    assert scalar_multiply(0, G) == SECP256K1_INFINITY
    assert scalar_multiply(SECP256K1_ORDER, G) == SECP256K1_INFINITY
    assert scalar_multiply(2 * SECP256K1_ORDER, G) == SECP256K1_INFINITY


def test_point_negation_preserves_additive_inverse() -> None:
    for k in (2, 5, 42, 100, 1000):
        pt = scalar_multiply(k, G)
        assert point_add(pt, point_negate(pt)) == SECP256K1_INFINITY


def test_verify_relation_rejects_infinity_nonce() -> None:
    d = 19
    k = 29
    r = 7
    s = 11
    z = (s * k - d * r) % SECP256K1_ORDER

    public_key_point = scalar_multiply(d, G)
    relation = derive_point_relation(_make_signature_record(r, s, z),
                                     public_key_point)

    with pytest.raises(InvalidSecp256k1PointError):
        relation.verify(SECP256K1_INFINITY)


def test_ecc_inverse_mod_rejects_non_int_modulus() -> None:
    with pytest.raises(InvalidSecp256k1PointError, match="must be an integer"):
        inverse_mod(1, "not-int")  # type: ignore[arg-type]


def test_ecc_inverse_mod_rejects_non_invertible() -> None:
    with pytest.raises(InvalidSecp256k1PointError,
                       match="not invertible modulo"):
        inverse_mod(7, 14)


def test_field_sqrt_no_root() -> None:
    with pytest.raises(InvalidSecp256k1PointError, match="no square root"):
        field_sqrt(3)


def test_field_sqrt_py_no_root() -> None:
    from bitcoin.ecc import field_sqrt_py

    with pytest.raises(InvalidSecp256k1PointError, match="no square root"):
        field_sqrt_py(3)


def test_field_sqrt_py_known_root() -> None:
    from bitcoin.ecc import field_sqrt_py

    root = field_sqrt_py(1)
    assert (root * root) % SECP256K1_FIELD_PRIME == 1


def test_is_on_curve_py_valid_g() -> None:
    from bitcoin.ecc import is_on_curve_py

    assert is_on_curve_py(G.x, G.y) is True


def test_is_on_curve_py_invalid() -> None:
    from bitcoin.ecc import is_on_curve_py

    assert is_on_curve_py(0, 0) is False
    assert is_on_curve_py(1, 2) is False
    assert is_on_curve_py(SECP256K1_FIELD_PRIME - 1, 0) is False


def test_point_sec_uncompressed_on_infinity() -> None:
    with pytest.raises(InvalidSecPublicKeyError, match="Infinity cannot"):
        SECP256K1_INFINITY.to_sec_uncompressed()


def test_point_init_non_bool_infinity() -> None:
    with pytest.raises(InvalidSecp256k1PointError, match="must be a boolean"):
        Secp256k1Point(infinity=1)  # type: ignore[arg-type]


def test_point_init_missing_coordinates() -> None:
    with pytest.raises(InvalidSecp256k1PointError, match="require x and y"):
        Secp256k1Point()


def test_point_repr_non_infinity() -> None:
    r = repr(G)
    assert "infinity=False" in r
    assert "x=0x" in r


def test_point_eq_non_point() -> None:
    assert G.__eq__("not-a-point") == NotImplemented


def test_parse_sec_bytearray_input() -> None:
    data = bytearray(G.to_sec_compressed())
    result = parse_sec_public_key(data)  # type: ignore[arg-type]
    assert result == G


def test_parse_sec_non_bytes_input() -> None:
    with pytest.raises(InvalidSecPublicKeyError, match="must be bytes"):
        parse_sec_public_key("not-bytes")  # type: ignore[arg-type]


def test_derive_point_relation_rejects_infinity_public_key() -> None:
    with pytest.raises(InvalidSecp256k1PointError, match="cannot be infinity"):
        derive_point_relation(_make_signature_record(1, 2, 3),
                              SECP256K1_INFINITY)


def test_linear_point_relation_collection_alpha_beta() -> None:
    d = 19
    k = 29
    r = 7
    s = 11
    z = (s * k - d * r) % SECP256K1_ORDER
    pk = scalar_multiply(d, G)
    rel = derive_point_relation(_make_signature_record(r, s, z), pk)
    collection = LinearPointRelationCollection(records=(rel,))
    assert collection.alpha == [rel.alpha]
    assert collection.beta == [rel.beta]


def test_point_relation_collection_to_json_compact() -> None:
    from bitcoin.serializer import point_relation_collection_to_json

    raw_hex, _, _ = build_p2pkh_transaction()
    collection = Transaction.parse_hex(raw_hex).extract().linear_points()
    result = point_relation_collection_to_json(collection, pretty=False)
    parsed = json.loads(result)
    assert parsed["count"] == 1


def test_signature_collection_to_json_compact() -> None:
    from bitcoin.serializer import signature_collection_to_json

    raw_hex, _, _ = build_p2pkh_transaction()
    collection = Transaction.parse_hex(raw_hex).extract()
    result = signature_collection_to_json(collection, pretty=False)
    parsed = json.loads(result)
    assert parsed["count"] == 1


def test_transaction_to_json_compact() -> None:
    from bitcoin.serializer import transaction_to_json

    raw_hex, _, _ = build_p2pkh_transaction()
    tx = Transaction.parse_hex(raw_hex)
    result = transaction_to_json(tx, pretty=False)
    parsed = json.loads(result)
    assert len(parsed["inputs"]) == 1


def test_point_to_json_infinity() -> None:
    from bitcoin.serializer import point_to_json

    d = json.loads(point_to_json(SECP256K1_INFINITY))
    assert d["infinity"] is True


def test_coordinate_negative_rejected() -> None:
    with pytest.raises(InvalidSecp256k1PointError, match="non-negative"):
        Secp256k1Point(x=-1, y=0, infinity=False)


def test_point_hash() -> None:
    s = {G}
    assert G in s


def test_repr_infinity() -> None:
    r = repr(SECP256K1_INFINITY)
    assert "infinity=True" in r


# ── TransformedPointRecord / derive_transformed_point ────────────────────


def test_derive_transformed_point_alpha_beta() -> None:
    d = 19
    k = 29
    r = 7
    s = 11
    z = (s * k - d * r) % SECP256K1_ORDER
    pk = scalar_multiply(d, G)
    record = derive_transformed_point(_make_signature_record(r, s, z), pk)
    expected_alpha = (s * inverse_mod(r, SECP256K1_ORDER)) % SECP256K1_ORDER
    expected_beta = (z * inverse_mod(r, SECP256K1_ORDER)) % SECP256K1_ORDER
    assert record.alpha == expected_alpha
    assert record.beta == expected_beta
    assert record.input_index == 0


def test_derive_transformed_point_new_d_point() -> None:
    d = 19
    k = 29
    r = 7
    s = 11
    z = (s * k - d * r) % SECP256K1_ORDER
    pk = scalar_multiply(d, G)
    record = derive_transformed_point(_make_signature_record(r, s, z), pk)
    d_prime = (d + record.beta) % SECP256K1_ORDER
    expected_point = scalar_multiply(d_prime, G)
    assert record.new_d_point == expected_point
    assert not record.new_d_point.infinity
    assert is_on_curve(record.new_d_point.x, record.new_d_point.y)


def test_derive_transformed_point_on_curve() -> None:
    d = 19
    k = 29
    r = 7
    s = 11
    z = (s * k - d * r) % SECP256K1_ORDER
    pk = scalar_multiply(d, G)
    record = derive_transformed_point(_make_signature_record(r, s, z), pk)
    assert record.new_d_point.x is not None
    assert record.new_d_point.y is not None
    assert is_on_curve(record.new_d_point.x, record.new_d_point.y)


def test_derive_transformed_point_rejects_infinity() -> None:
    with pytest.raises(InvalidSecp256k1PointError, match="cannot be infinity"):
        derive_transformed_point(_make_signature_record(1, 2, 3),
                                 SECP256K1_INFINITY)


def test_derive_transformed_point_rejects_zero_r() -> None:
    pk = scalar_multiply(19, G)
    with pytest.raises(InvalidLinearCoefficientError, match="must be non-zero"):
        derive_transformed_point(_make_signature_record(0, 11, 42), pk)


def test_transformed_point_record_validates_alpha_beta() -> None:
    pk = scalar_multiply(19, G)
    record = derive_transformed_point(_make_signature_record(7, 11, 42), pk)
    assert 0 <= record.alpha < SECP256K1_ORDER
    assert 0 <= record.beta < SECP256K1_ORDER


def test_transformed_point_collection() -> None:
    records = []
    for d, k in [(19, 29), (13, 7)]:
        r = 7
        s = 11
        z = (s * k - d * r) % SECP256K1_ORDER
        pk = scalar_multiply(d, G)
        records.append(
            derive_transformed_point(_make_signature_record(r, s, z), pk))
    collection = TransformedPointCollection(records=tuple(records))
    assert len(collection.records) == 2
    assert collection.records[0].alpha == collection.records[1].alpha
    assert collection.records[0].beta != collection.records[1].beta


def test_transformed_point_serialization() -> None:
    from bitcoin.serializer import transformed_point_collection_to_dict

    d = 19
    k = 29
    r = 7
    s = 11
    z = (s * k - d * r) % SECP256K1_ORDER
    pk = scalar_multiply(d, G)
    record = derive_transformed_point(_make_signature_record(r, s, z), pk)
    collection = TransformedPointCollection(records=(record,))
    result = transformed_point_collection_to_dict(collection)
    assert len(result) == 1
    entry = result[0]
    assert entry["curve"] == "secp256k1"
    assert entry["input_index"] == 0
    assert entry["alpha"].startswith("0x")
    assert entry["beta"].startswith("0x")
    assert entry["new_d_point"]["encoding"] == "affine"
    assert entry["new_d_point"]["on_curve"] is True
    assert entry["equations"]["scalar"] == "d' \u2261 \u03b1k (mod n)"
    assert entry["equations"]["point"] == "D' = d'G"
    assert entry["validation"]["alpha_in_range"] is True
    assert entry["validation"]["beta_in_range"] is True
    assert entry["validation"]["point_on_curve"] is True
