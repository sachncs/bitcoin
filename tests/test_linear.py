from __future__ import annotations

import json
import random

import pytest

from bitcoin.cli import main as cli_main
from bitcoin.cli import parse_input_values
from bitcoin.exceptions import (
    InvalidLinearCoefficientError,
    NonInvertibleLinearCoefficientError,
)
from bitcoin.linear import (
    SECP256K1_ORDER,
    LinearCoefficientRecord,
    derive_linear_coefficients,
    inverse_mod,
)
from bitcoin.models import SignatureRecord
from bitcoin.serializer import linear_collection_to_json
from tests.test_transaction import (
    build_p2pkh_transaction,
    build_p2sh_multisig_transaction,
)
from bitcoin.transaction import Transaction


def _hex_scalar(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big").hex()


def _make_signature_record(
    r: int,
    s: int,
    z: int,
    *,
    input_index: int = 0,
    sighash_flag: int = 1,
    script_type: str = "legacy-p2pkh",
) -> SignatureRecord:
    return SignatureRecord(
        r=_hex_scalar(r),
        s=_hex_scalar(s),
        z=_hex_scalar(z),
        sighash_flag=sighash_flag,
        input_index=input_index,
        public_key=None,
        script_type=script_type,
    )


def test_parse_input_values_empty() -> None:
    assert parse_input_values("") == []


def test_parse_input_values_whitespace() -> None:
    assert parse_input_values("  ") == []


def test_parse_input_values_single() -> None:
    assert parse_input_values("100") == [100]


def test_parse_input_values_multiple() -> None:
    assert parse_input_values("100,200,300") == [100, 200, 300]


def test_parse_input_values_with_none() -> None:
    assert parse_input_values("100,,300") == [100, None, 300]


def test_parse_input_values_with_spaces() -> None:
    assert parse_input_values(" 100 , 200 ") == [100, 200]


def test_linear_coefficient_record_validation() -> None:
    with pytest.raises(InvalidLinearCoefficientError):
        LinearCoefficientRecord(
            input_index=-1,
            r=1,
            s=1,
            z=1,
            alpha=1,
            beta=1,
            sighash_flag=1,
            script_type="p2pkh",
        )

    with pytest.raises(InvalidLinearCoefficientError):
        LinearCoefficientRecord(
            input_index=0,
            r=1,
            s=1,
            z=1,
            alpha=SECP256K1_ORDER,
            beta=1,
            sighash_flag=1,
            script_type="p2pkh",
        )

    with pytest.raises(InvalidLinearCoefficientError):
        LinearCoefficientRecord(
            input_index=0,
            r=1,
            s=1,
            z=1,
            alpha=1,
            beta=SECP256K1_ORDER,
            sighash_flag=1,
            script_type="p2pkh",
        )

    with pytest.raises(InvalidLinearCoefficientError):
        LinearCoefficientRecord(
            input_index=0,
            r=1,
            s=1,
            z=1,
            alpha=1,
            beta=1,
            sighash_flag=-1,
            script_type="p2pkh",
        )

    with pytest.raises(InvalidLinearCoefficientError):
        LinearCoefficientRecord(
            input_index=0,
            r=1,
            s=1,
            z=1,
            alpha=1,
            beta=1,
            sighash_flag=1,
            script_type="",
        )


def test_linear_relation_holds_for_randomized_vectors() -> None:
    rng = random.Random(0xC0FFEE)
    for input_index in range(12):
        r = rng.randrange(1, SECP256K1_ORDER)
        s = rng.randrange(1, SECP256K1_ORDER)
        k = rng.randrange(1, SECP256K1_ORDER)
        d = rng.randrange(1, SECP256K1_ORDER)
        z = (s * k - d * r) % SECP256K1_ORDER

        record = derive_linear_coefficients(
            _make_signature_record(r, s, z, input_index=input_index))

        r_inverse = inverse_mod(r, SECP256K1_ORDER)
        assert record.alpha == (s * r_inverse) % SECP256K1_ORDER
        assert record.beta == (z * r_inverse) % SECP256K1_ORDER
        assert ((d + record.beta) % SECP256K1_ORDER) == ((record.alpha * k) %
                                                         SECP256K1_ORDER)
        assert record.verify_linear_relation(k, d)
        assert d == ((s * k - z) * r_inverse) % SECP256K1_ORDER


def test_high_s_and_low_r_are_accepted() -> None:
    r = 1
    s = SECP256K1_ORDER - 1
    k = 9
    d = 11
    z = (s * k - d * r) % SECP256K1_ORDER

    record = derive_linear_coefficients(_make_signature_record(r, s, z))

    assert record.r == r
    assert record.s == s
    assert record.alpha == s
    assert record.beta == z % SECP256K1_ORDER
    assert record.verify_linear_relation(k, d)


def test_boundary_values_near_curve_order() -> None:
    r = SECP256K1_ORDER - 1
    s = SECP256K1_ORDER - 2
    k = SECP256K1_ORDER - 3
    d = SECP256K1_ORDER - 4
    z = (s * k - d * r) % SECP256K1_ORDER

    record = derive_linear_coefficients(_make_signature_record(r, s, z))

    assert record.alpha == (s *
                            inverse_mod(r, SECP256K1_ORDER)) % SECP256K1_ORDER
    assert record.beta == (z *
                           inverse_mod(r, SECP256K1_ORDER)) % SECP256K1_ORDER
    assert record.verify_linear_relation(k, d)


def test_inverse_mod_rejects_non_invertible_values() -> None:
    with pytest.raises(NonInvertibleLinearCoefficientError):
        inverse_mod(0, SECP256K1_ORDER)

    with pytest.raises(NonInvertibleLinearCoefficientError):
        inverse_mod(2, 4)


def test_derivation_rejects_invalid_signature_scalars() -> None:
    with pytest.raises(InvalidLinearCoefficientError):
        derive_linear_coefficients(
            SignatureRecord(
                r="00",
                s="01",
                z="01",
                sighash_flag=1,
                input_index=0,
                public_key=None,
                script_type="legacy-p2pkh",
            ))

    with pytest.raises(InvalidLinearCoefficientError):
        derive_linear_coefficients(
            SignatureRecord(
                r="not-hex",
                s="01",
                z="01",
                sighash_flag=1,
                input_index=0,
                public_key=None,
                script_type="legacy-p2pkh",
            ))


def test_transaction_extract_linear_integration() -> None:
    raw_hex, _, _ = build_p2pkh_transaction()
    collection = Transaction.parse_hex(raw_hex).extract().linear()

    assert len(collection.records) == 1
    assert collection.alpha == [collection.records[0].alpha]
    assert collection.beta == [collection.records[0].beta]
    assert collection.records[0].equation() == "d' \u2261 \u03b1k (mod n)"
    assert collection.records[0].expanded_equation().startswith("d + 0x")

    payload = json.loads(linear_collection_to_json(collection, pretty=True))
    assert payload["count"] == 1
    assert payload["records"][0]["input_index"] == 0


# ── Property-based test for linear relation ──────────────────────────────


def test_linear_relation_property_based() -> None:
    rng = random.Random(0xDEADBEEF)
    for _ in range(50):
        r = rng.randrange(1, SECP256K1_ORDER)
        s = rng.randrange(1, SECP256K1_ORDER)
        k = rng.randrange(1, SECP256K1_ORDER)
        d = rng.randrange(1, SECP256K1_ORDER)
        z = (s * k - d * r) % SECP256K1_ORDER

        record = derive_linear_coefficients(
            _make_signature_record(r, s, z, input_index=0))

        left = (d + record.beta) % SECP256K1_ORDER
        right = (record.alpha * k) % SECP256K1_ORDER
        assert left == right, (
            f"Linear relation failed: d={d}, k={k}, alpha={record.alpha}, "
            f"beta={record.beta}")
        assert record.verify_linear_relation(k, d)


def test_normalize_non_negative_rejects_non_int() -> None:
    with pytest.raises(InvalidLinearCoefficientError,
                       match="must be an integer"):
        inverse_mod(1.5, SECP256K1_ORDER)  # type: ignore[arg-type]


def test_inverse_mod_rejects_negative_value() -> None:
    with pytest.raises(InvalidLinearCoefficientError,
                       match="must be non-negative"):
        inverse_mod(-5, SECP256K1_ORDER)


def test_inverse_mod_rejects_non_int_modulus() -> None:
    with pytest.raises(InvalidLinearCoefficientError,
                       match="must be an integer"):
        inverse_mod(1, "not-int")  # type: ignore[arg-type]


def test_inverse_mod_rejects_modulus_le_one() -> None:
    with pytest.raises(InvalidLinearCoefficientError, match="greater than one"):
        inverse_mod(1, 1)


def test_inverse_mod_rejects_non_invertible_after_modulo() -> None:
    with pytest.raises(NonInvertibleLinearCoefficientError,
                       match="not invertible"):
        inverse_mod(SECP256K1_ORDER, SECP256K1_ORDER)


def test_linear_record_z_non_negative() -> None:
    with pytest.raises(InvalidLinearCoefficientError, match="non-negative"):
        LinearCoefficientRecord(
            input_index=0,
            r=1,
            s=1,
            z=-1,
            alpha=1,
            beta=1,
            sighash_flag=1,
            script_type="p2pkh",
        )


def test_linear_record_r_out_of_range() -> None:
    with pytest.raises(InvalidLinearCoefficientError, match="curve order"):
        LinearCoefficientRecord(
            input_index=0,
            r=SECP256K1_ORDER,
            s=1,
            z=1,
            alpha=1,
            beta=1,
            sighash_flag=1,
            script_type="p2pkh",
        )


def test_parse_signature_scalar_accepts_0x_prefix() -> None:
    record = derive_linear_coefficients(
        SignatureRecord(
            r="0x01",
            s="01",
            z="01",
            sighash_flag=1,
            input_index=0,
            public_key=None,
            script_type="legacy-p2pkh",
        ))
    assert record.r == 1


def test_parse_signature_scalar_rejects_empty_0x() -> None:
    with pytest.raises(InvalidLinearCoefficientError, match="cannot be empty"):
        derive_linear_coefficients(
            SignatureRecord(
                r="0x",
                s="01",
                z="01",
                sighash_flag=1,
                input_index=0,
                public_key=None,
                script_type="legacy-p2pkh",
            ))


def test_parse_signature_scalar_rejects_non_str() -> None:
    with pytest.raises(InvalidLinearCoefficientError,
                       match="must be a hexadecimal string"):
        derive_linear_coefficients(
            SignatureRecord(
                r=123,  # type: ignore[arg-type]
                s="01",
                z="01",
                sighash_flag=1,
                input_index=0,
                public_key=None,
                script_type="legacy-p2pkh",
            ))


def test_verify_linear_relation_rejects_non_int() -> None:
    record = LinearCoefficientRecord(
        input_index=0,
        r=1,
        s=1,
        z=1,
        alpha=1,
        beta=0,
        sighash_flag=1,
        script_type="p2pkh",
    )
    with pytest.raises(InvalidLinearCoefficientError, match="must be integers"):
        record.verify_linear_relation("not-k", 1)  # type: ignore[arg-type]


def test_cli_linear_prints_single_record(
        capsys: pytest.CaptureFixture[str]) -> None:
    raw_hex, _, _ = build_p2pkh_transaction()

    exit_code = cli_main(["linear", "--tx", raw_hex])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["input_index"] == 0
    assert payload["equation"] == "d' \u2261 \u03b1k (mod n)"
    assert "alpha" in payload
    assert "beta" in payload


def test_cli_linear_multi_record(capsys: pytest.CaptureFixture[str]) -> None:
    raw_hex, _ = build_p2sh_multisig_transaction()
    exit_code = cli_main(["linear", "--tx", raw_hex])

    captured = capsys.readouterr()
    assert exit_code == 0
    payload = json.loads(captured.out)
    assert payload["count"] == 2


def test_linear_collection_to_json_compact() -> None:
    raw_hex, _, _ = build_p2pkh_transaction()
    collection = Transaction.parse_hex(raw_hex).extract().linear()
    result = linear_collection_to_json(collection, pretty=False)
    parsed = json.loads(result)
    assert parsed["count"] == 1
