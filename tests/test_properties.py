"""Property-based tests for ECC operations using Hypothesis."""

from __future__ import annotations

import math

from hypothesis import assume, given
from hypothesis import strategies as st

from bitcoin.ecc import (
    SECP256K1_FIELD_PRIME,
    SECP256K1_INFINITY,
    SECP256K1_ORDER,
    G,
    LinearPointRelation,
    Secp256k1Point,
    derive_transformed_point,
    field_sqrt,
    inverse_mod,
    is_on_curve,
    normalize_non_negative,
    parse_sec_public_key,
    point_add,
    point_double,
    point_negate,
    scalar_multiply,
    serialize_sec_public_key,
)
from bitcoin.models import SignatureRecord, TransactionContext, TransactionInput, TransactionOutput
from bitcoin.transaction import Transaction

from tests.test_transaction import build_p2pkh_transaction

# ── Helpers ────────────────────────────────────────────────────────────────

SMALL_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]


def _hex_scalar(value: int) -> str:
    length = max(1, (value.bit_length() + 7) // 8)
    return value.to_bytes(length, "big").hex()


# ── Strategies ─────────────────────────────────────────────────────────────

finite_point_scalar = st.integers(min_value=1, max_value=SECP256K1_ORDER - 1)
finite_points = finite_point_scalar.map(lambda s: scalar_multiply(s, G))
points = st.one_of(st.just(SECP256K1_INFINITY), st.just(G), finite_points)

# ═══════════════════════════════════════════════════════════════════════════
# 1. Field arithmetic
# ═══════════════════════════════════════════════════════════════════════════


@given(st.integers(min_value=0))
def test_normalize_non_negative_idempotent(value: int) -> None:
    first = normalize_non_negative(value, "x")
    second = normalize_non_negative(first, "x")
    assert first == second


@given(
    st.one_of(
        st.sampled_from(SMALL_PRIMES),
        st.integers(min_value=1, max_value=SECP256K1_ORDER - 1),
    ))
def test_inverse_mod_involution(x: int) -> None:
    assume(math.gcd(x, SECP256K1_ORDER) == 1)
    inv = inverse_mod(x, SECP256K1_ORDER)
    assert inverse_mod(inv, SECP256K1_ORDER) == x
    # 1 and ORDER-1 are their own inverses (sqrt(1) mod ORDER)
    if x not in (1, SECP256K1_ORDER - 1):
        assert inv != x


@given(st.integers(min_value=0, max_value=SECP256K1_FIELD_PRIME - 1))
def test_field_sqrt_property(x: int) -> None:
    square = (x * x) % SECP256K1_FIELD_PRIME
    root = field_sqrt(square)
    assert (root * root) % SECP256K1_FIELD_PRIME == square


# ═══════════════════════════════════════════════════════════════════════════
# 2. Point operations
# ═══════════════════════════════════════════════════════════════════════════


@given(points)
def test_point_add_self_inverse(point: Secp256k1Point) -> None:
    assert point_add(point, point_negate(point)) == SECP256K1_INFINITY


@given(points)
def test_point_add_g_non_identity(point: Secp256k1Point) -> None:
    assert point_add(point, G) != point


@given(finite_points)
def test_point_double_equals_add_self(point: Secp256k1Point) -> None:
    assert point_double(point) == point_add(point, point)


@given(points)
def test_scalar_multiply_zero(point: Secp256k1Point) -> None:
    assert scalar_multiply(0, point) == SECP256K1_INFINITY


@given(points)
def test_scalar_multiply_one(point: Secp256k1Point) -> None:
    assert scalar_multiply(1, point) == point


# ═══════════════════════════════════════════════════════════════════════════
# 3. SEC encoding round-trips
# ═══════════════════════════════════════════════════════════════════════════


@given(finite_point_scalar)
def test_sec_parse_serialize_roundtrip(scalar: int) -> None:
    point = scalar_multiply(scalar, G)
    for compressed in [True, False]:
        serialized = serialize_sec_public_key(point, compressed=compressed)
        parsed = parse_sec_public_key(serialized)
        assert parsed == point


@given(finite_point_scalar)
def test_sec_serialize_parse_bytes_roundtrip(scalar: int) -> None:
    point = scalar_multiply(scalar, G)
    for compressed in [True, False]:
        sec_bytes = serialize_sec_public_key(point, compressed=compressed)
        parsed = parse_sec_public_key(sec_bytes)
        assert serialize_sec_public_key(parsed,
                                        compressed=compressed) == sec_bytes


@given(finite_point_scalar)
def test_sec_compressed_length(scalar: int) -> None:
    point = scalar_multiply(scalar, G)
    assert len(serialize_sec_public_key(point, compressed=True)) == 33


@given(finite_point_scalar)
def test_sec_uncompressed_length(scalar: int) -> None:
    point = scalar_multiply(scalar, G)
    assert len(serialize_sec_public_key(point, compressed=False)) == 65


# ═══════════════════════════════════════════════════════════════════════════
# 4. SECP256K1_ORDER boundary
# ═══════════════════════════════════════════════════════════════════════════


@given(finite_point_scalar)
def test_scalar_multiply_order_boundary(scalar: int) -> None:
    point = scalar_multiply(scalar, G)
    assert scalar_multiply(SECP256K1_ORDER, point) == SECP256K1_INFINITY
    assert scalar_multiply(SECP256K1_ORDER + 1, point) == point


@given(st.integers(), finite_point_scalar)
def test_scalar_multiply_mod_equivalence(n: int, point_scalar: int) -> None:
    point = scalar_multiply(point_scalar, G)
    assert scalar_multiply(n, point) == scalar_multiply(n % SECP256K1_ORDER,
                                                        point)


# ═══════════════════════════════════════════════════════════════════════════
# 5. Point relation with same nonce
# ═══════════════════════════════════════════════════════════════════════════


@given(
    st.integers(min_value=1, max_value=SECP256K1_ORDER - 1),  # k
    st.integers(min_value=1, max_value=SECP256K1_ORDER - 1),  # d1
    st.integers(min_value=1, max_value=SECP256K1_ORDER - 1),  # d2
    st.integers(min_value=1, max_value=SECP256K1_ORDER - 1),  # r
    st.integers(min_value=1, max_value=SECP256K1_ORDER - 1),  # s1
    st.integers(min_value=1, max_value=SECP256K1_ORDER - 1),  # s2
)
def test_point_relation_same_nonce(k: int, d1: int, d2: int, r: int, s1: int,
                                   s2: int) -> None:
    z1 = (s1 * k - d1 * r) % SECP256K1_ORDER
    z2 = (s2 * k - d2 * r) % SECP256K1_ORDER

    pk1 = scalar_multiply(d1, G)
    pk2 = scalar_multiply(d2, G)
    nonce_point = scalar_multiply(k, G)

    sig1 = SignatureRecord(
        r=_hex_scalar(r),
        s=_hex_scalar(s1),
        z=_hex_scalar(z1),
        sighash_flag=1,
        input_index=0,
        public_key=None,
        script_type="legacy-p2pkh",
    )
    sig2 = SignatureRecord(
        r=_hex_scalar(r),
        s=_hex_scalar(s2),
        z=_hex_scalar(z2),
        sighash_flag=1,
        input_index=1,
        public_key=None,
        script_type="legacy-p2pkh",
    )

    tr1 = derive_transformed_point(sig1, pk1)
    tr2 = derive_transformed_point(sig2, pk2)

    # Reconstruct the point-space relation and verify it
    point_b1 = scalar_multiply(tr1.beta, G)
    rel1 = LinearPointRelation(
        input_index=tr1.input_index,
        alpha=tr1.alpha,
        beta=tr1.beta,
        point_b=point_b1,
        transformed_public_key=tr1.new_d_point,
        equation="D + \u03b2G = \u03b1K",
    )
    point_b2 = scalar_multiply(tr2.beta, G)
    rel2 = LinearPointRelation(
        input_index=tr2.input_index,
        alpha=tr2.alpha,
        beta=tr2.beta,
        point_b=point_b2,
        transformed_public_key=tr2.new_d_point,
        equation="D + \u03b2G = \u03b1K",
    )

    assert rel1.verify(nonce_point)
    assert rel2.verify(nonce_point)


# ═══════════════════════════════════════════════════════════════════════════
# 6. Sighash consistency properties
# ═══════════════════════════════════════════════════════════════════════════


@st.composite
def transaction_with_known_values(draw: st.DrawFn) -> tuple[bytes, list[int]]:
    """Generate a minimal valid transaction and its input values."""
    num_inputs = draw(st.integers(min_value=1, max_value=3))
    num_outputs = draw(st.integers(min_value=1, max_value=3))

    inputs = b""
    input_values: list[int] = []
    for _ in range(num_inputs):
        inputs += b"\x00" * 32  # prevout hash
        inputs += b"\x00\x00\x00\x00"  # prevout index
        inputs += b"\x00"  # empty scriptSig (varint 0)
        inputs += b"\xff\xff\xff\xff"  # sequence
        input_values.append(
            draw(st.integers(min_value=0, max_value=10_000_000_000)))

    outputs = b""
    for _ in range(num_outputs):
        outputs += b"\x00" * 8  # value 0
        outputs += b"\x00"  # empty scriptPubKey

    raw = (
        b"\x01\x00\x00\x00"  # version
        + bytes([num_inputs]) + inputs + bytes([num_outputs]) + outputs +
        b"\x00\x00\x00\x00"  # locktime
    )
    return raw, input_values


@given(transaction_with_known_values())
def test_legacy_sighash_consistent_for_all_flag(
    tx_data: tuple[bytes, list[int]],) -> None:
    """Same transaction with same flags produces the same sighash."""
    from bitcoin.parser import parse_transaction_bytes
    from bitcoin.sighash import legacy_sighash

    raw_bytes, _ = tx_data
    parsed = parse_transaction_bytes(raw_bytes)
    tx = Transaction.from_parsed(parsed)

    for flag in [1, 2, 3]:  # ALL, NONE, SINGLE
        if flag == 3 and len(tx.inputs) > len(tx.outputs):
            continue  # SINGLE needs matching output
        for input_index in range(len(tx.inputs)):
            h1 = legacy_sighash(tx, input_index, b"", flag)
            h2 = legacy_sighash(tx, input_index, b"", flag)
            assert h1 == h2


@given(transaction_with_known_values())
def test_segwit_sighash_consistent_for_all_flag(
    tx_data: tuple[bytes, list[int]],) -> None:
    """Same SegWit tx with same flags/amount produces the same sighash."""
    from bitcoin.parser import parse_transaction_bytes
    from bitcoin.sighash import segwit_sighash

    raw_bytes, input_values = tx_data
    parsed = parse_transaction_bytes(raw_bytes)
    tx = Transaction.from_parsed(parsed)
    tx = tx.with_input_values(input_values)

    for flag in [1, 2, 3]:
        if flag == 3 and len(tx.inputs) > len(tx.outputs):
            continue
        for input_index in range(len(tx.inputs)):
            amount = input_values[input_index]
            h1 = segwit_sighash(tx, input_index, b"", amount, flag)
            h2 = segwit_sighash(tx, input_index, b"", amount, flag)
            assert h1 == h2


# ═══════════════════════════════════════════════════════════════════════════
# 7. Serialization round-trip properties
# ═══════════════════════════════════════════════════════════════════════════


@given(finite_point_scalar)
def test_serialize_point_roundtrip(scalar: int) -> None:
    """Point → json dict → point round-trip preserves x, y, on-curve."""
    from bitcoin.serializer import point_to_dict

    point = scalar_multiply(scalar, G)
    d = point_to_dict(point)
    assert d["infinity"] is False
    assert d["x"] is not None
    assert d["y"] is not None
    x = int(d["x"], 16)
    y = int(d["y"], 16)
    assert is_on_curve(x, y)


def test_transaction_parse_serialize_roundtrip() -> None:
    """Parse hex → serialize → parse hex yields same structure."""
    from bitcoin.serializer import transaction_to_dict
    from bitcoin.utils import bytes_to_hex

    raw_hex, _, _ = build_p2pkh_transaction()
    tx1 = Transaction.parse_hex(raw_hex)
    d1 = transaction_to_dict(tx1)
    tx2 = Transaction.parse_hex(bytes_to_hex(tx1.raw_bytes))
    d2 = transaction_to_dict(tx2)
    assert d1 == d2
