"""Property-based tests using Hypothesis.

Covers:
- Curve-point operations roundtrip
- DER encoding roundtrip
- SEC serialisation roundtrip
- Transaction serialisation roundtrip
"""
from __future__ import annotations

from hypothesis import assume, given, strategies as st

from bitcoin.curve import GENERATOR, INFINITY, add, double, multiply, negate, is_on_curve
from bitcoin.curve.params import CURVE_ORDER, FIELD_PRIME
from bitcoin.curve.point import Point
from bitcoin.encoding.der import encode_der, decode_der
from bitcoin.encoding.sec import serialize_sec, parse_sec
from bitcoin.field import inverse
from bitcoin.transaction import Tx, TxIn, TxOut, OutPoint, Witness, parse_tx
from bitcoin.transaction.models import EMPTY_WITNESS
from bitcoin.services.serializer import serialize_tx, serialize_legacy_tx


# ── Strategies ────────────────────────────────────────────────────

small_scalars = st.integers(min_value=1, max_value=2**32 - 1)
field_elements = st.integers(min_value=1, max_value=FIELD_PRIME - 1)
valid_scalars = st.integers(min_value=1, max_value=CURVE_ORDER - 1)
der_r = st.integers(min_value=1, max_value=CURVE_ORDER - 1)
der_s = st.integers(min_value=1, max_value=CURVE_ORDER // 2)  # low-s only

tx_version = st.integers(min_value=1, max_value=2)
lock_time = st.integers(min_value=0, max_value=500000000)
txid_bytes = st.binary(min_size=32, max_size=32)
vout_index = st.integers(min_value=0, max_value=0xFF)
script_sig = st.binary(min_size=0, max_size=32)
sequence = st.integers(min_value=0, max_value=0xFFFFFFFF)
value = st.integers(min_value=0, max_value=21000000 * 10**8)
script_pubkey = st.binary(min_size=0, max_size=32)
witness_items = st.lists(st.binary(min_size=0, max_size=32),
                         min_size=0, max_size=10)


@st.composite
def txin_strategy(draw: st.DrawFn) -> TxIn:
    """Build a random TxIn."""
    return TxIn(
        previous_output=OutPoint(
            txid=draw(txid_bytes),
            vout=draw(vout_index),
        ),
        script_sig=draw(script_sig),
        sequence=draw(sequence),
        witness=Witness(tuple(draw(witness_items))),
    )


@st.composite
def txout_strategy(draw: st.DrawFn) -> TxOut:
    """Build a random TxOut."""
    return TxOut(
        value=draw(value),
        script_pubkey=draw(script_pubkey),
    )


@st.composite
def tx_strategy(draw: st.DrawFn) -> Tx:
    """Build a random Tx (both legacy and segwit).

    At least one input is generated to avoid ambiguous segwit marker
    detection (0 inputs + 1 output produces ``\\x00\\x01`` at offset 4,
    which mimics the SegWit marker+flag).
    """
    n_inputs = draw(st.integers(min_value=1, max_value=3))
    n_outputs = draw(st.integers(min_value=0, max_value=3))
    return Tx(
        version=draw(tx_version),
        inputs=tuple(draw(txin_strategy()) for _ in range(n_inputs)),
        outputs=tuple(draw(txout_strategy()) for _ in range(n_outputs)),
        lock_time=draw(lock_time),
    )


# ── Curve point properties ────────────────────────────────────────


@given(small_scalars)
def test_multiply_double_equals_double_add(a: int) -> None:
    """a*G + a*G == 2*(a*G) == (2a)*G"""
    p = multiply(a, GENERATOR)
    sum_p = add(p, p)
    dbl_p = double(p)
    dbl_scalar = multiply(2 * a, GENERATOR)
    assert sum_p == dbl_p
    assert dbl_p == dbl_scalar


@given(small_scalars, small_scalars)
def test_multiply_add_equals_add_multiply(a: int, b: int) -> None:
    """a*G + b*G == (a + b)*G"""
    sum_p = add(multiply(a, GENERATOR), multiply(b, GENERATOR))
    combined = multiply(a + b, GENERATOR)
    assert sum_p == combined


@given(small_scalars, small_scalars)
def test_multiply_distributive(a: int, b: int) -> None:
    """(a + b)*G == a*G + b*G"""
    left = multiply(a + b, GENERATOR)
    right = add(multiply(a, GENERATOR), multiply(b, GENERATOR))
    assert left == right


@given(valid_scalars)
def test_negate_add_returns_infinity(k: int) -> None:
    """P + (-P) == INFINITY"""
    p = multiply(k, GENERATOR)
    neg_p = negate(p)
    assert add(p, neg_p) == INFINITY


@given(small_scalars)
def test_is_on_curve(k: int) -> None:
    """k*G is always on curve"""
    p = multiply(k, GENERATOR)
    assert is_on_curve(p)
    assert not p.infinity


@given(field_elements, field_elements)
def test_inverse_roundtrip(x: int, y: int) -> None:
    """inverse(a) * a % FIELD_PRIME == 1"""
    a = (x * y) % FIELD_PRIME
    if a == 0:
        return
    inv = inverse(a, FIELD_PRIME)
    assert (a * inv) % FIELD_PRIME == 1


# ── DER encoding ──────────────────────────────────────────────────


@given(der_r, der_s)
def test_der_roundtrip(r: int, s: int) -> None:
    """encode_der(decode_der(sig)) == sig"""
    sig = encode_der(r, s)
    r2, s2 = decode_der(sig)
    assert r == r2
    assert s == s2


# ── SEC encoding ──────────────────────────────────────────────────


@given(valid_scalars)
def test_sec_compressed_roundtrip(k: int) -> None:
    """parse_sec(serialize_sec(P)) == P for compressed"""
    p = multiply(k, GENERATOR)
    serialized = serialize_sec(p)
    parsed = parse_sec(serialized)
    assert parsed == p
    assert len(serialized) == 33


@given(valid_scalars)
def test_sec_uncompressed_roundtrip(k: int) -> None:
    """parse_sec(serialize_sec(P, compressed=False)) == P for uncompressed"""
    p = multiply(k, GENERATOR)
    serialized = serialize_sec(p, compressed=False)
    parsed = parse_sec(serialized)
    assert parsed == p
    assert len(serialized) == 65


# ── Transaction serialisation ─────────────────────────────────────


@given(tx_strategy())
def test_parse_serialize_roundtrip(tx: Tx) -> None:
    """serialize ∘ parse leaves wire format unchanged (legacy)."""
    all_empty = all(w.items == () for w in (i.witness for i in tx.inputs))
    assume(not tx.is_segwit() and all_empty)
    raw = serialize_tx(tx)
    parsed, _ = parse_tx(raw)
    assert parsed == tx


@given(tx_strategy())
def test_serialize_parse_roundtrip(tx: Tx) -> None:
    """parse ∘ serialize leaves Tx object unchanged."""
    all_empty = all(w.items == () for w in (i.witness for i in tx.inputs))
    assume(not tx.is_segwit() and all_empty)
    raw = serialize_tx(tx)
    parsed, _ = parse_tx(raw)
    assert parsed.version == tx.version
    assert parsed.lock_time == tx.lock_time
    assert len(parsed.inputs) == len(tx.inputs)
    assert len(parsed.outputs) == len(tx.outputs)


@given(tx_strategy())
def test_legacy_serialize_roundtrip(tx: Tx) -> None:
    """Legacy serialization round-trips correctly (no witness)."""
    all_empty = all(w.items == () for w in (i.witness for i in tx.inputs))
    assume(not tx.is_segwit() and all_empty)
    raw = serialize_legacy_tx(tx)
    parsed, _ = parse_tx(raw)
    assert parsed == tx


@given(tx_strategy())
def test_legacy_txid_unchanged(tx: Tx) -> None:
    """Legacy txid stays the same after serialize_then_parse."""
    all_empty = all(w.items == () for w in (i.witness for i in tx.inputs))
    assume(not tx.is_segwit() and all_empty)
    orig_id = tx.txid()
    raw = serialize_tx(tx)
    parsed, _ = parse_tx(raw)
    assert parsed.txid() == orig_id
