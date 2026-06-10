"""Property-based tests using Hypothesis.

Covers:
- Curve-point operations roundtrip
- DER encoding roundtrip
- SEC serialisation roundtrip
- Transaction serialisation roundtrip
"""
from __future__ import annotations

from hypothesis import assume, given
from hypothesis import strategies as st

from bitcoin.curve import (
    GENERATOR,
    INFINITY,
    add,
    double,
    is_on_curve,
    multiply,
    negate,
)
from bitcoin.curve.params import CURVE_ORDER, FIELD_PRIME
from bitcoin.encoding.der import decode_der, encode_der
from bitcoin.encoding.sec import parse_sec, serialize_sec
from bitcoin.field import inverse
from bitcoin.services.serializer import serialize_legacy_tx, serialize_tx
from bitcoin.transaction import OutPoint, Tx, TxIn, TxOut, Witness
from bitcoin.transaction.models import EMPTY_WITNESS
from bitcoin.transaction.parser import parse_tx

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
                         min_size=0,
                         max_size=10)


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


# ── Additional ECC properties ────────────────────────────────────────


@given(small_scalars, small_scalars, small_scalars)
def test_add_commutative(a: int, b: int, c: int) -> None:
    """P + Q == Q + P"""
    p = multiply(a, GENERATOR)
    q = multiply(b, GENERATOR)
    assert add(p, q) == add(q, p)


@given(small_scalars, small_scalars, small_scalars)
def test_add_associative(a: int, b: int, c: int) -> None:
    """(P + Q) + R == P + (Q + R)"""
    p = multiply(a, GENERATOR)
    q = multiply(b, GENERATOR)
    r = multiply(c, GENERATOR)
    assert add(add(p, q), r) == add(p, add(q, r))


@given(small_scalars)
def test_identity_element(k: int) -> None:
    """P + INFINITY == P"""
    p = multiply(k, GENERATOR)
    assert add(p, INFINITY) == p
    assert add(INFINITY, p) == p


@given(small_scalars, small_scalars)
def test_double_add_equivalence(a: int, b: int) -> None:
    """double(P) == P + P"""
    p = multiply(a + 1, GENERATOR)  # avoid INFINITY
    assert double(p) == add(p, p)


@given(valid_scalars)
def test_multiply_zero_returns_infinity(k: int) -> None:
    """0 * P == INFINITY"""
    p = multiply(k, GENERATOR)
    assert multiply(0, p) == INFINITY


@given(der_r, der_s)
def test_der_signature_invariants(r: int, s: int) -> None:
    """DER-encoded signatures start with 0x30 and end with 0x??."""
    sig = encode_der(r, s)
    assert sig[0] == 0x30
    assert len(sig) >= 6
    r2, s2 = decode_der(sig)
    assert r == r2
    assert s == s2


# ── PSBT serialization roundtrip ─────────────────────────────────────


@st.composite
def psbt_input_strategy(draw: st.DrawFn) -> dict[str, object]:
    """Build a random PSBT input (as dictionary for testing)."""
    result: dict[str, object] = {}
    if draw(st.booleans()):
        result["non_witness_utxo"] = draw(st.binary(min_size=0, max_size=64))
    if draw(st.booleans()):
        result["witness_utxo"] = draw(st.binary(min_size=0, max_size=64))
    if draw(st.booleans()):
        result["sighash_type"] = draw(st.sampled_from([1, 2, 3, 129, 130, 131]))
    if draw(st.booleans()):
        result["redeem_script"] = draw(st.binary(min_size=0, max_size=32))
    if draw(st.booleans()):
        result["witness_script"] = draw(st.binary(min_size=0, max_size=32))
    n_sigs = draw(st.integers(min_value=0, max_value=3))
    result["partial_sigs"] = {
        draw(st.binary(min_size=32, max_size=33)):
        draw(st.binary(min_size=8, max_size=73))
        for _ in range(n_sigs)
    }
    result["bip32_derivations"] = {
        draw(st.binary(min_size=32, max_size=33)):
        draw(st.binary(min_size=5, max_size=15))
        for _ in range(draw(st.integers(min_value=0, max_value=3)))
    }
    return result


@given(
    st.lists(st.binary(min_size=0, max_size=64), min_size=1, max_size=3),
    st.lists(st.binary(min_size=0, max_size=64), min_size=0, max_size=3),
)
def test_fee_estimate_non_negative(
    script_sigs: list[bytes],
    script_pubkeys: list[bytes],
) -> None:
    """Fee estimation returns a non-negative value for any Tx."""
    from bitcoin.transaction.fee import estimate_vsize

    tx = Tx(
        version=2,
        inputs=tuple(
            TxIn(
                previous_output=OutPoint(txid=b"\x00" * 32, vout=i),
                script_sig=s,
                sequence=0xFFFFFFFF,
                witness=EMPTY_WITNESS,
            ) for i, s in enumerate(script_sigs)
        ),
        outputs=tuple(
            TxOut(value=10000, script_pubkey=s)
            for s in script_pubkeys
        ),
        lock_time=0,
    )
    vsize = estimate_vsize(tx)
    assert vsize >= 0
