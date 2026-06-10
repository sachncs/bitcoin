"""Tests for the new curve/ package (Point, operations, backends)."""

import pytest

from bitcoin.curve import (
    CURVE_ORDER,
    FIELD_PRIME,
    GENERATOR,
    INFINITY,
    NativeBackend,
    Point,
    add,
    double,
    get_backend,
    is_on_curve,
    multiply,
    negate,
    set_backend,
)


class TestPoint:

    def test_creation(self) -> None:
        p = Point(x=1, y=2)
        assert p.x == 1
        assert p.y == 2
        assert not p.infinity

    def test_infinity(self) -> None:
        p = Point(infinity=True)
        assert p.infinity
        assert p.x is None
        assert p.y is None

    def test_equality(self) -> None:
        a = Point(x=1, y=2)
        b = Point(x=1, y=2)
        c = Point(x=1, y=3)
        assert a == b
        assert a != c
        assert INFINITY == Point(infinity=True)

    def test_hash(self) -> None:
        a = Point(x=1, y=2)
        b = Point(x=1, y=2)
        assert hash(a) == hash(b)

    def test_generator_on_curve(self) -> None:
        assert is_on_curve(GENERATOR)

    def test_infinity_on_curve(self) -> None:
        assert is_on_curve(INFINITY)

    def test_off_curve(self) -> None:
        p = Point(x=1, y=2)
        assert not is_on_curve(p)

    def test_invalid_field_range(self) -> None:
        with pytest.raises(ValueError, match="out of field"):
            Point(x=FIELD_PRIME + 1, y=0)

    def test_repr_infinity(self) -> None:
        assert repr(INFINITY) == "Point(infinity=True)"

    def test_repr_affine(self) -> None:
        r = repr(GENERATOR)
        assert r.startswith("Point(x=0x")


class TestPointOperations:

    def test_negate(self) -> None:
        neg = negate(GENERATOR)
        assert is_on_curve(neg)
        assert negate(neg) == GENERATOR

    def test_negate_infinity(self) -> None:
        assert negate(INFINITY) == INFINITY

    def test_add_generator_and_negation(self) -> None:
        result = add(GENERATOR, negate(GENERATOR))
        assert result == INFINITY

    def test_add_with_infinity(self) -> None:
        assert add(GENERATOR, INFINITY) == GENERATOR
        assert add(INFINITY, GENERATOR) == GENERATOR

    def test_double_generator(self) -> None:
        d = double(GENERATOR)
        assert is_on_curve(d)
        assert d != GENERATOR

    def test_double_infinity(self) -> None:
        assert double(INFINITY) == INFINITY

    def test_multiply_by_one(self) -> None:
        assert multiply(1, GENERATOR) == GENERATOR

    def test_multiply_by_zero(self) -> None:
        assert multiply(0, GENERATOR) == INFINITY

    def test_multiply_by_order(self) -> None:
        assert multiply(CURVE_ORDER, GENERATOR) == INFINITY

    def test_double_equals_add_self(self) -> None:
        assert double(GENERATOR) == add(GENERATOR, GENERATOR)


class TestPointSecRoundtrip:

    def test_compressed_roundtrip(self) -> None:
        ser = GENERATOR.to_sec_compressed()
        assert len(ser) == 33
        parsed = Point.from_sec_compressed(ser)
        assert parsed == GENERATOR

    def test_uncompressed_roundtrip(self) -> None:
        ser = GENERATOR.to_sec_uncompressed()
        assert len(ser) == 65
        parsed = Point.from_sec_uncompressed(ser)
        assert parsed == GENERATOR

    def test_compressed_prefix(self) -> None:
        ser = GENERATOR.to_sec_compressed()
        assert ser[0] in (0x02, 0x03)

    def test_invalid_sec(self) -> None:
        with pytest.raises(ValueError):
            Point.from_sec_compressed(b"\x00" * 33)
        with pytest.raises(ValueError):
            Point.from_sec_uncompressed(b"\x00" * 65)

    def test_infinity_cannot_serialize(self) -> None:
        from bitcoin.encoding.sec import serialize_sec
        with pytest.raises(ValueError, match="Cannot serialize"):
            serialize_sec(INFINITY)


class TestPointArithmetic:

    def test_arithmetic_negate(self) -> None:
        neg = GENERATOR.arithmetic.negate()
        assert neg.x == GENERATOR.x
        assert neg.y == -GENERATOR.y % FIELD_PRIME

    def test_arithmetic_add(self) -> None:
        result = GENERATOR.arithmetic.add(GENERATOR)
        assert result == double(GENERATOR)

    def test_arithmetic_double(self) -> None:
        result = GENERATOR.arithmetic.double()
        assert result == double(GENERATOR)

    def test_arithmetic_multiply(self) -> None:
        result = GENERATOR.arithmetic.multiply(2)
        assert result == double(GENERATOR)

    def test_arithmetic_multiply_by_zero(self) -> None:
        result = GENERATOR.arithmetic.multiply(0)
        assert result.infinity

    def test_arithmetic_is_on_curve(self) -> None:
        assert GENERATOR.arithmetic.is_on_curve()

    def test_arithmetic_is_on_curve_infinity(self) -> None:
        assert INFINITY.arithmetic.is_on_curve()

    def test_arithmetic_serialize_compressed(self) -> None:
        ser = GENERATOR.arithmetic.serialize(compressed=True)
        assert len(ser) == 33

    def test_arithmetic_serialize_uncompressed(self) -> None:
        ser = GENERATOR.arithmetic.serialize(compressed=False)
        assert len(ser) == 65


class TestBackendDispatch:

    def test_default_backend(self) -> None:
        assert get_backend() is None

    def test_set_backend(self) -> None:
        backend = NativeBackend()
        set_backend(backend)
        assert get_backend() is backend
        import bitcoin.curve.dispatch as d
        d.backend = None
        assert get_backend() is None

    def test_invalid_backend(self) -> None:
        with pytest.raises(TypeError):
            set_backend("invalid")  # type: ignore[arg-type]

    def test_dispatch_auto_resolve(self) -> None:
        """Dispatch functions auto-resolve backend without explicit set_backend."""
        from bitcoin.curve.dispatch import resolve_backend
        backend = resolve_backend()
        from bitcoin.curve.backend.native import NativeBackend
        assert isinstance(backend, NativeBackend)

    def test_dispatch_functions_work_without_set_backend(self) -> None:
        """Operations work with auto-resolved backend."""
        from bitcoin.curve.dispatch import add, is_on_curve, negate
        assert is_on_curve(GENERATOR)
        neg = negate(GENERATOR)
        assert add(GENERATOR, neg) == INFINITY
