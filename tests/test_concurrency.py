# ruff: noqa: E501
"""Threading and concurrency safety tests."""
from __future__ import annotations

import threading

import pytest

from bitcoin.curve import (
    GENERATOR,
    INFINITY,
    CURVE_ORDER,
    set_backend,
    get_backend,
    multiply,
    NativeBackend,
)
from bitcoin.settings import Settings


class TestSettingsThreadSafety:

    def test_concurrent_read_write(self) -> None:
        local_settings = Settings()
        errors: list[Exception] = []

        def worker() -> None:
            try:
                local_settings.strict_mode = True
                _ = local_settings.strict_mode
                local_settings.max_extraction_inputs = 500
                _ = local_settings.max_extraction_inputs
                local_settings.default_backend = "native"
                _ = local_settings.default_backend
                local_settings.strict_mode = False
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors

    def test_settings_repr_thread_safe(self) -> None:
        local_settings = Settings()
        errors: list[Exception] = []

        def worker() -> None:
            try:
                local_settings.strict_mode = True
                _ = repr(local_settings)
                local_settings.strict_mode = False
                _ = repr(local_settings)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors


class TestBackendDispatchRaceCondition:

    def setup_method(self) -> None:
        import bitcoin.curve.dispatch as d
        d.backend = None

    def teardown_method(self) -> None:
        import bitcoin.curve.dispatch as d
        d.backend = None

    def test_set_and_get_concurrent(self) -> None:
        errors: list[Exception] = []

        def setter() -> None:
            try:
                backend = NativeBackend()
                set_backend(backend)
            except Exception as exc:
                errors.append(exc)

        def getter() -> None:
            try:
                _ = get_backend()
            except Exception as exc:
                errors.append(exc)

        threads = ([threading.Thread(target=setter) for _ in range(2)] +
                   [threading.Thread(target=getter) for _ in range(2)])
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors

    def test_resolve_backend_under_contention(self) -> None:
        from bitcoin.curve.dispatch import resolve_backend

        errors: list[Exception] = []

        def worker() -> None:
            try:
                resolved = resolve_backend()
                assert resolved is not None
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors

    def test_multiply_after_concurrent_set(self) -> None:
        errors: list[Exception] = []

        def set_and_multiply() -> None:
            try:
                backend = NativeBackend()
                set_backend(backend)
                p = multiply(2, GENERATOR)
                assert not p.infinity
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=set_and_multiply) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors


class TestMultiplyScalarNormalization:

    def setup_method(self) -> None:
        import bitcoin.curve.dispatch as d
        d.backend = None

    def teardown_method(self) -> None:
        import bitcoin.curve.dispatch as d
        d.backend = None

    def test_negative_scalar_raises(self) -> None:
        with pytest.raises(ValueError, match="non-negative"):
            multiply(-1, GENERATOR)

    def test_zero_scalar(self) -> None:
        assert multiply(0, GENERATOR) == INFINITY

    def test_one_scalar(self) -> None:
        assert multiply(1, GENERATOR) == GENERATOR

    def test_scalar_equal_curve_order(self) -> None:
        assert multiply(CURVE_ORDER, GENERATOR) == INFINITY

    def test_scalar_above_curve_order(self) -> None:
        assert multiply(CURVE_ORDER + 1, GENERATOR) == GENERATOR

    def test_large_scalar(self) -> None:
        p = multiply(CURVE_ORDER * 100 + 42, GENERATOR)
        assert not p.infinity


class TestPsbtMaxSizeLimits:

    def test_key_exceeds_max_size(self) -> None:
        from bitcoin.encoding.varint import encode_varint
        from bitcoin.psbt import parse_psbt
        from bitcoin.psbt.parser import MAX_KEY_SIZE

        magic = b"psbt\xff"
        key_len_varint = encode_varint(MAX_KEY_SIZE + 1)
        data = magic + key_len_varint

        with pytest.raises(ValueError, match="exceeds maximum"):
            parse_psbt(data)

    def test_value_exceeds_max_size(self) -> None:
        from bitcoin.encoding.varint import encode_varint
        from bitcoin.psbt import parse_psbt
        from bitcoin.psbt.parser import MAX_VALUE_SIZE

        magic = b"psbt\xff"
        data = (
            magic + encode_varint(1)  # key_len = 1
            + b"\x00"  # key_type = 0 (unsigned tx)
            + encode_varint(MAX_VALUE_SIZE + 1)  # value_len too large
        )

        with pytest.raises(ValueError, match="exceeds maximum"):
            parse_psbt(data)

    def test_max_map_entries(self) -> None:
        from bitcoin.encoding.varint import encode_varint
        from bitcoin.psbt import parse_psbt
        from bitcoin.psbt.parser import MAX_KEY_VALUE_MAP_ENTRIES

        magic = b"psbt\xff"
        entry = (
            encode_varint(1)  # key_len = 1
            + b"\x01"  # key_type
            + encode_varint(1)  # value_len = 1
            + b"\x01"  # value
        )
        data = magic + entry * (MAX_KEY_VALUE_MAP_ENTRIES + 1)

        with pytest.raises(ValueError, match="exceeds maximum"):
            parse_psbt(data)
