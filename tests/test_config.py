"""Tests for the Settings singleton."""
from __future__ import annotations

import pytest

from bitcoin.settings import Settings, settings


def test_defaults() -> None:
    assert settings.strict_mode is False
    assert settings.default_backend is None
    assert settings.max_extraction_inputs == 100_000


def test_strict_mode_toggle() -> None:
    s = Settings()
    assert s.strict_mode is False
    s.strict_mode = True
    assert s.strict_mode is True
    s.strict_mode = False
    assert s.strict_mode is False


def test_default_backend() -> None:
    s = Settings()
    s.default_backend = "native"
    assert s.default_backend == "native"
    s.default_backend = "libsecp"
    assert s.default_backend == "libsecp"
    s.default_backend = None
    assert s.default_backend is None


def test_default_backend_invalid() -> None:
    s = Settings()
    with pytest.raises(ValueError, match="default_backend"):
        s.default_backend = "invalid"


def test_max_extraction_inputs() -> None:
    s = Settings()
    assert s.max_extraction_inputs == 100_000
    s.max_extraction_inputs = 1
    assert s.max_extraction_inputs == 1
    s.max_extraction_inputs = 500
    assert s.max_extraction_inputs == 500


def test_max_extraction_inputs_invalid() -> None:
    s = Settings()
    with pytest.raises(ValueError, match="max_extraction_inputs"):
        s.max_extraction_inputs = 0


def test_repr() -> None:
    s = Settings()
    r = repr(s)
    assert "strict_mode" in r
    assert "default_backend" in r
    assert "max_extraction_inputs" in r
