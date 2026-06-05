"""Tests for the health module."""
from __future__ import annotations

from unittest.mock import patch

from bitcoin.health import health, check_backend, check_imports


class TestHealth:
    def test_health_returns_dict(self) -> None:
        result = health()
        assert isinstance(result, dict)
        assert "version" in result
        assert "imports" in result
        assert "backends" in result
        assert "curve_operation" in result

    def test_health_version(self) -> None:
        result = health()
        assert isinstance(result["version"], str)
        assert result["version"] == "0.4.0"

    def test_health_curve_operation_ok(self) -> None:
        result = health()
        curve_op = result["curve_operation"]
        assert isinstance(curve_op, dict)
        assert curve_op["ok"] is True

    def test_health_imports_all_true(self) -> None:
        result = health()
        imports = result["imports"]
        assert isinstance(imports, dict)
        for mod, ok in imports.items():
            assert ok, f"Module {mod} failed to import"

    def test_health_curve_operation_failure(self) -> None:
        with patch("bitcoin.curve.multiply", side_effect=RuntimeError("boom")):
            result = health()
            assert not result["curve_operation"]["ok"]
            assert "boom" in result["curve_operation"]["error"]


class TestCheckBackend:
    def test_returns_dict(self) -> None:
        result = check_backend()
        assert isinstance(result, dict)

    def test_native_backend_available(self) -> None:
        result = check_backend()
        assert "native" in result
        assert result["native"]["available"] is True
        assert result["native"]["multiply"] is True

    def test_libsecp_backend_entry(self) -> None:
        result = check_backend()
        assert "libsecp256k1" in result
        entry = result["libsecp256k1"]
        assert "available" in entry

    def test_native_backend_failure(self) -> None:
        with patch("bitcoin.curve.backend.native.NativeBackend",
                   side_effect=RuntimeError("fail")):
            result = check_backend()
            assert not result["native"]["available"]
            assert "fail" in result["native"]["error"]

    def test_libsecp_backend_failure(self) -> None:
        with patch("bitcoin.curve.backend.libsec.LibsecpBackend",
                   side_effect=RuntimeError("fail")):
            result = check_backend()
            assert not result["libsecp256k1"]["available"]
            assert "fail" in result["libsecp256k1"]["error"]


class TestCheckImports:
    def test_returns_dict_of_bools(self) -> None:
        result = check_imports()
        assert isinstance(result, dict)
        for mod, ok in result.items():
            assert isinstance(ok, bool)

    def test_all_modules_import(self) -> None:
        result = check_imports()
        for mod, ok in result.items():
            assert ok, f"Module {mod} could not be imported"

    def test_expected_modules_present(self) -> None:
        result = check_imports()
        expected = [
            "bitcoin.curve",
            "bitcoin.encoding",
            "bitcoin.field",
            "bitcoin.script",
            "bitcoin.transaction",
            "bitcoin.psbt",
            "bitcoin.services",
            "bitcoin.cli",
        ]
        for mod in expected:
            assert mod in result

    def test_import_failure(self) -> None:
        with patch("bitcoin.health.importlib.import_module",
                   side_effect=ImportError("no such module")):
            result = check_imports()
            for mod, ok in result.items():
                assert not ok
