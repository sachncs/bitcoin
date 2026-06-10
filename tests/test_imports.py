"""Test that the top-level public API imports correctly and has no circular deps."""

import bitcoin


def test_version_exists() -> None:
    assert hasattr(bitcoin, "__version__")


def test_core_imports() -> None:
    assert bitcoin.Point is not None
    assert bitcoin.GENERATOR is not None
    assert bitcoin.INFINITY is not None
    assert bitcoin.CURVE_ORDER is not None
    assert bitcoin.FIELD_PRIME is not None


def test_function_imports() -> None:
    assert callable(bitcoin.inverse)
    assert callable(bitcoin.sqrt)
    assert callable(bitcoin.add)
    assert callable(bitcoin.double)
    assert callable(bitcoin.multiply)
    assert callable(bitcoin.is_on_curve)
    assert callable(bitcoin.encode_der)
    assert callable(bitcoin.decode_der)
    assert callable(bitcoin.parse_sec)
    assert callable(bitcoin.serialize_sec)
    assert callable(bitcoin.parse_tx)
    assert callable(bitcoin.sighash_legacy)
    assert callable(bitcoin.extract_signatures)
    assert callable(bitcoin.linearize_signatures)
    assert callable(bitcoin.verify_sig)


def test_class_imports() -> None:
    assert bitcoin.CurveBackend is not None
    assert bitcoin.NativeBackend is not None
    assert bitcoin.Tx is not None
    assert bitcoin.TxIn is not None
    assert bitcoin.TxOut is not None
    assert bitcoin.OutPoint is not None
    assert bitcoin.Witness is not None
    assert bitcoin.Record is not None
    assert bitcoin.Psbt is not None


def test_exception_imports() -> None:
    assert bitcoin.NotInvertible is not None
    assert bitcoin.PointError is not None
    assert bitcoin.ParsingError is not None


def test_removed_exceptions_gone() -> None:
    """Verify removed exception classes no longer exist."""
    import bitcoin.exceptions

    for name in ("InvalidSignature", "InvalidDerSignature",
                 "NotInvertibleError", "InvalidLinearCoefficientError",
                 "NonInvertibleLinearCoefficientError"):
        assert not hasattr(bitcoin.exceptions,
                           name), f"{name} should have been removed"


def test_derive_linear_coefficients_import_path() -> None:
    """Verify derive_linear_coefficients imports from correct module."""
    from bitcoin.signature.linearization.coefficients import (
        LinearCoefficientCollection,
        LinearCoefficientRecord,
        derive_linear_coefficients,
    )
    assert callable(derive_linear_coefficients)
    assert LinearCoefficientCollection is not None
    assert LinearCoefficientRecord is not None


def test_attack_imports_correct() -> None:
    """Verify attack module imports from correct locations."""
    from bitcoin.signature.attack import (
        NonceReuseGroup,
        RecoveredKey,
        detect_nonce_reuse,
        recover_from_nonce_reuse,
    )
    assert RecoveredKey is not None
    assert NonceReuseGroup is not None
    assert callable(recover_from_nonce_reuse)
    assert callable(detect_nonce_reuse)


def test_signer_imports() -> None:
    """Verify signer module imports."""
    from bitcoin.signature import sign, sign_tx_input
    assert callable(sign)
    assert callable(sign_tx_input)


def test_settings_import() -> None:
    assert bitcoin.settings is not None
    assert hasattr(bitcoin.settings, "strict_mode")
    assert hasattr(bitcoin.settings, "default_backend")
    assert hasattr(bitcoin.settings, "max_extraction_inputs")


def test_no_circular_imports() -> None:
    """Import every package module and submodule explicitly."""
