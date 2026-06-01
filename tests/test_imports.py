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
    assert bitcoin.InvalidSignature is not None
    assert bitcoin.InvalidDerSignature is not None
    assert bitcoin.ParsingError is not None


def test_settings_import() -> None:
    assert bitcoin.settings is not None
    assert hasattr(bitcoin.settings, "strict_mode")
    assert hasattr(bitcoin.settings, "default_backend")
    assert hasattr(bitcoin.settings, "max_extraction_inputs")


def test_no_circular_imports() -> None:
    """Import every package module and submodule explicitly."""
    import bitcoin
    import bitcoin.field
    import bitcoin.field.modular
    import bitcoin.field.sqrt
    import bitcoin.curve
    import bitcoin.curve.params
    import bitcoin.curve.point
    import bitcoin.curve.operations
    import bitcoin.curve.backend
    import bitcoin.curve.backend.base
    import bitcoin.curve.backend.native
    import bitcoin.curve.backend.libsec
    import bitcoin.curve.dispatch
    import bitcoin.encoding
    import bitcoin.encoding.hex
    import bitcoin.encoding.binary
    import bitcoin.encoding.varint
    import bitcoin.encoding.der
    import bitcoin.encoding.sec
    import bitcoin.encoding.hasher
    import bitcoin.script
    import bitcoin.script.opcodes
    import bitcoin.script.parser
    import bitcoin.script.classifier
    import bitcoin.script.builder
    import bitcoin.transaction
    import bitcoin.transaction.models
    import bitcoin.transaction.parser
    import bitcoin.transaction.tx
    import bitcoin.sighash
    import bitcoin.sighash.flag
    import bitcoin.sighash.legacy
    import bitcoin.sighash.segwit
    import bitcoin.sighash.taproot
    import bitcoin.signature
    import bitcoin.signature.record
    import bitcoin.signature.check
    import bitcoin.signature.extraction
    import bitcoin.signature.extraction.engine
    import bitcoin.signature.linearization
    import bitcoin.signature.linearization.engine
    import bitcoin.psbt
    import bitcoin.psbt.models
    import bitcoin.psbt.parser
    import bitcoin.services
    import bitcoin.services.serializer
    import bitcoin.cli
    import bitcoin.cli.app
    import bitcoin.exceptions
    import bitcoin.settings
