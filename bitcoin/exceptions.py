"""Exception types for Bitcoin parsing and extraction."""

from __future__ import annotations

__all__ = [
    "BitcoinError",
    "InvalidDerSignatureError",
    "InvalidHexError",
    "InvalidLinearCoefficientError",
    "InvalidSecPublicKeyError",
    "InvalidSecp256k1PointError",
    "InvalidSighashFlagError",
    "LinearCoefficientError",
    "MalformedVarintError",
    "MissingInputValueError",
    "NonInvertibleLinearCoefficientError",
    "ScriptParseError",
    "TruncatedTransactionError",
    "UnsupportedScriptPathError",
    "UnsupportedTransactionError",
]


class BitcoinError(Exception):
    """Base class for Bitcoin package errors."""


class InvalidHexError(BitcoinError):
    """Raised when a transaction hex string is malformed."""


class TruncatedTransactionError(BitcoinError):
    """Raised when transaction bytes end unexpectedly."""


class MalformedVarintError(BitcoinError):
    """Raised when a compact size integer is invalid."""


class UnsupportedTransactionError(BitcoinError):
    """Raised when a transaction uses an unsupported structure."""


class UnsupportedScriptPathError(BitcoinError):
    """Raised when a transaction uses an unsupported script path."""


class InvalidDerSignatureError(BitcoinError):
    """Raised when a signature does not satisfy strict DER rules."""


class InvalidSighashFlagError(BitcoinError):
    """Raised when a signature hash flag is unsupported."""


class MissingInputValueError(BitcoinError):
    """Raised when SegWit extraction needs an input value that is unavailable."""


class ScriptParseError(BitcoinError):
    """Raised when a script cannot be parsed safely."""


class LinearCoefficientError(BitcoinError):
    """Raised when linear coefficient derivation fails."""


class InvalidLinearCoefficientError(LinearCoefficientError):
    """Raised when a signature value is invalid for linearization."""


class NonInvertibleLinearCoefficientError(LinearCoefficientError):
    """Raised when a coefficient has no modular inverse."""


class InvalidSecp256k1PointError(BitcoinError):
    """Raised when a secp256k1 point or SEC encoding is invalid."""


class InvalidSecPublicKeyError(InvalidSecp256k1PointError):
    """Raised when SEC public key parsing or serialization fails."""
