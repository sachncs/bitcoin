"""Exception types for the bitcoin package."""


class BitcoinError(ValueError):
    """Base exception for all bitcoin package errors."""


class NotInvertible(BitcoinError):
    """Raised when a value is not invertible in the given finite field."""


class PointError(BitcoinError):
    """Raised for invalid curve-point operations."""


class InvalidSignature(BitcoinError):
    """Raised when a signature is malformed or cannot be decoded."""


class InvalidDerSignature(BitcoinError):
    """Raised specifically for malformed DER-encoded signatures."""


class ParsingError(BitcoinError):
    """Raised when binary parsing fails."""


class NotInvertibleError(BitcoinError):
    """Raised when a linear coefficient is not invertible.  Deprecated —
    prefer ``NotInvertible``."""


class InvalidLinearCoefficientError(BitcoinError):
    """Raised for invalid linear coefficients."""


class NonInvertibleLinearCoefficientError(BitcoinError):
    """Raised when a linear coefficient cannot be inverted."""


class UnsupportedScriptPathError(BitcoinError):
    """Raised when a script contains unsupported structures or features."""
