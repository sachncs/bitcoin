"""Exception types for the bitcoin package."""

__all__ = [
    "BitcoinError",
    "NotInvertible",
    "PointError",
    "ParsingError",
    "UnsupportedScriptPathError",
]


class BitcoinError(ValueError):
    """Base exception for all bitcoin package errors."""


class NotInvertible(BitcoinError):  # noqa: N818
    """Raised when a value is not invertible in the given finite field."""


class PointError(BitcoinError):
    """Raised for invalid curve-point operations."""


class ParsingError(BitcoinError):
    """Raised when binary parsing fails."""


class UnsupportedScriptPathError(BitcoinError):
    """Raised when a script contains unsupported structures or features."""
