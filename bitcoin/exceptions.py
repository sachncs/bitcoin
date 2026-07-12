# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Exception hierarchy for the bitcoin package.

A small tree of domain exceptions rooted at :exc:`BitcoinError`,
which itself inherits from :exc:`ValueError` so it integrates
transparently with stdlib APIs that catch value errors (e.g.
``json.loads``).

Hierarchy::

    ValueError
    └── BitcoinError
        ├── NotInvertible        # field arithmetic
        ├── PointError           # curve point failures
        ├── ParsingError         # binary wire-format parsing
        └── UnsupportedScriptPathError  # script features this
                                         # library does not implement

Callers should catch :exc:`BitcoinError` to handle every library
error in a single ``except`` clause, or the more specific subclasses
when finer-grained recovery logic is needed.
"""

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
