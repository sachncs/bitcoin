"""Pluggable secp256k1 curve backends.

Exports:
    CurveBackend: Abstract base class for curve operation backends.
"""
from bitcoin.curve.backend.base import CurveBackend

__all__ = ["CurveBackend"]
