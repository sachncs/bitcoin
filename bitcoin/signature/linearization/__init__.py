"""Top-level linearization API — re-exports ``linearize_signatures``."""

from bitcoin.signature.linearization.engine import linearize_signatures

__all__ = [
    "linearize_signatures",
]
