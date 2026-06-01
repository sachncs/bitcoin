"""Top-level extraction API — re-exports ``extract_signatures``."""

from bitcoin.signature.extraction.engine import extract_signatures

__all__ = [
    "extract_signatures",
]
