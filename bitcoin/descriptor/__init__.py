"""Miniscript descriptor compiler and analyzer.

Supports a subset of the Bitcoin Miniscript language for expressing
spending conditions and compiling them to Bitcoin Script or extracting
embedded public keys.
"""

from bitcoin.descriptor.analyzer import (
    analyze_descriptor,
    extract_keys,
)
from bitcoin.descriptor.compiler import (
    DescriptorError,
    compile_descriptor,
    parse_descriptor,
)

__all__ = [
    "DescriptorError",
    "analyze_descriptor",
    "compile_descriptor",
    "extract_keys",
    "parse_descriptor",
]
