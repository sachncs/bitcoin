# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Miniscript descriptor compiler and analyzer.

Supports a subset of the Bitcoin Miniscript language (see
https://bitcoin.sipa.be/miniscript/) for expressing spending
conditions and converting them to:

- **Bitcoin Script** – :func:`compile_descriptor` from
  :mod:`bitcoin.descriptor.compiler` produces an assembly-style string
  with placeholders for keys and hashes.  The internal helpers
  :func:`split_args` and :func:`emit_script` are also re-exported for
  callers that want to drive the compiler from a pre-parsed AST.
- **Structured analysis** – :func:`analyze_descriptor` from
  :mod:`bitcoin.descriptor.analyzer` extracts the script type, public
  keys, timelock / hash-lock flags, and an estimate of the minimum
  satisfaction size.  The internal helpers :func:`collect_info`,
  :func:`collect_keys`, :func:`contains_op`, :func:`estimate_satisfaction`,
  and :func:`sorted_unique` are re-exported for callers analysing
  descriptor ASTs directly.

The two submodules share a common AST node (:class:`DescriptorNode`)
returned by :func:`parse_descriptor`, which is also re-exported here.

Limitations: the supported fragment set is a subset of Miniscript
(``pk``, ``pkh``, ``wpkh``, ``or`` / ``or_b``, ``and`` /
``and_v`` / ``and_b``, ``sha256``, ``hash256``, ``ripemd160``,
``hash160``, ``older``, ``after``).  Sufficient for the common
descriptor patterns used in production wallets, but not a full
Miniscript implementation.
"""

from bitcoin.descriptor.analyzer import (
    ESTIMATED_SATISFACTION,
    DescriptorInfo,
    analyze_descriptor,
    collect_info,
    collect_keys,
    contains_op,
    estimate_satisfaction,
    extract_keys,
    sorted_unique,
)
from bitcoin.descriptor.compiler import (
    DescriptorError,
    DescriptorNode,
    compile_descriptor,
    emit_script,
    parse_descriptor,
    split_args,
)

__all__ = [
    "DescriptorError",
    "DescriptorInfo",
    "DescriptorNode",
    "ESTIMATED_SATISFACTION",
    "analyze_descriptor",
    "collect_info",
    "collect_keys",
    "compile_descriptor",
    "contains_op",
    "emit_script",
    "estimate_satisfaction",
    "extract_keys",
    "parse_descriptor",
    "sorted_unique",
    "split_args",
]
