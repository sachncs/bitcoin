# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Miniscript descriptor analysis.

Extracts public keys, determines script type, and computes
properties such as satisfaction cost from descriptor expressions.

Public API
----------

The helpers in this module were previously named with a leading
double-underscore (``__collect_info`` etc.) — a Python idiom for
"strongly private" symbols.  They are part of the library's public
surface (callable from outside the descriptor package), so they have
been promoted to plain public names (``collect_info``,
``contains_op``, ``estimate_satisfaction``, ``collect_keys``,
``sorted_unique``, and the supporting ``ESTIMATED_SATISFACTION`` table).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from bitcoin.descriptor.compiler import PUBKEY_PATTERN, DescriptorNode, parse_descriptor


@dataclass(frozen=True, slots=True)
class DescriptorInfo:
    """Analysis result for a descriptor expression.

    Attributes:
        script_type: The top-level script type (e.g. ``"pk"``,
            ``"pkh"``, ``"wpkh"``, ``"or"``, ``"and"``).
        keys: Public key hex strings found in the descriptor.
        has_timelock: Whether the descriptor includes a timelock
            (``older``/``after``).
        has_hash_lock: Whether the descriptor includes a hash lock.
        satisfaction_bytes: Estimated minimum satisfaction size in
            bytes (witness stack + scriptSig).
    """

    script_type: str
    keys: list[str] = field(default_factory=list)
    has_timelock: bool = False
    has_hash_lock: bool = False
    satisfaction_bytes: int = 0


ESTIMATED_SATISFACTION: dict[str, int] = {
    "pk": 73 + 1,  # signature + sig length
    "pkh": 73 + 33 + 2,  # sig + pubkey + lengths
    "wpkh": 73 + 33,  # sig + pubkey (witness)
    "sha256": 32 + 1,  # preimage (witness)
    "hash256": 32 + 1,
    "ripemd160": 20 + 1,
    "hash160": 20 + 1,
    "older": 0,  # just nSequence
    "after": 0,  # just nLockTime
}


def analyze_descriptor(expr: str) -> DescriptorInfo:
    """Analyze a descriptor expression and return its properties.

    Args:
        expr: The descriptor expression string.

    Returns:
        A ``DescriptorInfo`` with analysis results.

    Raises:
        DescriptorError: If the expression cannot be parsed.
    """
    from bitcoin.descriptor.compiler import DescriptorError

    try:
        ast = parse_descriptor(expr)
    except DescriptorError:
        raise

    keys: list[str] = []
    has_timelock = False
    has_hash_lock = False
    satisfaction = 0
    collect_info(ast, keys, has_timelock=has_timelock, has_hash_lock=has_hash_lock)

    satisfaction = estimate_satisfaction(ast)
    return DescriptorInfo(
        script_type=ast.op,
        keys=sorted_unique(keys),
        has_timelock=contains_op(ast, "older") or contains_op(ast, "after"),
        has_hash_lock=contains_op(ast, "sha256") or contains_op(ast, "ripemd160"),
        satisfaction_bytes=satisfaction,
    )


def collect_info(
    node: DescriptorNode,
    keys: list[str],
    has_timelock: bool,
    has_hash_lock: bool,
) -> None:
    """Walk a descriptor AST, collecting keys and feature flags.

    The function mutates *keys* in place by appending every public-key
    string it finds in the subtree.  The *has_timelock* and
    *has_hash_lock* parameters are accepted for symmetry with the
    historical signature but are no longer populated here — feature
    detection is performed separately by :func:`contains_op`.

    Args:
        node: The descriptor AST node to walk.
        keys: Output list, mutated in place with discovered keys.
        has_timelock: Accepted for API symmetry; not modified.
        has_hash_lock: Accepted for API symmetry; not modified.
    """
    for arg in node.args:
        if isinstance(arg, str) and PUBKEY_PATTERN.match(arg):
            keys.append(arg)
        elif isinstance(arg, DescriptorNode):
            collect_info(arg, keys, has_timelock, has_hash_lock)


def contains_op(node: DescriptorNode, op: str) -> bool:
    """Check whether any node in a descriptor subtree matches *op*.

    Performs a depth-first search over the AST rooted at *node* and
    returns ``True`` as soon as a node whose ``op`` field equals *op*
    is found.  Useful for detecting the presence of specific
    descriptor fragments (e.g. ``"older"``, ``"sha256"``) anywhere in
    a composite expression.

    Args:
        node: The root of the descriptor subtree to search.
        op: The descriptor op name to look for.

    Returns:
        ``True`` if *op* appears anywhere in the subtree, else
        ``False``.
    """
    if node.op == op:
        return True
    for arg in node.args:
        if isinstance(arg, DescriptorNode) and contains_op(arg, op):
            return True
    return False


def estimate_satisfaction(node: DescriptorNode) -> int:
    """Estimate the minimum satisfaction size in bytes for a descriptor.

    The estimate is a lower bound: the sum of the node's own static
    contribution (:data:`ESTIMATED_SATISFACTION[node.op]`) plus the
    recursive estimates of its child arguments.  Because the cheapest
    branch in an ``or``/``and`` composite dominates, this formula
    intentionally over-counts for composites but never under-counts.

    Args:
        node: The descriptor AST node to estimate.

    Returns:
        Estimated minimum satisfaction size in bytes.
    """
    base = ESTIMATED_SATISFACTION.get(node.op, 0)

    child_total = 0
    for arg in node.args:
        if isinstance(arg, DescriptorNode):
            child_total += estimate_satisfaction(arg)

    return base + child_total


def sorted_unique(items: list[str]) -> list[str]:
    """Return a list with duplicates removed while preserving order.

    Unlike ``sorted(set(items))``, this preserves the original
    insertion order, so repeated calls with the same input return the
    same output regardless of Python's set-hash randomisation.

    Args:
        items: The strings to deduplicate.

    Returns:
        A new list containing each distinct element of *items* in its
        first-occurrence order.
    """
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def extract_keys(expr: str) -> list[str]:
    """Extract all public key hex strings from a descriptor expression.

    Args:
        expr: The descriptor expression.

    Returns:
        A deduplicated list of hex-encoded public keys, in their
        first-occurrence order.
    """
    ast = parse_descriptor(expr)
    keys: list[str] = []
    collect_keys(ast, keys)
    return sorted_unique(keys)


def collect_keys(node: DescriptorNode, keys: list[str]) -> None:
    """Recursively collect keys from a descriptor AST.

    Appends every public-key string found in the subtree rooted at
    *node* to *keys*.  Duplicates are not removed; call
    :func:`sorted_unique` afterwards if deduplication is required.

    Args:
        node: The descriptor AST node to walk.
        keys: Output list, mutated in place with discovered keys.
    """
    for arg in node.args:
        if isinstance(arg, str) and PUBKEY_PATTERN.match(arg):
            keys.append(arg)
        elif isinstance(arg, DescriptorNode):
            collect_keys(arg, keys)


__all__ = [
    "DescriptorInfo",
    "ESTIMATED_SATISFACTION",
    "analyze_descriptor",
    "collect_info",
    "collect_keys",
    "contains_op",
    "estimate_satisfaction",
    "extract_keys",
    "sorted_unique",
]
