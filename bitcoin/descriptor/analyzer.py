# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Miniscript descriptor analysis.

Extracts public keys, determines script type, and computes
properties such as satisfaction cost from descriptor expressions.
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


__ESTIMATED_SATISFACTION: dict[str, int] = {
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
    __collect_info(ast, keys, has_timelock=has_timelock, has_hash_lock=has_hash_lock)

    satisfaction = __estimate_satisfaction(ast)
    return DescriptorInfo(
        script_type=ast.op,
        keys=__sorted_unique(keys),
        has_timelock=__contains_op(ast, "older") or __contains_op(ast, "after"),
        has_hash_lock=__contains_op(ast, "sha256") or __contains_op(ast, "ripemd160"),
        satisfaction_bytes=satisfaction,
    )


def __collect_info(
    node: DescriptorNode,
    keys: list[str],
    has_timelock: bool,
    has_hash_lock: bool,
) -> None:
    """Collect keys and flags from an AST node (mutates in-place)."""
    for arg in node.args:
        if isinstance(arg, str) and PUBKEY_PATTERN.match(arg):
            keys.append(arg)
        elif isinstance(arg, DescriptorNode):
            __collect_info(arg, keys, has_timelock, has_hash_lock)


def __contains_op(node: DescriptorNode, op: str) -> bool:
    """Check if any subtree contains a given operation."""
    if node.op == op:
        return True
    for arg in node.args:
        if isinstance(arg, DescriptorNode) and __contains_op(arg, op):
            return True
    return False


def __estimate_satisfaction(node: DescriptorNode) -> int:
    """Estimate minimum satisfaction size in bytes."""
    base = __ESTIMATED_SATISFACTION.get(node.op, 0)

    child_total = 0
    for arg in node.args:
        if isinstance(arg, DescriptorNode):
            child_total += __estimate_satisfaction(arg)

    if node.op in ("or", "or_b"):
        return base + child_total
    if node.op in ("and", "and_v", "and_b"):
        return base + child_total
    return base + child_total


def __sorted_unique(items: list[str]) -> list[str]:
    """Return sorted, deduplicated list."""
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
        A sorted, deduplicated list of hex-encoded public keys.
    """
    ast = parse_descriptor(expr)
    keys: list[str] = []
    __collect_keys(ast, keys)
    return __sorted_unique(keys)


def __collect_keys(node: DescriptorNode, keys: list[str]) -> None:
    """Recursively collect keys from AST."""
    for arg in node.args:
        if isinstance(arg, str) and PUBKEY_PATTERN.match(arg):
            keys.append(arg)
        elif isinstance(arg, DescriptorNode):
            __collect_keys(arg, keys)


__all__ = [
    "DescriptorInfo",
    "analyze_descriptor",
    "extract_keys",
]
