# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Miniscript descriptor expression compiler.

Parses descriptor expression strings such as ``"pk(A)"`` or
``"or(pk(A),pkh(B))`` into a lightweight :class:`DescriptorNode`
AST, then compiles the AST into a Bitcoin Script assembly string via
:func:`compile_descriptor`.

Internals:

- :data:`PUBKEY_PATTERN` matches 33-byte compressed (prefix ``0x02``
  / ``0x03``) or 65-byte uncompressed (prefix ``0x04``) SEC-1 public
  keys.
- :data:`COMPILER` maps each supported descriptor op to its template
  Script fragment and arity.
- :func:`split_args` parses comma-separated arguments while
  respecting nested parentheses, so ``or(pk(A),pkh(B))`` is split
  correctly at the top-level commas only.
- :func:`emit_script` recursively substitutes arguments into
  templates, falling back to positional ``<a>``, ``<b>``, ... for
  composites (``or``, ``and``, ...).

The output is an *assembly-style* string — readable but not directly
executable.  Convert it to Bitcoin Script bytes by feeding it to a
full Miniscript implementation, or use it for analysis and inspection.

Both helpers are part of the public API and are also re-exported
from :mod:`bitcoin.descriptor` for convenience.
"""

from __future__ import annotations

import re
from typing import NamedTuple

PUBKEY_PATTERN = re.compile(r"^[023][0-9a-fA-F]{65}$")


class DescriptorError(Exception):
    """Raised when a descriptor expression is invalid."""


class DescriptorNode(NamedTuple):
    """A node in the parsed descriptor AST."""

    op: str
    args: list[str | DescriptorNode]


COMPILER: dict[str, tuple[str, int]] = {
    "pk": ("<pubkey> OP_CHECKSIG", 1),  # pk(key)
    "pkh": ("OP_DUP OP_HASH160 <hash160> OP_EQUALVERIFY OP_CHECKSIG", 1),
    "wpkh": ("<hash160> OP_EQUAL", 1),  # wpkh(key) – script part
    "or": ("[IF <a> ELSE <b> ENDIF]", 2),  # or(a,b)
    "and": ("<a> OP_SWAP <b> OP_BOOLAND", 2),  # and(a,b)
    "and_v": ("<a> <b>", 2),  # and_v(a,b) – v: verify
    "or_b": ("[IF <a> NOTIF <b> ENDIF]", 2),  # or_b(a,b)
    "sha256": ("<hash> OP_SHA256 OP_EQUAL", 1),  # sha256(h)
    "hash256": ("<hash> OP_HASH256 OP_EQUAL", 1),  # hash256(h)
    "ripemd160": ("<hash> OP_RIPEMD160 OP_EQUAL", 1),  # ripemd160(h)
    "hash160": ("<hash> OP_HASH160 OP_EQUAL", 1),  # hash160(h)
    "older": ("<n> OP_CHECKSEQUENCEVERIFY", 1),  # older(n)
    "after": ("<n> OP_CHECKLOCKTIMEVERIFY", 1),  # after(n)
}


def parse_descriptor(expr: str) -> DescriptorNode:
    """Parse a descriptor expression into an AST.

    Supports nested function-style expressions:
    ``pk(03abc...)``, ``or(pk(A),pkh(B))``, etc.

    Args:
        expr: The descriptor expression string.

    Returns:
        A ``DescriptorNode`` representing the AST.

    Raises:
        DescriptorError: If the expression is malformed.
    """
    expr = expr.strip()
    if not expr:
        raise DescriptorError("Empty descriptor expression.")

    # Match the opening operator name.
    m = re.match(r"^([a-zA-Z_][a-zA-Z0-9_]*)\((.*)\)$", expr)
    if not m:
        # Single key only (bare key descriptor).
        if PUBKEY_PATTERN.match(expr):
            return DescriptorNode("pk", [expr])
        raise DescriptorError(f"Cannot parse descriptor: {expr!r}")

    op = m.group(1)
    inner = m.group(2)

    if op not in COMPILER:
        raise DescriptorError(f"Unknown descriptor op: {op!r}")

    _, arity = COMPILER[op]
    args = split_args(inner)
    if len(args) != arity:
        raise DescriptorError(f"{op} expects {arity} argument(s), got {len(args)}.")

    parsed_args: list[str | DescriptorNode] = []
    for arg in args:
        if PUBKEY_PATTERN.match(arg):
            parsed_args.append(arg)
        elif re.match(r"^[0-9]+$", arg):
            parsed_args.append(arg)
        elif re.match(r"^[0-9a-fA-F]{40,64}$", arg):
            parsed_args.append(arg)
        else:
            parsed_args.append(parse_descriptor(arg))
    return DescriptorNode(op, parsed_args)


def split_args(inner: str) -> list[str]:
    """Split a comma-separated argument list, respecting nested parens.

    Top-level commas (those outside any nested parenthesis pair)
    act as argument separators; commas inside nested expressions
    (e.g. ``or(pk(A),pkh(B))``) are preserved as part of their
    containing argument.  Each returned argument is stripped of
    surrounding whitespace.

    Args:
        inner: The text between the outer parentheses of a descriptor
            fragment (e.g. ``"pk(A),pkh(B)"``).

    Returns:
        The list of individual argument strings.
    """
    args: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in inner:
        if ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            current.append(ch)
    if current:
        args.append("".join(current).strip())
    return args


def compile_descriptor(expr: str) -> str:
    """Compile a descriptor expression to a Bitcoin Script string.

    Args:
        expr: The descriptor expression.

    Returns:
        The compiled Bitcoin Script (assembly-style string).

    Raises:
        DescriptorError: If the expression is invalid.
    """
    ast = parse_descriptor(expr)
    return emit_script(ast)


def emit_script(node: DescriptorNode) -> str:
    """Recursively render a descriptor AST as Bitcoin Script text.

    Walks the AST rooted at *node* and produces an assembly-style
    string by substituting each argument into the corresponding
    template from :data:`COMPILER`.  Unknown placeholders are
    stripped, and runs of whitespace are collapsed to single spaces
    before returning.

    Args:
        node: The descriptor AST node to render.

    Returns:
        The compiled Bitcoin Script text.
    """
    template, arity = COMPILER[node.op]
    args = node.args

    # Substitute arguments into the template.
    substituted = template
    for i, arg in enumerate(args):
        for pname in ("pubkey", "hash160", "hash", "n"):
            pat = f"<{pname}>"
            if pat in substituted:
                val = arg if isinstance(arg, str) else emit_script(arg)
                substituted = substituted.replace(pat, val, 1)
                break
        else:
            # Use positional placeholder.
            if isinstance(arg, DescriptorNode):
                arg_script = emit_script(arg)
            else:
                arg_script = arg
            if f"<{['a', 'b', 'c', 'd', 'e'][i]}>" in substituted:
                substituted = substituted.replace(
                    f"<{['a', 'b', 'c', 'd', 'e'][i]}>", arg_script, 1
                )
            else:
                substituted = substituted.replace(f"<{pname}>", arg_script, 1)

    # Clean up remaining placeholders (if any).
    substituted = re.sub(r"<[^>]+>", "", substituted)
    substituted = re.sub(r"\s+", " ", substituted).strip()
    return substituted


__all__ = [
    "DescriptorError",
    "DescriptorNode",
    "compile_descriptor",
    "emit_script",
    "parse_descriptor",
    "split_args",
]
