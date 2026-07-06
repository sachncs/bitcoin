# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Tests for the descriptor module (miniscript parser and compiler)."""

import pytest

from bitcoin.descriptor import analyze_descriptor, compile_descriptor, extract_keys
from bitcoin.descriptor.compiler import (
    DescriptorError,
    DescriptorNode,
    parse_descriptor,
)

# ── Parser Tests ─────────────────────────────────────────────────────


class TestParseDescriptor:
    """Tests for parse_descriptor function."""

    def test_bare_pubkey(self):
        """Bare public key descriptor."""
        key = "02" + "ab" * 32
        result = parse_descriptor(key)
        assert result.op == "pk"
        assert result.args == [key]

    def test_pk_single_key(self):
        """pk() with single key."""
        key = "02" + "ab" * 32
        result = parse_descriptor(f"pk({key})")
        assert result.op == "pk"
        assert result.args == [key]

    def test_pkh_single_key(self):
        """pkh() with single key."""
        key = "02" + "ab" * 32
        result = parse_descriptor(f"pkh({key})")
        assert result.op == "pkh"
        assert result.args == [key]

    def test_nested_or(self):
        """Nested or(pk, pk) descriptor."""
        key1 = "02" + "ab" * 32
        key2 = "03" + "cd" * 32
        result = parse_descriptor(f"or(pk({key1}),pk({key2}))")
        assert result.op == "or"
        assert len(result.args) == 2
        assert isinstance(result.args[0], DescriptorNode)
        assert isinstance(result.args[1], DescriptorNode)
        assert result.args[0].op == "pk"
        assert result.args[1].op == "pk"

    def test_and_v(self):
        """and_v() descriptor."""
        key1 = "02" + "ab" * 32
        key2 = "03" + "cd" * 32
        result = parse_descriptor(f"and_v(pk({key1}),pk({key2}))")
        assert result.op == "and_v"
        assert len(result.args) == 2

    def test_sha256_hash(self):
        """sha256() with hash."""
        h = "ab" * 32
        result = parse_descriptor(f"sha256({h})")
        assert result.op == "sha256"
        assert result.args == [h]

    def test_hash160_hash(self):
        """hash160() with hash."""
        h = "ab" * 20
        result = parse_descriptor(f"hash160({h})")
        assert result.op == "hash160"
        assert result.args == [h]

    def test_older_n(self):
        """older(n) with timelock."""
        result = parse_descriptor("older(100)")
        assert result.op == "older"
        assert result.args == ["100"]

    def test_after_n(self):
        """after(n) with timelock."""
        result = parse_descriptor("after(500000)")
        assert result.op == "after"
        assert result.args == ["500000"]

    def test_empty_raises(self):
        """Empty expression raises DescriptorError."""
        with pytest.raises(DescriptorError, match="Empty descriptor"):
            parse_descriptor("")

    def test_unknown_op_raises(self):
        """Unknown operator raises DescriptorError."""
        with pytest.raises(DescriptorError, match="Unknown descriptor op"):
            parse_descriptor("unknown(arg)")

    def test_wrong_arity_raises(self):
        """Wrong number of arguments raises DescriptorError."""
        with pytest.raises(DescriptorError, match="expects 1 argument"):
            parse_descriptor("pk(a,b)")

    def test_nested_deep(self):
        """Deeply nested descriptor."""
        key1 = "02" + "ab" * 32
        key2 = "03" + "cd" * 32
        key3 = "02" + "ef" * 32
        expr = f"or(and_v(pk({key1}),pk({key2})),pk({key3}))"
        result = parse_descriptor(expr)
        assert result.op == "or"
        assert len(result.args) == 2
        assert result.args[0].op == "and_v"


# ── Compiler Tests ───────────────────────────────────────────────────


class TestCompileDescriptor:
    """Tests for compile_descriptor function."""

    def test_pk_compiles(self):
        """pk() compiles to OP_CHECKSIG."""
        key = "02" + "ab" * 32
        result = compile_descriptor(f"pk({key})")
        assert "OP_CHECKSIG" in result
        assert key in result

    def test_pkh_compiles(self):
        """pkh() compiles to standard script."""
        key = "02" + "ab" * 32
        result = compile_descriptor(f"pkh({key})")
        assert "OP_DUP" in result
        assert "OP_HASH160" in result
        assert "OP_EQUALVERIFY" in result
        assert "OP_CHECKSIG" in result

    def test_sha256_compiles(self):
        """sha256() compiles to hash check."""
        h = "ab" * 32
        result = compile_descriptor(f"sha256({h})")
        assert "OP_SHA256" in result
        assert "OP_EQUAL" in result

    def test_older_compiles(self):
        """older() compiles to CSV check."""
        result = compile_descriptor("older(100)")
        assert "OP_CHECKSEQUENCEVERIFY" in result

    def test_after_compiles(self):
        """after() compiles to CLTV check."""
        result = compile_descriptor("after(500000)")
        assert "OP_CHECKLOCKTIMEVERIFY" in result

    def test_nested_compiles(self):
        """Nested descriptor compiles correctly."""
        key1 = "02" + "ab" * 32
        key2 = "03" + "cd" * 32
        result = compile_descriptor(f"or(pk({key1}),pk({key2}))")
        assert "OP_CHECKSIG" in result


# ── Analyzer Tests ───────────────────────────────────────────────────


class TestAnalyzeDescriptor:
    """Tests for analyze_descriptor function."""

    def test_pk_analysis(self):
        """pk() analysis returns correct type."""
        key = "02" + "ab" * 32
        info = analyze_descriptor(f"pk({key})")
        assert info.script_type == "pk"
        assert key in info.keys
        assert not info.has_timelock
        assert not info.has_hash_lock
        assert info.satisfaction_bytes > 0

    def test_pkh_analysis(self):
        """pkh() analysis returns correct type."""
        key = "02" + "ab" * 32
        info = analyze_descriptor(f"pkh({key})")
        assert info.script_type == "pkh"
        assert key in info.keys

    def test_wpkh_analysis(self):
        """wpkh() analysis returns correct type."""
        key = "02" + "ab" * 32
        info = analyze_descriptor(f"wpkh({key})")
        assert info.script_type == "wpkh"
        assert key in info.keys

    def test_timelock_detection(self):
        """older() detected as timelock."""
        info = analyze_descriptor("older(100)")
        assert info.has_timelock

    def test_after_detection(self):
        """after() detected as timelock."""
        info = analyze_descriptor("after(500000)")
        assert info.has_timelock

    def test_hash_lock_detection(self):
        """sha256() detected as hash lock."""
        h = "ab" * 32
        info = analyze_descriptor(f"sha256({h})")
        assert info.has_hash_lock

    def test_nested_analysis(self):
        """Nested descriptor collects all keys."""
        key1 = "02" + "ab" * 32
        key2 = "03" + "cd" * 32
        info = analyze_descriptor(f"or(pk({key1}),pk({key2}))")
        assert info.script_type == "or"
        assert len(info.keys) == 2
        assert key1 in info.keys
        assert key2 in info.keys


# ── Extract Keys Tests ───────────────────────────────────────────────


class TestExtractKeys:
    """Tests for extract_keys function."""

    def test_extract_single_key(self):
        """Extract single key from pk()."""
        key = "02" + "ab" * 32
        keys = extract_keys(f"pk({key})")
        assert keys == [key]

    def test_extract_multiple_keys(self):
        """Extract keys from nested descriptor."""
        key1 = "02" + "ab" * 32
        key2 = "03" + "cd" * 32
        keys = extract_keys(f"or(pk({key1}),pk({key2}))")
        assert len(keys) == 2
        assert key1 in keys
        assert key2 in keys

    def test_extract_sorted_unique(self):
        """Keys are sorted and deduplicated."""
        key1 = "02" + "ab" * 32
        key2 = "03" + "cd" * 32
        keys = extract_keys(f"or(pk({key1}),pk({key2}))")
        assert keys == sorted(keys)

    def test_extract_no_keys(self):
        """Descriptor without keys returns empty list."""
        keys = extract_keys("older(100)")
        assert keys == []


# ── DescriptorNode Tests ─────────────────────────────────────────────


class TestDescriptorNode:
    """Tests for DescriptorNode dataclass."""

    def test_node_creation(self):
        """Create a DescriptorNode."""
        node = DescriptorNode(op="pk", args=["02ab"])
        assert node.op == "pk"
        assert node.args == ["02ab"]

    def test_node_equality(self):
        """Nodes are equal if op and args match."""
        node1 = DescriptorNode(op="pk", args=["02ab"])
        node2 = DescriptorNode(op="pk", args=["02ab"])
        assert node1 == node2

    def test_node_not_hashable_with_list(self):
        """Nodes with list args are not hashable (lists are mutable)."""
        node = DescriptorNode(op="pk", args=["02ab"])
        # NamedTuple with list is not hashable
        with pytest.raises(TypeError, match="unhashable type"):
            hash(node)
