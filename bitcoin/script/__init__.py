# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Bitcoin Script parsing, classification, building, and Taproot helpers.

This subpackage owns every aspect of Bitcoin Script that the rest of
the library needs:

- :mod:`bitcoin.script.opcodes` – the small subset of opcodes used by
  the classifiers and builders, plus the ``OPCODES_BY_NAME`` /
  ``OPCODES_BY_VALUE`` lookup dicts.
- :mod:`bitcoin.script.parser` – low-level parsing of raw script bytes
  into :class:`ScriptChunk` or flat ``(push, opcode)`` element lists,
  plus decompilation to a human-readable string and multisig redeem
  script decoding.
- :mod:`bitcoin.script.classifier` – pattern-matching helpers that
  identify standard output (P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR)
  and spending (scriptSig) script types, and detect OP_RETURN,
  multisig, and timelock scripts.
- :mod:`bitcoin.script.builder` – :func:`build_p2pk`,
  :func:`build_p2pkh`, :func:`build_p2wpkh`, :func:`build_p2wsh`,
  :func:`build_p2sh`, :func:`build_p2tr`, :func:`make_p2pkh_script`
  constructors.
- :mod:`bitcoin.script.taproot` – Taproot control-block parsing,
  tapleaf-hash and tweak computation, script-path witness parsing,
  and x-only public-key extraction.

Public re-exports of the most useful names are kept here so callers
can ``from bitcoin.script import classify_script_pubkey`` without
reaching into a submodule.
"""

from bitcoin.script.builder import (
    build_p2pk,
    build_p2pkh,
    build_p2sh,
    build_p2tr,
    build_p2wpkh,
    build_p2wsh,
    make_p2pkh_script,
)
from bitcoin.script.classifier import (
    MULTISIG,
    NON_STANDARD,
    P2PK,
    P2PKH,
    P2SH,
    P2TR,
    P2WPKH,
    P2WSH,
    TIMELOCK,
    classify_detailed,
    classify_script_pubkey,
    classify_script_sig,
    has_timelocks,
    is_bare_multisig,
    is_op_return,
)
from bitcoin.script.opcodes import (
    OP_0,
    OP_1,
    OP_1NEGATE,
    OP_16,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_PUSHDATA1,
    OP_PUSHDATA2,
    OP_PUSHDATA4,
    OP_RETURN,
    OPCODES_BY_NAME,
    OPCODES_BY_VALUE,
)
from bitcoin.script.parser import (
    Opcode,
    Push,
    ScriptChunk,
    ScriptElement,
    parse_multisig_redeem_script,
    reject_code_separators,
    script_to_string,
    serialize_script,
)
from bitcoin.script.parser import parse_script_chunks as parse_script
from bitcoin.script.taproot import (
    TaprootControlBlock,
    TaprootScriptPath,
    compute_tapleaf_hash,
    compute_tweak,
    get_key_path_signature,
    get_x_only_pubkey,
    is_key_path_spend,
    is_valid_leaf_version,
    parse_control_block,
    parse_taproot_witness_stack,
)

__all__ = [
    "MULTISIG",
    "NON_STANDARD",
    "OP_0",
    "OP_1",
    "OP_16",
    "OP_1NEGATE",
    "OP_CHECKSIG",
    "OP_CHECKLOCKTIMEVERIFY",
    "OP_CHECKMULTISIG",
    "OP_CHECKSEQUENCEVERIFY",
    "OP_DUP",
    "OP_EQUAL",
    "OP_EQUALVERIFY",
    "OP_HASH160",
    "OP_PUSHDATA1",
    "OP_PUSHDATA2",
    "OP_PUSHDATA4",
    "OP_RETURN",
    "OPCODES_BY_NAME",
    "OPCODES_BY_VALUE",
    "Opcode",
    "P2PK",
    "P2PKH",
    "P2SH",
    "P2TR",
    "P2WPKH",
    "P2WSH",
    "Push",
    "ScriptChunk",
    "ScriptElement",
    "TaprootControlBlock",
    "TaprootScriptPath",
    "compute_tapleaf_hash",
    "compute_tweak",
    "get_key_path_signature",
    "get_x_only_pubkey",
    "is_key_path_spend",
    "is_valid_leaf_version",
    "parse_control_block",
    "parse_taproot_witness_stack",
    "TIMELOCK",
    "build_p2pk",
    "build_p2pkh",
    "build_p2sh",
    "build_p2tr",
    "build_p2wpkh",
    "build_p2wsh",
    "classify_detailed",
    "classify_script_pubkey",
    "classify_script_sig",
    "has_timelocks",
    "is_bare_multisig",
    "is_op_return",
    "make_p2pkh_script",
    "parse_multisig_redeem_script",
    "parse_script",
    "reject_code_separators",
    "script_to_string",
    "serialize_script",
]
