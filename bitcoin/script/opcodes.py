# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Bitcoin Script opcode constants and lookup dictionaries.

Provides the named ``OP_*`` constants used throughout the library,
together with the auto-generated ``OPCODES_BY_NAME`` and
``OPCODES_BY_VALUE`` dictionaries for bidirectional lookup by mnemonic
and numeric value.

Only the opcodes the library actually needs are exposed as constants
(``OP_0``, ``OP_PUSHDATA1/2/4``, ``OP_1``–``OP_16``, ``OP_CHECKSIG``,
``OP_CHECKMULTISIG``, ``OP_RETURN``, ``OP_DUP``, ``OP_HASH160``,
``OP_EQUAL``, ``OP_EQUALVERIFY``, ``OP_1NEGATE``,
``OP_CHECKSEQUENCEVERIFY``, ``OP_CHECKLOCKTIMEVERIFY``).  For full
coverage, callers should consult the Bitcoin Script specification
directly.
"""

OP_0 = 0x00
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E
OP_1 = 0x51
OP_16 = 0x60
OP_CHECKSIG = 0xAC
OP_CHECKMULTISIG = 0xAE
OP_RETURN = 0x6A
OP_DUP = 0x76
OP_HASH160 = 0xA9
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_1NEGATE = 0x4F
OP_CHECKSEQUENCEVERIFY = 0xB2
OP_CHECKLOCKTIMEVERIFY = 0xB1

OPCODES_BY_NAME: dict[str, int] = {
    name: value for name, value in globals().items() if name.startswith("OP_")
}

OPCODES_BY_VALUE: dict[int, str] = {
    value: name for name, value in OPCODES_BY_NAME.items()
}
