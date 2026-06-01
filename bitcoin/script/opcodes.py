"""Bitcoin script opcode constants and lookup dictionaries.

Provides all named OP_* constants used in Bitcoin Script, along with
``OPCODES_BY_NAME`` and ``OPCODES_BY_VALUE`` dictionaries for bidirectional
lookup by mnemonic and numeric value.
"""

OP_0 = 0x00
OP_PUSHDATA1 = 0x4C
OP_PUSHDATA2 = 0x4D
OP_PUSHDATA4 = 0x4E
OP_1 = 0x51
OP_16 = 0x60
OP_CHECKSIG = 0xAC
OP_CHECKSIGVERIFY = 0xAD
OP_CHECKMULTISIG = 0xAE
OP_CHECKMULTISIGVERIFY = 0xAF
OP_RETURN = 0x6A
OP_DUP = 0x76
OP_HASH160 = 0xA9
OP_EQUAL = 0x87
OP_EQUALVERIFY = 0x88
OP_IF = 0x63
OP_ELSE = 0x67
OP_ENDIF = 0x68
OP_NOTIF = 0x64
OP_1NEGATE = 0x4F
OP_CHECKSEQUENCEVERIFY = 0xB2
OP_CHECKLOCKTIMEVERIFY = 0xB1

OPCODES_BY_NAME: dict[str, int] = {
    name: value for name, value in globals().items() if name.startswith("OP_")
}

OPCODES_BY_VALUE: dict[int, str] = {
    value: name for name, value in OPCODES_BY_NAME.items()
}
