"""Standard script type classification for Bitcoin Script.

Provides ``classify_script_pubkey`` and ``classify_script_sig`` for
recognising standard output and spending script types, along with
constants naming each type identifier.
"""
from __future__ import annotations

from bitcoin.script.opcodes import (
    OP_0,
    OP_1,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKMULTISIG,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_DUP,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_HASH160,
    OP_RETURN,
)

# Standard script type identifiers returned by classify_script_pubkey.
P2PK = "p2pk"
P2PKH = "p2pkh"
P2SH = "p2sh"
P2WPKH = "p2wpkh"
P2WSH = "p2wsh"
P2TR = "p2tr"
NON_STANDARD = "non_standard"

# Additional script type identifiers returned by classify_detailed.
MULTISIG = "multisig"
TIMELOCK = "timelock"


def classify_script_pubkey(script: bytes) -> str:
    """Classify a scriptPubKey into a standard type.

    Args:
        script: The raw script bytes.

    Returns:
        One of ``P2PK``, ``P2PKH``, ``P2SH``, ``P2WPKH``, ``P2WSH``,
        ``P2TR``, or ``NON_STANDARD``.
    """
    if not script:
        return NON_STANDARD

    # P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if (len(script) == 25 and script[0] == OP_DUP and script[1] == OP_HASH160 and
            script[2] == 0x14 and script[23] == OP_EQUALVERIFY and
            script[24] == OP_CHECKSIG):
        return P2PKH

    # P2SH: OP_HASH160 <20 bytes> OP_EQUAL
    if (len(script) == 23 and script[0] == OP_HASH160 and script[1] == 0x14 and
            script[-1] == OP_EQUAL):
        return P2SH

    # P2WPKH: OP_0 <20 bytes>
    if (len(script) == 22 and script[0] == OP_0 and script[1] == 0x14):
        return P2WPKH

    # P2WSH: OP_0 <32 bytes>
    if (len(script) == 34 and script[0] == OP_0 and script[1] == 0x20):
        return P2WSH

    # P2TR: OP_1 <32 bytes>
    if (len(script) == 34 and script[0] == OP_1 and script[1] == 0x20):
        return P2TR

    # P2PK: <push> <pubkey> OP_CHECKSIG (simplified heuristic)
    if len(script) >= 35 and script[-1] == OP_CHECKSIG:
        pubkey_len = script[0]
        if pubkey_len in (33, 65) and len(script) == pubkey_len + 2:
            return P2PK

    return NON_STANDARD


def classify_script_sig(script: bytes) -> str:
    """Classify a scriptSig into a standard type.

    Args:
        script: The raw script bytes.

    Returns:
        ``"p2pkh"``, ``"empty"``, or ``"non_standard"``.
    """
    if not script:
        return "empty"

    # P2PKH: <sig> <pubkey>
    if len(script) > 2:
        sig_len = script[0]
        pubkey_len = script[sig_len + 1] if sig_len + 1 < len(script) else 0
        if pubkey_len in (33, 65) and len(script) == sig_len + pubkey_len + 2:
            return P2PKH

    return NON_STANDARD


def parse_p2pkh_script_sig(script: bytes) -> tuple[bytes, bytes]:
    """Extract ``(signature, public_key)`` from a P2PKH scriptSig.

    Args:
        script: Raw scriptSig bytes.

    Returns:
        ``(signature, public_key)`` as bytes.

    Raises:
        ValueError: If the script is empty or truncated.
    """
    if not script:
        raise ValueError("Empty scriptSig.")
    sig_len = script[0]
    offset = 1
    sig = script[offset:offset + sig_len]
    offset += sig_len
    if offset >= len(script):
        raise ValueError("Truncated scriptSig (missing pubkey).")
    pubkey_len = script[offset]
    offset += 1
    pubkey = script[offset:offset + pubkey_len]
    return sig, pubkey


def is_p2sh(script: bytes) -> bool:
    """Check whether *script* is a Pay-to-Script-Hash output.

    Args:
        script: The raw script bytes.

    Returns:
        ``True`` if the script is classified as P2SH.
    """
    return classify_script_pubkey(script) == P2SH


def is_op_return(script_pubkey: bytes) -> bool:
    """Check whether *script_pubkey* is an ``OP_RETURN`` output.

    Args:
        script_pubkey: The raw script bytes.

    Returns:
        ``True`` if the script starts with ``OP_RETURN`` (0x6A).
    """
    return len(script_pubkey) >= 1 and script_pubkey[0] == OP_RETURN


def is_bare_multisig(script_pubkey: bytes) -> bool:
    """Check whether *script_pubkey* is a bare multisig output.

    A bare multisig has the form
    ``OP_m <pubkey_1> ... <pubkey_k> OP_n OP_CHECKMULTISIG`` where
    ``1 <= m <= n <= 16``.

    Args:
        script_pubkey: The raw script bytes.

    Returns:
        ``True`` if the script matches the bare-multisig pattern.
    """
    if len(script_pubkey) < 37:
        return False
    if script_pubkey[0] < 0x51 or script_pubkey[0] > 0x60:
        return False
    if script_pubkey[-1] != OP_CHECKMULTISIG:
        return False
    if script_pubkey[-2] < 0x51 or script_pubkey[-2] > 0x60:
        return False
    return True


def has_timelocks(script_pubkey: bytes) -> bool:
    """Check whether *script_pubkey* contains timelock opcodes.

    Detects ``OP_CHECKLOCKTIMEVERIFY`` (0xB1) and
    ``OP_CHECKSEQUENCEVERIFY`` (0xB2).

    Args:
        script_pubkey: The raw script bytes.

    Returns:
        ``True`` if either timelock opcode is present.
    """
    return (OP_CHECKLOCKTIMEVERIFY in script_pubkey or
            OP_CHECKSEQUENCEVERIFY in script_pubkey)


def classify_detailed(script_pubkey: bytes) -> str:
    """Classify a scriptPubKey with support for additional script types.

    Tries the standard ``classify_script_pubkey`` first, then falls back
    to detecting ``OP_RETURN``, bare multisig, and timelock scripts.

    Args:
        script_pubkey: The raw script bytes.

    Returns:
        One of ``P2PK``, ``P2PKH``, ``P2SH``, ``P2WPKH``, ``P2WSH``,
        ``P2TR``, ``OP_RETURN``, ``MULTISIG``, ``TIMELOCK``, or
        ``NON_STANDARD``.
    """
    if not script_pubkey:
        return NON_STANDARD
    if is_op_return(script_pubkey):
        return "op_return"
    if is_bare_multisig(script_pubkey):
        return MULTISIG
    basic = classify_script_pubkey(script_pubkey)
    if basic != NON_STANDARD:
        return basic
    if has_timelocks(script_pubkey):
        return TIMELOCK
    return NON_STANDARD
