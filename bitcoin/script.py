"""Bitcoin script parsing and classification."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from bitcoin.exceptions import ScriptParseError, UnsupportedScriptPathError
from bitcoin.utils import hash160

logger = logging.getLogger(__name__)

OPCODE_PUSH_DATA_1 = 0x4C
OPCODE_PUSH_DATA_2 = 0x4D
OPCODE_PUSH_DATA_4 = 0x4E
OPCODE_CHECK_MULTI_SIG = 0xAE
OPCODE_CHECK_SIG = 0xAC
OPCODE_CODE_SEPARATOR = 0xAB


@dataclass(frozen=True, slots=True)
class ScriptChunk:
    """Represents one parsed script item."""

    opcode: int
    data: bytes | None

    @property
    def is_push(self) -> bool:
        return self.data is not None


__all__ = [
    "OPCODE_CHECK_MULTI_SIG",
    "OPCODE_CHECK_SIG",
    "OPCODE_CODE_SEPARATOR",
    "OPCODE_PUSH_DATA_1",
    "OPCODE_PUSH_DATA_2",
    "OPCODE_PUSH_DATA_4",
    "ScriptChunk",
    "chunks_to_pushes",
    "is_p2pkh_pushes",
    "is_taproot",
    "is_taproot_script_path",
    "is_witness_program",
    "make_p2pkh_script",
    "parse_multisig_redeem_script",
    "parse_script",
    "remove_code_separators",
    "witness_program_hash_size",
]


def parse_script(script: bytes) -> tuple[ScriptChunk, ...]:
    """Parse a Bitcoin script into a tuple of chunks."""
    chunks: list[ScriptChunk] = []
    position = 0
    while position < len(script):
        opcode = script[position]
        position += 1
        if 1 <= opcode <= 75:
            end = position + opcode
            if end > len(script):
                raise ScriptParseError("Pushdata exceeds script length.")
            chunks.append(ScriptChunk(opcode=opcode, data=script[position:end]))
            position = end
            continue
        if opcode == OPCODE_PUSH_DATA_1:
            if position >= len(script):
                raise ScriptParseError("PUSHDATA1 length byte is missing.")
            length = script[position]
            position += 1
            end = position + length
            if end > len(script):
                raise ScriptParseError("PUSHDATA1 exceeds script length.")
            chunks.append(ScriptChunk(opcode=opcode, data=script[position:end]))
            position = end
            continue
        if opcode == OPCODE_PUSH_DATA_2:
            if position + 1 >= len(script):
                raise ScriptParseError("PUSHDATA2 length bytes are missing.")
            length = int.from_bytes(script[position:position + 2], "little")
            position += 2
            end = position + length
            if end > len(script):
                raise ScriptParseError("PUSHDATA2 exceeds script length.")
            chunks.append(ScriptChunk(opcode=opcode, data=script[position:end]))
            position = end
            continue
        if opcode == OPCODE_PUSH_DATA_4:
            if position + 3 >= len(script):
                raise ScriptParseError("PUSHDATA4 length bytes are missing.")
            length = int.from_bytes(script[position:position + 4], "little")
            position += 4
            end = position + length
            if end > len(script):
                raise ScriptParseError("PUSHDATA4 exceeds script length.")
            chunks.append(ScriptChunk(opcode=opcode, data=script[position:end]))
            position = end
            continue
        logger.debug("Non-push opcode 0x%02x at position %d", opcode,
                     position - 1)
        chunks.append(ScriptChunk(opcode=opcode, data=None))
    return tuple(chunks)


def chunks_to_pushes(chunks: tuple[ScriptChunk, ...]) -> list[bytes]:
    """Extract pushed data items from parsed script chunks."""
    pushes: list[bytes] = []
    for chunk in chunks:
        if chunk.data is not None:
            pushes.append(chunk.data)
    return pushes


def remove_code_separators(script: bytes) -> bytes:
    """Verify that no OP_CODESEPARATOR appears in the script."""
    for chunk in parse_script(script):
        if chunk.opcode == OPCODE_CODE_SEPARATOR and chunk.data is None:
            raise UnsupportedScriptPathError(
                "OP_CODESEPARATOR is not supported.")
    return script


def is_p2pkh_pushes(pushes: list[bytes]) -> bool:
    """Return whether the pushes match a P2PKH pattern (signature + public key)."""
    return len(pushes) == 2 and len(pushes[1]) in {33, 65}


def is_witness_program(script: bytes, version: int = 0) -> bool:
    """Return whether the script is a SegWit witness program of the given version."""
    if len(script) not in {22, 34}:
        return False
    if script[0] != version:
        return False
    if len(script) == 22:
        return script[1] == 20
    return script[1] == 32


def witness_program_hash_size(script: bytes) -> int | None:
    """Return the hash size of a witness program, or None if not a witness program."""
    if not is_witness_program(script):
        return None
    return script[1]


def is_taproot(script: bytes) -> bool:
    """Return whether the script is a Taproot output (OP_1 <32-byte push>)."""
    return len(script) == 34 and script[0] == 0x51 and script[1] == 0x20


def is_taproot_script_path(witness_items: list[bytes]) -> bool:
    """Return whether the witness stack indicates a Taproot script path spend."""
    if len(witness_items) < 2:
        return False
    if len(witness_items[-1]) >= 10000:
        return False
    script_item = witness_items[-2]
    if not script_item:
        return False
    return 0x50 <= script_item[0] <= 0x5F


def make_p2pkh_script(pubkey: bytes) -> bytes:
    """Build a P2PKH scriptPubKey from a public key."""
    digest = hash160(pubkey)
    return b"\x76\xa9\x14" + digest + b"\x88\xac"


def parse_multisig_redeem_script(script: bytes) -> tuple[int, list[bytes]]:
    """Parse a multisig redeem script, returning (m, pubkeys)."""
    chunks = parse_script(script)
    if len(chunks) < 3:
        raise UnsupportedScriptPathError("Multisig script is too short.")
    if chunks[-1].opcode != OPCODE_CHECK_MULTI_SIG:
        raise UnsupportedScriptPathError(
            "Multisig script is missing CHECKMULTISIG.")
    if chunks[0].data is not None or chunks[-2].data is not None:
        raise UnsupportedScriptPathError(
            "Multisig script has invalid structure.")
    if not (0x51 <= chunks[0].opcode <= 0x60):
        raise UnsupportedScriptPathError("Multisig m value is unsupported.")
    if not (0x51 <= chunks[-2].opcode <= 0x60):
        raise UnsupportedScriptPathError("Multisig n value is unsupported.")

    m = chunks[0].opcode - 0x50
    n = chunks[-2].opcode - 0x50
    pubkeys = [chunk.data for chunk in chunks[1:-2] if chunk.data is not None]
    if len(pubkeys) != n:
        raise UnsupportedScriptPathError(
            "Multisig pubkey count is inconsistent.")
    for pubkey in pubkeys:
        if len(pubkey) not in {33, 65}:
            raise UnsupportedScriptPathError(
                "Unsupported multisig public key length.")
    if m < 1 or m > n:
        raise UnsupportedScriptPathError("Multisig threshold is invalid.")
    return m, pubkeys
