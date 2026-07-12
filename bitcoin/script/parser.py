# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Bitcoin Script parsing, serialisation, and decompilation.

Two parsing APIs are provided:

- :func:`parse_script_chunks` returns a list of :class:`ScriptChunk`
  objects that retain the opcode byte alongside any pushed data.  Use
  this when you need both opcode and data (e.g. for multisig analysis).
- :func:`parse_script` returns a flat list of ``(push, opcode)``
  elements, where pushes are ``bytes`` and opcodes are ``int``.  This
  is the simpler API most callers want.

Companion functions handle the inverse direction
(:func:`serialize_script`), pretty-printing (:func:`script_to_string`),
multisig redeem-script decoding (:func:`parse_multisig_redeem_script`),
and rejection of the legacy ``OP_CODESEPARATOR`` opcode
(:func:`reject_code_separators`), which this library does not model.
"""

from __future__ import annotations

from dataclasses import dataclass

from bitcoin.script.opcodes import (
    OP_0,
    OP_1,
    OP_1NEGATE,
    OP_16,
    OP_PUSHDATA1,
    OP_PUSHDATA2,
    OP_PUSHDATA4,
    OPCODES_BY_VALUE,
)

Push = bytes
Opcode = int
ScriptElement = Push | Opcode


@dataclass
class ScriptChunk:
    """One parsed script item from the chunk-based parsing API.

    Attributes:
        opcode: The opcode byte value.
        data: The associated push data, or ``None`` if this chunk
            is not a data-pushing opcode.
    """

    __slots__ = ("opcode", "data")

    opcode: int
    data: bytes | None

    @property
    def is_push(self) -> bool:
        """Whether this chunk is a data push (has associated data)."""
        return self.data is not None


def parse_script_chunks(script_bytes: bytes) -> list[ScriptChunk]:
    """Parse raw script bytes into a list of ``ScriptChunk`` objects.

    This is the original chunk-based parsing API that preserves
    ``ScriptChunk`` structures with opcode and optional data fields.

    Args:
        script_bytes: The raw script byte string.

    Returns:
        List of ``ScriptChunk`` instances parsed from the script.
    """
    chunks: list[ScriptChunk] = []
    i = 0
    while i < len(script_bytes):
        opcode = script_bytes[i]
        i += 1
        if opcode == OP_0:
            chunks.append(ScriptChunk(opcode=opcode, data=b""))
        elif opcode == OP_1NEGATE:
            chunks.append(ScriptChunk(opcode=opcode, data=None))
        elif 0x01 <= opcode <= OP_PUSHDATA1 - 1:
            push_len = opcode
            data = script_bytes[i : i + push_len]
            i += push_len
            chunks.append(ScriptChunk(opcode=opcode, data=data))
        elif opcode == OP_PUSHDATA1:
            push_len = script_bytes[i]
            i += 1
            data = script_bytes[i : i + push_len]
            i += push_len
            chunks.append(ScriptChunk(opcode=opcode, data=data))
        elif opcode == OP_PUSHDATA2:
            push_len = int.from_bytes(script_bytes[i : i + 2], "little")
            i += 2
            data = script_bytes[i : i + push_len]
            i += push_len
            chunks.append(ScriptChunk(opcode=opcode, data=data))
        elif opcode == OP_PUSHDATA4:
            push_len = int.from_bytes(script_bytes[i : i + 4], "little")
            i += 4
            data = script_bytes[i : i + push_len]
            i += push_len
            chunks.append(ScriptChunk(opcode=opcode, data=data))
        elif OP_1 <= opcode <= OP_16:
            chunks.append(ScriptChunk(opcode=opcode, data=None))
        else:
            chunks.append(ScriptChunk(opcode=opcode, data=None))
    return chunks


def chunks_to_pushes(chunks: list[ScriptChunk]) -> list[bytes]:
    """Extract pushed data items from parsed script chunks.

    Args:
        chunks: The script chunks to process.

    Returns:
        List of data bytes from chunks that represent data pushes.
    """
    return [c.data for c in chunks if c.data is not None]


def reject_code_separators(script: bytes) -> bytes:
    """Verify that no OP_CODESEPARATOR appears in the script.

    Args:
        script: The raw script bytes to check.

    Returns:
        The script unchanged if no OP_CODESEPARATOR is found.

    Raises:
        UnsupportedScriptPathError: If an OP_CODESEPARATOR is found.
    """
    for chunk in parse_script_chunks(script):
        if chunk.opcode == 0xAB and chunk.data is None:
            from bitcoin.exceptions import UnsupportedScriptPathError

            raise UnsupportedScriptPathError("OP_CODESEPARATOR is not supported.")
    return script


def parse_script(script_bytes: bytes) -> list[ScriptElement]:
    """Decompile raw script bytes into a list of pushes and opcodes.

    Each element is either ``bytes`` (a data push) or ``int`` (an opcode).
    Zero-length pushes are represented as ``b""``, and small integers
    (OP_1–OP_16) are kept as their opcode value.

    Args:
        script_bytes: The raw script byte string.

    Returns:
        List of ``ScriptElement`` instances (``bytes`` or ``int``).
    """
    elements: list[ScriptElement] = []
    i = 0
    while i < len(script_bytes):
        op = script_bytes[i]
        i += 1
        if op == OP_0:
            elements.append(b"")
        elif op == OP_1NEGATE:
            elements.append(OP_1NEGATE)
        elif 0x01 <= op <= OP_PUSHDATA1 - 1:
            push_len = op
            chunk = script_bytes[i : i + push_len]
            i += push_len
            elements.append(chunk)
        elif op == OP_PUSHDATA1:
            push_len = script_bytes[i]
            i += 1
            chunk = script_bytes[i : i + push_len]
            i += push_len
            elements.append(chunk)
        elif op == OP_PUSHDATA2:
            push_len = int.from_bytes(script_bytes[i : i + 2], "little")
            i += 2
            chunk = script_bytes[i : i + push_len]
            i += push_len
            elements.append(chunk)
        elif op == OP_PUSHDATA4:
            push_len = int.from_bytes(script_bytes[i : i + 4], "little")
            i += 4
            chunk = script_bytes[i : i + push_len]
            i += push_len
            elements.append(chunk)
        elif OP_1 <= op <= OP_16:
            elements.append(op)
        else:
            elements.append(op)
    return elements


def serialize_script(elements: list[ScriptElement]) -> bytes:
    """Compile a list of pushes/opcodes back into a script byte string.

    Encodes ``bytes`` elements using the appropriate compact push
    encoding (small integers, OP_PUSHDATA1/2/4) and writes ``int``
    elements as literal opcode bytes.

    Args:
        elements: The script elements to serialize.

    Returns:
        The serialized script bytes.

    Raises:
        TypeError: If an element is neither ``bytes`` nor ``int``.
    """
    result = bytearray()
    for elem in elements:
        if isinstance(elem, bytes):
            if len(elem) == 0:
                result.append(OP_0)
            elif len(elem) <= 75:
                result.append(len(elem))
                result.extend(elem)
            elif len(elem) <= 0xFF:
                result.append(OP_PUSHDATA1)
                result.append(len(elem))
                result.extend(elem)
            elif len(elem) <= 0xFFFF:
                result.append(OP_PUSHDATA2)
                result.extend(len(elem).to_bytes(2, "little"))
                result.extend(elem)
            else:
                result.append(OP_PUSHDATA4)
                result.extend(len(elem).to_bytes(4, "little"))
                result.extend(elem)
        elif isinstance(elem, int):
            if 0 <= elem <= 16:
                result.append(elem if elem >= 1 else OP_0)
            else:
                result.append(elem)
        else:
            raise TypeError(f"Unexpected script element type: {type(elem)}.")
    return bytes(result)


def script_to_string(elements: list[ScriptElement]) -> str:
    """Return a human-readable string representation of a script.

    Data pushes are shown in hex. Known opcodes are replaced by their
    mnemonic name (e.g. ``OP_CHECKSIG``). Unknown opcodes are shown as
    ``OP_UNKNOWN(<value>)``.

    Args:
        elements: The script elements to format.

    Returns:
        A space-separated string of human-readable script tokens.
    """
    parts: list[str] = []
    for elem in elements:
        if isinstance(elem, bytes):
            parts.append(elem.hex())
        elif elem in OPCODES_BY_VALUE:
            parts.append(OPCODES_BY_VALUE[elem])
        else:
            parts.append(f"OP_UNKNOWN({elem})")
    return " ".join(parts)


def parse_multisig_redeem_script(script: bytes) -> tuple[int, list[bytes]]:
    """Parse a multisig redeem script and return the threshold and public keys.

    Expects the standard bare multisig format:
    ``OP_m <pubkey_1> ... <pubkey_n> OP_n OP_CHECKMULTISIG`` where *m*
    and *n* are encoded as ``OP_1``–``OP_16``.

    Args:
        script: The raw multisig redeem script bytes.

    Returns:
        A tuple ``(m, pubkeys)`` where *m* is the required signature
        count and *pubkeys* is the list of public key bytes.

    Raises:
        UnsupportedScriptPathError: If the script is too short, has an
            invalid structure, uses unsupported m/n values, contains
            unexpected pubkey lengths, or has an inconsistent pubkey
            count.
    """
    chunks = parse_script_chunks(script)
    if len(chunks) < 3:
        from bitcoin.exceptions import UnsupportedScriptPathError

        raise UnsupportedScriptPathError("Multisig script is too short.")
    from bitcoin.script.opcodes import OP_CHECKSIG

    if chunks[-1].opcode != OP_CHECKSIG:
        from bitcoin.exceptions import UnsupportedScriptPathError

        raise UnsupportedScriptPathError("Multisig script is missing CHECKMULTISIG.")
    if chunks[0].data is not None or chunks[-2].data is not None:
        from bitcoin.exceptions import UnsupportedScriptPathError

        raise UnsupportedScriptPathError("Multisig script has invalid structure.")
    if not (0x51 <= chunks[0].opcode <= 0x60):
        from bitcoin.exceptions import UnsupportedScriptPathError

        raise UnsupportedScriptPathError("Multisig m value is unsupported.")
    if not (0x51 <= chunks[-2].opcode <= 0x60):
        from bitcoin.exceptions import UnsupportedScriptPathError

        raise UnsupportedScriptPathError("Multisig n value is unsupported.")

    m = chunks[0].opcode - 0x50
    n = chunks[-2].opcode - 0x50
    pubkeys = [c.data for c in chunks[1:-2] if c.data is not None]
    if len(pubkeys) != n:
        from bitcoin.exceptions import UnsupportedScriptPathError

        raise UnsupportedScriptPathError("Multisig pubkey count is inconsistent.")
    for pubkey in pubkeys:
        if len(pubkey) not in {33, 65}:
            from bitcoin.exceptions import UnsupportedScriptPathError

            raise UnsupportedScriptPathError("Unsupported multisig public key length.")
    if m < 1 or m > n:
        from bitcoin.exceptions import UnsupportedScriptPathError

        raise UnsupportedScriptPathError("Multisig threshold is invalid.")
    return m, pubkeys
