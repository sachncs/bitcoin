# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""PSBT binary parsing and serialisation (BIP-174).

Implements the BIP-174 wire format:

- 5-byte magic header (``b"psbt\\xff"``).
- A *global* key-value map (mandatory: contains the unsigned
  transaction).
- One *input* key-value map per transaction input.
- One *output* key-value map per transaction output.
- ``0x00`` separator bytes between maps.

Each key-value map is a sequence of ``(key_length, key, value_length,
value)`` records terminated by a zero-length key (``0x00``).  Key
lengths are varint-prefixed; values are arbitrary bytes.

Specialised helpers:

- :func:`parse_witness_stack` / :func:`serialize_witness_stack` for
  the varint-prefixed witness item lists used by the
  ``PSBT_IN_FINAL_SCRIPTWITNESS`` field.
- :func:`parse_keypath_value` for the BIP-32 keypath blob format
  (4-byte fingerprint + varint count + ``count * 4``-byte LE uint32
  indices).

References:

- BIP-174 "Partially Signed Bitcoin Transaction Format"
"""

from __future__ import annotations

import logging

from bitcoin.encoding.varint import decode_varint, encode_varint
from bitcoin.psbt.extraction import (  # noqa: F401
    extract_pubkey_from_elements,
    psbt_extract_signatures,
)
from bitcoin.psbt.models import Psbt, PsbtInput, PsbtOutput
from bitcoin.transaction.parser import parse_tx

logger = logging.getLogger(__name__)

MAX_KEY_VALUE_MAP_ENTRIES = 10000
MAX_KEY_SIZE = 102400
MAX_VALUE_SIZE = 10_000_000
MAX_PSBT_WITNESS_ITEMS = 10000
MAX_PSBT_WITNESS_ITEM_SIZE = 10_000_000

# BIP-174 key-type identifiers.  Values 0x00–0x0B are reserved by the
# specification; unknown keys are still preserved in the ``unknown`` map.
PSBT_GLOBAL_UNSIGNED_TX = 0x00  # Global: unsigned transaction (mandatory).
PSBT_IN_NON_WITNESS_UTXO = 0x00  # Input: full non-witness UTXO (previous tx).
PSBT_IN_WITNESS_UTXO = 0x01  # Input: witness UTXO (value + scriptPubKey).
PSBT_IN_PARTIAL_SIG = 0x02  # Input: partial signature {pubkey -> sig}.
PSBT_IN_SIGHASH_TYPE = 0x03  # Input: 4-byte little-endian sighash type.
PSBT_IN_REDEEM_SCRIPT = 0x04  # Input: redeem script (for P2SH).
PSBT_IN_WITNESS_SCRIPT = 0x05  # Input: witness script (for P2WSH).
PSBT_IN_BIP32_DERIVATION = 0x06  # Input: BIP-32 derivation paths.
PSBT_IN_FINAL_SCRIPTSIG = 0x07  # Input: finalised scriptSig.
PSBT_IN_FINAL_SCRIPTWITNESS = 0x08  # Input: finalised scriptWitness.
PSBT_OUT_REDEEM_SCRIPT = 0x00  # Output: redeem script (for P2SH).
PSBT_OUT_WITNESS_SCRIPT = 0x01  # Output: witness script (for P2WSH).
PSBT_OUT_BIP32_DERIVATION = 0x02  # Output: BIP-32 derivation paths.


def parse_psbt(data: bytes | memoryview) -> Psbt:
    """Parse a PSBT from raw binary data (BIP-174).

    Args:
        data: The raw PSBT bytes (must start with ``b"psbt\\xff"``).
            Accepts ``memoryview`` for zero-copy slicing.

    Returns:
        A ``Psbt`` instance.

    Raises:
        ValueError: If the magic bytes are missing, the unsigned
            transaction is absent, or parsing otherwise fails.
    """
    if isinstance(data, memoryview):
        data = bytes(data)
    return parse_psbt_impl(data)


def parse_psbt_from_file(path: str, *, mmap_threshold: int = 100_000_000) -> Psbt:
    """Parse a PSBT from a file, optionally using memory-mapped I/O.

    For files larger than *mmap_threshold* bytes, the file is
    memory-mapped for zero-copy parsing.  Smaller files are read
    directly into memory.

    Args:
        path: Path to the PSBT file.
        mmap_threshold: Size in bytes above which to use ``mmap``
            (default 100 MB).

    Returns:
        A ``Psbt`` instance.

    Raises:
        FileNotFoundError: If *path* does not exist.
        ValueError: If the PSBT data is invalid.
    """
    import os

    size = os.path.getsize(path)
    if size > mmap_threshold:
        import mmap

        with open(path, "rb") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
                # mmap supports the buffer protocol and is indexable
                # like bytes; cast to bytes for the parser.
                return parse_psbt_impl(bytes(m))
    else:
        with open(path, "rb") as f:
            return parse_psbt_impl(f.read())


def parse_psbt_impl(data: bytes) -> Psbt:
    """Low-level PSBT parser used by the public entry points.

    Parses a complete BIP-174 PSBT starting at the magic header and
    returns the constructed :class:`Psbt`.  This function performs
    **no** I/O — the raw bytes must already be in memory — so it is
    also suitable for callers that have already loaded the PSBT (for
    instance over the network or from an in-memory cache) and want
    to share a single implementation with the file-based entry point.

    Args:
        data: The full PSBT bytes (must start with ``b"psbt\\xff"``).

    Returns:
        A :class:`Psbt` instance.

    Raises:
        ValueError: If the magic bytes are missing, the unsigned
            transaction is absent, or parsing otherwise fails.
    """
    if data[:5] != b"psbt\xff":
        raise ValueError("Invalid PSBT magic bytes.")
    offset = 5

    # Global map
    global_map, offset = parse_key_value_map(data, offset)
    unsigned_tx = global_map.get(PSBT_GLOBAL_UNSIGNED_TX)
    if unsigned_tx is None:
        raise ValueError("PSBT missing unsigned transaction.")

    # Input maps
    parsed_tx, _ = parse_tx(unsigned_tx)
    num_inputs = len(parsed_tx.inputs)
    num_outputs = len(parsed_tx.outputs)
    inputs: list[PsbtInput] = []
    for _ in range(num_inputs):
        inp_map, offset = parse_input_map(data, offset)
        inputs.append(inp_map)

    # Output maps
    outputs: list[PsbtOutput] = []
    for _ in range(num_outputs):
        out_map, offset = parse_output_map(data, offset)
        outputs.append(out_map)

    return Psbt(
        tx=unsigned_tx,
        inputs=tuple(inputs),
        outputs=tuple(outputs),
    )


def serialize_psbt(psbt: Psbt) -> bytes:
    """Serialize a ``Psbt`` to its binary wire format (BIP-174).

    Args:
        psbt: The ``Psbt`` instance to serialize.

    Returns:
        The serialized PSBT bytes.
    """
    result = bytearray(b"psbt\xff")

    # Global map
    result.extend(serialize_key_value(PSBT_GLOBAL_UNSIGNED_TX, psbt.tx, [b"\x00"]))
    result.append(0x00)  # global map separator

    # Input maps
    for inp in psbt.inputs:
        result.extend(serialize_input_map(inp))
        result.append(0x00)

    # Output maps
    for out in psbt.outputs:
        result.extend(serialize_output_map(out))
        result.append(0x00)

    return bytes(result)


# ── Internal helpers ────────────────────────────────────────────────────


def parse_key_value_map(data: bytes, offset: int) -> tuple[dict[int, bytes], int]:
    """Parse a PSBT key-value map (global, input, or output).

    Args:
        data: Raw PSBT bytes.
        offset: Starting byte offset.

    Returns:
        A tuple of ``(map_dict, new_offset)``.

    Raises:
        ValueError: If a key or value exceeds size limits or the map
            has too many entries.
    """
    result: dict[int, bytes] = {}
    count = 0
    while offset < len(data):
        if data[offset : offset + 1] == b"\x00":
            offset += 1
            break
        count += 1
        if count > MAX_KEY_VALUE_MAP_ENTRIES:
            raise ValueError(
                f"Key-value map entry count {count} exceeds maximum "
                f"{MAX_KEY_VALUE_MAP_ENTRIES}"
            )
        key_len, offset = decode_varint(data, offset)
        if key_len > MAX_KEY_SIZE:
            raise ValueError(f"Key length {key_len} exceeds maximum {MAX_KEY_SIZE}")
        key_type = data[offset]
        offset += key_len
        value_len, offset = decode_varint(data, offset)
        if value_len > MAX_VALUE_SIZE:
            raise ValueError(
                f"Value length {value_len} exceeds maximum {MAX_VALUE_SIZE}"
            )
        value = data[offset : offset + value_len]
        offset += value_len
        result[key_type] = value
    return result, offset


def serialize_key_value(key_type: int, value: bytes, key_data: list[bytes]) -> bytes:
    """Serialize a single PSBT key-value pair.

    Args:
        key_type: The key-type byte.
        value: The value bytes.
        key_data: Additional key data (each element appended to key_type).

    Returns:
        The serialized key-value bytes.
    """
    result = bytearray()
    full_key = bytes([key_type])
    for kd in key_data:
        full_key += kd
    result.extend(encode_varint(len(full_key)))
    result.extend(full_key)
    result.extend(encode_varint(len(value)))
    result.extend(value)
    return bytes(result)


def parse_input_map(data: bytes, offset: int) -> tuple[PsbtInput, int]:
    """Parse a single PSBT input map from *data* at *offset*.

    Args:
        data: Raw PSBT bytes.
        offset: Starting byte offset.

    Returns:
        A tuple of ``(PsbtInput, new_offset)``.
    """
    non_witness_utxo: bytes | None = None
    witness_utxo: bytes | None = None
    sighash_type: int | None = None
    redeem_script: bytes | None = None
    witness_script: bytes | None = None
    final_script_sig: bytes | None = None
    final_script_witness: tuple[bytes, ...] | None = None
    partial_sigs: dict[bytes, bytes] = {}
    bip32_derivations: dict[bytes, bytes] = {}
    unknown: dict[bytes, bytes] = {}

    while offset < len(data):
        if data[offset : offset + 1] == b"\x00":
            offset += 1
            break
        key_len, offset = decode_varint(data, offset)
        key_type = data[offset]
        key_data = data[offset + 1 : offset + key_len]
        offset += key_len
        value_len, offset = decode_varint(data, offset)
        value = data[offset : offset + value_len]
        offset += value_len
        if key_type == PSBT_IN_NON_WITNESS_UTXO:
            non_witness_utxo = value
        elif key_type == PSBT_IN_WITNESS_UTXO:
            witness_utxo = value
        elif key_type == PSBT_IN_SIGHASH_TYPE:
            sighash_type = int.from_bytes(value, "little")
        elif key_type == PSBT_IN_REDEEM_SCRIPT:
            redeem_script = value
        elif key_type == PSBT_IN_WITNESS_SCRIPT:
            witness_script = value
        elif key_type == PSBT_IN_FINAL_SCRIPTSIG:
            final_script_sig = value
        elif key_type == PSBT_IN_FINAL_SCRIPTWITNESS:
            final_script_witness = parse_witness_stack(value)
        elif key_type == PSBT_IN_PARTIAL_SIG:
            partial_sigs[key_data] = value
        elif key_type == PSBT_IN_BIP32_DERIVATION:
            bip32_derivations[key_data] = value
        else:
            unknown[bytes([key_type]) + key_data] = value

    inp = PsbtInput(
        non_witness_utxo=non_witness_utxo,
        witness_utxo=witness_utxo,
        sighash_type=sighash_type,
        redeem_script=redeem_script,
        witness_script=witness_script,
        final_script_sig=final_script_sig,
        final_script_witness=final_script_witness,
        partial_sigs=partial_sigs,
        bip32_derivations=bip32_derivations,
        unknown=unknown,
    )
    return inp, offset


def serialize_input_map(inp: PsbtInput) -> bytes:
    """Serialize a single PSBT input map to wire format.

    Args:
        inp: The ``PsbtInput`` to serialize.

    Returns:
        The serialized bytes.
    """
    result = bytearray()
    if inp.non_witness_utxo is not None:
        key = PSBT_IN_NON_WITNESS_UTXO
        result.extend(serialize_key_value(key, inp.non_witness_utxo, [b""]))
    if inp.witness_utxo is not None:
        key = PSBT_IN_WITNESS_UTXO
        result.extend(serialize_key_value(key, inp.witness_utxo, [b""]))
    if inp.sighash_type is not None:
        key = PSBT_IN_SIGHASH_TYPE
        result.extend(
            serialize_key_value(key, inp.sighash_type.to_bytes(4, "little"), [b""])
        )
    if inp.redeem_script is not None:
        key = PSBT_IN_REDEEM_SCRIPT
        result.extend(serialize_key_value(key, inp.redeem_script, [b""]))
    if inp.witness_script is not None:
        key = PSBT_IN_WITNESS_SCRIPT
        result.extend(serialize_key_value(key, inp.witness_script, [b""]))
    if inp.final_script_sig is not None:
        key = PSBT_IN_FINAL_SCRIPTSIG
        result.extend(serialize_key_value(key, inp.final_script_sig, [b""]))
    if inp.final_script_witness is not None:
        key = PSBT_IN_FINAL_SCRIPTWITNESS
        result.extend(
            serialize_key_value(
                key,
                serialize_witness_stack(inp.final_script_witness),
                [b""],
            )
        )
    for pubkey, sig in inp.partial_sigs.items():
        key = PSBT_IN_PARTIAL_SIG
        result.extend(serialize_key_value(key, sig, [pubkey]))
    for pubkey, path in inp.bip32_derivations.items():
        key = PSBT_IN_BIP32_DERIVATION
        result.extend(serialize_key_value(key, path, [pubkey]))
    for key_data, value in inp.unknown.items():
        key_type = key_data[0]
        extra = key_data[1:]
        result.extend(serialize_key_value(key_type, value, [extra]))
    return bytes(result)


def parse_output_map(data: bytes, offset: int) -> tuple[PsbtOutput, int]:
    """Parse a single PSBT output map from *data* at *offset*.

    Args:
        data: Raw PSBT bytes.
        offset: Starting byte offset.

    Returns:
        A tuple of ``(PsbtOutput, new_offset)``.
    """
    bip32_derivations: dict[bytes, bytes] = {}
    unknown: dict[bytes, bytes] = {}
    redeem_script: bytes | None = None
    witness_script: bytes | None = None

    while offset < len(data):
        if data[offset : offset + 1] == b"\x00":
            offset += 1
            break
        key_len, offset = decode_varint(data, offset)
        key_type = data[offset]
        key_data = data[offset + 1 : offset + key_len]
        offset += key_len
        value_len, offset = decode_varint(data, offset)
        value = data[offset : offset + value_len]
        offset += value_len
        if key_type == PSBT_OUT_REDEEM_SCRIPT:
            redeem_script = value
        elif key_type == PSBT_OUT_WITNESS_SCRIPT:
            witness_script = value
        elif key_type == PSBT_OUT_BIP32_DERIVATION:
            bip32_derivations[key_data] = value
        else:
            unknown[bytes([key_type]) + key_data] = value

    out = PsbtOutput(
        redeem_script=redeem_script,
        witness_script=witness_script,
        bip32_derivations=bip32_derivations,
        unknown=unknown,
    )
    return out, offset


def serialize_output_map(out: PsbtOutput) -> bytes:
    """Serialize a single PSBT output map to wire format.

    Args:
        out: The ``PsbtOutput`` to serialize.

    Returns:
        The serialized bytes.
    """
    result = bytearray()
    if out.redeem_script is not None:
        result.extend(
            serialize_key_value(PSBT_OUT_REDEEM_SCRIPT, out.redeem_script, [b""])
        )
    if out.witness_script is not None:
        result.extend(
            serialize_key_value(PSBT_OUT_WITNESS_SCRIPT, out.witness_script, [b""])
        )
    for pubkey, path in out.bip32_derivations.items():
        result.extend(serialize_key_value(PSBT_OUT_BIP32_DERIVATION, path, [pubkey]))
    for key_data, value in out.unknown.items():
        key_type = key_data[0]
        extra = key_data[1:]
        result.extend(serialize_key_value(key_type, value, [extra]))
    return bytes(result)


def parse_psbt_hex(hex_str: str) -> Psbt:
    """Parse a PSBT from a hexadecimal string.

    Args:
        hex_str: Hex-encoded PSBT data.

    Returns:
        A ``Psbt`` instance.
    """
    return parse_psbt(bytes.fromhex(hex_str))


def parse_keypath_value(value: bytes) -> tuple[str, tuple[str, ...]]:
    """Parse a BIP-32 keypath value from a PSBT field.

    Value format: 4-byte fingerprint + compact-size count +
    ``count * 4``-byte little-endian uint32 indices.

    Args:
        value: Raw keypath bytes.

    Returns:
        A tuple of ``(fingerprint_hex, path_tuple)`` where each path
        element is a string representation of the derivation index.
    """
    offset = 0
    fingerprint = value[offset : offset + 4].hex()
    offset += 4
    count = value[offset]
    offset += 1
    if len(value) < 5 + count * 4:
        raise ValueError(
            f"Keypath value too short: {len(value)} bytes "
            f"for {count} derivations (need {5 + count * 4})"
        )
    path: list[str] = []
    for _ in range(count):
        idx = int.from_bytes(value[offset : offset + 4], "little")
        offset += 4
        path.append(str(idx))
    return fingerprint, tuple(path)


def parse_witness_stack(data: bytes) -> tuple[bytes, ...]:
    """Parse a serialised witness stack from raw bytes.

    Args:
        data: Raw witness stack bytes (varint-prefixed items).

    Returns:
        A tuple of witness item bytes.

    Raises:
        ValueError: If the number of items or an item size exceeds limits.
    """
    offset = 0
    items: list[bytes] = []
    while offset < len(data):
        n, offset = decode_varint(data, offset)
        if n > MAX_PSBT_WITNESS_ITEM_SIZE:
            raise ValueError(
                f"Witness item size {n} exceeds maximum {MAX_PSBT_WITNESS_ITEM_SIZE}"
            )
        items.append(data[offset : offset + n])
        offset += n
        if len(items) > MAX_PSBT_WITNESS_ITEMS:
            raise ValueError(
                f"Witness item count {len(items)} exceeds maximum "
                f"{MAX_PSBT_WITNESS_ITEMS}",
            )
    return tuple(items)


def serialize_witness_stack(items: tuple[bytes, ...]) -> bytes:
    """Serialize a witness stack to wire format (varint-prefixed items).

    Args:
        items: A tuple of witness item bytes.

    Returns:
        The serialized bytes.
    """
    result = bytearray()
    for item in items:
        result.extend(encode_varint(len(item)))
        result.extend(item)
    return bytes(result)
