"""PSBT binary parsing and serialization (BIP-174)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Dict, Sequence, Tuple

if TYPE_CHECKING:
    from bitcoin.signature.collection import SignatureCollection
    from bitcoin.curve.point import Point

from bitcoin.encoding.varint import decode_varint, encode_varint
from bitcoin.psbt.models import Psbt, PsbtInput, PsbtOutput
from bitcoin.transaction.parser import parse_tx

logger = logging.getLogger(__name__)

MAX_KEY_VALUE_MAP_ENTRIES = 10000

# Key type constants (BIP-174)
PSBT_GLOBAL_UNSIGNED_TX = 0x00  #: Global: unsigned transaction.
PSBT_IN_NON_WITNESS_UTXO = 0x00  #: Input: non-witness UTXO.
PSBT_IN_WITNESS_UTXO = 0x01  #: Input: witness UTXO.
PSBT_IN_PARTIAL_SIG = 0x02  #: Input: partial signature.
PSBT_IN_SIGHASH_TYPE = 0x03  #: Input: sighash type.
PSBT_IN_REDEEM_SCRIPT = 0x04  #: Input: redeem script.
PSBT_IN_WITNESS_SCRIPT = 0x05  #: Input: witness script.
PSBT_IN_BIP32_DERIVATION = 0x06  #: Input: BIP-32 derivation.
PSBT_IN_FINAL_SCRIPTSIG = 0x07  #: Input: final scriptSig.
PSBT_IN_FINAL_SCRIPTWITNESS = 0x08  #: Input: final scriptWitness.
PSBT_OUT_REDEEM_SCRIPT = 0x00  #: Output: redeem script.
PSBT_OUT_WITNESS_SCRIPT = 0x01  #: Output: witness script.
PSBT_OUT_BIP32_DERIVATION = 0x02  #: Output: BIP-32 derivation.


def parse_psbt(data: bytes) -> Psbt:
    """Parse a PSBT from raw binary data (BIP-174).

    Args:
        data: The raw PSBT bytes (must start with ``b"psbt\\xff"``).

    Returns:
        A ``Psbt`` instance.

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
    result.extend(
        serialize_key_value(PSBT_GLOBAL_UNSIGNED_TX, psbt.tx, [b"\x00"]))
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


def parse_key_value_map(data: bytes,
                          offset: int) -> Tuple[Dict[int, bytes], int]:
    """Parse a PSBT key-value map (global, input, or output).

    Args:
        data: Raw PSBT bytes.
        offset: Starting byte offset.

    Returns:
        A tuple of ``(map_dict, new_offset)``.
    """
    result: Dict[int, bytes] = {}
    count = 0
    while offset < len(data):
        if data[offset:offset + 1] == b"\x00":
            offset += 1
            break
        count += 1
        if count > MAX_KEY_VALUE_MAP_ENTRIES:
            raise ValueError(
                f"Key-value map entry count {count} exceeds maximum "
                f"{MAX_KEY_VALUE_MAP_ENTRIES}")
        key_len, offset = decode_varint(data, offset)
        key_type = data[offset]
        key_data = data[offset:offset + key_len]
        offset += key_len
        value_len, offset = decode_varint(data, offset)
        value = data[offset:offset + value_len]
        offset += value_len
        result[key_type] = value
    return result, offset


def serialize_key_value(key_type: int, value: bytes,
                          key_data: list[bytes]) -> bytes:
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


def parse_input_map(data: bytes, offset: int) -> Tuple[PsbtInput, int]:
    """Parse a single PSBT input map from *data* at *offset*.

    Args:
        data: Raw PSBT bytes.
        offset: Starting byte offset.

    Returns:
        A tuple of ``(PsbtInput, new_offset)``.
    """
    inp = PsbtInput()
    while offset < len(data):
        if data[offset:offset + 1] == b"\x00":
            offset += 1
            break
        key_len, offset = decode_varint(data, offset)
        key_type = data[offset]
        key_data = data[offset + 1:offset + key_len]
        offset += key_len
        value_len, offset = decode_varint(data, offset)
        value = data[offset:offset + value_len]
        offset += value_len
        if key_type == PSBT_IN_NON_WITNESS_UTXO:
            object.__setattr__(inp, "non_witness_utxo", value)
        elif key_type == PSBT_IN_WITNESS_UTXO:
            object.__setattr__(inp, "witness_utxo", value)
        elif key_type == PSBT_IN_SIGHASH_TYPE:
            object.__setattr__(inp, "sighash_type",
                               int.from_bytes(value, "little"))
        elif key_type == PSBT_IN_REDEEM_SCRIPT:
            object.__setattr__(inp, "redeem_script", value)
        elif key_type == PSBT_IN_WITNESS_SCRIPT:
            object.__setattr__(inp, "witness_script", value)
        elif key_type == PSBT_IN_FINAL_SCRIPTSIG:
            object.__setattr__(inp, "final_script_sig", value)
        elif key_type == PSBT_IN_FINAL_SCRIPTWITNESS:
            object.__setattr__(inp, "final_script_witness",
                               parse_witness_stack(value))
        elif key_type == PSBT_IN_PARTIAL_SIG:
            dict.__setitem__(inp.partial_sigs, key_data, value)
        elif key_type == PSBT_IN_BIP32_DERIVATION:
            dict.__setitem__(inp.bip32_derivations, key_data, value)
        else:
            dict.__setitem__(inp.unknown, bytes([key_type]) + key_data, value)
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
            serialize_key_value(key, inp.sighash_type.to_bytes(4, "little"),
                                  [b""]))
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
            serialize_key_value(key, serialize_witness_stack(inp.final_script_witness), [b""]))
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


def parse_output_map(data: bytes, offset: int) -> Tuple[PsbtOutput, int]:
    """Parse a single PSBT output map from *data* at *offset*.

    Args:
        data: Raw PSBT bytes.
        offset: Starting byte offset.

    Returns:
        A tuple of ``(PsbtOutput, new_offset)``.
    """
    out = PsbtOutput()
    while offset < len(data):
        if data[offset:offset + 1] == b"\x00":
            offset += 1
            break
        key_len, offset = decode_varint(data, offset)
        key_type = data[offset]
        key_data = data[offset + 1:offset + key_len]
        offset += key_len
        value_len, offset = decode_varint(data, offset)
        value = data[offset:offset + value_len]
        offset += value_len
        if key_type == PSBT_OUT_REDEEM_SCRIPT:
            object.__setattr__(out, "redeem_script", value)
        elif key_type == PSBT_OUT_WITNESS_SCRIPT:
            object.__setattr__(out, "witness_script", value)
        elif key_type == PSBT_OUT_BIP32_DERIVATION:
            dict.__setitem__(out.bip32_derivations, key_data, value)
        else:
            dict.__setitem__(out.unknown, bytes([key_type]) + key_data, value)
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
            serialize_key_value(PSBT_OUT_REDEEM_SCRIPT, out.redeem_script,
                                  [b""]))
    if out.witness_script is not None:
        result.extend(
            serialize_key_value(PSBT_OUT_WITNESS_SCRIPT, out.witness_script,
                                  [b""]))
    for pubkey, path in out.bip32_derivations.items():
        result.extend(
            serialize_key_value(PSBT_OUT_BIP32_DERIVATION, path, [pubkey]))
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
    fingerprint = value[offset:offset + 4].hex()
    offset += 4
    count = value[offset]
    offset += 1
    if len(value) < 5 + count * 4:
        raise ValueError(
            f"Keypath value too short: {len(value)} bytes "
            f"for {count} derivations (need {5 + count * 4})")
    path: list[str] = []
    for _ in range(count):
        idx = int.from_bytes(value[offset:offset + 4], "little")
        offset += 4
        path.append(str(idx))
    return fingerprint, tuple(path)


def psbt_extract_signatures(
    psbt: Psbt,
    *,
    input_values: list[int] | None = None,
) -> SignatureCollection:
    """Extract ECDSA signatures from PSBT partial signatures.

    For each input, extracts ``(pubkey, signature)`` pairs from
    ``partial_sigs`` and creates ``Record`` objects.  Also handles
    finalized inputs (``final_script_sig`` / ``final_script_witness``)
    as a fallback when ``partial_sigs`` is empty.

    Args:
        psbt: A parsed ``Psbt`` instance.
        input_values: Optional per-input UTXO values in satoshis.

    Returns:
        A ``SignatureCollection`` containing all extracted records.
    """
    from bitcoin.curve import parse_public_key
    from bitcoin.encoding.der import decode_der
    from bitcoin.signature.record import Record
    from bitcoin.signature.collection import SignatureCollection
    from bitcoin.transaction.parser import parse_tx

    tx, _ = parse_tx(psbt.tx)
    txid = tx.txid()
    records: list[Record] = []

    for vin, inp in enumerate(psbt.inputs):
        value = input_values[vin] if input_values else 0

        # Extract from partial_sigs
        for pubkey_bytes, sig_bytes in inp.partial_sigs.items():
            try:
                public_key = parse_public_key(pubkey_bytes)
            except (ValueError, TypeError):
                continue
            if len(sig_bytes) < 2:
                continue
            sig_der = sig_bytes[:-1]
            flag = sig_bytes[-1]
            try:
                decode_der(sig_der)
            except ValueError:
                continue
            records.append(
                Record(
                    txid=txid,
                    vin=vin,
                    sig=sig_der,
                    public_key=public_key,
                    script_type="psbt_partial",
                    sighash_flag=flag,
                    amount=value,
                ))

        # Extract from finalized scriptSig
        if inp.final_script_sig:
            try:
                from bitcoin.script.parser import parse_script
                parsed = parse_script(inp.final_script_sig)
                for element in parsed:
                    if isinstance(element, bytes) and len(element) > 1:
                        sig_candidate = element[:-1]
                        flag = element[-1]
                        decode_der(sig_candidate)
                        # Try to extract pubkey from scriptSig; skip if not found
                        pubkey = extract_pubkey_from_elements(parsed)
                        if pubkey is None or pubkey.infinity:
                            continue
                        records.append(
                            Record(
                                txid=txid,
                                vin=vin,
                                sig=sig_candidate,
                                public_key=pubkey,
                                script_type="finalized",
                                sighash_flag=flag,
                                amount=value,
                            ))
            except (ValueError, IndexError):
                logger.debug("Failed to parse finalized scriptSig for input %d", vin)

    return SignatureCollection(records=tuple(records))


def extract_pubkey_from_elements(
        elements: Sequence[object]) -> Point | None:
    """Extract the public key from a list of parsed script elements.

    Searches for a 33- or 65-byte element that is a valid SEC-encoded
    public key on the secp256k1 curve.

    Args:
        elements: Parsed script elements.

    Returns:
        The public key ``Point``, or ``None`` if no valid pubkey found.
    """
    from bitcoin.curve import parse_public_key
    for element in reversed(tuple(elements)):
        if isinstance(element, bytes) and len(element) in (33, 65):
            try:
                point = parse_public_key(element)
                if point is not None and not point.infinity:
                    return point
            except (ValueError, TypeError):
                continue
    return None


def parse_witness_stack(data: bytes) -> Tuple[bytes, ...]:
    """Parse a serialised witness stack from raw bytes.

    Args:
        data: Raw witness stack bytes (varint-prefixed items).

    Returns:
        A tuple of witness item bytes.
    """
    offset = 0
    items: list[bytes] = []
    while offset < len(data):
        n, offset = decode_varint(data, offset)
        items.append(data[offset:offset + n])
        offset += n
    return tuple(items)


def serialize_witness_stack(items: Tuple[bytes, ...]) -> bytes:
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
