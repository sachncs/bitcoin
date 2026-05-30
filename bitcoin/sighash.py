"""Transaction signature hash reconstruction."""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from bitcoin.exceptions import InvalidSighashFlagError, MissingInputValueError
from bitcoin.script import make_p2pkh_script, remove_code_separators
from bitcoin.utils import int_to_little_endian_bytes, sha256d

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from bitcoin.transaction import Transaction

FLAG_ANYONE_CAN_PAY = 0x80
FLAG_BASE_MASK = 0x1F
FLAG_ALL = 0x01
FLAG_NONE = 0x02
FLAG_SINGLE = 0x03

__all__ = [
    "FLAG_ALL",
    "FLAG_ANYONE_CAN_PAY",
    "FLAG_BASE_MASK",
    "FLAG_NONE",
    "FLAG_SINGLE",
    "SighashPlan",
    "legacy_sighash",
    "p2wpkh_script_code",
    "parse_sighash_flag",
    "segwit_sighash",
    "serialize_script",
    "serialize_transaction_output",
    "serialize_varint",
    "serialize_varint_and_join",
    "tagged_hash",
    "taproot_sighash",
]


@dataclass(frozen=True, slots=True)
class SighashPlan:
    """Describes how a signature hash should be computed."""

    base_type: int
    anyone_can_pay: bool


def parse_sighash_flag(flag: int) -> SighashPlan:
    """Parse and validate a sighash flag byte."""
    if flag & ~0x83:
        raise InvalidSighashFlagError("Unsupported sighash flag bits are set.")
    base_type = flag & FLAG_BASE_MASK
    anyone_can_pay = bool(flag & FLAG_ANYONE_CAN_PAY)
    if base_type not in {FLAG_ALL, FLAG_NONE, FLAG_SINGLE}:
        raise InvalidSighashFlagError("Unsupported sighash base type.")
    return SighashPlan(base_type=base_type, anyone_can_pay=anyone_can_pay)


def legacy_sighash(
    transaction: Transaction,
    input_index: int,
    script_code: bytes,
    sighash_flag: int,
) -> bytes:
    """Compute the legacy (pre-SegWit) signature hash."""
    plan = parse_sighash_flag(sighash_flag)
    if plan.base_type == FLAG_SINGLE and input_index >= len(
            transaction.outputs):
        logger.warning(
            "Legacy SINGLE sighash at input %d has no matching output; "
            "returning consensus-mandated sentinel 0x00...01",
            input_index,
        )
        return int_to_little_endian_bytes(1, 32)

    script_code = remove_code_separators(script_code)
    inputs = transaction.inputs
    input_chunks: list[bytes] = []
    output_chunks: list[bytes] = []

    if plan.anyone_can_pay:
        current = inputs[input_index]
        input_chunks.append(
            current.prevout_hash +
            int_to_little_endian_bytes(current.prevout_index, 4) +
            serialize_script(script_code) +
            int_to_little_endian_bytes(current.sequence, 4))
    else:
        for index, current in enumerate(inputs):
            script = script_code if index == input_index else b""
            sequence = current.sequence
            if index != input_index and plan.base_type in {
                    FLAG_NONE, FLAG_SINGLE
            }:
                sequence = 0
            input_chunks.append(
                current.prevout_hash +
                int_to_little_endian_bytes(current.prevout_index, 4) +
                serialize_script(script) +
                int_to_little_endian_bytes(sequence, 4))

    if plan.base_type == FLAG_ALL:
        for output in transaction.outputs:
            output_chunks.append(
                serialize_transaction_output(output.value,
                                             output.script_pubkey))
    elif plan.base_type == FLAG_SINGLE:
        for index in range(input_index + 1):
            if index < input_index:
                output_chunks.append(
                    serialize_transaction_output(0xFFFFFFFFFFFFFFFF, b""))
            else:
                output = transaction.outputs[index]
                output_chunks.append(
                    serialize_transaction_output(output.value,
                                                 output.script_pubkey))

    payload = (int_to_little_endian_bytes(transaction.version, 4) +
               serialize_varint_and_join(input_chunks) +
               serialize_varint_and_join(output_chunks) +
               int_to_little_endian_bytes(transaction.locktime, 4) +
               int_to_little_endian_bytes(sighash_flag, 4))
    return sha256d(payload)


def segwit_sighash(
    transaction: Transaction,
    input_index: int,
    script_code: bytes,
    amount: int | None,
    sighash_flag: int,
) -> bytes:
    """Compute the SegWit v0 signature hash (BIP-143)."""
    if amount is None:
        logger.error("Missing input value for SegWit sighash at input %d",
                     input_index)
        raise MissingInputValueError("SegWit inputs need a spent output value.")
    plan = parse_sighash_flag(sighash_flag)
    script_code = remove_code_separators(script_code)

    if plan.anyone_can_pay:
        hash_prevouts = b"\x00" * 32
    else:
        prevout_parts = [
            current.prevout_hash +
            int_to_little_endian_bytes(current.prevout_index, 4)
            for current in transaction.inputs
        ]
        hash_prevouts = sha256d(b"".join(prevout_parts))

    if plan.anyone_can_pay or plan.base_type in {FLAG_NONE, FLAG_SINGLE}:
        hash_sequence = b"\x00" * 32
    else:
        sequence_parts = [
            int_to_little_endian_bytes(current.sequence, 4)
            for current in transaction.inputs
        ]
        hash_sequence = sha256d(b"".join(sequence_parts))

    if plan.base_type == FLAG_ALL:
        output_parts = [
            int_to_little_endian_bytes(output.value, 8) +
            serialize_script(output.script_pubkey)
            for output in transaction.outputs
        ]
        hash_outputs = sha256d(b"".join(output_parts))
    elif plan.base_type == FLAG_SINGLE and input_index < len(
            transaction.outputs):
        output = transaction.outputs[input_index]
        hash_outputs = sha256d(
            int_to_little_endian_bytes(output.value, 8) +
            serialize_script(output.script_pubkey))
    else:
        hash_outputs = b"\x00" * 32

    current = transaction.inputs[input_index]
    payload = (int_to_little_endian_bytes(transaction.version, 4) +
               hash_prevouts + hash_sequence + current.prevout_hash +
               int_to_little_endian_bytes(current.prevout_index, 4) +
               serialize_script(script_code) +
               int_to_little_endian_bytes(amount, 8) +
               int_to_little_endian_bytes(current.sequence, 4) + hash_outputs +
               int_to_little_endian_bytes(transaction.locktime, 4) +
               int_to_little_endian_bytes(sighash_flag, 4))
    return sha256d(payload)


def serialize_varint_and_join(chunks: list[bytes]) -> bytes:
    """Serialize a varint-prefixed list of byte chunks."""
    payload = b"".join(chunks)
    return serialize_varint(len(chunks)) + payload


def serialize_transaction_output(value: int, script: bytes) -> bytes:
    """Serialize a transaction output for sighash computation."""
    return int_to_little_endian_bytes(value, 8) + serialize_script(script)


def serialize_varint(value: int) -> bytes:
    """Serialize an integer as a Bitcoin varint."""
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + int_to_little_endian_bytes(value, 2)
    if value <= 0xFFFFFFFF:
        return b"\xfe" + int_to_little_endian_bytes(value, 4)
    return b"\xff" + int_to_little_endian_bytes(value, 8)


def serialize_script(script: bytes) -> bytes:
    """Serialize a script with a varint length prefix."""
    return serialize_varint(len(script)) + script


def p2wpkh_script_code(pubkey: bytes) -> bytes:
    """Build the P2WPKH script code from a public key."""
    return make_p2pkh_script(pubkey)


def tagged_hash(tag: str, data: bytes) -> bytes:
    """Compute a BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)."""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


def taproot_sighash(
    transaction: Transaction,
    input_index: int,
    script_code: bytes,
    amount: int,
    sighash_flag: int,
    script_pubkeys: Sequence[bytes],
    spend_type: int = 0x00,
    annex: bytes | None = None,
) -> bytes:
    """Compute the BIP-341 Taproot signature hash."""
    amounts = transaction.context.input_values if transaction.context else None
    if amounts is None:
        raise MissingInputValueError(
            f"Taproot sighash at input {input_index} needs input values.")
    if any(a is None for a in amounts):
        raise MissingInputValueError(f"Taproot sighash at input {input_index}: "
                                     f"some input values are None.")

    plan = parse_sighash_flag(sighash_flag)

    if plan.anyone_can_pay:
        sha_prevouts = b"\x00" * 32
        sha_amounts = b"\x00" * 32
        sha_scriptpubkeys = b"\x00" * 32
        sha_sequences = b"\x00" * 32
    else:
        prevouts = b"".join(i.prevout_hash +
                            int_to_little_endian_bytes(i.prevout_index, 4)
                            for i in transaction.inputs)
        sha_prevouts = tagged_hash("TapSighash", prevouts)

        amount_parts: list[bytes] = []
        for a in amounts:
            assert a is not None
            amount_parts.append(int_to_little_endian_bytes(a, 8))
        amount_bytes = b"".join(amount_parts)
        sha_amounts = tagged_hash("TapSighash", amount_bytes)

        spk_bytes = b"".join(serialize_script(spk) for spk in script_pubkeys)
        sha_scriptpubkeys = tagged_hash("TapSighash", spk_bytes)

        seq_bytes = b"".join(
            int_to_little_endian_bytes(i.sequence, 4)
            for i in transaction.inputs)
        sha_sequences = tagged_hash("TapSighash", seq_bytes)

    if plan.base_type == FLAG_NONE:
        sha_outputs = b"\x00" * 32
    elif plan.base_type == FLAG_SINGLE:
        if input_index >= len(transaction.outputs):
            logger.warning(
                "Taproot SINGLE sighash at input %d has no matching output; "
                "returning consensus-mandated sentinel 0x00...01",
                input_index,
            )
            return int_to_little_endian_bytes(1, 32)
        output = transaction.outputs[input_index]
        sha_outputs = tagged_hash(
            "TapSighash",
            serialize_transaction_output(output.value, output.script_pubkey),
        )
    else:
        out_bytes = b"".join(
            serialize_transaction_output(o.value, o.script_pubkey)
            for o in transaction.outputs)
        sha_outputs = tagged_hash("TapSighash", out_bytes)

    hash_annex = tagged_hash("TapSighash", annex) if annex else b"\x00" * 32

    sigmsg = (bytes([sighash_flag]) +
              int_to_little_endian_bytes(transaction.version, 4) +
              int_to_little_endian_bytes(transaction.locktime, 4) +
              sha_prevouts + sha_amounts + sha_scriptpubkeys + sha_sequences +
              sha_outputs + bytes([spend_type]) +
              int_to_little_endian_bytes(input_index, 4) + hash_annex)

    return tagged_hash("TapSighash", sigmsg)
