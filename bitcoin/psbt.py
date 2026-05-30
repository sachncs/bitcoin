"""PSBT (Partially Signed Bitcoin Transaction) parsing and signature extraction.

Implements BIP-174 parsing for key-value map extraction and PSBT-based
signature extraction for ECDSA signatures found in partial_sigs fields.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass

from bitcoin.der import parse_der_signature
from bitcoin.exceptions import BitcoinError, InvalidHexError, MissingInputValueError
from bitcoin.models import SignatureRecord
from bitcoin.parser import parse_transaction_bytes
from bitcoin.script import is_witness_program
from bitcoin.sighash import legacy_sighash, p2wpkh_script_code, segwit_sighash
from bitcoin.signature import SignatureCollection
from bitcoin.transaction import Transaction
from bitcoin.utils import ByteReader, bytes_to_hex, validate_hex_string

logger = logging.getLogger(__name__)

GLOBAL_UNSIGNED_TX = 0x00

INPUT_NON_WITNESS_UTXO = 0x00
INPUT_WITNESS_UTXO = 0x01
INPUT_PARTIAL_SIG = 0x02
INPUT_SIGHASH_TYPE = 0x03
INPUT_REDEEM_SCRIPT = 0x04
INPUT_WITNESS_SCRIPT = 0x05
INPUT_BIP32_KEYPATH = 0x06

OUTPUT_REDEEM_SCRIPT = 0x00
OUTPUT_WITNESS_SCRIPT = 0x01
OUTPUT_BIP32_KEYPATH = 0x02

PSBT_MAGIC = b"psbt\xff"

__all__ = [
    "GLOBAL_UNSIGNED_TX",
    "INPUT_BIP32_KEYPATH",
    "INPUT_NON_WITNESS_UTXO",
    "INPUT_PARTIAL_SIG",
    "INPUT_REDEEM_SCRIPT",
    "INPUT_SIGHASH_TYPE",
    "INPUT_WITNESS_SCRIPT",
    "INPUT_WITNESS_UTXO",
    "OUTPUT_BIP32_KEYPATH",
    "OUTPUT_REDEEM_SCRIPT",
    "OUTPUT_WITNESS_SCRIPT",
    "PSBT_MAGIC",
    "Psbt",
    "PsbtInput",
    "PsbtOutput",
    "psbt_extract_signatures",
    "parse_keypath_value",
    "parse_psbt",
    "parse_psbt_hex",
    "read_input_map",
    "read_key_value",
    "read_output_map",
]


@dataclass(frozen=True, slots=True)
class PsbtInput:
    """Per-input PSBT key-value data."""

    non_witness_utxo: bytes | None  # raw prevout tx
    witness_utxo: tuple[int, bytes] | None  # (value, script_pubkey)
    partial_sigs: dict[str, str]  # pubkey_hex -> der_sig_hex
    redeem_script: bytes | None
    witness_script: bytes | None
    # pubkey_hex -> (fingerprint_hex, derivation_path)
    keypaths: dict[str, tuple[str, ...]]
    sighash_type: int | None


@dataclass(frozen=True, slots=True)
class PsbtOutput:
    """Per-output PSBT key-value data."""

    redeem_script: bytes | None
    witness_script: bytes | None
    keypaths: dict[str, tuple[str, ...]]


@dataclass(frozen=True, slots=True)
class Psbt:
    """Parsed PSBT with full key-value data."""

    raw_bytes: bytes
    unsigned_tx: Transaction
    inputs: tuple[PsbtInput, ...]
    outputs: tuple[PsbtOutput, ...]
    unknown: dict[str, bytes]


# ── Parsing helpers ──────────────────────────────────────────────────────


def read_key_value(reader: ByteReader) -> tuple[bytes | None, bytes]:
    """Read one PSBT key-value pair.

    Returns ``(key_data, value_data)`` where *key_data* is ``None`` when the
    separator (empty key, ``0x00``) is encountered.
    """
    key_len = reader.read_varint()
    if key_len == 0:
        return None, b""
    key = reader.read(key_len)
    value_len = reader.read_varint()
    value = reader.read(value_len)
    return key, value


def parse_keypath_value(value: bytes) -> tuple[str, tuple[str, ...]]:
    """Parse a BIP32 keypath value into (fingerprint_hex, path_tuple).

    Value format: 4-byte fingerprint + compact-size count + count*4-byte uint32.
    """
    vreader = ByteReader(value)
    fingerprint = bytes_to_hex(vreader.read(4))
    count = vreader.read_varint()
    path: list[str] = []
    for _ in range(count):
        idx = int.from_bytes(vreader.read(4), "little")
        path.append(str(idx))
    return fingerprint, tuple(path)


def read_input_map(reader: ByteReader) -> PsbtInput:
    """Read one PSBT input key-value map."""
    non_witness_utxo: bytes | None = None
    witness_utxo: tuple[int, bytes] | None = None
    partial_sigs: dict[str, str] = {}
    redeem_script: bytes | None = None
    witness_script: bytes | None = None
    keypaths: dict[str, tuple[str, ...]] = {}
    sighash_type: int | None = None

    while True:
        key_raw, value = read_key_value(reader)
        if key_raw is None:
            break
        key_type = key_raw[0]
        key_data = key_raw[1:]

        if key_type == INPUT_NON_WITNESS_UTXO:
            non_witness_utxo = value
        elif key_type == INPUT_WITNESS_UTXO:
            vreader = ByteReader(value)
            amount = vreader.read_uint64()
            script_pubkey = vreader.read_varbytes()
            witness_utxo = (amount, script_pubkey)
        elif key_type == INPUT_PARTIAL_SIG:
            pubkey_hex = bytes_to_hex(key_data)
            sig_hex = bytes_to_hex(value)
            partial_sigs[pubkey_hex] = sig_hex
        elif key_type == INPUT_SIGHASH_TYPE:
            sighash_type = int.from_bytes(value, "little")
        elif key_type == INPUT_REDEEM_SCRIPT:
            redeem_script = value
        elif key_type == INPUT_WITNESS_SCRIPT:
            witness_script = value
        elif key_type == INPUT_BIP32_KEYPATH:
            pubkey_hex = bytes_to_hex(key_data)
            fingerprint, path = parse_keypath_value(value)
            keypaths[pubkey_hex] = (fingerprint,) + path
        else:
            logger.warning("Unknown input key type 0x%02x in PSBT input map",
                           key_type)

    return PsbtInput(
        non_witness_utxo=non_witness_utxo,
        witness_utxo=witness_utxo,
        partial_sigs=partial_sigs,
        redeem_script=redeem_script,
        witness_script=witness_script,
        keypaths=keypaths,
        sighash_type=sighash_type,
    )


def read_output_map(reader: ByteReader) -> PsbtOutput:
    """Read one PSBT output key-value map."""
    redeem_script: bytes | None = None
    witness_script: bytes | None = None
    keypaths: dict[str, tuple[str, ...]] = {}

    while True:
        key_raw, value = read_key_value(reader)
        if key_raw is None:
            break
        key_type = key_raw[0]
        key_data = key_raw[1:]

        if key_type == OUTPUT_REDEEM_SCRIPT:
            redeem_script = value
        elif key_type == OUTPUT_WITNESS_SCRIPT:
            witness_script = value
        elif key_type == OUTPUT_BIP32_KEYPATH:
            pubkey_hex = bytes_to_hex(key_data)
            fingerprint, path = parse_keypath_value(value)
            keypaths[pubkey_hex] = (fingerprint,) + path
        else:
            logger.warning("Unknown output key type 0x%02x in PSBT output map",
                           key_type)

    return PsbtOutput(
        redeem_script=redeem_script,
        witness_script=witness_script,
        keypaths=keypaths,
    )


# ── Public API ───────────────────────────────────────────────────────────


def parse_psbt(data: bytes) -> Psbt:
    """Parse a PSBT from raw bytes (BIP-174).

    Args:
        data: Raw PSBT bytes.

    Returns:
        A ``Psbt`` instance with parsed key-value data.

    Raises:
        BitcoinError: If the PSBT magic bytes are invalid or parsing fails.
    """
    reader = ByteReader(data)
    magic = reader.read(5)
    if magic != b"psbt\xff":
        raise BitcoinError(
            f"Invalid PSBT magic: expected b'psbt\\xff', got {magic!r}")

    # ── Global map ─────────────────────────────────────────────────────
    unsigned_tx: Transaction | None = None
    unknown: dict[str, bytes] = {}

    while True:
        key_raw, value = read_key_value(reader)
        if key_raw is None:
            break
        key_type = key_raw[0]
        key_data = key_raw[1:]

        if key_type == GLOBAL_UNSIGNED_TX:
            unsigned_tx = Transaction.parse_hex(value.hex())
        else:
            composite_key = bytes([key_type]) + key_data
            unknown[composite_key.hex()] = value

    if unsigned_tx is None:
        raise BitcoinError("PSBT is missing the unsigned transaction.")

    # ── Input maps ─────────────────────────────────────────────────────
    inputs: list[PsbtInput] = []
    for _ in range(len(unsigned_tx.inputs)):
        inputs.append(read_input_map(reader))

    # ── Output maps ────────────────────────────────────────────────────
    outputs: list[PsbtOutput] = []
    for _ in range(len(unsigned_tx.outputs)):
        outputs.append(read_output_map(reader))

    return Psbt(
        raw_bytes=data,
        unsigned_tx=unsigned_tx,
        inputs=tuple(inputs),
        outputs=tuple(outputs),
        unknown=unknown,
    )


def parse_psbt_hex(hex_str: str) -> Psbt:
    """Parse a PSBT from a hex string.

    Args:
        hex_str: PSBT encoded as a hex string.

    Returns:
        A ``Psbt`` instance.
    """
    raw = validate_hex_string(hex_str)
    return parse_psbt(raw)


def psbt_extract_signatures(
    psbt: Psbt,
    *,
    input_values: Sequence[int] | None = None,
) -> SignatureCollection:
    """Extract ECDSA signatures from a PSBT.

    For each input with ``partial_sigs``, each (pubkey, DER signature) pair
    is converted into a ``SignatureRecord``.  The signature hash (``z``) is
    computed using either legacy or segwit sighash depending on the UTXO
    type available in the PSBT input.

    Args:
        psbt: The parsed PSBT.
        input_values: Optional per-input values used as a fallback for
            segwit sighash when ``witness_utxo`` is absent.

    Returns:
        A ``SignatureCollection`` of extracted records.
    """
    records: list[SignatureRecord] = []
    tx = psbt.unsigned_tx
    values = list(input_values) if input_values is not None else []

    for input_index, psbt_in in enumerate(psbt.inputs):
        for pubkey_hex, der_sig_hex in psbt_in.partial_sigs.items():
            try:
                der_sig = bytes.fromhex(der_sig_hex)
            except ValueError as error:
                raise InvalidHexError(
                    f"Invalid DER signature hex for input {input_index}, "
                    f"pubkey {pubkey_hex}: {error}") from error
            parsed = parse_der_signature(der_sig)
            sighash_flag = parsed.sighash_flag

            script_type: str
            z: bytes

            # ── Segwit: witness_utxo present ────────────────────────
            if psbt_in.witness_utxo is not None:
                amount, script_pubkey = psbt_in.witness_utxo
                if psbt_in.witness_script is not None:
                    script_code = psbt_in.witness_script
                elif is_witness_program(script_pubkey):
                    pubkey_bytes = bytes.fromhex(pubkey_hex)
                    script_code = p2wpkh_script_code(pubkey_bytes)
                else:
                    script_code = script_pubkey
                z = segwit_sighash(
                    tx,
                    input_index,
                    script_code,
                    amount,
                    sighash_flag,
                )
                script_type = "psbt-segwit"

            # ── Legacy: non_witness_utxo present ────────────────────
            elif psbt_in.non_witness_utxo is not None:
                prevout_tx = parse_transaction_bytes(psbt_in.non_witness_utxo)
                prevout_index = tx.inputs[input_index].prevout_index
                if prevout_index >= len(prevout_tx.outputs):
                    raise BitcoinError(
                        f"Non-witness UTXO for input {input_index} "
                        f"has no output at index {prevout_index}.")
                outpoint = prevout_tx.outputs[prevout_index]
                script_code = outpoint.script_pubkey
                z = legacy_sighash(tx, input_index, script_code, sighash_flag)
                script_type = "psbt-legacy"

            # ── Fallback: user-provided input values ─────────────────
            elif input_values is not None and input_index < len(values):
                amount = values[input_index]
                if amount is None:
                    raise MissingInputValueError(
                        f"No value available for input {input_index}.")
                script_code = (psbt_in.witness_script
                               if psbt_in.witness_script is not None else b"")
                z = segwit_sighash(
                    tx,
                    input_index,
                    script_code,
                    amount,
                    sighash_flag,
                )
                script_type = "psbt-unknown"

            # ── No UTXO data at all ─────────────────────────────────
            else:
                raise MissingInputValueError(
                    f"Cannot determine sighash for input {input_index}: "
                    f"no UTXO data available.")

            records.append(
                SignatureRecord(
                    r=bytes_to_hex(parsed.r),
                    s=bytes_to_hex(parsed.s),
                    z=bytes_to_hex(z),
                    sighash_flag=sighash_flag,
                    input_index=input_index,
                    public_key=pubkey_hex,
                    script_type=script_type,
                ))

    return SignatureCollection(records=tuple(records))
