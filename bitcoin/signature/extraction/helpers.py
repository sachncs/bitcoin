"""Shared helpers for signature extraction: pubkey recovery, sighash, script code."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING

from bitcoin.curve import is_on_curve, parse_public_key
from bitcoin.curve.point import Point
from bitcoin.signature.check import recover_public_key

if TYPE_CHECKING:
    from bitcoin.transaction.models import Tx

logger = logging.getLogger(__name__)


def extract_pubkey_from_script_sig(script_sig: Sequence[object]) -> bytes | None:
    """Extract the public key from a legacy P2PKH ``scriptSig``.

    Searches from the end for a 33- or 65-byte push that is the
    uncompressed or compressed public key.

    Args:
        script_sig: Parsed ``scriptSig`` elements.

    Returns:
        The public key bytes, or ``None`` if not found.
    """
    for element in reversed(script_sig):
        if isinstance(element, bytes) and len(element) in {33, 65}:
            return element
    return None


def recover_or_parse_pubkey(
    tx: Tx,
    vin: int,
    sig: bytes,
    flag: int,
    script: bytes = b"",
    value: int = 0,
    pubkey_bytes: bytes | None = None,
) -> Point | None:
    """Recover a public key from a signature, falling back to SEC parsing.

    Computes the sighash and tries all four recovery IDs.  If recovery
    fails and *pubkey_bytes* is provided, attempts to parse it as an
    SEC-encoded public key instead.

    Args:
        tx: The parent transaction.
        vin: Input index.
        sig: DER-encoded signature (without the sighash byte).
        flag: Sighash flag byte.
        script: Script code used for sighash computation.
        value: UTXO value in satoshis (used for SegWit sighashes).
        pubkey_bytes: Optional SEC-encoded public key as fallback.

    Returns:
        The recovered ``Point``, or ``None`` if every method fails.

    Raises:
        AttributeError: If *tx* is malformed.
    """
    try:
        message = compute_sighash(tx, vin, script, flag, value)
    except ValueError:
        logger.debug("Sighash computation failed for input %d", vin)
        return None
    for rec_id in range(4):
        recovery_flag = 27 + rec_id + 4
        try:
            return recover_public_key(message, sig, recovery_flag)
        except ValueError:
            continue
    logger.debug("Public key recovery failed for input %d", vin)
    if pubkey_bytes:
        try:
            point = parse_public_key(pubkey_bytes)
            if point is not None and not point.infinity and is_on_curve(point):
                return point
        except (ValueError, TypeError):
            logger.debug("Failed to parse fallback public key for input %d", vin)
    return None


def compute_sighash(tx: Tx, vin: int, script: bytes, flag: int, value: int) -> bytes:
    """Compute the transaction sighash for a given input.

    Dispatches to legacy or SegWit sighash depending on whether the
    *script* is a witness program (``OP_0 <20|32 bytes>``).  This is
    correct even for P2SH-wrapped SegWit inputs where the transaction
    itself may not have witness data.

    Args:
        tx: The transaction.
        vin: Input index.
        script: Script code.
        flag: Sighash flag byte.
        value: UTXO value in satoshis (required for SegWit).

    Returns:
        The 32-byte sighash digest.

    Raises:
        ValueError: If ``SIGHASH_SINGLE`` is used with out-of-bounds
            input index, or for other invalid flag combinations.
    """
    from bitcoin.sighash.legacy import sighash_legacy
    from bitcoin.sighash.segwit import sighash_segwit

    is_witness = (len(script) >= 2 and script[0] == 0x00 and script[1] in (0x14, 0x20))
    if is_witness:
        return sighash_segwit(tx, vin, script, value, flag)
    return sighash_legacy(tx, vin, script, flag)


def p2wpkh_script_code(script_pubkey: bytes) -> bytes:
    """Derive the P2WPKH script code from the witness program.

    The script code for a P2WPKH input is the 25-byte P2PKH script
    constructed from the 20-byte pubkey hash inside the witness program.

    Args:
        script_pubkey: The P2WPKH witness program (typically 22 bytes:
            ``0x00 0x14 <20-byte-hash>``).

    Returns:
        The 25-byte script code suitable for SegWit sighash computation.
    """
    if len(script_pubkey) >= 2:
        program = script_pubkey[2:] if script_pubkey[:1] == b"\x00" else script_pubkey
        if len(program) >= 20:
            return build_p2pkh_script_code(program[:20])
    return default_script_code()


def build_p2pkh_script_code(pubkey_hash: bytes) -> bytes:
    """Build the 25-byte P2PKH script code from a 20-byte pubkey hash.

    Args:
        pubkey_hash: The 20-byte HASH160 of the public key.

    Returns:
        A 25-byte script: ``<len> OP_DUP OP_HASH160 OP_PUSH_20 <hash>
        OP_EQUALVERIFY OP_CHECKSIG``.

    Raises:
        ValueError: If *pubkey_hash* is not 20 bytes.
    """
    if len(pubkey_hash) != 20:
        raise ValueError(f"pubkey_hash must be 20 bytes, got {len(pubkey_hash)}")
    return b"".join([
        bytes([0x19]),
        bytes([0x76]),
        bytes([0xA9]),
        bytes([0x14]),
        pubkey_hash,
        bytes([0x88]),
        bytes([0xAC]),
    ])


def default_script_code() -> bytes:
    """Return a fallback script code when the real one cannot be determined.

    Returns:
        22 zero bytes — a placeholder that will not match any real script.
    """
    return b"\x00" * 22


__all__ = [
    "build_p2pkh_script_code",
    "compute_sighash",
    "default_script_code",
    "extract_pubkey_from_script_sig",
    "p2wpkh_script_code",
    "recover_or_parse_pubkey",
]
