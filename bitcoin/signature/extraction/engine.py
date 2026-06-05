"""Engine for extracting ECDSA signatures from Bitcoin transactions.

Supports legacy (P2PK, P2PKH), SegWit (P2WPKH, P2WSH), P2SH-wrapped
SegWit, and Taproot (P2TR) input types.  Public-key recovery is attempted
for each discovered signature.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from collections.abc import Sequence

from bitcoin.curve import INFINITY, Point
from bitcoin.encoding.der import decode_der
from bitcoin.sighash.flag import SIGHASH_ALL
from bitcoin.signature.check import recover_public_key
from bitcoin.signature.record import Record
from bitcoin.script.classifier import (
    P2SH,
    P2WPKH,
    P2WSH,
    P2TR,
    classify_script_pubkey,
)
from bitcoin.script.parser import parse_script

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from bitcoin.transaction.models import Tx, TxIn


def extract_signatures(
    tx: Tx,
    utxo_script_pubkeys: list[bytes] | None = None,
    utxo_values: list[int] | None = None,
) -> list[Record]:
    """Extract all signatures (ECDSA and Schnorr) from a transaction.

    Iterates over each input, determines the script type, and dispatches
    to the appropriate extraction handler (legacy, P2WPKH, P2WSH,
    P2SH-SegWit, or Taproot).

    Args:
        tx: The transaction to extract from.
        utxo_script_pubkeys: The ``scriptPubKey`` for each UTXO being spent.
            Required for P2SH, P2WPKH, P2WSH, and P2TR.
        utxo_values: The value (in satoshis) for each UTXO being spent.
            Required for SegWit inputs (used in sighash computation).

    Returns:
        A list of ``Record`` instances — one per extracted signature.

    Raises:
        IndexError: If *utxo_script_pubkeys* or *utxo_values* are shorter
            than *tx.inputs*.
        AttributeError: If *tx* is malformed.
        ValueError: If sighash computation fails (e.g. invalid flag).
    """
    records: list[Record] = []
    script_type_counts: dict[str, int] = {}
    failed_inputs = 0

    if not tx.inputs:
        return records

    for vin, txin in enumerate(tx.inputs):
        parsed_sig: Sequence[object] = list(parse_script(
            txin.script_sig)) if txin.script_sig else []
        script_pubkey = utxo_script_pubkeys[vin] if utxo_script_pubkeys else b""
        script_type = determine_script_type(script_pubkey, parsed_sig)
        script_type_counts[script_type] = script_type_counts.get(
            script_type, 0) + 1
        logger.debug("Processing input %d, script_type=%s", vin, script_type)
        value = utxo_values[vin] if utxo_values else 0
        is_segwit = bool(txin.witness.items)

        if is_segwit:
            if script_type == P2WPKH:
                records.extend(
                    extract_p2wpkh(tx, vin, script_pubkey, value,
                                     txin.witness.items))
            elif script_type == P2WSH:
                records.extend(
                    extract_p2wsh(tx, vin, script_pubkey, value,
                                    txin.witness.items))
            elif script_type == P2SH:
                records.extend(
                    extract_p2sh_segwit(tx, vin, script_pubkey, value, txin))
            elif script_type == P2TR:
                records.extend(
                    extract_taproot(tx, vin, script_pubkey, value,
                                      txin.witness.items))
            else:
                failed_inputs += 1
        else:
                records.extend(extract_legacy(tx, vin, script_pubkey, parsed_sig))

    type_summary = ", ".join(
        f"{n} {t}" for t, n in sorted(script_type_counts.items()))
    logger.info(
        "Extracted %d signatures from %d inputs (%s). failed=%d",
        len(records), len(tx.inputs), type_summary, failed_inputs)
    return records


def determine_script_type(script_pubkey: bytes,
                          script_sig: Sequence[object]) -> str:
    """Classify the script type from the ``scriptPubKey``.

    Args:
        script_pubkey: The output script as raw bytes.
        script_sig: The input ``scriptSig`` (unused, kept for signature
            compatibility).

    Returns:
        A script-type string (e.g. ``"p2pkh"``, ``"p2wpkh"``) or
        ``"unknown"`` if *script_pubkey* is empty.
    """
    if not script_pubkey:
        return "unknown"
    return classify_script_pubkey(script_pubkey)


# ── Legacy (non-segwit) extraction ─────────────────────────────────


def extract_legacy(
    tx: Tx,
    vin: int,
    script_pubkey: bytes,
    script_sig: Sequence[object],
) -> list[Record]:
    """Extract signatures from a non-SegWit (legacy) input.

    Scans the ``scriptSig`` for DER-encoded signatures and attempts
    public-key recovery for each.

    Args:
        tx: The parent transaction.
        vin: Input index.
        script_pubkey: The UTXO ``scriptPubKey``.
        script_sig: Parsed ``scriptSig`` elements.

    Returns:
        A list of ``Record`` instances.

    Raises:
        AttributeError: If *tx* is malformed (e.g. ``tx.txid()`` fails).
    """
    records: list[Record] = []
    guessed = guess_p2pkh_script(script_sig)
    effective_script = script_pubkey or guessed or b""
    pubkey_bytes = extract_pubkey_from_script_sig(script_sig)
    for element in script_sig:
        if isinstance(element, bytes) and len(element) > 1:
            try:
                der = element[:-1]
                flag = element[-1]
                decode_der(der)
                pubkey = recover_or_parse_pubkey(
                    tx,
                    vin,
                    der,
                    flag,
                    effective_script,
                    value=0,
                    pubkey_bytes=pubkey_bytes,
                )
                if pubkey is None:
                    logger.debug("Pubkey recovery failed for input %d", vin)
                    continue
                records.append(
                    Record(
                        txid=tx.txid(),
                        input_index=vin,
                        signature=der,
                        public_key=pubkey,
                        script_type=determine_script_type(
                            script_pubkey, script_sig),
                        sighash_flag=flag,
                        amount=0,
                    ))
                logger.debug("Signature extracted from input %d", vin)
            except (ValueError, TypeError, IndexError) as exc:
                logger.warning("Signature skipped for input %d: %s", vin, exc)
                continue
    return records


def guess_p2pkh_script(script_sig: Sequence[object]) -> bytes | None:
    """Build a P2PKH scriptPubKey from the pubkey in *script_sig*, if present.

    Returns:
        The P2PKH ``scriptPubKey`` bytes, or ``None`` if no pubkey found.
    """
    for element in script_sig:
        if isinstance(element, bytes) and len(element) in {33, 65}:
            from bitcoin.script.builder import make_p2pkh_script
            return make_p2pkh_script(element)
    return None


# ── SegWit extraction ─────────────────────────────────────────────


def extract_p2wpkh(
    tx: Tx,
    vin: int,
    script_pubkey: bytes,
    value: int,
    witness_items: tuple[bytes, ...],
) -> list[Record]:
    """Extract signatures from a P2WPKH witness stack.

    Args:
        tx: The parent transaction.
        vin: Input index.
        script_pubkey: The P2WPKH witness program.
        value: UTXO value in satoshis (used for sighash).
        witness_items: Witness stack items.

    Returns:
        A list of ``Record`` instances.

    Raises:
        AttributeError: If *tx* is malformed.
    """
    script_code = p2wpkh_script_code(
        script_pubkey) if script_pubkey else default_script_code()
    records: list[Record] = []
    for item in witness_items[:-1]:
        if len(item) > 1:
            try:
                der = item[:-1]
                flag = item[-1]
                decode_der(der)
                pubkey = recover_or_parse_pubkey(
                    tx,
                    vin,
                    der,
                    flag,
                    script_code,
                    value=value,
                )
                if pubkey is None:
                    logger.debug("P2WPKH pubkey recovery failed for input %d",
                                 vin)
                    continue
                records.append(
                    Record(
                        txid=tx.txid(),
                        input_index=vin,
                        signature=der,
                        public_key=pubkey,
                        script_type=P2WPKH,
                        sighash_flag=flag,
                        amount=value,
                    ))
                logger.debug("P2WPKH signature extracted for input %d", vin)
            except (ValueError, TypeError, IndexError) as exc:
                logger.warning("P2WPKH signature skipped for input %d: %s",
                               vin, exc)
                continue
    return records


def extract_p2wsh(
    tx: Tx,
    vin: int,
    script_pubkey: bytes,
    value: int,
    witness_items: tuple[bytes, ...],
) -> list[Record]:
    """Extract signatures from a P2WSH witness stack.

    The last witness item is treated as the witness script (used as the
    script code for sighash computation).

    Args:
        tx: The parent transaction.
        vin: Input index.
        script_pubkey: The P2WSH witness program.
        value: UTXO value in satoshis.
        witness_items: Witness stack items.

    Returns:
        A list of ``Record`` instances.

    Raises:
        AttributeError: If *tx* is malformed.
    """
    witness_script = witness_items[-1] if witness_items else b""
    script_code = witness_script if witness_script else default_script_code()
    records: list[Record] = []
    for item in witness_items[:-1]:
        if len(item) > 1:
            try:
                der = item[:-1]
                flag = item[-1]
                decode_der(der)
                pubkey = recover_or_parse_pubkey(
                    tx,
                    vin,
                    der,
                    flag,
                    script_code,
                    value=value,
                )
                if pubkey is None:
                    logger.debug("P2WSH pubkey recovery failed for input %d",
                                 vin)
                    continue
                records.append(
                    Record(
                        txid=tx.txid(),
                        input_index=vin,
                        signature=der,
                        public_key=pubkey,
                        script_type=P2WSH,
                        sighash_flag=flag,
                        amount=value,
                    ))
                logger.debug("P2WSH signature extracted for input %d", vin)
            except (ValueError, TypeError, IndexError) as exc:
                logger.warning("P2WSH signature skipped for input %d: %s",
                               vin, exc)
                continue
    return records


def extract_p2sh_segwit(
    tx: Tx,
    vin: int,
    script_pubkey: bytes,
    value: int,
    txin: TxIn,
) -> list[Record]:
    """Extract signatures from a P2SH-wrapped SegWit input.

    Unwraps the redeem script from ``scriptSig`` to determine whether it
    wraps P2WPKH or P2WSH, then derives the appropriate script code.

    Args:
        tx: The parent transaction.
        vin: Input index.
        script_pubkey: The P2SH ``scriptPubKey``.
        value: UTXO value in satoshis.
        txin: The full ``TxIn`` (provides both ``scriptSig`` and witness).

    Returns:
        A list of ``Record`` instances.

    Raises:
        AttributeError: If *tx* or *txin* is malformed.
    """
    records: list[Record] = []
    parsed_sig = list(parse_script(txin.script_sig))
    if not parsed_sig:
        return records
    redeem_script = parsed_sig[-1] if isinstance(parsed_sig[-1], bytes) else b""
    redeem_type = classify_script_pubkey(
        redeem_script) if redeem_script else "unknown"

    witness_items = txin.witness.items
    # Determine script code from the redeem type
    script_code: bytes
    if redeem_type == P2WPKH:
        script_code = p2wpkh_script_code(redeem_script)
    elif redeem_type == P2WSH:
        script_code = witness_items[-1] if witness_items else b""
    else:
        script_code = default_script_code()

    for item in witness_items[:-1]:
        if len(item) > 1:
            try:
                der = item[:-1]
                flag = item[-1]
                decode_der(der)
                pubkey = recover_or_parse_pubkey(
                    tx,
                    vin,
                    der,
                    flag,
                    script_code,
                    value=value,
                )
                if pubkey is None:
                    logger.debug(
                        "P2SH-SegWit pubkey recovery failed for input %d", vin)
                    continue
                records.append(
                    Record(
                        txid=tx.txid(),
                        input_index=vin,
                        signature=der,
                        public_key=pubkey,
                        script_type=f"p2sh_{redeem_type}",
                        sighash_flag=flag,
                        amount=value,
                    ))
                logger.debug("P2SH-SegWit signature extracted for input %d",
                             vin)
            except (ValueError, TypeError, IndexError) as exc:
                logger.warning("P2SH-SegWit signature skipped for input %d: %s",
                               vin, exc)
                continue
    return records


# ── Taproot extraction ────────────────────────────────────────────


def extract_taproot(
    tx: Tx,
    vin: int,
    script_pubkey: bytes,
    value: int,
    witness_items: tuple[bytes, ...],
) -> list[Record]:
    """Extract Schnorr signatures from a P2TR (Taproot) input.

    Handles both key-path spends (single 64/65-byte witness item) and
    script-path spends (multiple witness items where the last is the
    control block).  The public key is recovered from the P2TR
    ``scriptPubKey`` (x-only pubkey with even y-coordinate per BIP-340).

    Args:
        tx: The parent transaction.
        vin: Input index.
        script_pubkey: The P2TR ``scriptPubKey``.
        value: UTXO value in satoshis.
        witness_items: Witness stack items.

    Returns:
        A list of ``Record`` instances.

    Raises:
        AttributeError: If *tx* is malformed.
    """
    records: list[Record] = []
    if not witness_items:
        return records

    pubkey = pubkey_from_p2tr_script(script_pubkey)

    # Key-path spend: single witness item (signature)
    if len(witness_items) == 1:
        sig_bytes = witness_items[0]
        if len(sig_bytes) < 1:
            return records
        try:
            # Taproot signature: 64-byte Schnorr + optional sighash byte
            if len(sig_bytes) == 64:
                flag = SIGHASH_ALL
            elif len(sig_bytes) == 65:
                flag = sig_bytes[-1]
            else:
                return records
            records.append(
                Record(
                    txid=tx.txid(),
                    input_index=vin,
                    signature=sig_bytes,
                    public_key=pubkey,
                    script_type=P2TR,
                    sighash_flag=flag,
                    amount=value,
                ))
        except ValueError:
            logger.debug("Taproot key-path spend extraction failed for input %d", vin)
        return records




    # Script-path spend: stack is [sig, ..., script, control_block]
    last_idx = len(witness_items) - 1
    if last_idx < 1:
        return records
    for i in range(last_idx):
        item = witness_items[i]
        if len(item) < 1:
            continue
        try:
            if len(item) == 64 or len(item) == 65:
                sig_bytes = item[:64]
                flag = item[64] if len(item) == 65 else SIGHASH_ALL
                records.append(
                    Record(
                        txid=tx.txid(),
                        input_index=vin,
                        signature=sig_bytes,
                        public_key=pubkey,
                        script_type=P2TR,
                        sighash_flag=flag,
                        amount=value,
                    ))
        except ValueError:
            logger.debug("Taproot script-path item skipped for input %d", vin)
    return records


def pubkey_from_p2tr_script(script_pubkey: bytes) -> Point:
    """Recover the public key Point from a P2TR scriptPubKey.

    P2TR outputs contain a 32-byte x-only public key.  We reconstruct
    the full Point with even y-coordinate (BIP-340 convention) using
    ``Point.from_sec_compressed`` with a 0x02 prefix.

    Args:
        script_pubkey: The P2TR ``scriptPubKey`` (34 bytes:
            ``0x51 0x20 <32-byte-xonly>``).

    Returns:
        The public key ``Point``, or ``INFINITY`` if extraction fails.
    """
    if (len(script_pubkey) == 34 and script_pubkey[0] == 0x51 and
            script_pubkey[1] == 0x20):
        xonly = script_pubkey[2:34]
        try:
            return Point.from_sec_compressed(bytes([0x02]) + xonly)
        except ValueError:
            logger.debug("Failed to lift x-only pubkey from P2TR script")
    return INFINITY


# ── Public key recovery ───────────────────────────────────────────


def extract_pubkey_from_script_sig(
        script_sig: Sequence[object]) -> bytes | None:
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
        from bitcoin.curve import parse_public_key, is_on_curve
        try:
            point = parse_public_key(pubkey_bytes)
            if point is not None and not point.infinity and is_on_curve(point):
                return point
        except (ValueError, TypeError):
            logger.debug("Failed to parse fallback public key for input %d",
                         vin)
    return None


# ── Sighash computation ───────────────────────────────────────────


def compute_sighash(tx: Tx, vin: int, script: bytes, flag: int,
                    value: int) -> bytes:
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

    # A witness program is OP_0 followed by a 20- or 32-byte push.
    is_witness = (len(script) >= 2 and script[0] == 0x00
                  and script[1] in (0x14, 0x20))
    if is_witness:
        return sighash_segwit(tx, vin, script, value, flag)
    return sighash_legacy(tx, vin, script, flag)


# ── Script code helpers ───────────────────────────────────────────


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
        program = script_pubkey[
            2:] if script_pubkey[:1] == b"\x00" else script_pubkey
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
        raise ValueError(
            f"pubkey_hash must be 20 bytes, got {len(pubkey_hash)}")
    return b"".join([
        bytes([0x19]),  # length
        bytes([0x76]),  # OP_DUP
        bytes([0xA9]),  # OP_HASH160
        bytes([0x14]),  # OP_PUSH_20
        pubkey_hash,
        bytes([0x88]),  # OP_EQUALVERIFY
        bytes([0xAC]),  # OP_CHECKSIG
    ])


def default_script_code() -> bytes:
    """Return a fallback script code when the real one cannot be determined.

    Returns:
        22 zero bytes — a placeholder that will not match any real script.
    """
    return b"\x00" * 22
