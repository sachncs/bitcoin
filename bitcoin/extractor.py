"""Signature extraction from parsed transactions."""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING

from bitcoin.der import parse_der_signature
from bitcoin.exceptions import MissingInputValueError, UnsupportedScriptPathError
from bitcoin.models import SignatureRecord, TransactionContext, TransactionInput
from bitcoin.script import (
    chunks_to_pushes,
    is_p2pkh_pushes,
    is_taproot,
    is_taproot_script_path,
    is_witness_program,
    make_p2pkh_script,
    parse_multisig_redeem_script,
    parse_script,
)
from bitcoin.sighash import (
    legacy_sighash,
    p2wpkh_script_code,
    segwit_sighash,
    taproot_sighash,
)
from bitcoin.signature import SignatureCollection
from bitcoin.utils import bytes_to_hex

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from bitcoin.transaction import Transaction

__all__ = [
    "build_records",
    "extract_input_signatures",
    "extract_legacy_p2pkh",
    "extract_legacy_p2sh_multisig",
    "extract_native_p2wpkh",
    "extract_native_p2wsh_multisig",
    "extract_p2sh_p2wpkh",
    "extract_p2sh_p2wsh_multisig",
    "extract_signatures",
    "extract_taproot_key_path",
    "extract_taproot_script_path",
    "resolve_input_value",
]


def extract_signatures(
    transaction: Transaction,
    script_pubkeys: Sequence[bytes] | None = None,
) -> SignatureCollection:
    """Extract all ECDSA signatures from a parsed transaction."""
    records: list[SignatureRecord] = []
    for input_index, txin in enumerate(transaction.inputs):
        records.extend(
            extract_input_signatures(transaction, input_index, txin,
                                     transaction.context, script_pubkeys))
    return SignatureCollection(records=tuple(records))


def extract_input_signatures(
    transaction: Transaction,
    input_index: int,
    txin: TransactionInput,
    context: TransactionContext | None,
    script_pubkeys: Sequence[bytes] | None = None,
) -> list[SignatureRecord]:
    """Extract signatures from a single tx input, dispatching by script type."""
    script_chunks = parse_script(txin.script_sig)
    script_pushes = chunks_to_pushes(script_chunks)
    witness_items = list(txin.witness)

    # Taproot detection
    if witness_items:
        script_pubkey = script_pubkeys[input_index] if script_pubkeys else None
        if script_pubkey and is_taproot(script_pubkey):
            if len(witness_items) == 1:
                return extract_taproot_key_path(
                    transaction,
                    input_index,
                    txin,
                    script_pubkey,
                    context,
                    script_pubkeys,
                )
            if is_taproot_script_path(witness_items):
                return extract_taproot_script_path(
                    transaction,
                    input_index,
                    txin,
                    script_pubkey,
                    context,
                    script_pubkeys,
                )

    if not witness_items:
        if is_p2pkh_pushes(script_pushes):
            return extract_legacy_p2pkh(transaction, input_index, txin,
                                        script_pushes)
        if script_pushes and script_pushes[-1]:
            return extract_legacy_p2sh_multisig(transaction, input_index, txin,
                                                script_pushes)
        logger.error("Unsupported non-SegWit script path at input %d",
                     input_index)
        raise UnsupportedScriptPathError("Unsupported non-SegWit script path.")

    if not txin.script_sig:
        if len(witness_items) == 2 and len(witness_items[1]) in {33, 65}:
            return extract_native_p2wpkh(transaction, input_index, txin,
                                         witness_items, context)
        if len(witness_items) >= 2:
            return extract_native_p2wsh_multisig(transaction, input_index, txin,
                                                 witness_items, context)
        logger.error(
            "Unsupported SegWit witness stack at input %d: %d items",
            input_index,
            len(witness_items),
        )
        raise UnsupportedScriptPathError("Unsupported SegWit witness stack.")

    if len(script_pushes) == 1 and is_witness_program(script_pushes[0]):
        program = script_pushes[0]
        if len(program) == 22:
            return extract_p2sh_p2wpkh(transaction, input_index, txin,
                                       witness_items, context)
        if len(program) == 34:
            return extract_p2sh_p2wsh_multisig(transaction, input_index, txin,
                                               witness_items, context)

    logger.error(
        "Unsupported script path at input %d: witness=%s, script_sig_len=%d",
        input_index,
        bool(witness_items),
        len(txin.script_sig),
    )
    raise UnsupportedScriptPathError("Unsupported script path.")


# ── Unified record builder ───────────────────────────────────────────────


def build_records(
    transaction: Transaction,
    input_index: int,
    txin: TransactionInput,
    context: TransactionContext | None,
    raw_signatures: Sequence[bytes],
    script_code: bytes,
    pubkeys: Sequence[bytes | None],
    script_type: str,
    use_segwit: bool,
) -> list[SignatureRecord]:
    """Build signature records from raw DER signatures, computing signature hashes."""
    records: list[SignatureRecord] = []
    amount = resolve_input_value(context, input_index) if use_segwit else None

    for index, raw_sig in enumerate(raw_signatures):
        parsed = parse_der_signature(raw_sig)
        if use_segwit:
            digest = segwit_sighash(transaction, input_index, script_code,
                                    amount, parsed.sighash_flag)
        else:
            digest = legacy_sighash(transaction, input_index, script_code,
                                    parsed.sighash_flag)
        public_key = pubkeys[index] if index < len(pubkeys) else None
        records.append(
            SignatureRecord(
                r=bytes_to_hex(parsed.r),
                s=bytes_to_hex(parsed.s),
                z=bytes_to_hex(digest),
                sighash_flag=parsed.sighash_flag,
                input_index=input_index,
                public_key=bytes_to_hex(public_key)
                if public_key is not None else None,
                script_type=script_type,
            ))
    return records


# ── Concrete extractors (thin wrappers around build_records) ────────────


def extract_legacy_p2pkh(
    transaction: Transaction,
    input_index: int,
    txin: TransactionInput,
    pushes: list[bytes],
) -> list[SignatureRecord]:
    """Extract a signature from a legacy P2PKH input."""
    signature = pushes[0]
    pubkey = pushes[1]
    return build_records(
        transaction,
        input_index,
        txin,
        None,
        raw_signatures=[signature],
        script_code=make_p2pkh_script(pubkey),
        pubkeys=[pubkey],
        script_type="legacy-p2pkh",
        use_segwit=False,
    )


def extract_legacy_p2sh_multisig(
    transaction: Transaction,
    input_index: int,
    txin: TransactionInput,
    pushes: list[bytes],
) -> list[SignatureRecord]:
    """Extract signatures from a legacy P2SH multisig input."""
    if len(pushes) < 2:
        raise UnsupportedScriptPathError("P2SH multisig script is too short.")
    redeem_script = pushes[-1]
    raw_signatures = [item for item in pushes[:-1] if item]
    _, pubkeys = parse_multisig_redeem_script(redeem_script)
    return build_records(
        transaction,
        input_index,
        txin,
        None,
        raw_signatures=raw_signatures,
        script_code=redeem_script,
        pubkeys=pubkeys,
        script_type="legacy-p2sh-multisig",
        use_segwit=False,
    )


def extract_native_p2wpkh(
    transaction: Transaction,
    input_index: int,
    txin: TransactionInput,
    witness_items: list[bytes],
    context: TransactionContext | None,
) -> list[SignatureRecord]:
    """Extract a signature from a native SegWit P2WPKH input."""
    signature = witness_items[0]
    pubkey = witness_items[1]
    return build_records(
        transaction,
        input_index,
        txin,
        context,
        raw_signatures=[signature],
        script_code=p2wpkh_script_code(pubkey),
        pubkeys=[pubkey],
        script_type="segwit-v0-p2wpkh",
        use_segwit=True,
    )


def extract_p2sh_p2wpkh(
    transaction: Transaction,
    input_index: int,
    txin: TransactionInput,
    witness_items: list[bytes],
    context: TransactionContext | None,
) -> list[SignatureRecord]:
    """Extract a signature from a P2SH-wrapped P2WPKH input."""
    if len(witness_items) != 2:
        raise UnsupportedScriptPathError(
            "P2SH-P2WPKH witness stack is invalid.")
    signature = witness_items[0]
    pubkey = witness_items[1]
    return build_records(
        transaction,
        input_index,
        txin,
        context,
        raw_signatures=[signature],
        script_code=p2wpkh_script_code(pubkey),
        pubkeys=[pubkey],
        script_type="segwit-v0-p2sh-p2wpkh",
        use_segwit=True,
    )


def extract_native_p2wsh_multisig(
    transaction: Transaction,
    input_index: int,
    txin: TransactionInput,
    witness_items: list[bytes],
    context: TransactionContext | None,
) -> list[SignatureRecord]:
    """Extract signatures from a native SegWit P2WSH multisig input."""
    witness_script = witness_items[-1]
    raw_signatures = [item for item in witness_items[:-1] if item]
    _, pubkeys = parse_multisig_redeem_script(witness_script)
    return build_records(
        transaction,
        input_index,
        txin,
        context,
        raw_signatures=raw_signatures,
        script_code=witness_script,
        pubkeys=pubkeys,
        script_type="segwit-v0-p2wsh",
        use_segwit=True,
    )


def extract_p2sh_p2wsh_multisig(
    transaction: Transaction,
    input_index: int,
    txin: TransactionInput,
    witness_items: list[bytes],
    context: TransactionContext | None,
) -> list[SignatureRecord]:
    """Extract signatures from a P2SH-wrapped P2WSH multisig input."""
    if len(witness_items) < 2:
        raise UnsupportedScriptPathError("P2SH-P2WSH witness stack is invalid.")
    witness_script = witness_items[-1]
    raw_signatures = [item for item in witness_items[:-1] if item]
    _, pubkeys = parse_multisig_redeem_script(witness_script)
    return build_records(
        transaction,
        input_index,
        txin,
        context,
        raw_signatures=raw_signatures,
        script_code=witness_script,
        pubkeys=pubkeys,
        script_type="segwit-v0-p2sh-p2wsh",
        use_segwit=True,
    )


# ── Taproot extractors ──────────────────────────────────────────────────


def extract_taproot_key_path(
    transaction: Transaction,
    input_index: int,
    txin: TransactionInput,
    script_pubkey: bytes,
    context: TransactionContext | None,
    script_pubkeys: Sequence[bytes] | None,
) -> list[SignatureRecord]:
    """Extract a signature from a Taproot key-path spend (single witness item)."""
    witness_items = list(txin.witness)
    signature = witness_items[0]
    parsed = parse_der_signature(signature)
    amount = resolve_input_value(context, input_index)
    if amount is None:
        raise MissingInputValueError(
            f"Taproot key path spend at input {input_index} "
            f"needs the spent output value.")
    internal_pubkey = script_pubkey[2:34]
    spk_list = list(script_pubkeys) if script_pubkeys else [script_pubkey]
    digest = taproot_sighash(transaction, input_index, script_pubkey, amount,
                             parsed.sighash_flag, spk_list)
    return [
        SignatureRecord(
            r=bytes_to_hex(parsed.r),
            s=bytes_to_hex(parsed.s),
            z=bytes_to_hex(digest),
            sighash_flag=parsed.sighash_flag,
            input_index=input_index,
            public_key=bytes_to_hex(internal_pubkey),
            script_type="segwit-v1-taproot-keypath",
        )
    ]


def extract_taproot_script_path(
    transaction: Transaction,
    input_index: int,
    txin: TransactionInput,
    script_pubkey: bytes,
    context: TransactionContext | None,
    script_pubkeys: Sequence[bytes] | None,
) -> list[SignatureRecord]:
    """Extract signatures from a Taproot script-path spend."""
    witness_items = list(txin.witness)
    witness_script = witness_items[-2]
    raw_signatures = [item for item in witness_items[:-2] if item]

    script_chunks = parse_script(witness_script)
    pushes = chunks_to_pushes(script_chunks)
    pubkeys = [p for p in pushes if len(p) in {32, 33}]

    amount = resolve_input_value(context, input_index)
    if amount is None:
        raise MissingInputValueError(
            f"Taproot script path spend at input {input_index} "
            f"needs the spent output value.")

    spk_list = list(script_pubkeys) if script_pubkeys else [script_pubkey]

    records: list[SignatureRecord] = []
    for index, raw_sig in enumerate(raw_signatures):
        parsed = parse_der_signature(raw_sig)
        digest = taproot_sighash(
            transaction,
            input_index,
            witness_script,
            amount,
            parsed.sighash_flag,
            spk_list,
            spend_type=0xC0,
        )
        public_key = pubkeys[index] if index < len(pubkeys) else None
        records.append(
            SignatureRecord(
                r=bytes_to_hex(parsed.r),
                s=bytes_to_hex(parsed.s),
                z=bytes_to_hex(digest),
                sighash_flag=parsed.sighash_flag,
                input_index=input_index,
                public_key=bytes_to_hex(public_key)
                if public_key is not None else None,
                script_type="segwit-v1-taproot-scriptpath",
            ))
    return records


def resolve_input_value(context: TransactionContext | None,
                        input_index: int) -> int | None:
    """Return the spent output value for an input from the transaction context."""
    if context is None:
        return None
    if input_index >= len(context.input_values):
        raise MissingInputValueError(
            f"Input index {input_index} exceeds context "
            f"({len(context.input_values)} values available).")
    return context.input_values[input_index]
