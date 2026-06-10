"""Taproot (BIP-341) sighash computation.

Implements the BIP-341 signature hash algorithm, supporting both key-path
and script-path spending, with correct handling of all SIGHASH flags.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from bitcoin.encoding.hasher import tagged_hash
from bitcoin.encoding.varint import encode_varint
from bitcoin.sighash.flag import (
    SIGHASH_ANYONECANPAY,
    SIGHASH_MASK,
    SIGHASH_NONE,
    SIGHASH_SINGLE,
)

if TYPE_CHECKING:
    from bitcoin.transaction.models import Tx

NO_CODESEPARATOR = 0xFFFFFFFF

# BIP-341 hash_type extension byte values
HASH_TYPE_KEY_PATH = 0
HASH_TYPE_SCRIPT_PATH = 1


def sighash_taproot(
    transaction: Tx,
    input_index: int,
    script: bytes | None,
    sighash_flag: int,
    *,
    extension: bytes = b"",
    tapleaf_hash: bytes | None = None,
    key_version: int = 0,
    codeseparator_position: int = NO_CODESEPARATOR,
    annex: bytes | None = None,
    amounts: tuple[int, ...] | None = None,
) -> bytes:
    """Compute the BIP-341 Taproot sighash for a transaction input.

    Supports both key-path (``script=None``) and script-path spending.
    The hash is computed as ``tagged_hash("TapSighash", ...)``.

    NOTE: BIP-341 requires the UTXO value for **every** input.  When
    *amounts* is ``None`` the amounts are treated as zero, which
    produces a non-standard sighash.  Callers MUST provide *amounts*
    for signature verification to be compliant.

    Args:
        transaction: The transaction.
        input_index: Index of the input being signed.
        script: The script being executed, or ``None`` for key-path
            spending.
        sighash_flag: SIGHASH flag byte (``0x00`` for default, or
            standard sighash values ``0x01``–``0x83``).
        extension: Extra data for future extensions (default ``b""``).
        tapleaf_hash: The ``tapleaf_hash`` as defined in BIP-341.
            Required when *script* is not ``None``.
        key_version: Key version byte (``0`` for current BIP-341
            specification).
        codeseparator_position: Position of the last
            ``OP_CODESEPARATOR`` executed (default ``0xFFFFFFFF``).
        annex: Optional annex data (BIP-341).
        amounts: Tuple of UTXO values (one per input).  When ``None``
            all amounts default to zero.

    Returns:
        The 32-byte tagged sighash digest.

    Raises:
        IndexError: If *input_index* is out of range for the
            transaction inputs.
        ValueError: If *script* is provided but *tapleaf_hash* is
            ``None``, or if ``SIGHASH_SINGLE`` is used with an
            out-of-range index.
    """

    if input_index >= len(transaction.inputs):
        raise IndexError("Input index out of range.")
    inp = transaction.inputs[input_index]

    base_flag = sighash_flag & SIGHASH_MASK

    data = bytearray()
    data.extend(sighash_flag.to_bytes(1, "little"))
    data.extend(extension)

    # ── Hash type (key-path vs. script-path) ──────────────────────
    if script is not None:
        if tapleaf_hash is None:
            raise ValueError("tapleaf_hash required for script-path signing.")
        data.extend(HASH_TYPE_SCRIPT_PATH.to_bytes(1, "little"))
        data.extend(tapleaf_hash)
        data.extend(key_version.to_bytes(1, "little"))
        data.extend(codeseparator_position.to_bytes(4, "little"))
    else:
        data.extend(HASH_TYPE_KEY_PATH.to_bytes(1, "little"))

    # ── Spent outputs (outpoints) ─────────────────────────────────
    if sighash_flag & SIGHASH_ANYONECANPAY:
        data.extend(encode_varint(1))
        data.extend(inp.previous_output.txid)
        data.extend(inp.previous_output.vout.to_bytes(4, "little"))
    else:
        data.extend(encode_varint(len(transaction.inputs)))
        for txin in transaction.inputs:
            data.extend(txin.previous_output.txid)
            data.extend(txin.previous_output.vout.to_bytes(4, "little"))

    # ── Input amounts (BIP-341 requires all or ACP only) ──────────
    if amounts is not None:
        if sighash_flag & SIGHASH_ANYONECANPAY:
            data.extend(encode_varint(1))
            data.extend(amounts[input_index].to_bytes(8, "little"))
        else:
            data.extend(encode_varint(len(amounts)))
            for amt in amounts:
                data.extend(amt.to_bytes(8, "little"))
    else:
        # Fallback: zero amounts (non-standard but preserves the API)
        if sighash_flag & SIGHASH_ANYONECANPAY:
            data.extend(encode_varint(1))
            data.extend(b"\x00" * 8)
        else:
            data.extend(encode_varint(len(transaction.inputs)))
            for _ in transaction.inputs:
                data.extend(b"\x00" * 8)

    # ── Input script pubkeys (empty for Taproot) ──────────────────
    if sighash_flag & SIGHASH_ANYONECANPAY:
        data.extend(encode_varint(1))
        data.append(0x00)
    else:
        n_inputs = len(transaction.inputs)
        data.extend(encode_varint(n_inputs))
        for _ in transaction.inputs:
            data.append(0x00)

    # ── Input sequences ───────────────────────────────────────────
    if sighash_flag & SIGHASH_ANYONECANPAY:
        data.extend(encode_varint(1))
        data.extend(inp.sequence.to_bytes(4, "little"))
    elif base_flag in (SIGHASH_NONE, SIGHASH_SINGLE):
        n_inputs = len(transaction.inputs)
        data.extend(encode_varint(n_inputs))
        for _ in transaction.inputs:
            data.extend(b"\x00\x00\x00\x00")
    else:
        n_inputs = len(transaction.inputs)
        data.extend(encode_varint(n_inputs))
        for txin in transaction.inputs:
            data.extend(txin.sequence.to_bytes(4, "little"))

    # ── Outputs ───────────────────────────────────────────────────
    if base_flag == SIGHASH_NONE:
        data.append(0x00)
    elif base_flag == SIGHASH_SINGLE:
        if input_index >= len(transaction.outputs):
            raise ValueError(f"Input index {input_index} out of bounds for "
                             f"SIGHASH_SINGLE with {len(transaction.outputs)} outputs.")
        data.extend(encode_varint(1))
        out = transaction.outputs[input_index]
        data.extend(out.value.to_bytes(8, "little"))
        data.extend(encode_varint(len(out.script_pubkey)))
        data.extend(out.script_pubkey)
    else:
        data.extend(encode_varint(len(transaction.outputs)))
        for txout in transaction.outputs:
            data.extend(txout.value.to_bytes(8, "little"))
            data.extend(encode_varint(len(txout.script_pubkey)))
            data.extend(txout.script_pubkey)

    # ── Annex ─────────────────────────────────────────────────────
    if annex is not None:
        data.append(0x01)
        data.extend(annex)
    else:
        data.append(0x00)

    # ── Script (script-path only) ─────────────────────────────────
    if script is not None:
        data.extend(encode_varint(len(script)))
        data.extend(script)

    return tagged_hash("TapSighash", bytes(data))
