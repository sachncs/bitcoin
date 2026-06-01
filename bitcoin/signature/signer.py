"""ECDSA signing utilities.

Provides ``sign`` for creating DER-encoded signatures from a message
hash and private key, and ``sign_tx_input`` for signing Bitcoin
transaction inputs using the appropriate sighash algorithm.
"""

from __future__ import annotations

import hashlib

from typing import TYPE_CHECKING

from bitcoin.curve import CURVE_ORDER, GENERATOR, multiply
from bitcoin.encoding.der import encode_der
from bitcoin.signature.extraction.engine import compute_sighash

if TYPE_CHECKING:
    from bitcoin.transaction.models import Tx


def sign(message_hash: bytes, private_key: int) -> bytes:
    """Create a DER-encoded ECDSA signature.

    Uses a simplified RFC 6979 deterministic nonce (SHA256 of the
    private key concatenated with the message hash) rather than the
    full HMAC-DRBG construction.

    Args:
        message_hash: 32-byte message hash.
        private_key: Private key as an integer.

    Returns:
        DER-encoded signature bytes (without a sighash byte).

    Raises:
        ValueError: If *message_hash* is not 32 bytes or the signing
            computation fails.
    """
    if len(message_hash) != 32:
        raise ValueError(
            f"Message hash must be 32 bytes, got {len(message_hash)}.")

    z = int.from_bytes(message_hash, "big")
    d = private_key

    # Deterministic k via simplified RFC 6979
    data = private_key.to_bytes(32, "big") + message_hash
    k = int.from_bytes(hashlib.sha256(data).digest(), "big") % CURVE_ORDER
    if k == 0:
        k = 1

    # R = k * G
    R = multiply(k, GENERATOR)
    if R.infinity:
        raise ValueError("Generated point at infinity during signing.")
    r_x = R.x
    if r_x is None:
        raise ValueError("R has no x coordinate.")
    r = r_x % CURVE_ORDER
    if r == 0:
        raise ValueError("Signature r is zero — try a different k.")

    # s = k^-1 * (z + r * d) mod n
    k_inv = pow(k, -1, CURVE_ORDER)
    s = (k_inv * (z + r * d)) % CURVE_ORDER
    if s == 0:
        raise ValueError("Signature s is zero.")

    return encode_der(r, s)


def sign_tx_input(
    tx: Tx,
    vin: int,
    private_key: int,
    *,
    script: bytes = b"",
    value: int = 0,
    sighash_flag: int = 1,
) -> bytes:
    """Sign a transaction input.

    Computes the appropriate sighash (legacy or SegWit depending on
    whether *tx* has witness data), signs it, and appends the sighash
    flag byte.

    Args:
        tx: The transaction containing the input to sign.
        vin: Index of the input being signed.
        private_key: Private key as an integer.
        script: Script code used for sighash computation (typically the
            ``scriptPubKey`` for legacy or the witness script for SegWit).
        value: UTXO value in satoshis (required for SegWit sighashes).
        sighash_flag: Sighash flag byte (default ``1`` = ``SIGHASH_ALL``).

    Returns:
        Signature bytes (DER-encoded signature + sighash flag byte).
    """
    message_hash = compute_sighash(tx, vin, script, sighash_flag, value)
    der_sig = sign(message_hash, private_key)
    return der_sig + bytes([sighash_flag])
