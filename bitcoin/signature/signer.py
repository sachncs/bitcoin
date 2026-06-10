"""ECDSA signing utilities.

Provides ``sign`` for creating DER-encoded signatures from a message
hash and private key, and ``sign_tx_input`` for signing Bitcoin
transaction inputs using the appropriate sighash algorithm.
"""

from __future__ import annotations

import hmac
from typing import TYPE_CHECKING

from bitcoin.curve import CURVE_ORDER, GENERATOR, multiply
from bitcoin.encoding.der import encode_der
from bitcoin.signature.extraction.engine import compute_sighash

if TYPE_CHECKING:
    from bitcoin.transaction.models import Tx

HASH_BYTE_LENGTH = 32
HMAC_DRBG_MAX_RETRIES = 1000


def bits2int(data: bytes) -> int:
    """Convert bytes to an integer, right-shifted to match curve order bit length.

    Args:
        data: The bytes to convert.

    Returns:
        The integer value right-shifted by ``(8 * len(data) - qlen)`` bits.
    """
    return int.from_bytes(data, "big") >> (len(data) * 8 - CURVE_ORDER.bit_length())


def hmac_drbg_generate_k(private_key_bytes: bytes,
                         message_hash: bytes,
                         q: int = CURVE_ORDER) -> int:
    """Generate a deterministic nonce *k* via RFC 6979 HMAC-DRBG.

    Args:
        private_key_bytes: 32-byte big-endian encoding of the private key.
        message_hash: 32-byte message hash (``H(m)``).
        q: Curve order (default ``CURVE_ORDER``).

    Returns:
        A non-zero integer *k* in ``[1, q-1]``.
    """
    qlen = q.bit_length()
    rolen = (qlen + 7) // 8

    K = b"\x00" * HASH_BYTE_LENGTH
    V = b"\x01" * HASH_BYTE_LENGTH

    K = hmac.new(K, V + b"\x00" + private_key_bytes + message_hash, "sha256").digest()
    V = hmac.new(K, V, "sha256").digest()

    K = hmac.new(K, V + b"\x01" + private_key_bytes + message_hash, "sha256").digest()
    V = hmac.new(K, V, "sha256").digest()

    for _ in range(HMAC_DRBG_MAX_RETRIES):
        T = b""
        while len(T) < rolen:
            V = hmac.new(K, V, "sha256").digest()
            T += V

        k = bits2int(T[:rolen])
        if 1 <= k < q:
            return k

        K = hmac.new(K, V + b"\x00", "sha256").digest()
        V = hmac.new(K, V, "sha256").digest()

    raise RuntimeError(f"HMAC-DRBG failed to generate a valid k after "
                       f"{HMAC_DRBG_MAX_RETRIES} attempts.")


def sign(message_hash: bytes, private_key: int) -> bytes:
    """Create a DER-encoded ECDSA signature.

    Uses the full RFC 6979 HMAC-DRBG construction (section 3.2) to
    generate a deterministic nonce *k*.

    Args:
        message_hash: 32-byte message hash.
        private_key: Private key as an integer.

    Returns:
        DER-encoded signature bytes (without a sighash byte).

    Raises:
        ValueError: If *message_hash* is not 32 bytes or the signing
            computation fails.
    """
    if len(message_hash) != HASH_BYTE_LENGTH:
        raise ValueError(f"Message hash must be {HASH_BYTE_LENGTH} bytes, "
                         f"got {len(message_hash)}.")

    z = int.from_bytes(message_hash, "big") % CURVE_ORDER
    d = private_key

    x = private_key.to_bytes(HASH_BYTE_LENGTH, "big")
    h1 = message_hash
    k = hmac_drbg_generate_k(x, h1)

    R = multiply(k, GENERATOR)
    if R.infinity:
        raise ValueError("Generated point at infinity during signing.")
    r_x = R.x
    if r_x is None:
        raise ValueError("R has no x coordinate.")
    r = r_x % CURVE_ORDER
    if r == 0:
        raise ValueError("Signature r is zero — try a different k.")

    k_inv = pow(k, -1, CURVE_ORDER)
    s = (k_inv * (z + r * d)) % CURVE_ORDER
    if s == 0:
        raise ValueError("Signature s is zero.")

    # Wipe sensitive values from the stack frame to reduce
    # exposure in core dumps / memory snapshots.
    x = b"\x00" * len(x)
    k = 0
    k_inv = 0
    d = 0
    z = 0

    return encode_der(r, s)


def sign_tx_input(
    transaction: Tx,
    input_index: int,
    private_key: int,
    *,
    script: bytes = b"",
    value: int = 0,
    sighash_flag: int = 1,
) -> bytes:
    """Sign a transaction input.

    Computes the appropriate sighash (legacy or SegWit depending on
    whether *transaction* has witness data), signs it, and appends the
    sighash flag byte.

    Args:
        transaction: The transaction containing the input to sign.
        input_index: Index of the input being signed.
        private_key: Private key as an integer.
        script: Script code used for sighash computation (typically the
            ``scriptPubKey`` for legacy or the witness script for SegWit).
        value: UTXO value in satoshis (required for SegWit sighashes).
        sighash_flag: Sighash flag byte (default ``1`` = ``SIGHASH_ALL``).

    Returns:
        Signature bytes (DER-encoded signature + sighash flag byte).
    """
    message_hash = compute_sighash(transaction, input_index, script, sighash_flag,
                                   value)
    der_signature = sign(message_hash, private_key)
    return der_signature + bytes([sighash_flag])
