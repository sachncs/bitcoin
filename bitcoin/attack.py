"""ECDSA nonce recovery and private key recovery from signature weaknesses.

Given two signatures from the same private key, this module exploits:

- **Nonce reuse** (same ``r``): :math:`k_1 = k_2`
  :math:`d = \\alpha_1 \\cdot k - \\beta_1 \\pmod{n}`

- **Related nonces** (:math:`k_2 = k_1 + \\delta`):
  :math:`k_1 = (\\beta_1 - \\beta_2 + \\alpha_2 \\cdot \\delta)`
  :math:`\\cdot (\\alpha_1 - \\alpha_2)^{-1} \\pmod{n}`
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass

from bitcoin.arithmetic import inverse_mod as arithmetic_inverse
from bitcoin.exceptions import BitcoinError
from bitcoin.linear import (
    SECP256K1_ORDER,
    LinearCoefficientCollection,
    LinearCoefficientRecord,
    derive_linear_coefficients,
)
from bitcoin.models import SignatureRecord
from bitcoin.signature import SignatureCollection

logger = logging.getLogger(__name__)


class NonceRecoveryError(BitcoinError):
    """Raised when nonce or key recovery fails."""


class SameNonceError(NonceRecoveryError):
    """Raised when two signatures have different r values."""


class NoNonceReuseError(NonceRecoveryError):
    """Raised when no nonce reuse is detected."""


@dataclass(frozen=True, slots=True)
class RecoveredKey:
    """Result of a successful private-key and nonce recovery."""

    private_key: int
    nonce: int
    input_index_1: int
    input_index_2: int


@dataclass(frozen=True, slots=True)
class NonceReuseGroup:
    """Group of signatures sharing the same ``r`` value."""

    r: int
    indices: tuple[int, ...]

    @property
    def count(self) -> int:
        return len(self.indices)


def recover_from_nonce_reuse(
    record_1: SignatureRecord | LinearCoefficientRecord,
    record_2: SignatureRecord | LinearCoefficientRecord,
) -> RecoveredKey:
    """Recover the private key and nonce from two signatures sharing the same ``r``.

    When the same nonce ``k`` is used twice with the same private key ``d``,
    the two signatures share the same ``r`` value.

    Args:
        record_1: First signature.
        record_2: Second signature (must have same ``r``).

    Returns:
        The recovered private key and nonce.

    Raises:
        SameNonceError: If the ``r`` values differ.
        NonInvertibleLinearCoefficientError: If :math:`\\alpha_1 - \\alpha_2`
            has no modular inverse.
    """
    lin_1 = _to_linear(record_1)
    lin_2 = _to_linear(record_2)

    if lin_1.r != lin_2.r:
        raise SameNonceError(
            f"r values differ (0x{lin_1.r:x} != 0x{lin_2.r:x}).")

    alpha_diff = (lin_1.alpha - lin_2.alpha) % SECP256K1_ORDER
    if alpha_diff == 0:
        raise SameNonceError(
            "alpha values are identical; signatures may not be from"
            " the same private key.")

    beta_diff = (lin_1.beta - lin_2.beta) % SECP256K1_ORDER
    alpha_diff_inv = arithmetic_inverse(alpha_diff, SECP256K1_ORDER)
    nonce = (beta_diff * alpha_diff_inv) % SECP256K1_ORDER
    private_key = (lin_1.alpha * nonce - lin_1.beta) % SECP256K1_ORDER

    return RecoveredKey(
        private_key=private_key,
        nonce=nonce,
        input_index_1=lin_1.input_index,
        input_index_2=lin_2.input_index,
    )


def recover_from_related_nonces(
    record_1: SignatureRecord | LinearCoefficientRecord,
    record_2: SignatureRecord | LinearCoefficientRecord,
    delta: int,
) -> RecoveredKey:
    """Recover the private key and nonce when :math:`k_2 = k_1 + \\delta`.

    Args:
        record_1: First signature (nonce :math:`k_1`).
        record_2: Second signature (nonce :math:`k_2 = k_1 + \\delta`).
        delta: The known difference :math:`\\delta`.

    Returns:
        The recovered private key and nonce :math:`k_1`.

    Raises:
        NonInvertibleLinearCoefficientError: If :math:`\\alpha_1 - \\alpha_2`
            has no modular inverse.
    """
    lin_1 = _to_linear(record_1)
    lin_2 = _to_linear(record_2)

    alpha_diff = (lin_1.alpha - lin_2.alpha) % SECP256K1_ORDER
    if alpha_diff == 0:
        raise SameNonceError("alpha values are identical; cannot solve for k1.")

    beta_diff = (lin_1.beta - lin_2.beta) % SECP256K1_ORDER
    alpha_diff_inv = arithmetic_inverse(alpha_diff, SECP256K1_ORDER)

    delta_mod = delta % SECP256K1_ORDER
    nonce_1 = ((beta_diff + lin_2.alpha * delta_mod) *
               alpha_diff_inv) % SECP256K1_ORDER
    private_key = (lin_1.alpha * nonce_1 - lin_1.beta) % SECP256K1_ORDER

    return RecoveredKey(
        private_key=private_key,
        nonce=nonce_1,
        input_index_1=lin_1.input_index,
        input_index_2=lin_2.input_index,
    )


def detect_nonce_reuse(
    collection: SignatureCollection | LinearCoefficientCollection,
) -> list[NonceReuseGroup]:
    """Find groups of signatures that share the same ``r`` value.

    Args:
        collection: Extracted signatures or linear coefficients.

    Returns:
        A list of groups (one per distinct ``r`` with 2+ occurrences),
        sorted by descending count.
    """
    r_to_indices: defaultdict[int, list[int]] = defaultdict(list)

    if isinstance(collection, SignatureCollection):
        coeffs = collection.linear()
    else:
        coeffs = collection

    for idx, record in enumerate(coeffs.records):
        r_to_indices[record.r].append(idx)

    groups: list[NonceReuseGroup] = []
    for r, indices in r_to_indices.items():
        if len(indices) >= 2:
            groups.append(NonceReuseGroup(r=r, indices=tuple(indices)))

    groups.sort(key=lambda g: g.count, reverse=True)
    return groups


def _to_linear(
    record: SignatureRecord | LinearCoefficientRecord,
) -> LinearCoefficientRecord:
    """Convert a ``SignatureRecord`` to ``LinearCoefficientRecord`` if needed."""
    if isinstance(record, LinearCoefficientRecord):
        return record
    return derive_linear_coefficients(record)


# ── Helpers ──────────────────────────────────────────────────────────────

__all__ = [
    "NonceReuseGroup",
    "NonceRecoveryError",
    "NoNonceReuseError",
    "RecoveredKey",
    "SameNonceError",
    "detect_nonce_reuse",
    "recover_from_nonce_reuse",
    "recover_from_related_nonces",
]
