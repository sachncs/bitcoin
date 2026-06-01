"""ECDSA nonce recovery and private-key recovery from signature weaknesses.

Given two signatures created by the same private key, this module exploits:

- **Nonce reuse** (same ``r``): :math:`k_1 = k_2`
  :math:`d = \\alpha_1 \\cdot k - \\beta_1 \\pmod{n}`

- **Related nonces** (:math:`k_2 = k_1 + \\delta`):
  :math:`k_1 = (\\beta_1 - \\beta_2 + \\alpha_2 \\cdot \\delta)`
  :math:`\\cdot (\\alpha_1 - \\alpha_2)^{-1} \\pmod{n}`
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Sequence

from bitcoin.field import inverse as field_inverse
from bitcoin.curve.params import CURVE_ORDER
from bitcoin.exceptions import BitcoinError
from bitcoin.signature.linearization.coefficients import (
    LinearCoefficientCollection,
    LinearCoefficientRecord,
    derive_linear_coefficients,
)


class NonceRecoveryError(BitcoinError):
    """Raised when nonce or private-key recovery fails."""


class SameNonceError(NonceRecoveryError):
    """Raised when two signatures have different ``r`` values."""


class NoNonceReuseError(NonceRecoveryError):
    """Raised when no nonce reuse can be detected."""


@dataclass(frozen=True, slots=True)
class RecoveredKey:
    """Result of a successful private-key and nonce recovery.

    Attributes:
        private_key: The recovered private key ``d``.
        nonce: The recovered nonce ``k``.
        input_index_1: Index of the first signature used.
        input_index_2: Index of the second signature used.
    """

    private_key: int
    nonce: int
    input_index_1: int
    input_index_2: int


@dataclass(frozen=True, slots=True)
class NonceReuseGroup:
    """Group of signatures sharing the same ``r`` value.

    Attributes:
        r: The shared ``r`` value.
        indices: Indices (into the original collection) of the grouped
            signatures.
    """

    r: int
    indices: tuple[int, ...]

    @property
    def count(self) -> int:
        """Number of signatures in this group."""
        return len(self.indices)


def recover_from_nonce_reuse(
    record_1: LinearCoefficientRecord,
    record_2: LinearCoefficientRecord,
) -> RecoveredKey:
    """Recover the private key and nonce from two signatures sharing the same ``r``.

    When the same nonce ``k`` is used twice with the same private key ``d``,
    the two signatures share the same ``r`` value.

    Args:
        record_1: First signature (linear coefficient record).
        record_2: Second signature (must have same ``r``).

    Returns:
        The recovered private key and nonce.

    Raises:
        SameNonceError: If the ``r`` values differ.
    """
    if record_1.r != record_2.r:
        raise SameNonceError(
            f"r values differ (0x{record_1.r:x} != 0x{record_2.r:x}).")

    alpha_diff = (record_1.alpha - record_2.alpha) % CURVE_ORDER
    if alpha_diff == 0:
        raise SameNonceError(
            "alpha values are identical; signatures may not be from"
            " the same private key.")

    beta_diff = (record_1.beta - record_2.beta) % CURVE_ORDER
    alpha_diff_inv = field_inverse(alpha_diff, CURVE_ORDER)
    nonce = (beta_diff * alpha_diff_inv) % CURVE_ORDER
    private_key = (record_1.alpha * nonce - record_1.beta) % CURVE_ORDER

    return RecoveredKey(
        private_key=private_key,
        nonce=nonce,
        input_index_1=record_1.input_index,
        input_index_2=record_2.input_index,
    )


def recover_from_related_nonces(
    record_1: LinearCoefficientRecord,
    record_2: LinearCoefficientRecord,
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
        SameNonceError: If :math:`\\alpha_1 - \\alpha_2` has no modular inverse.
    """
    alpha_diff = (record_1.alpha - record_2.alpha) % CURVE_ORDER
    if alpha_diff == 0:
        raise SameNonceError("alpha values are identical; cannot solve for k1.")

    beta_diff = (record_1.beta - record_2.beta) % CURVE_ORDER
    alpha_diff_inv = field_inverse(alpha_diff, CURVE_ORDER)

    delta_mod = delta % CURVE_ORDER
    nonce_1 = (
        (beta_diff + record_2.alpha * delta_mod) * alpha_diff_inv) % CURVE_ORDER
    private_key = (record_1.alpha * nonce_1 - record_1.beta) % CURVE_ORDER

    return RecoveredKey(
        private_key=private_key,
        nonce=nonce_1,
        input_index_1=record_1.input_index,
        input_index_2=record_2.input_index,
    )


def detect_nonce_reuse(
    collection: LinearCoefficientCollection,) -> list[NonceReuseGroup]:
    """Find groups of signatures that share the same ``r`` value.

    Args:
        collection: Linear coefficients to scan.

    Returns:
        A list of ``NonceReuseGroup`` instances (one per distinct ``r`` with
        2+ occurrences), sorted by descending count.
    """
    r_to_indices: defaultdict[int, list[int]] = defaultdict(list)

    for idx, record in enumerate(collection.records):
        r_to_indices[record.r].append(idx)

    groups: list[NonceReuseGroup] = []
    for r, indices in r_to_indices.items():
        if len(indices) >= 2:
            groups.append(NonceReuseGroup(r=r, indices=tuple(indices)))

    groups.sort(key=lambda g: g.count, reverse=True)
    return groups


__all__ = [
    "LinearCoefficientCollection",
    "LinearCoefficientRecord",
    "NonceReuseGroup",
    "NonceRecoveryError",
    "NoNonceReuseError",
    "RecoveredKey",
    "SameNonceError",
    "derive_linear_coefficients",
    "detect_nonce_reuse",
    "recover_from_nonce_reuse",
    "recover_from_related_nonces",
]
