# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Linear coefficient derivation for ECDSA signature analysis.

Given an ECDSA signature triple ``(r, s, z)``, the standard ECDSA
verification equation

    s · k ≡ z + r · d    (mod n)

can be rewritten as

    d = α · k − β        (mod n)

where

    α ≡ s · r⁻¹  (mod n)
    β ≡ z · r⁻¹  (mod n)

This module provides:

- :class:`LinearCoefficientRecord` – a frozen dataclass storing
  ``(α, β)`` alongside the original ``(r, s, z)`` triple and the
  input-index / script-type metadata needed for analysis.
- :class:`LinearCoefficientCollection` – an immutable tuple of
  :class:`LinearCoefficientRecord` with ``alpha`` / ``beta`` list
  views.
- :func:`derive_linear_coefficients` – compute ``α`` and ``β`` for a
  single signature.

Once a collection is built, the
:func:`~bitcoin.signature.attack.detect_nonce_reuse` scan finds all
groups of records sharing an ``r`` value, and
:func:`~bitcoin.signature.attack.recover_from_nonce_reuse` /
:func:`~bitcoin.signature.attack.recover_from_related_nonces` use
the coefficients to recover the private key in microseconds.

Reference: "ECDSA nonce reuse" — see the docstring of
:mod:`bitcoin.signature.attack` for the algebraic derivation.
"""

from __future__ import annotations

from dataclasses import dataclass

from bitcoin.curve.params import CURVE_ORDER
from bitcoin.field import inverse


@dataclass(frozen=True, slots=True)
class LinearCoefficientRecord:
    """A single linearised signature relation — ``(α, β)`` with metadata.

    Attributes:
        input_index: Transaction input index.
        r: The ``r`` value (x-coordinate of nonce point).
        s: The ``s`` value.
        z: The message hash (integer).
        alpha: ``s · r⁻¹  (mod n)``.
        beta: ``z · r⁻¹  (mod n)``.
        sighash_flag: SIGHASH flag byte.
        script_type: Script type identifier (e.g. ``"p2pkh"``).
    """

    input_index: int
    r: int
    s: int
    z: int
    alpha: int
    beta: int
    sighash_flag: int
    script_type: str


@dataclass(frozen=True, slots=True)
class LinearCoefficientCollection:
    """Immutable collection of ``LinearCoefficientRecord`` instances.

    Attributes:
        records: Tuple of linear coefficient records in order.
    """

    records: tuple[LinearCoefficientRecord, ...]

    @property
    def alpha(self) -> list[int]:
        """List of all α values from the contained records."""
        return [r.alpha for r in self.records]

    @property
    def beta(self) -> list[int]:
        """List of all β values from the contained records."""
        return [r.beta for r in self.records]


def derive_linear_coefficients(
    r: int,
    s: int,
    z: int,
    *,
    input_index: int = 0,
    sighash_flag: int = 1,
    script_type: str = "p2pkh",
) -> LinearCoefficientRecord:
    """Compute linear coefficients from raw signature integers.

    Args:
        r: The ``r`` value of the ECDSA signature.
        s: The ``s`` value.
        z: The message hash.
        input_index: Transaction input index.
        sighash_flag: SIGHASH flag byte.
        script_type: Script type identifier (e.g. ``"p2pkh"``).

    Returns:
        A ``LinearCoefficientRecord`` with derived α and β.
    """
    r_inv = inverse(r, CURVE_ORDER) if r else 0
    alpha = (s * r_inv) % CURVE_ORDER
    beta = (z * r_inv) % CURVE_ORDER
    return LinearCoefficientRecord(
        input_index=input_index,
        r=r,
        s=s,
        z=z,
        alpha=alpha,
        beta=beta,
        sighash_flag=sighash_flag,
        script_type=script_type,
    )
