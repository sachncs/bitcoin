"""Linear coefficient derivation for ECDSA signature analysis.

Given a signature ``(r, s)`` on message hash ``z``, computes the
linearisation coefficients:
    α ≡ s · r⁻¹  (mod n)
    β ≡ z · r⁻¹  (mod n)
such that ``d = α · k − β  (mod n)`` for private key ``d`` and nonce ``k``.
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
