# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Finite-field arithmetic helpers used by secp256k1.

Provides modular arithmetic primitives needed by the curve layer:

- :mod:`bitcoin.field.modular` – modular inverse via the extended
  Euclidean algorithm and non-negative integer validation.
- :mod:`bitcoin.field.sqrt` – modular square root via Tonelli-Shanks,
  specialised to the case ``p ≡ 3 (mod 4)`` (which secp256k1's
  field prime satisfies, giving the closed-form solution
  ``sqrt(a) = a^((p+1)/4) mod p``).

All functions operate on Python ``int`` values, so the size of the
modulus is limited only by available memory.  The Tonelli-Shanks
specialisation assumes the caller passes a prime modulus and does
**not** verify primality — callers must ensure correctness of the
modulus they pass (the dispatch layer uses
:data:`bitcoin.curve.params.FIELD_PRIME` which is a well-known prime).
"""

from bitcoin.field.modular import inverse, validate_non_negative
from bitcoin.field.sqrt import pow_mod, sqrt

__all__ = [
    "inverse",
    "pow_mod",
    "sqrt",
    "validate_non_negative",
]
