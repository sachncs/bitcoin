# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Secp256k1 curve parameters (SEC-1 / SEC-2, ANSI X9.62).

Defines the secp256k1 Koblitz curve used by Bitcoin:

    y² = x³ + a · x + b  (mod p)

with ``a = 0`` (the curve has no ``x`` term).

Constants
---------

- ``FIELD_PRIME`` (``p``): 256-bit prime defining the underlying field.
- ``CURVE_A``: curve coefficient ``a = 0``.
- ``CURVE_B``: curve coefficient ``b = 7``.
- ``CURVE_ORDER`` (``n``): prime order of the generator point.
- ``GENERATOR_X`` / ``GENERATOR_Y``: affine coordinates of the
  standard generator ``G``.

References
----------

- SEC-2 v2.0: "Recommended Elliptic Curve Domain Parameters"
- ANSI X9.62-2005: "Public Key Cryptography for the Financial Services
  Industry"
"""

# y² = x³ + CURVE_A · x + CURVE_B  over GF(FIELD_PRIME).
FIELD_PRIME = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
CURVE_A = 0
CURVE_B = 7
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

GENERATOR_X = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GENERATOR_Y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
