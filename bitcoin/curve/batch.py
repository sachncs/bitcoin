# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Batched elliptic-curve operations.

Provides multi-exponentiation via **Straus's algorithm** (a.k.a.
interleaved windowing) and batch helpers for on-curve validation and
coordinate normalisation.  These routines trade a constant-factor
amount of memory for a substantial speedup when the same point is
used in many multiplications, or when many independent multiplications
can be interleaved.

Algorithms:

- :func:`multi_multiply` implements Straus's algorithm: build a
  4-bit window table per input point, then process all points in lock
  step across the windows.  Worst case ``O(n · log s)`` group
  operations for ``n`` pairs ``(scalar, point)`` with maximum scalar
  bit-length ``s``, much better than ``O(n · s)`` for sequential
  scalar multiplications.
- :func:`batch_validate` is a convenience wrapper that calls the
  (cached) :func:`bitcoin.curve.dispatch.is_on_curve` dispatch for
  each point.
- :func:`batch_normalize` reduces every affine coordinate modulo
  ``FIELD_PRIME`` in a single pass; useful after arithmetic that may
  have produced values outside the canonical range.
"""

from __future__ import annotations

from bitcoin.curve.dispatch import add, double
from bitcoin.curve.point import Point

INFINITY = Point(infinity=True)


def multi_multiply(pairs: list[tuple[int, Point]]) -> Point:
    """Return the sum of scalar-point products using Straus's algorithm.

    ``sum(scalar_i * point_i for scalar_i, point_i in pairs)``

    Uses a 4-bit window for each point and processes all points
    simultaneously, which is significantly faster than sequential
    multiply-and-add for small-to-moderate batch sizes.

    Args:
        pairs: A list of ``(scalar, point)`` pairs.

    Returns:
        The resulting point, or the point at infinity if *pairs* is
        empty or all scalars are zero.
    """
    if not pairs:
        return INFINITY

    # Determine the number of 4-bit windows needed.
    max_bits = max(s.bit_length() for s, _ in pairs)
    num_windows = (max_bits + 3) // 4
    if num_windows == 0:
        return INFINITY

    # Build look-up tables: table[i][w] = w * point_i  for w = 0..15
    tables: list[list[Point]] = []
    for _, point in pairs:
        tbl: list[Point] = [INFINITY, point]
        for i in range(2, 16):
            tbl.append(add(tbl[i - 1], point))
        tables.append(tbl)

    result = INFINITY
    for j in range(num_windows - 1, -1, -1):
        for _ in range(4):
            result = double(result)
        for i, (scalar, _) in enumerate(pairs):
            w = (scalar >> (j * 4)) & 0xF
            if w:
                result = add(result, tables[i][w])
    return result


def batch_validate(points: list[Point]) -> list[bool]:
    """Check whether each point lies on the secp256k1 curve.

    Uses cached ``is_on_curve`` dispatch; this is mainly a convenience
    wrapper for bulk validation.

    Args:
        points: A list of ``Point`` instances.

    Returns:
        A list of booleans parallel to *points*.
    """
    from bitcoin.curve.dispatch import is_on_curve

    return [is_on_curve(p) for p in points]


def batch_normalize(points: list[Point]) -> list[Point]:
    """Normalize (reduce coordinates modulo FIELD_PRIME) many points.

    Args:
        points: A list of ``Point`` instances.

    Returns:
        A list of normalized points.
    """
    from bitcoin.curve.dispatch import normalize

    result: list[Point] = []
    for p in points:
        if p.infinity:
            result.append(p)
        else:
            result.append(
                Point(
                    x=normalize(p.x) if p.x is not None else None,
                    y=normalize(p.y) if p.y is not None else None,
                )
            )
    return result


__all__ = [
    "batch_normalize",
    "batch_validate",
    "multi_multiply",
]
