"""Coincurve-based secp256k1 backend using libsecp256k1."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from bitcoin.ecc_backend import EccBackend

if TYPE_CHECKING:
    from bitcoin.ecc import Secp256k1Point

logger = logging.getLogger(__name__)

__all__ = [
    "CoincurveBackend",
    "check_coincurve",
]


class CoincurveBackend(EccBackend):
    """ECC backend backed by coincurve (libsecp256k1 C bindings)."""

    def __init__(self) -> None:
        check_coincurve()

    def point_negate(self, point: Secp256k1Point) -> Secp256k1Point:
        # coincurve doesn't expose raw point negation; fall back
        from bitcoin.ecc import point_negate_py

        return point_negate_py(point)

    def point_add(self, left: Secp256k1Point,
                  right: Secp256k1Point) -> Secp256k1Point:
        # coincurve doesn't expose raw point addition; fall back
        from bitcoin.ecc import point_add_py

        return point_add_py(left, right)

    def point_double(self, point: Secp256k1Point) -> Secp256k1Point:
        from bitcoin.ecc import point_double_py

        return point_double_py(point)

    def scalar_multiply(self, scalar: int,
                        point: Secp256k1Point) -> Secp256k1Point:
        import coincurve

        from bitcoin.ecc import (
            SECP256K1_ORDER,
            parse_sec_py,
            serialize_sec_py,
        )

        if point.infinity:
            from bitcoin.ecc import SECP256K1_INFINITY

            return SECP256K1_INFINITY

        scalar %= SECP256K1_ORDER
        if scalar == 0:
            from bitcoin.ecc import SECP256K1_INFINITY

            return SECP256K1_INFINITY

        sec = serialize_sec_py(point, compressed=True)
        pub = coincurve.PublicKey(sec)
        tweak = scalar.to_bytes(32, "big")
        new_pub = pub.multiply(tweak)
        raw = new_pub.format(compressed=True)
        return parse_sec_py(raw)

    def is_on_curve(self, x: int, y: int) -> bool:
        import coincurve

        from bitcoin.ecc import int_to_bytes

        sec = b"\x04" + int_to_bytes(x) + int_to_bytes(y)
        try:
            coincurve.PublicKey(sec)
            return True
        except ValueError:
            logger.warning("coincurve rejected point (x=%d, y=%d) as invalid",
                           x, y)
            return False

    def field_sqrt(self, value: int) -> int:
        from bitcoin.ecc import field_sqrt_py

        return field_sqrt_py(value)

    def parse_sec_public_key(self, data: bytes) -> Secp256k1Point:
        import coincurve

        from bitcoin.ecc import Secp256k1Point

        pub = coincurve.PublicKey(data)
        raw = pub.format(compressed=False)
        x = int.from_bytes(raw[1:33], "big")
        y = int.from_bytes(raw[33:], "big")
        return Secp256k1Point(x=x, y=y, infinity=False)

    def serialize_sec_public_key(self,
                                 point: Secp256k1Point,
                                 compressed: bool = True) -> bytes:
        import coincurve

        from bitcoin.ecc import InvalidSecPublicKeyError, serialize_sec_py

        if point.infinity:
            raise InvalidSecPublicKeyError("Cannot serialize infinity point")

        xu = serialize_sec_py(point, compressed=False)
        pub = coincurve.PublicKey(xu)
        return pub.format(compressed=compressed)


def check_coincurve() -> None:
    try:
        import coincurve  # noqa: F401
    except ImportError:
        msg = ("coincurve is required for the CoincurveBackend. "
               "Install it with: pip install bitcoin[coincurve]")
        raise ImportError(msg) from None
    logger.debug(
        "CoincurveBackend initialized; point_negate, point_add, point_double "
        "will fall back to pure Python (coincurve does not expose those operations)."
    )
