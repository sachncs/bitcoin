"""Pluggable ECC backend interface for secp256k1 operations."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from bitcoin.ecc import Secp256k1Point

__all__ = [
    "EccBackend",
    "get_backend",
    "set_backend",
]


class EccBackend(ABC):
    """Abstract interface for secp256k1 elliptic-curve backends."""

    @abstractmethod
    def point_negate(self, point: Secp256k1Point) -> Secp256k1Point:
        ...

    @abstractmethod
    def point_add(self, left: Secp256k1Point,
                  right: Secp256k1Point) -> Secp256k1Point:
        ...

    @abstractmethod
    def point_double(self, point: Secp256k1Point) -> Secp256k1Point:
        ...

    @abstractmethod
    def scalar_multiply(self, scalar: int,
                        point: Secp256k1Point) -> Secp256k1Point:
        ...

    @abstractmethod
    def is_on_curve(self, x: int, y: int) -> bool:
        ...

    @abstractmethod
    def field_sqrt(self, value: int) -> int:
        ...

    @abstractmethod
    def parse_sec_public_key(self, data: bytes) -> Secp256k1Point:
        ...

    @abstractmethod
    def serialize_sec_public_key(self,
                                 point: Secp256k1Point,
                                 compressed: bool = True) -> bytes:
        ...


_BACKEND: EccBackend | None = None


def get_backend() -> EccBackend | None:
    """Return the currently active ECC backend, or None if using the default."""
    global _BACKEND
    return _BACKEND


def set_backend(backend: EccBackend) -> None:
    """Set the active ECC backend.

    All subsequent calls to ``ecc`` module functions will dispatch through
    this backend for supported operations.

    Args:
        backend: An ``EccBackend`` instance.

    Raises:
        TypeError: If *backend* is not an ``EccBackend`` instance.
    """
    if not isinstance(backend, EccBackend):
        raise TypeError(
            f"Expected EccBackend instance, got {type(backend).__name__}.")
    global _BACKEND
    _BACKEND = backend
