"""Utility helpers for Bitcoin parsing and serialization."""

from __future__ import annotations

import hashlib
import logging
import re

from bitcoin.exceptions import (
    InvalidHexError,
    MalformedVarintError,
    TruncatedTransactionError,
)

logger = logging.getLogger(__name__)

HEX_PATTERN = re.compile(r"^[0-9a-fA-F]*$")

__all__ = [
    "ByteReader",
    "HEX_PATTERN",
    "bytes_to_hex",
    "hash160",
    "int_to_hex",
    "int_to_little_endian_bytes",
    "little_endian_bytes_to_int",
    "sha256d",
    "validate_hex_string",
]


def validate_hex_string(text: str) -> bytes:
    """Validate a hex string and return the decoded bytes."""
    stripped = text.strip()
    if not stripped:
        raise InvalidHexError("Transaction hex is empty.")
    if len(stripped) % 2 != 0:
        raise InvalidHexError("Transaction hex must have an even length.")
    if not HEX_PATTERN.fullmatch(stripped):
        raise InvalidHexError("Transaction hex contains non-hex characters.")
    return bytes.fromhex(stripped)


def bytes_to_hex(data: bytes) -> str:
    """Encode bytes as a lowercase hex string."""
    return data.hex()


def int_to_hex(value: int) -> str:
    """Format a non-negative integer as a lowercase hex string."""
    if value < 0:
        raise ValueError("Integer value must be non-negative.")
    return format(value, "x")


def little_endian_bytes_to_int(data: bytes) -> int:
    """Convert little-endian bytes to an integer."""
    return int.from_bytes(data, byteorder="little", signed=False)


def int_to_little_endian_bytes(value: int, length: int) -> bytes:
    """Serialize a non-negative integer as little-endian bytes of the given length."""
    if value < 0:
        raise ValueError("Integer values must be non-negative.")
    return value.to_bytes(length, byteorder="little", signed=False)


def sha256d(data: bytes) -> bytes:
    """Return the double-SHA256 hash of the input."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def hash160(data: bytes) -> bytes:
    """Return the HASH160 (SHA256 followed by RIPEMD160) of the input."""
    sha_digest = hashlib.sha256(data).digest()
    try:
        ripe_digest = hashlib.new("ripemd160", sha_digest).digest()
    except ValueError as error:
        raise RuntimeError("RIPEMD160 is not available in hashlib.") from error
    return ripe_digest


class ByteReader:
    """Reads transaction bytes with explicit bounds checks."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.position = 0

    def remaining(self) -> int:
        return len(self.data) - self.position

    def read(self, length: int) -> bytes:
        if length < 0:
            raise ValueError("Length must be non-negative.")
        end = self.position + length
        if end > len(self.data):
            raise TruncatedTransactionError("Transaction ended unexpectedly.")
        chunk = self.data[self.position:end]
        self.position = end
        return chunk

    def read_uint8(self) -> int:
        return self.read(1)[0]

    def read_uint16(self) -> int:
        return little_endian_bytes_to_int(self.read(2))

    def read_uint32(self) -> int:
        return little_endian_bytes_to_int(self.read(4))

    def read_uint64(self) -> int:
        return little_endian_bytes_to_int(self.read(8))

    def read_varint(self) -> int:
        prefix = self.read_uint8()
        if prefix < 0xFD:
            return prefix
        if prefix == 0xFD:
            value = self.read_uint16()
            if value < 0xFD:
                raise MalformedVarintError("Non-minimal compact size integer.")
            return value
        if prefix == 0xFE:
            value = self.read_uint32()
            if value <= 0xFFFF:
                raise MalformedVarintError("Non-minimal compact size integer.")
            return value
        value = self.read_uint64()
        if value <= 0xFFFFFFFF:
            raise MalformedVarintError("Non-minimal compact size integer.")
        return value

    def read_varbytes(self) -> bytes:
        length = self.read_varint()
        return self.read(length)
