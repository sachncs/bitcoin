"""Strict DER signature parsing."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from bitcoin.exceptions import InvalidDerSignatureError

logger = logging.getLogger(__name__)

__all__ = [
    "ParsedSignature",
    "parse_der_signature",
    "validate_der_integer",
]


@dataclass(frozen=True, slots=True)
class ParsedSignature:
    """Represents a parsed DER signature."""

    r: bytes
    s: bytes
    sighash_flag: int


def parse_der_signature(signature: bytes) -> ParsedSignature:
    """Parse a DER-encoded ECDSA signature with a trailing sighash byte."""
    if len(signature) < 9:
        logger.warning("Signature too short: %d bytes", len(signature))
        raise InvalidDerSignatureError("Signature is too short.")
    if len(signature) > 73:
        logger.warning("Signature too long: %d bytes", len(signature))
        raise InvalidDerSignatureError("Signature is too long.")

    sighash_flag = signature[-1]
    der = signature[:-1]

    if der[0] != 0x30:
        raise InvalidDerSignatureError("DER sequence tag is missing.")
    if der[1] != len(der) - 2:
        raise InvalidDerSignatureError("DER length is inconsistent.")
    if der[2] != 0x02:
        raise InvalidDerSignatureError("DER R integer tag is missing.")

    rend = 4 + der[3]
    r = der[4:rend]
    if der[rend] != 0x02:
        raise InvalidDerSignatureError("DER S integer tag is missing.")

    sstart = rend + 2
    s = der[sstart:]

    validate_der_integer(r, "R")
    validate_der_integer(s, "S")

    return ParsedSignature(r=r, s=s, sighash_flag=sighash_flag)


def validate_der_integer(value: bytes, label: str) -> None:
    """Validate a DER-encoded integer is non-negative and properly encoded."""
    if len(value) == 0:
        raise InvalidDerSignatureError(f"DER {label} integer is empty.")
    if value[0] & 0x80:
        raise InvalidDerSignatureError(f"DER {label} integer is negative.")
    if len(value) > 1 and value[0] == 0x00 and not (value[1] & 0x80):
        raise InvalidDerSignatureError(
            f"DER {label} integer has a leading zero.")
