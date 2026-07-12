# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Low-level binary encodings and hash primitives for Bitcoin.

A small, dependency-free toolkit covering every binary encoding needed
to read and write Bitcoin wire-format structures:

- :mod:`bitcoin.encoding.binary` – ``bytes_to_int``/``int_to_bytes``
  plus :func:`read_exactly` and :func:`iter_bytes`.
- :mod:`bitcoin.encoding.hex` – :func:`encode_hex` / :func:`decode_hex`.
- :mod:`bitcoin.encoding.varint` – Bitcoin variable-length integer
  (``compact size``) codec.
- :mod:`bitcoin.encoding.der` – DER signature codec used by ECDSA.
- :mod:`bitcoin.encoding.sec` – SEC-1 public-key codec.
- :mod:`bitcoin.encoding.hasher` – SHA-256, double-SHA-256, HASH-160,
  and BIP-340 tagged hash.

None of these helpers perform any I/O or hold any state; they are
suitable for use in hot paths.
"""

from bitcoin.encoding.binary import bytes_to_int, int_to_bytes, iter_bytes, read_exactly
from bitcoin.encoding.der import decode_der, encode_der
from bitcoin.encoding.hasher import hash160, hash256, sha256, tagged_hash
from bitcoin.encoding.hex import decode_hex, encode_hex
from bitcoin.encoding.sec import parse_sec, serialize_sec
from bitcoin.encoding.varint import decode_varint, encode_varint

__all__ = [
    "bytes_to_int",
    "decode_der",
    "decode_hex",
    "decode_varint",
    "encode_der",
    "encode_hex",
    "encode_varint",
    "hash160",
    "hash256",
    "int_to_bytes",
    "iter_bytes",
    "parse_sec",
    "read_exactly",
    "serialize_sec",
    "sha256",
    "tagged_hash",
]
