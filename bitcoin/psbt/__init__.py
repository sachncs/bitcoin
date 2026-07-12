# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Partially Signed Bitcoin Transaction (PSBT) types, parsing, editing, and extraction.

Implements BIP-174 (and the BIP-174 + Taproot extensions implicitly
via unknown-key preservation).  The subpackage contains:

- :mod:`bitcoin.psbt.models` – frozen dataclasses :class:`Psbt`,
  :class:`PsbtInput`, :class:`PsbtOutput` with serialise / extract
  methods.
- :mod:`bitcoin.psbt.parser` – BIP-174 binary reader and writer,
  including the key-type constants, witness-stack parsing, the
  BIP-32 keypath parser, and the in-memory
  :func:`parse_psbt_impl` helper shared with the file entry point.
- :mod:`bitcoin.psbt.editor` – :class:`PsbtEditor` fluent API for
  programmatically constructing or signing a PSBT.
- :mod:`bitcoin.psbt.extraction` – :func:`psbt_extract_signatures` and
  the helper that finds the public key in a parsed script.
- :mod:`bitcoin.psbt.pipeline` – :func:`process_psbt_batch` /
  :func:`process_psbt_batch_with` for parallel PSBT file processing
  with structured logging and graceful error capture.  The
  :func:`parse_psbt_worker` callable is also re-exported for
  callers that want to drive the process pool directly.

Defensive limits
----------------

:mod:`bitcoin.psbt.parser` enforces four safety limits on untrusted
input:

- :data:`MAX_KEY_VALUE_MAP_ENTRIES` – number of key-value pairs per
  map.
- :data:`MAX_KEY_SIZE` – size of a single key.
- :data:`MAX_VALUE_SIZE` – size of a single value.
- :data:`MAX_PSBT_WITNESS_ITEMS` / :data:`MAX_PSBT_WITNESS_ITEM_SIZE`
  – per-input witness stack bounds.

These defaults are deliberately generous (a real mainnet PSBT has at
most a few dozen entries per map and kilobyte-sized values).
"""

from bitcoin.psbt.editor import PsbtEditor
from bitcoin.psbt.models import Psbt, PsbtInput, PsbtOutput
from bitcoin.psbt.parser import (
    parse_keypath_value,
    parse_psbt,
    parse_psbt_from_file,
    parse_psbt_hex,
    parse_psbt_impl,
    psbt_extract_signatures,
    serialize_psbt,
)
from bitcoin.psbt.pipeline import (
    parse_psbt_worker,
    process_psbt_batch,
    process_psbt_batch_with,
)

__all__ = [
    "Psbt",
    "PsbtEditor",
    "PsbtInput",
    "PsbtOutput",
    "parse_keypath_value",
    "parse_psbt",
    "parse_psbt_from_file",
    "parse_psbt_hex",
    "parse_psbt_impl",
    "parse_psbt_worker",
    "process_psbt_batch",
    "process_psbt_batch_with",
    "psbt_extract_signatures",
    "serialize_psbt",
]
