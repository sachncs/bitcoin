# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""ECDSA and Schnorr signature types.

This subpackage is the analytical heart of the library: it takes raw
transactions as input and produces structured ``Record`` objects
containing the ``(r, s, z)`` triple needed for nonce-reuse analysis.

Submodules:

- :mod:`bitcoin.signature.record` – the :class:`Record` dataclass and
  its convenience properties.
- :mod:`bitcoin.signature.collection` – :class:`SignatureCollection`
  and the ``sort_records`` helper.
- :mod:`bitcoin.signature.check` – ECDSA verification and public-key
  recovery from signatures.
- :mod:`bitcoin.signature.batch_verify` – sequential verification of
  multiple signatures.
- :mod:`bitcoin.signature.schnorr` – BIP-340 Schnorr verification and
  the ``lift_x`` helper.
- :mod:`bitcoin.signature.signer` – RFC-6979 deterministic ECDSA
  signing and the high-level :func:`sign_tx_input` helper.
- :mod:`bitcoin.signature.extraction` – :class:`ExtractorPlugin`
  registry and the polymorphic ``extract_signatures`` dispatcher
  that handles every standard script type.
- :mod:`bitcoin.signature.linearization` – derivation of the
  ``(α, β)`` linear coefficients used by the nonce-reuse attack.
- :mod:`bitcoin.signature.attack` – nonce-reuse detection and
  private-key recovery.
- :mod:`bitcoin.signature.pipeline` – batch and parallel extraction
  with graceful shutdown, per-batch logging, and cross-transaction
  correlation.

The two halves of the pipeline (``extraction`` and ``linearization``)
are deliberately decoupled: the extractor produces raw records, and
the lineariser produces the algebraic coefficients.  This lets
attack code work on either form without depending on parsing logic.
"""

from bitcoin.signature.attack import NonceReuseGroup
from bitcoin.signature.batch_verify import batch_verify, verify_all
from bitcoin.signature.check import recover_public_key, verify_sig
from bitcoin.signature.collection import SignatureCollection
from bitcoin.signature.extraction import extract_signatures
from bitcoin.signature.linearization import linearize_signatures
from bitcoin.signature.pipeline import (
    BatchResult,
    batch_extract,
    batch_extract_from_file,
    correlate_across_transactions,
    merge_records,
)
from bitcoin.signature.record import Record
from bitcoin.signature.schnorr import lift_x, verify_schnorr_sig
from bitcoin.signature.signer import sign, sign_tx_input

__all__ = [
    "BatchResult",
    "NonceReuseGroup",
    "Record",
    "SignatureCollection",
    "batch_extract",
    "batch_extract_from_file",
    "batch_verify",
    "correlate_across_transactions",
    "extract_signatures",
    "lift_x",
    "linearize_signatures",
    "merge_records",
    "recover_public_key",
    "sign",
    "sign_tx_input",
    "verify_all",
    "verify_sig",
    "verify_schnorr_sig",
]
