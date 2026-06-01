"""ECDSA signature types, extraction, linearization, verification, and signing."""

from bitcoin.signature.attack import NonceReuseGroup
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
from bitcoin.signature.batch_verify import batch_verify
from bitcoin.signature.signer import sign, sign_tx_input

__all__ = [
    "BatchResult",
    "NonceReuseGroup",
    "Record",
    "SignatureCollection",
    "batch_extract",
    "batch_verify",
    "batch_extract_from_file",
    "correlate_across_transactions",
    "extract_signatures",
    "lift_x",
    "linearize_signatures",
    "merge_records",
    "recover_public_key",
    "sign",
    "sign_tx_input",
    "verify_sig",
    "verify_schnorr_sig",
]
