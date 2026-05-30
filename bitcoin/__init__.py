"""Bitcoin transaction signature extraction package."""

from bitcoin.batch import BatchProcessor, SignatureStream, batch_process
from bitcoin.coincurve_backend import CoincurveBackend
from bitcoin.config import Config
from bitcoin.ecc import (
    SECP256K1_INFINITY,
    G,
    LinearPointRelation,
    LinearPointRelationCollection,
    Secp256k1Point,
    TransformedPointCollection,
    TransformedPointRecord,
    derive_point_relation,
    derive_transformed_point,
    field_sqrt,
    inverse_mod,
    is_on_curve,
    normalize_field_element,
    normalize_non_negative,
    parse_sec_public_key,
    point_add,
    point_double,
    point_negate,
    scalar_multiply,
    serialize_sec_public_key,
)
from bitcoin.ecc_backend import EccBackend, get_backend, set_backend
from bitcoin.linear import LinearCoefficientCollection, LinearCoefficientRecord
from bitcoin.models import SignatureRecord
from bitcoin.psbt import Psbt, PsbtInput, PsbtOutput, parse_psbt, parse_psbt_hex
from bitcoin.signature import SignatureCollection
from bitcoin.transaction import Transaction
from bitcoin.utils import hash160, sha256d

__all__ = [
    "BatchProcessor",
    "CoincurveBackend",
    "Config",
    "EccBackend",
    "G",
    "LinearCoefficientCollection",
    "LinearCoefficientRecord",
    "LinearPointRelation",
    "LinearPointRelationCollection",
    "Psbt",
    "PsbtInput",
    "PsbtOutput",
    "SECP256K1_INFINITY",
    "Secp256k1Point",
    "SignatureCollection",
    "SignatureRecord",
    "SignatureStream",
    "Transaction",
    "TransformedPointCollection",
    "TransformedPointRecord",
    "batch_process",
    "derive_point_relation",
    "derive_transformed_point",
    "field_sqrt",
    "get_backend",
    "hash160",
    "inverse_mod",
    "is_on_curve",
    "normalize_field_element",
    "normalize_non_negative",
    "parse_psbt",
    "parse_psbt_hex",
    "parse_sec_public_key",
    "point_add",
    "point_double",
    "point_negate",
    "scalar_multiply",
    "serialize_sec_public_key",
    "set_backend",
    "sha256d",
]
