"""Tests for the batch/streaming module."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from bitcoin.batch import SignatureStream, batch_process
from bitcoin.models import SignatureRecord
from tests.test_transaction import build_p2pkh_transaction
from bitcoin.transaction import Transaction


def test_signature_stream_empty() -> None:
    raw_hex, _, _ = build_p2pkh_transaction()
    tx = Transaction.parse_hex(raw_hex)
    stream = SignatureStream(tx)
    records = list(stream)
    assert len(records) == 1
    assert isinstance(records[0], SignatureRecord)


def test_signature_stream_filter() -> None:
    raw_hex, _, _ = build_p2pkh_transaction()
    tx = Transaction.parse_hex(raw_hex)
    stream = SignatureStream(tx)
    filtered = stream.filter(lambda r: r.script_type == "legacy-p2pkh")
    records = list(filtered)
    assert len(records) == 1


def test_signature_stream_collect() -> None:
    raw_hex, _, _ = build_p2pkh_transaction()
    tx = Transaction.parse_hex(raw_hex)
    stream = SignatureStream(tx)
    records = stream.collect()
    assert len(records) == 1


def test_signature_stream_to_collection() -> None:
    raw_hex, _, _ = build_p2pkh_transaction()
    tx = Transaction.parse_hex(raw_hex)
    stream = SignatureStream(tx)
    coll = stream.to_collection()
    assert len(coll.records) == 1


def test_batch_process_sequential() -> None:
    from bitcoin.fetcher import fetch_transaction

    raw_hex, _, _ = build_p2pkh_transaction()
    tx = Transaction.parse_hex(raw_hex)
    with patch("bitcoin.batch.fetch_transaction", return_value=tx):
        results = batch_process("a" * 64,
                                network="mainnet",
                                timeout=5,
                                mp=False)
    assert len(results) == 1
    assert len(results[0].records) >= 1


@pytest.mark.skipif(
    True,
    reason=
    "multiprocessing.Pool does not propagate unittest.mock patches to worker processes",
)
def test_batch_process_multiprocessing() -> None:
    """Structural smoke-test for the multiprocessing code path.

    This test verifies that the multiprocessing branch of ``batch_process``
    compiles and runs without import errors.  Mocking does not propagate to
    worker processes, so real network calls are avoided by marking as skip.
    """
    from bitcoin.fetcher import fetch_transaction

    raw_hex, _, _ = build_p2pkh_transaction()
    tx = Transaction.parse_hex(raw_hex)
    with patch("bitcoin.batch.fetch_transaction", return_value=tx):
        results = batch_process("a" * 64,
                                "b" * 64,
                                network="mainnet",
                                timeout=5,
                                mp=True)
    assert len(results) == 2
