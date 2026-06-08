"""CLI integration tests using typer.testing.CliRunner."""
from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from bitcoin.cli.app import app

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "bitcoin v" in result.stdout


def test_extract_no_signatures() -> None:
    # Minimal valid tx with 0 inputs, 0 outputs
    result = runner.invoke(app, ["extract", "010000000000000000"])
    assert result.exit_code == 0
    assert "No signatures found" in result.stdout


def test_extract_p2pkh() -> None:
    # A simple P2PKH tx: version(4) + inputs(1) + outputs(1) + locktime(4)
    # This is a 1-input 1-output P2PKH transaction
    tx_hex = "".join([
        "01000000",  # version
        "01",  # input count
        "abcd1234" * 8,  # prevout hash (32 bytes)
        "01000000",  # prevout index
        "00",  # scriptSig length (empty — no sig for CLI test)
        "ffffffff",  # sequence
        "01",  # output count
        "00e1f50500000000",  # value
        "1976a914000000000000000000000000000000000000000088ac",  # scriptPubKey
        "00000000",  # locktime
    ])
    result = runner.invoke(app, ["extract", tx_hex])
    assert result.exit_code == 0
    # No signatures in scriptSig
    assert "No signatures found" in result.stdout


def test_linearize_empty() -> None:
    result = runner.invoke(app, ["linearize", "010000000000000000"])
    assert result.exit_code == 0


def test_parse_input_values() -> None:
    from bitcoin.cli.app import parse_input_values

    assert parse_input_values("") == []
    assert parse_input_values("100,200,300") == [100, 200, 300]
    assert parse_input_values("100,,300") == [100, None, 300]
    assert parse_input_values("   ") == []


def test_decode_empty() -> None:
    result = runner.invoke(app, ["decode", "010000000000000000"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["version"] == 1
    assert data["lock_time"] == 0
    assert data["inputs"] == []
    assert data["outputs"] == []


def test_decode_with_tx() -> None:
    tx_hex = "".join([
        "01000000",
        "01",
        "abcd1234" * 8,
        "01000000",
        "00",
        "ffffffff",
        "01",
        "00e1f50500000000",
        "1976a914000000000000000000000000000000000000000088ac",
        "00000000",
    ])
    result = runner.invoke(app, ["decode", tx_hex])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["version"] == 1
    assert len(data["inputs"]) == 1
    assert len(data["outputs"]) == 1
    assert data["inputs"][0]["vout"] == 1
    assert data["outputs"][0]["value"] == 100000000


def test_extract_with_progress() -> None:
    result = runner.invoke(app, ["extract", "--progress", "010000000000000000"])
    assert result.exit_code == 0
    assert "inputs" in result.stdout or "No signatures" in result.stdout


def test_linearize_with_progress() -> None:
    result = runner.invoke(app,
                           ["linearize", "--progress", "010000000000000000"])
    assert result.exit_code == 0
    assert "inputs" in result.stdout or "No signatures" in result.stdout


def test_decode_input_file(tmp_path: Path) -> None:
    f = tmp_path / "tx.hex"
    f.write_text("010000000000000000")
    result = runner.invoke(app, ["decode", "--input-file", str(f)])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["version"] == 1
