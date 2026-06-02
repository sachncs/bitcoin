"""Comprehensive CLI tests covering every branch in bitcoin/cli/app.py."""
from __future__ import annotations

from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from bitcoin.cli.app import app, main, parse_input_values
from bitcoin.curve import INFINITY
from bitcoin.signature.record import Record

runner = CliRunner()


# --- parse_input_values ---

def test_parse_input_values_empty() -> None:
    assert parse_input_values("") == []


def test_parse_input_values_whitespace() -> None:
    assert parse_input_values("   ") == []


def test_parse_input_values_normal() -> None:
    assert parse_input_values("100,200,300") == [100, 200, 300]


def test_parse_input_values_with_none() -> None:
    assert parse_input_values("100,,300") == [100, None, 300]


def test_parse_input_values_invalid() -> None:
    with pytest.raises(ValueError):
        parse_input_values("abc")


# --- main() entry-point wrapper ---

def test_main_with_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "0." in result.stdout


def test_main_with_extract() -> None:
    result = runner.invoke(app, ["extract", "010000000000000000"])
    assert result.exit_code == 0


def test_main_returns_zero() -> None:
    from bitcoin.cli.app import main
    with patch("bitcoin.cli.app.app") as mock_app:
        assert main(["version"]) == 0
    mock_app.assert_called_once_with(["version"])


# --- --help for every command ---

def test_app_help() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "Usage:" in result.stdout


def test_extract_help() -> None:
    result = runner.invoke(app, ["extract", "--help"])
    assert result.exit_code == 0


def test_linearize_help() -> None:
    result = runner.invoke(app, ["linearize", "--help"])
    assert result.exit_code == 0


def test_version_help() -> None:
    result = runner.invoke(app, ["version", "--help"])
    assert result.exit_code == 0


# --- error paths: extract ---

def test_extract_invalid_hex() -> None:
    result = runner.invoke(app, ["extract", "not-hex"])
    assert result.exit_code != 0


def test_extract_odd_hex() -> None:
    result = runner.invoke(app, ["extract", "abc"])
    assert result.exit_code != 0


def test_extract_missing_argument() -> None:
    result = runner.invoke(app, ["extract"])
    assert result.exit_code != 0


# --- error paths: linearize ---

def test_linearize_invalid_hex() -> None:
    result = runner.invoke(app, ["linearize", "not-hex"])
    assert result.exit_code != 0


def test_linearize_missing_argument() -> None:
    result = runner.invoke(app, ["linearize"])
    assert result.exit_code != 0


# --- extract with --utxo-script / --utxo-value ---

def test_extract_with_utxo_script() -> None:
    result = runner.invoke(
        app,
        ["extract", "010000000000000000", "--utxo-script", "0014" + "00" * 20],
    )
    assert result.exit_code == 0


def test_extract_with_utxo_value() -> None:
    result = runner.invoke(
        app,
        ["extract", "010000000000000000", "--utxo-value", "100000"],
    )
    assert result.exit_code == 0


# --- extract with found records (mocked) ---

def test_extract_with_records() -> None:
    mock_record = Record(
        txid=b"\x00" * 32,
        vin=0,
        sig=b"\x30\x45\x02\x21\x00" + b"\xaa" * 28 + b"\x02\x20" + b"\xbb" * 32 + b"\x01",
        public_key=INFINITY,
        script_type="p2pkh",
        sighash_flag=1,
        amount=100000,
    )
    with patch("bitcoin.cli.app.extract_signatures", return_value=[mock_record]):
        result = runner.invoke(app, ["extract", "010000000000000000"])
    assert result.exit_code == 0
    assert "txid:" in result.stdout
    assert "vin:" in result.stdout
    assert "sig:" in result.stdout
    assert "type:" in result.stdout
    assert "flag:" in result.stdout
    assert "value:" in result.stdout
    assert "---" in result.stdout


# --- linearize with found records (mocked) ---

def test_linearize_with_records() -> None:
    mock_record = Record(
        txid=b"\x00" * 32,
        vin=0,
        sig=b"\x30\x45\x02\x21\x00" + b"\xaa" * 28 + b"\x02\x20" + b"\xbb" * 32 + b"\x01",
        public_key=INFINITY,
        script_type="p2pkh",
        sighash_flag=1,
        amount=100000,
    )
    with patch("bitcoin.cli.app.extract_signatures", return_value=[mock_record]):
        result = runner.invoke(app, ["linearize", "010000000000000000"])
    assert result.exit_code == 0
