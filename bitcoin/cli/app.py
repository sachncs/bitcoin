# ruff: noqa: B008
"""Typer-based CLI app: decode, extract, linearize, version commands."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Sequence
from pathlib import Path

import typer

from bitcoin.services.serializer import tx_to_json
from bitcoin.signature import extract_signatures, linearize_signatures
from bitcoin.signature.record import Record
from bitcoin.encoding.hex import decode_hex, encode_hex
from bitcoin.transaction import parse_tx

app = typer.Typer(name="bitcoin")


def parse_input_values(value_str: str) -> list[int | None]:
    """Parse a comma-separated string of input values into integers.

    Empty entries (e.g. ``"100,,300"``) yield ``None``.

    Args:
        value_str: Comma-separated integer values (e.g. ``"100,200,300"``).

    Returns:
        A list where each entry is an ``int`` or ``None`` for empty fields.
    """
    if not value_str or value_str.strip() == "":
        return []
    result: list[int | None] = []
    for part in value_str.split(","):
        part = part.strip()
        if part == "":
            result.append(None)
        else:
            result.append(int(part))
    return result


def resolve_output_format(
    *,
    json_output: bool,
    csv_output: bool,
    output_format: str,
) -> str:
    """Resolve the effective output format, erroring on conflicting flags."""
    if json_output and csv_output:
        typer.echo("--json and --csv are mutually exclusive", err=True)
        raise typer.Exit(1)
    if output_format != "text":
        return output_format
    if json_output:
        return "json"
    if csv_output:
        return "csv"
    return "text"


def read_tx_hex(tx_hex: str | None, input_file: Path | None) -> str:
    """Return tx hex from the positional arg or ``--input-file``.

    If both are provided ``--input-file`` wins.
    """
    if input_file is not None:
        return input_file.read_text().strip()
    if tx_hex is not None:
        return tx_hex
    typer.echo("Either provide tx_hex as argument or use --input-file",
               err=True)
    raise typer.Exit(1)


def output_records(records: list[Record], fmt: str) -> None:
    """Output records (for ``extract``) in the requested format."""
    if not records:
        typer.echo("No signatures found.")
        raise typer.Exit(0)

    if fmt == "json":
        data = [{
            "txid": encode_hex(r.txid),
            "input_index": r.input_index,
            "signature": encode_hex(r.signature),
            "type": r.script_type,
            "sighash_flag": r.sighash_flag,
            "value": r.amount,
        } for r in records]
        typer.echo(json.dumps(data, indent=2))
    elif fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "txid", "input_index", "signature", "type", "sighash_flag", "value"
        ])
        for r in records:
            writer.writerow([
                encode_hex(r.txid),
                r.input_index,
                encode_hex(r.signature),
                r.script_type,
                r.sighash_flag,
                r.amount,
            ])
        typer.echo(buf.getvalue().rstrip())
    else:
        for rec in records:
            typer.echo(f"txid:  {encode_hex(rec.txid)}")
            typer.echo(f"input_index: {rec.input_index}")
            typer.echo(f"signature:   {encode_hex(rec.signature)}")
            typer.echo(f"type:  {rec.script_type}")
            typer.echo(f"sighash_flag:  {rec.sighash_flag}")
            typer.echo(f"value: {rec.amount}")
            typer.echo("---")


def output_sorted_records(records: list[Record], fmt: str) -> None:
    """Output sorted/linearized records (for ``linearize``) in the requested format."""
    if not records:
        typer.echo("No signatures found.")
        raise typer.Exit(0)

    if fmt == "json":
        data = [{
            "txid": encode_hex(r.txid),
            "input_index": r.input_index,
            "signature": encode_hex(r.signature),
        } for r in records]
        typer.echo(json.dumps(data, indent=2))
    elif fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["txid", "input_index", "signature"])
        for r in records:
            writer.writerow(
                [encode_hex(r.txid), r.input_index,
                 encode_hex(r.signature)])
        typer.echo(buf.getvalue().rstrip())
    else:
        for rec in records:
            typer.echo(
                f"{encode_hex(rec.txid)}:{rec.input_index} {encode_hex(rec.signature)}"
            )


@app.command()
def decode(
    tx_hex: str | None = typer.Argument(None, help="Transaction hex"),
    input_file: Path | None = typer.Option(None,
                                           "--input-file",
                                           help="Read tx hex from file"),
) -> None:
    """Decode a raw transaction and output as JSON."""
    tx_hex_resolved = read_tx_hex(tx_hex, input_file)
    tx_bytes = decode_hex(tx_hex_resolved)
    tx, _ = parse_tx(tx_bytes)
    typer.echo(json.dumps(tx_to_json(tx), indent=2))


@app.command()
def extract(
    tx_hex: str | None = typer.Argument(None, help="Transaction hex"),
    utxo_scripts: list[str] | None = typer.Option(
        None, "--utxo-script", help="UTXO scriptPubKey (one per input)"),
    utxo_values: list[int] | None = typer.Option(
        None, "--utxo-value", help="UTXO value in satoshis (one per input)"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    csv_output: bool = typer.Option(False, "--csv", help="Output as CSV"),
    output_format: str = typer.Option("text", "--format", help="Output format"),
    input_file: Path | None = typer.Option(None,
                                           "--input-file",
                                           help="Read tx hex from file"),
    progress: bool = typer.Option(False,
                                  "--progress",
                                  "-p",
                                  help="Show progress dots"),
) -> None:
    """Extract ECDSA signatures from a raw transaction hex."""
    fmt = resolve_output_format(
        json_output=json_output,
        csv_output=csv_output,
        output_format=output_format,
    )
    tx_hex_resolved = read_tx_hex(tx_hex, input_file)

    tx_bytes = decode_hex(tx_hex_resolved)
    tx, _ = parse_tx(tx_bytes)

    script_pubkeys = ([decode_hex(s) for s in utxo_scripts]
                      if utxo_scripts else None)

    if progress:
        typer.echo(
            f"Parsed tx with {len(tx.inputs)} inputs, "
            f"{len(tx.outputs)} outputs.",
            err=True)

    records = extract_signatures(tx, script_pubkeys, utxo_values)

    if progress:
        typer.echo(f" Found {len(records)} signature(s).", err=True)

    output_records(records, fmt)


@app.command()
def linearize(
    tx_hex: str | None = typer.Argument(None, help="Transaction hex"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
    csv_output: bool = typer.Option(False, "--csv", help="Output as CSV"),
    output_format: str = typer.Option("text", "--format", help="Output format"),
    input_file: Path | None = typer.Option(None,
                                           "--input-file",
                                           help="Read tx hex from file"),
    progress: bool = typer.Option(False,
                                  "--progress",
                                  "-p",
                                  help="Show progress dots"),
) -> None:
    """Extract and linearize (sort) signatures from a raw transaction hex."""
    fmt = resolve_output_format(
        json_output=json_output,
        csv_output=csv_output,
        output_format=output_format,
    )
    tx_hex_resolved = read_tx_hex(tx_hex, input_file)

    tx_bytes = decode_hex(tx_hex_resolved)
    tx, _ = parse_tx(tx_bytes)

    if progress:
        typer.echo(
            f"Parsed tx with {len(tx.inputs)} inputs, "
            f"{len(tx.outputs)} outputs.",
            err=True)

    records = extract_signatures(tx)
    sorted_records = linearize_signatures(records)

    if progress:
        typer.echo(f" Linearized {len(sorted_records)} signature(s).", err=True)

    output_sorted_records(sorted_records, fmt)


@app.command()
def version() -> None:
    """Print the installed bitcoin package version."""
    from bitcoin import __version__ as ver

    typer.echo(f"bitcoin v{ver}")


def main(args: Sequence[str] | None = None) -> int:
    """CLI entry point — delegates to the Typer app.

    Args:
        args: Optional argument list.  If ``None``, uses ``sys.argv``.

    Returns:
        Always ``0``.
    """
    if args is not None:
        app(args)
    else:
        app()
    return 0
