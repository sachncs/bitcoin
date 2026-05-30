"""Command line interface for Bitcoin transaction extraction.

Usage:
    bitcoin parse --tx <hex>
    bitcoin extract --tx <hex> [--input-values <vals>]
    bitcoin linear --tx <hex> [--input-values <vals>]
    bitcoin points --tx <hex> [--input-values <vals>]
    bitcoin transform --tx <hex> [--input-values <vals>]
"""

from __future__ import annotations

import json
import logging
import sys
from collections.abc import Sequence
from typing import Any

import click
import typer

from bitcoin.exceptions import BitcoinError
from bitcoin.serializer import (
    linear_collection_to_json,
    point_relation_collection_to_json,
    point_relation_to_dict,
    signature_collection_to_json,
    transaction_to_json,
    transformed_point_collection_to_dict,
)
from bitcoin.transaction import Transaction

logger = logging.getLogger(__name__)

app = typer.Typer(
    name="bitcoin",
    help=
    "Bitcoin transaction signature extraction and ECDSA transformation tool.",
    no_args_is_help=True,
    add_completion=False,
)


def parse_input_values(text: str) -> list[int | None]:
    """Parse a comma-separated string of satoshi values.

    Args:
        text: Comma-separated satoshi values (e.g. ``"100000,200000"``).

    Returns:
        List of parsed values, with empty entries as ``None``.

    Raises:
        ValueError: If any entry is not a valid integer.
    """
    if not text.strip():
        return []
    values: list[int | None] = []
    for item in text.split(","):
        item = item.strip()
        if not item:
            values.append(None)
            continue
        try:
            values.append(int(item))
        except ValueError:
            logger.error("Invalid input value: %r", item)
            raise ValueError(f"Invalid input value: {item!r}.") from None
    return values


def _resolve_transaction(
    tx_hex: str,
    input_values: str | None = None,
) -> Transaction:
    """Parse a transaction hex string and optionally attach input values.

    Args:
        tx_hex: Raw transaction in hexadecimal.
        input_values: Optional comma-separated satoshi values.

    Returns:
        A ready-to-use ``Transaction``.

    Raises:
        BitcoinError: If the hex is invalid or input values mismatch.
    """
    transaction = Transaction.parse_hex(tx_hex)
    if input_values:
        parsed_values = parse_input_values(input_values)
        if len(parsed_values) != len(transaction.inputs):
            msg = (f"input value count must match input count "
                   f"({len(parsed_values)} != {len(transaction.inputs)}).")
            logger.error(
                "Input value count %d does not match input count %d",
                len(parsed_values),
                len(transaction.inputs),
            )
            raise ValueError(msg)
        transaction = transaction.with_input_values(parsed_values)
    return transaction


def _format_error(message: str) -> str:
    """Return a structured JSON error string for stderr output.

    Args:
        message: Human-readable error description.

    Returns:
        JSON string with an ``"error"`` key.
    """
    return json.dumps({"error": message}, sort_keys=True, ensure_ascii=False)


# ── Commands ────────────────────────────────────────────────────────────────


@app.command()
def parse(
    tx: str = typer.Option(
        ...,
        "--tx",
        help="Raw transaction hex to parse.",
        prompt="Enter raw transaction hex",
        show_default=False,
    ),
    compact: bool = typer.Option(
        False,
        "--compact",
        help="Output compact JSON instead of pretty-printed.",
    ),
) -> None:
    """Parse a raw Bitcoin transaction and display its structure."""
    transaction = _resolve_transaction(tx)
    print(transaction_to_json(transaction, pretty=not compact))


@app.command()
def extract(
    tx: str = typer.Option(
        ...,
        "--tx",
        help="Raw transaction hex to extract signatures from.",
        prompt="Enter raw transaction hex",
        show_default=False,
    ),
    input_values: str | None = typer.Option(
        None,
        "--input-values",
        help="Comma-separated satoshi values for SegWit inputs.",
        show_default=False,
    ),
    compact: bool = typer.Option(
        False,
        "--compact",
        help="Output compact JSON instead of pretty-printed.",
    ),
) -> None:
    """Extract r, s, z values from signatures in a raw transaction.

    SegWit v0 inputs need their spent output values to reconstruct z.
    Provide them via ``--input-values`` (e.g. ``--input-values 100000,200000``).
    """
    transaction = _resolve_transaction(tx, input_values)
    collection = transaction.extract()
    print(signature_collection_to_json(collection, pretty=not compact))


@app.command()
def linear(
    tx: str = typer.Option(
        ...,
        "--tx",
        help="Raw transaction hex to derive coefficients from.",
        prompt="Enter raw transaction hex",
        show_default=False,
    ),
    input_values: str | None = typer.Option(
        None,
        "--input-values",
        help="Comma-separated satoshi values for SegWit inputs.",
        show_default=False,
    ),
    compact: bool = typer.Option(
        False,
        "--compact",
        help="Output compact JSON instead of pretty-printed.",
    ),
) -> None:
    """Derive linear ECDSA coefficients α and β from extracted signatures.

    Computes α ≡ s·r⁻¹ (mod n) and β ≡ z·r⁻¹ (mod n) for each signature,
    giving the transformed scalar relation d' ≡ αk (mod n).
    """
    transaction = _resolve_transaction(tx, input_values)
    coefficients = transaction.extract().linear()
    if len(coefficients.records) == 1:
        coeff = coefficients.records[0]
        print(
            json.dumps(
                {
                    "alpha": f"0x{coeff.alpha:064x}",
                    "beta": f"0x{coeff.beta:064x}",
                    "equation": coeff.equation(),
                    "input_index": coeff.input_index,
                },
                sort_keys=True,
                indent=None if compact else 2,
                ensure_ascii=False,
            ),)
    else:
        print(linear_collection_to_json(coefficients, pretty=not compact))


@app.command()
def points(
    tx: str = typer.Option(
        ...,
        "--tx",
        help="Raw transaction hex to derive point relations from.",
        prompt="Enter raw transaction hex",
        show_default=False,
    ),
    input_values: str | None = typer.Option(
        None,
        "--input-values",
        help="Comma-separated satoshi values for SegWit inputs.",
        show_default=False,
    ),
    compact: bool = typer.Option(
        False,
        "--compact",
        help="Output compact JSON instead of pretty-printed.",
    ),
) -> None:
    """Derive point-space ECDSA relations D + βG = αK.

    Lifts the scalar identity into secp256k1 affine point arithmetic.
    Requires public keys (available from all supported script paths).
    """
    transaction = _resolve_transaction(tx, input_values)
    relations = transaction.extract().linear_points()
    if len(relations.records) == 1:
        point_rel = relations.records[0]
        rel_dict = point_relation_to_dict(point_rel)
        transformed = rel_dict["transformed_public_key"]
        assert isinstance(transformed, dict)
        print(
            json.dumps(
                {
                    "alpha": f"0x{point_rel.alpha:064x}",
                    "beta": f"0x{point_rel.beta:064x}",
                    "equation": point_rel.equation,
                    "input_index": point_rel.input_index,
                    "transformed_public_key": {
                        "x": transformed["x"],
                        "y": transformed["y"],
                    },
                },
                sort_keys=True,
                indent=None if compact else 2,
                ensure_ascii=False,
            ),)
    else:
        print(point_relation_collection_to_json(relations, pretty=not compact))


@app.command()
def transform(
    tx: str = typer.Option(
        ...,
        "--tx",
        help="Raw transaction hex to transform signatures from.",
        prompt="Enter raw transaction hex",
        show_default=False,
    ),
    input_values: str | None = typer.Option(
        None,
        "--input-values",
        help="Comma-separated satoshi values for SegWit inputs.",
        show_default=False,
    ),
    compact: bool = typer.Option(
        False,
        "--compact",
        help="Output compact JSON instead of pretty-printed.",
    ),
) -> None:
    """Transform signatures into D' = d'G point-space.

    Computes D' = D + βG = (d + β)G and validates the resulting
    affine point against secp256k1.
    """
    transaction = _resolve_transaction(tx, input_values)
    transformed = transaction.extract().transform_points()
    payload = transformed_point_collection_to_dict(transformed)
    kw: Any = {
        "sort_keys": True,
        "ensure_ascii": False,
    }
    if compact:
        kw["separators"] = (",", ":")
    else:
        kw["indent"] = 2
    if len(transformed.records) == 1:
        print(json.dumps(payload[0], **kw))
    else:
        print(json.dumps(payload, **kw))


# ── Entry point ─────────────────────────────────────────────────────────────


def main(args: Sequence[str] | None = None) -> int:
    """Entry point for the Bitcoin CLI.

    Args:
        args: Command-line arguments (``None`` uses ``sys.argv[1:]``).

    Returns:
        Exit code (0 for success, 1 for errors, 2 for usage errors).
    """
    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s:%(name)s:%(message)s",
    )

    try:
        app(args, standalone_mode=False)
        return 0
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 1
    except click.ClickException as exc:
        print(_format_error(exc.format_message()), file=sys.stderr)
        return exc.exit_code
    except click.UsageError as exc:
        print(_format_error(exc.format_message()), file=sys.stderr)
        return exc.exit_code
    except BitcoinError as exc:
        logger.exception("Bitcoin error")
        print(_format_error(str(exc)), file=sys.stderr)
        return 1
    except ValueError as exc:
        logger.exception("Value error")
        print(_format_error(str(exc)), file=sys.stderr)
        return 1
    except Exception as exc:
        logger.exception("Unexpected error")
        print(_format_error(f"Unexpected error: {exc}"), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
