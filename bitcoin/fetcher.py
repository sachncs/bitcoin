"""Fetch Bitcoin transactions and address data from the blockstream.info API.

This module uses the public Blockstream API to fetch raw transactions, address
history, and UTXO sets. No external HTTP dependencies are required — all
requests use ``urllib.request`` from the standard library.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from typing import Any
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from bitcoin.exceptions import BitcoinError
from bitcoin.signature import SignatureCollection
from bitcoin.transaction import Transaction

logger = logging.getLogger(__name__)

API_BASE = "https://blockstream.info"
API_BASE_TESTNET = "https://blockstream.info/testnet"

__all__ = [
    "API_BASE",
    "API_BASE_TESTNET",
    "api_url",
    "fetch_address_transactions",
    "fetch_address_utxos",
    "fetch_and_extract",
    "fetch_transaction",
    "fetch_transaction_hex",
]


def api_url(network: str) -> str:
    if network == "mainnet":
        return API_BASE
    return API_BASE_TESTNET


def fetch_transaction_hex(txid: str,
                          *,
                          network: str = "mainnet",
                          timeout: int = 30) -> str:
    """Fetch a raw transaction hex string from blockstream.info.

    Args:
        txid: The transaction ID (64-char hex string).
        network: ``"mainnet"`` (default), ``"testnet"``, or ``"signet"``.
        timeout: HTTP request timeout in seconds.

    Returns:
        The raw transaction as a hex string.

    Raises:
        BitcoinError: If the API returns a non-200 status.
    """
    base = api_url(network)
    url = f"{base}/api/tx/{txid}/hex"
    req = Request(url)
    try:
        with urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                raise BitcoinError(
                    f"Blockstream API returned HTTP {resp.status} for tx {txid}"
                )
            return resp.read().decode("utf-8")
    except (HTTPError, UnicodeDecodeError) as exc:
        if isinstance(exc, HTTPError):
            raise BitcoinError(
                f"Blockstream API returned HTTP {exc.code} for tx {txid}: {exc.reason}"
            ) from exc
        raise BitcoinError(
            f"Blockstream API returned non-UTF-8 response for tx {txid}"
        ) from exc


def fetch_transaction(txid: str,
                      *,
                      network: str = "mainnet",
                      timeout: int = 30) -> Transaction:
    """Fetch and parse a Bitcoin transaction by txid.

    Args:
        txid: The transaction ID.
        network: ``"mainnet"`` (default), ``"testnet"``, or ``"signet"``.
        timeout: HTTP request timeout in seconds.

    Returns:
        A parsed ``Transaction`` object.
    """
    hex_str = fetch_transaction_hex(txid, network=network, timeout=timeout)
    return Transaction.parse_hex(hex_str)


def fetch_address_transactions(address: str,
                               *,
                               network: str = "mainnet",
                               limit: int = 25,
                               timeout: int = 30) -> list[Transaction]:
    """Fetch recent transactions for a Bitcoin address.

    Args:
        address: A base58 or bech32 Bitcoin address.
        network: ``"mainnet"`` (default), ``"testnet"``, or ``"signet"``.
        limit: Maximum number of transactions to return (default 25).
        timeout: HTTP request timeout in seconds.

    Returns:
        A list of ``Transaction`` objects.
    """
    base = api_url(network)
    url = f"{base}/api/address/{address}/txs"
    req = Request(url)
    try:
        with urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                raise BitcoinError(
                    f"Blockstream API returned HTTP {resp.status} for address {address}"
                )
            data: list[dict[str, Any]] = json.loads(resp.read().decode("utf-8"))
    except (HTTPError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        if isinstance(exc, HTTPError):
            raise BitcoinError(f"Blockstream API returned HTTP {exc.code} "
                               f"for address {address}: {exc.reason}") from exc
        raise BitcoinError(
            f"Blockstream API returned invalid response for address {address}: {exc}"
        ) from exc

    result: list[Transaction] = []
    for entry in data[:limit]:
        hex_str = entry.get("hex")
        if hex_str:
            try:
                result.append(Transaction.parse_hex(hex_str))
            except (BitcoinError, ValueError):
                logger.exception("Failed to parse transaction %s",
                                 entry.get("txid"))
    return result


def fetch_address_utxos(address: str,
                        *,
                        network: str = "mainnet",
                        timeout: int = 30) -> list[dict[str, Any]]:
    """Fetch UTXOs for a Bitcoin address.

    Args:
        address: A base58 or bech32 Bitcoin address.
        network: ``"mainnet"`` (default), ``"testnet"``, or ``"signet"``.
        timeout: HTTP request timeout in seconds.

    Returns:
        A list of dicts with keys ``txid``, ``vout``, ``value``, ``status``.
    """
    base = api_url(network)
    url = f"{base}/api/address/{address}/utxo"
    req = Request(url)
    try:
        with urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                raise BitcoinError(
                    f"Blockstream API returned HTTP {resp.status} for address {address}"
                )
            return json.loads(resp.read().decode("utf-8"))
    except (HTTPError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        if isinstance(exc, HTTPError):
            raise BitcoinError(f"Blockstream API returned HTTP {exc.code} "
                               f"for address {address}: {exc.reason}") from exc
        raise BitcoinError(
            f"Blockstream API returned invalid response for address {address}: {exc}"
        ) from exc


def fetch_and_extract(
    txid: str,
    *,
    network: str = "mainnet",
    input_values: Sequence[int] | None = None,
    timeout: int = 30,
) -> SignatureCollection:
    """Fetch, optionally attach input values, and extract signatures.

    Args:
        txid: The transaction ID.
        network: ``"mainnet"`` (default), ``"testnet"``, or ``"signet"``.
        input_values: Optional sequence of input values for SegWit sighash
            computation.  If provided, calls ``.with_input_values()`` on the
            transaction before extracting.
        timeout: HTTP request timeout in seconds.

    Returns:
        The extracted ``SignatureCollection``.
    """
    tx = fetch_transaction(txid, network=network, timeout=timeout)
    if input_values is not None:
        tx = tx.with_input_values(input_values)
    return tx.extract()
