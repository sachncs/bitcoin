"""Blockchain data fetching with pluggable backends.

Provides a ``BlockchainProvider`` protocol and concrete implementations
for Blockstream.info and blockchain.info APIs, plus convenience functions
to enrich raw transactions with UTXO data.
"""

from __future__ import annotations

import json
import logging
import time
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from bitcoin.encoding.hex import decode_hex, encode_hex
from bitcoin.transaction.parser import parse_tx

if TYPE_CHECKING:
    from bitcoin.signature.record import Record

logger = logging.getLogger(__name__)

USER_AGENT = "bitcoin/0.4.0"
DEFAULT_HTTP_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_BACKOFF = 1.0  # seconds
RETRYABLE_STATUSES = {429, 500, 502, 503, 504}
TXID_PATTERN = "0123456789abcdefABCDEF"


@runtime_checkable
class BlockchainProvider(Protocol):
    """Protocol for blockchain data providers.

    Implementations fetch transaction data and UTXO information from
    a blockchain explorer API.  All methods raise ``OSError`` on
    network or HTTP errors, and ``ValueError`` on malformed responses.
    """

    def get_transaction_hex(self, txid: str) -> str:
        """Fetch a raw transaction in hex format.

        Args:
            txid: The 64-character transaction ID (hash).

        Returns:
            The raw transaction as a hex-encoded string.

        Raises:
            OSError: On network or HTTP errors.
            ValueError: If the response is malformed.
        """
        ...

    def get_utxo_script_pubkey(self, txid: str, vout: int) -> bytes:
        """Fetch the ``scriptPubKey`` of a specific UTXO.

        Args:
            txid: The transaction ID containing the output.
            vout: The output index.

        Returns:
            The ``scriptPubKey`` as raw bytes.

        Raises:
            OSError: On network or HTTP errors.
            ValueError: If the output does not exist.
        """
        ...

    def get_utxo_value(self, txid: str, vout: int) -> int:
        """Fetch the value (in satoshis) of a specific UTXO.

        Args:
            txid: The transaction ID containing the output.
            vout: The output index.

        Returns:
            The value in satoshis.

        Raises:
            OSError: On network or HTTP errors.
            ValueError: If the output does not exist.
        """
        ...


class BlockstreamProvider:
    """Blockstream.info API blockchain provider.

    Fetches data from ``https://blockstream.info/api/``.  Supports
    mainnet by default; override ``BASE_URL`` for testnet or other
    instances.

    Attributes:
        BASE_URL: Base URL of the Blockstream API.
    """

    BASE_URL = "https://blockstream.info/api"

    def get_transaction_hex(self, txid: str) -> str:
        """Fetch a raw transaction hex from Blockstream.

        Args:
            txid: The 64-character transaction ID.

        Returns:
            The raw transaction as a hex string.

        Raises:
            OSError: On network failure or non-200 status.
            ValueError: If the response cannot be decoded.
        """
        validate_txid(txid)
        url = f"{self.BASE_URL}/tx/{txid}/hex"
        return fetch_text(url)

    def get_utxo_script_pubkey(self, txid: str, vout: int) -> bytes:
        """Fetch the ``scriptPubKey`` for a given UTXO.

        Args:
            txid: The transaction ID containing the output.
            vout: The output index.

        Returns:
            The ``scriptPubKey`` as raw bytes.

        Raises:
            OSError: On network failure or non-200 status.
            ValueError: If *vout* is out of range.
        """
        validate_txid(txid)
        tx_json = self.fetch_tx_json(txid)
        try:
            output = tx_json["vout"][vout]
        except IndexError:
            raise ValueError(
                f"vout {vout} out of range for tx {txid} "
                f"(only {len(tx_json['vout'])} outputs).") from None
        return decode_hex(output["scriptpubkey"])

    def get_utxo_value(self, txid: str, vout: int) -> int:
        """Fetch the value in satoshis for a given UTXO.

        Args:
            txid: The transaction ID containing the output.
            vout: The output index.

        Returns:
            Value in satoshis.

        Raises:
            OSError: On network failure or non-200 status.
            ValueError: If *vout* is out of range.
        """
        validate_txid(txid)
        tx_json = self.fetch_tx_json(txid)
        try:
            return int(tx_json["vout"][vout]["value"])
        except IndexError:
            raise ValueError(
                f"vout {vout} out of range for tx {txid} "
                f"(only {len(tx_json['vout'])} outputs).") from None

    def fetch_tx_json(self, txid: str) -> dict[str, Any]:
        """Fetch the full transaction JSON from Blockstream.

        Args:
            txid: The 64-character transaction ID.

        Returns:
            Parsed JSON response as a dict.

        Raises:
            OSError: On network failure or non-200 status.
            ValueError: If the response is not valid JSON.
        """
        validate_txid(txid)
        url = f"{self.BASE_URL}/tx/{txid}"
        raw = fetch_text(url)
        try:
            data: dict[str, Any] = json.loads(raw)
            return data
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSON response from {url}: {exc}") from exc


class BlockchainInfoProvider:
    """blockchain.info API blockchain provider.

    Uses the raw transaction endpoint at
    ``https://blockchain.info/rawtx/``.

    Attributes:
        BASE_URL: Base URL of the blockchain.info API.
    """

    BASE_URL = "https://blockchain.info"

    def get_transaction_hex(self, txid: str) -> str:
        """Fetch a raw transaction hex from blockchain.info.

        Args:
            txid: The 64-character transaction ID.

        Returns:
            The raw transaction as a hex string.

        Raises:
            OSError: On network failure or non-200 status.
            ValueError: If the response cannot be decoded.
        """
        validate_txid(txid)
        url = f"{self.BASE_URL}/rawtx/{txid}?format=hex"
        return fetch_text(url)

    def get_utxo_script_pubkey(self, txid: str, vout: int) -> bytes:
        """Fetch the ``scriptPubKey`` for a given UTXO.

        Args:
            txid: The transaction ID containing the output.
            vout: The output index.

        Returns:
            The ``scriptPubKey`` as raw bytes.

        Raises:
            OSError: On network failure or non-200 status.
            ValueError: If *vout* is out of range.
        """
        validate_txid(txid)
        tx_json = self.fetch_tx_json(txid)
        try:
            output = tx_json["out"][vout]
        except IndexError:
            raise ValueError(f"vout {vout} out of range for tx {txid} "
                             f"(only {len(tx_json['out'])} outputs).") from None
        raw_script = output.get("script")
        if raw_script is None:
            raise ValueError(f"No script for vout {vout} in tx {txid}.")
        return decode_hex(raw_script)

    def get_utxo_value(self, txid: str, vout: int) -> int:
        """Fetch the value in satoshis for a given UTXO.

        Args:
            txid: The transaction ID containing the output.
            vout: The output index.

        Returns:
            Value in satoshis.

        Raises:
            OSError: On network failure or non-200 status.
            ValueError: If *vout* is out of range.
        """
        validate_txid(txid)
        tx_json = self.fetch_tx_json(txid)
        try:
            return int(tx_json["out"][vout]["value"])
        except IndexError:
            raise ValueError(f"vout {vout} out of range for tx {txid} "
                             f"(only {len(tx_json['out'])} outputs).") from None

    def fetch_tx_json(self, txid: str) -> dict[str, Any]:
        """Fetch the full transaction JSON from blockchain.info.

        Args:
            txid: The 64-character transaction ID.

        Returns:
            Parsed JSON response as a dict.

        Raises:
            OSError: On network failure or non-200 status.
            ValueError: If the response is not valid JSON.
        """
        validate_txid(txid)
        url = f"{self.BASE_URL}/rawtx/{txid}"
        raw = fetch_text(url)
        try:
            data: dict[str, Any] = json.loads(raw)
            return data
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSON response from {url}: {exc}") from exc


def validate_txid(txid: str) -> str:
    """Validate that *txid* is a 64-character hex string.

    Args:
        txid: The transaction ID to validate.

    Returns:
        *txid* unchanged on success.

    Raises:
        ValueError: If *txid* is not a valid 64-character hex string.
    """
    if len(txid) != 64 or not all(c in TXID_PATTERN for c in txid):
        raise ValueError(f"Invalid txid: {txid!r}")
    return txid


# ── Internal helpers ───────────────────────────────────────────────


def fetch_text(url: str) -> str:
    """Fetch a URL and return the response body as text.

    Retries up to ``MAX_RETRIES`` times with exponential backoff for
    transient HTTP errors (429, 500, 502, 503, 504) and URL errors.

    Args:
        url: The URL to fetch.

    Returns:
        The response body decoded as UTF-8.

    Raises:
        OSError: On repeated network failure (wraps ``HTTPError``,
            ``URLError``).
    """
    last_error: OSError | None = None
    for attempt in range(MAX_RETRIES):
        try:
            req = Request(url, headers={"User-Agent": USER_AGENT})
            with urlopen(req, timeout=DEFAULT_HTTP_TIMEOUT) as resp:
                data: bytes = resp.read()
                return data.decode("utf-8")
        except HTTPError as exc:
            msg = f"HTTP {exc.code} fetching {url}: {exc.reason}"
            if exc.code in RETRYABLE_STATUSES and attempt < MAX_RETRIES - 1:
                wait = RETRY_BACKOFF * (2 ** attempt)
                logger.debug(
                    "HTTP %d fetching %s, retrying in %.1fs (attempt %d/%d)",
                    exc.code, url, wait, attempt + 1, MAX_RETRIES)
                time.sleep(wait)
                last_error = OSError(msg)
                continue
            raise OSError(msg) from exc
        except URLError as exc:
            msg = f"URL error fetching {url}: {exc.reason}"
            if attempt < MAX_RETRIES - 1:
                wait = RETRY_BACKOFF * (2 ** attempt)
                logger.debug(
                    "URL error fetching %s, retrying in %.1fs (attempt %d/%d)",
                    url, wait, attempt + 1, MAX_RETRIES)
                time.sleep(wait)
                last_error = OSError(msg)
                continue
            raise OSError(msg) from exc
    if last_error is not None:
        raise last_error
    raise OSError(f"Failed to fetch {url} after {MAX_RETRIES} attempts.")


# ── Convenience functions ──────────────────────────────────────────


def enrich_transaction(
    tx_hex: str,
    *,
    provider: BlockchainProvider | None = None,
) -> tuple[list[bytes], list[int]]:
    """Fetch UTXO scripts and values for all inputs in a transaction.

    Parses *tx_hex* and uses *provider* to look up the ``scriptPubKey``
    and value of each previous output being spent.

    Args:
        tx_hex: The raw transaction as a hex-encoded string.
        provider: A ``BlockchainProvider`` instance.  If ``None``,
            a ``BlockstreamProvider`` is created automatically.

    Returns:
        A tuple ``(script_pubkeys, values)`` where each list has one
        element per input, in input order.

    Raises:
        OSError: On network or HTTP errors during lookups.
        ValueError: If *tx_hex* cannot be parsed.
    """
    if provider is None:
        provider = BlockstreamProvider()

    raw = decode_hex(tx_hex.strip())
    tx, _ = parse_tx(raw)

    scripts: list[bytes] = []
    values: list[int] = []
    for txin in tx.inputs:
        prev_txid = encode_hex(txin.previous_output.txid)
        vout = txin.previous_output.vout
        scripts.append(provider.get_utxo_script_pubkey(prev_txid, vout))
        values.append(provider.get_utxo_value(prev_txid, vout))

    return scripts, values


def fetch_and_extract(
    txid_or_hex: str,
    *,
    provider: BlockchainProvider | None = None,
) -> list[Record]:
    """Fetch a transaction and extract signatures in one call.

    If *txid_or_hex* looks like a 64-character hex transaction ID, the
    full transaction hex is fetched first via *provider*.  Otherwise it
    is treated as a raw hex-encoded transaction.  UTXO data is fetched
    automatically via ``enrich_transaction``.

    Args:
        txid_or_hex: A 64-character txid **or** a hex-encoded raw
            transaction.
        provider: A ``BlockchainProvider`` instance.  If ``None``,
            a ``BlockstreamProvider`` is created automatically.

    Returns:
        A list of ``Record`` instances, one per extracted signature.

    Raises:
        OSError: On network or HTTP errors.
        ValueError: If the input cannot be parsed.
    """
    if provider is None:
        provider = BlockstreamProvider()

    is_txid = len(txid_or_hex) == 64 and all(
        c in "0123456789abcdefABCDEF" for c in txid_or_hex)

    if is_txid:
        tx_hex = provider.get_transaction_hex(txid_or_hex)
    else:
        tx_hex = txid_or_hex

    scripts, values = enrich_transaction(tx_hex, provider=provider)
    raw = decode_hex(tx_hex.strip())
    tx, _ = parse_tx(raw)

    from bitcoin.signature.extraction.engine import extract_signatures

    return extract_signatures(tx, utxo_script_pubkeys=scripts, utxo_values=values)


class MempoolSpaceProvider:
    """mempool.space API blockchain provider.

    Fetches data from ``https://mempool.space/api/``.  Uses a compatible
    JSON format to Blockstream; supports mainnet by default and a
    configurable ``BASE_URL`` for testnet/signet instances.

    Attributes:
        BASE_URL: Base URL of the mempool.space API.
    """

    BASE_URL = "https://mempool.space/api"

    def get_transaction_hex(self, txid: str) -> str:
        """Fetch a raw transaction hex from mempool.space.

        Args:
            txid: The 64-character transaction ID.

        Returns:
            The raw transaction as a hex string.

        Raises:
            OSError: On network failure or non-200 status.
            ValueError: If the response cannot be decoded.
        """
        url = f"{self.BASE_URL}/tx/{txid}/hex"
        return fetch_text(url)

    def get_utxo_script_pubkey(self, txid: str, vout: int) -> bytes:
        """Fetch the ``scriptPubKey`` for a given UTXO.

        Args:
            txid: The transaction ID containing the output.
            vout: The output index.

        Returns:
            The ``scriptPubKey`` as raw bytes.

        Raises:
            OSError: On network failure or non-200 status.
            ValueError: If *vout* is out of range.
        """
        tx_json = self.fetch_tx_json(txid)
        try:
            output = tx_json["vout"][vout]
        except IndexError:
            raise ValueError(
                f"vout {vout} out of range for tx {txid} "
                f"(only {len(tx_json['vout'])} outputs).") from None
        return decode_hex(output["scriptpubkey"])

    def get_utxo_value(self, txid: str, vout: int) -> int:
        """Fetch the value in satoshis for a given UTXO.

        Args:
            txid: The transaction ID containing the output.
            vout: The output index.

        Returns:
            Value in satoshis.

        Raises:
            OSError: On network failure or non-200 status.
            ValueError: If *vout* is out of range.
        """
        tx_json = self.fetch_tx_json(txid)
        try:
            return int(tx_json["vout"][vout]["value"])
        except IndexError:
            raise ValueError(
                f"vout {vout} out of range for tx {txid} "
                f"(only {len(tx_json['vout'])} outputs).") from None

    def fetch_tx_json(self, txid: str) -> dict[str, Any]:
        """Fetch the full transaction JSON from mempool.space.

        Args:
            txid: The 64-character transaction ID.

        Returns:
            Parsed JSON response as a dict.

        Raises:
            OSError: On network failure or non-200 status.
            ValueError: If the response is not valid JSON.
        """
        url = f"{self.BASE_URL}/tx/{txid}"
        raw = fetch_text(url)
        try:
            data: dict[str, Any] = json.loads(raw)
            return data
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Invalid JSON response from {url}: {exc}") from exc


__all__ = [
    "BlockchainInfoProvider",
    "BlockchainProvider",
    "BlockstreamProvider",
    "MempoolSpaceProvider",
    "enrich_transaction",
    "fetch_and_extract",
]
