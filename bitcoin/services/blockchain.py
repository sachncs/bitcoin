"""Blockchain data fetching with pluggable backends.

Provides a ``BlockchainProvider`` protocol and concrete implementations
for Blockstream.info and blockchain.info APIs, plus convenience functions
to enrich raw transactions with UTXO data.

All concrete providers inherit from ``BaseBlockchainProvider`` via the
Template Method pattern to eliminate ~95% code duplication.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from bitcoin.encoding.hex import decode_hex, encode_hex
from bitcoin.transaction.parser import parse_tx

if TYPE_CHECKING:
    from bitcoin.signature.record import Record

logger = logging.getLogger(__name__)

USER_AGENT = "bitcoin/0.4.0 (+https://github.com/sachn-cs/bitcoin)"
HTTP_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_BACKOFF = 1.0  # seconds
RETRYABLE_STATUSES = {429, 500, 502, 503, 504}
TXID_PATTERN = "0123456789abcdefABCDEF"
SSL_CONTEXT = ssl.create_default_context()


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

    def broadcast_transaction(self, tx_hex: str) -> str:
        """Broadcast a raw transaction to the Bitcoin network.

        Args:
            tx_hex: The raw transaction as a hex-encoded string.

        Returns:
            The txid of the broadcast transaction as a string.

        Raises:
            OSError: On network or HTTP errors.
            ValueError: If the transaction is invalid.
        """
        ...

    async def async_get_transaction_hex(self, txid: str) -> str:
        """Async version of :meth:`get_transaction_hex`."""
        ...

    async def async_get_utxo_script_pubkey(self, txid: str, vout: int) -> bytes:
        """Async version of :meth:`get_utxo_script_pubkey`."""
        ...

    async def async_get_utxo_value(self, txid: str, vout: int) -> int:
        """Async version of :meth:`get_utxo_value`."""
        ...

    async def async_broadcast_transaction(self, tx_hex: str) -> str:
        """Async version of :meth:`broadcast_transaction`."""
        ...


# ── Template-Method base for providers ────────────────────────────────
# Polymorphism: shared logic lives here; subclasses override only the
# JSON key paths that differ between APIs.


class BaseBlockchainProvider:
    """Base implementing the Template Method pattern for blockchain providers.

    Subclasses set ``BASE_URL`` and optionally override ``outputs_key``,
    ``script_key``, ``value_key``, ``do_get_transaction_hex``, and
    ``tx_json_url`` to adapt to each API's JSON structure.
    """

    BASE_URL: str = ""

    # JSON key paths differ per provider:
    #   Blockstream/Mempool: {"vout": [{scriptpubkey, value}]}
    #   Blockchain.info:     {"out": [{script, value}]}
    outputs_key: str = "vout"
    script_key: str = "scriptpubkey"
    value_key: str = "value"

    def get_transaction_hex(self, txid: str) -> str:
        """Fetch a raw transaction hex.

        Args:
            txid: The 64-character transaction ID.

        Returns:
            The raw transaction as a hex string.
        """
        return self.do_get_transaction_hex(txid)

    def do_get_transaction_hex(self, txid: str) -> str:
        """Template hook for tx hex URL; may be overridden."""
        validate_txid(txid)
        url = f"{self.BASE_URL}/tx/{txid}/hex"
        return fetch_text(url)

    def get_utxo_script_pubkey(self, txid: str, vout: int) -> bytes:
        """Fetch the ``scriptPubKey`` for a given UTXO."""
        validate_txid(txid)
        tx_json = self.fetch_tx_json(txid)
        outputs = tx_json.get(self.outputs_key, [])
        if vout >= len(outputs):
            raise ValueError(f"vout {vout} out of range for tx {txid} "
                             f"(only {len(outputs)} outputs).")
        raw_script = outputs[vout].get(self.script_key)
        if raw_script is None:
            raise ValueError(f"No script for vout {vout} in tx {txid}.")
        if isinstance(raw_script, str):
            return decode_hex(raw_script)
        return raw_script

    def get_utxo_value(self, txid: str, vout: int) -> int:
        """Fetch the value in satoshis for a given UTXO."""
        validate_txid(txid)
        tx_json = self.fetch_tx_json(txid)
        outputs = tx_json.get(self.outputs_key, [])
        if vout >= len(outputs):
            raise ValueError(f"vout {vout} out of range for tx {txid} "
                             f"(only {len(outputs)} outputs).")
        return int(outputs[vout][self.value_key])

    def fetch_tx_json(self, txid: str) -> dict[str, Any]:
        """Fetch the full transaction JSON.

        Args:
            txid: The 64-character transaction ID.

        Returns:
            Parsed JSON response as a dict.

        Raises:
            OSError: On network failure or non-200 status.
            ValueError: If the response is not valid JSON.
        """
        validate_txid(txid)
        url = self.tx_json_url(txid)
        raw = fetch_text(url)
        try:
            data: dict[str, Any] = json.loads(raw)
            return data
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON response from {url}: {exc}") from exc

    def tx_json_url(self, txid: str) -> str:
        """Template method: URL for the full tx JSON endpoint."""
        return f"{self.BASE_URL}/tx/{txid}"

    def broadcast_transaction(self, tx_hex: str) -> str:
        """Broadcast a raw transaction.

        Args:
            tx_hex: Raw transaction as hex string.

        Returns:
            The txid of the broadcast transaction.

        Raises:
            OSError: On network failure.
            ValueError: If the transaction is invalid.
        """
        return self.do_broadcast_transaction(tx_hex)

    def do_broadcast_transaction(self, tx_hex: str) -> str:
        """Template hook for broadcasting.  Subclasses may override."""
        url = self.broadcast_url()
        raw_tx = decode_hex(tx_hex.strip())
        response = post_data(url, raw_tx)
        txid = response.strip()
        return txid

    def broadcast_url(self) -> str:
        """Template method: URL for the broadcast endpoint."""
        return f"{self.BASE_URL}/tx"

    # ── Async delegate helpers ─────────────────────────────────────────
    # These wrap the sync methods with ``asyncio.to_thread`` so that
    # callers can use ``await`` without adding any new dependencies.

    async def async_get_transaction_hex(self, txid: str) -> str:
        """Async version of :meth:`get_transaction_hex`."""
        return await asyncio.to_thread(self.get_transaction_hex, txid)

    async def async_get_utxo_script_pubkey(self, txid: str, vout: int) -> bytes:
        """Async version of :meth:`get_utxo_script_pubkey`."""
        return await asyncio.to_thread(self.get_utxo_script_pubkey, txid, vout)

    async def async_get_utxo_value(self, txid: str, vout: int) -> int:
        """Async version of :meth:`get_utxo_value`."""
        return await asyncio.to_thread(self.get_utxo_value, txid, vout)

    async def async_broadcast_transaction(self, tx_hex: str) -> str:
        """Async version of :meth:`broadcast_transaction`."""
        return await asyncio.to_thread(self.broadcast_transaction, tx_hex)


class BlockstreamProvider(BaseBlockchainProvider):
    """Blockstream.info API blockchain provider.

    Attributes:
        BASE_URL: Base URL of the Blockstream API.
    """

    BASE_URL = "https://blockstream.info/api"


class BlockchainInfoProvider(BaseBlockchainProvider):
    """blockchain.info API blockchain provider.

    Attributes:
        BASE_URL: Base URL of the blockchain.info API.
    """

    BASE_URL = "https://blockchain.info"
    outputs_key = "out"
    script_key = "script"
    value_key = "value"

    def do_get_transaction_hex(self, txid: str) -> str:
        """Blockchain.info uses a different URL path with ``?format=hex``."""
        validate_txid(txid)
        url = f"{self.BASE_URL}/rawtx/{txid}?format=hex"
        return fetch_text(url)

    def tx_json_url(self, txid: str) -> str:
        return f"{self.BASE_URL}/rawtx/{txid}"


class MempoolSpaceProvider(BaseBlockchainProvider):
    """mempool.space API blockchain provider.

    Attributes:
        BASE_URL: Base URL of the mempool.space API.
    """

    BASE_URL = "https://mempool.space/api"


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


def fetch_text(url: str, *, timeout: int = HTTP_TIMEOUT) -> str:
    """Fetch a URL and return the response body as text.

    Retries up to ``MAX_RETRIES`` times with exponential backoff for
    transient HTTP errors (429, 500, 502, 503, 504) and URL errors.
    Uses an explicit SSL context for certificate verification.

    Args:
        url: The URL to fetch.
        timeout: Request timeout in seconds (default ``HTTP_TIMEOUT``, 30).

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
            with urlopen(req, timeout=timeout, context=SSL_CONTEXT) as resp:
                data: bytes = resp.read()
                return data.decode("utf-8")
        except HTTPError as exc:
            msg = f"HTTP {exc.code} fetching {url}: {exc.reason}"
            if exc.code in RETRYABLE_STATUSES and attempt < MAX_RETRIES - 1:
                wait = RETRY_BACKOFF * (2**attempt)
                logger.debug("HTTP %d fetching %s, retrying in %.1fs (attempt %d/%d)",
                             exc.code, url, wait, attempt + 1, MAX_RETRIES)
                time.sleep(wait)
                last_error = OSError(msg)
                continue
            raise OSError(msg) from exc
        except URLError as exc:
            msg = f"URL error fetching {url}: {exc.reason}"
            if attempt < MAX_RETRIES - 1:
                wait = RETRY_BACKOFF * (2**attempt)
                logger.debug("URL error fetching %s, retrying in %.1fs (attempt %d/%d)",
                             url, wait, attempt + 1, MAX_RETRIES)
                time.sleep(wait)
                last_error = OSError(msg)
                continue
            raise OSError(msg) from exc
    if last_error is not None:
        raise last_error
    raise OSError(f"Failed to fetch {url} after {MAX_RETRIES} attempts.")


def post_data(url: str, data: bytes, *, timeout: int = HTTP_TIMEOUT) -> str:
    """POST *data* to *url* and return the response body as text.

    Uses ``Content-Type: application/octet-stream`` (the standard for
    Bitcoin raw transaction broadcast).  Retries on transient errors.

    Args:
        url: The URL to POST to.
        data: The raw bytes to send.
        timeout: Request timeout (default 30 s).

    Returns:
        The response body decoded as UTF-8.

    Raises:
        OSError: On repeated network failure.
        ValueError: If the response indicates a malformed transaction.
    """
    last_error: OSError | None = None
    for attempt in range(MAX_RETRIES):
        try:
            req = Request(
                url,
                data=data,
                headers={
                    "User-Agent": USER_AGENT,
                    "Content-Type": "application/octet-stream",
                },
                method="POST",
            )
            with urlopen(req, timeout=timeout, context=SSL_CONTEXT) as resp:
                resp_data: bytes = resp.read()
                return resp_data.decode("utf-8")
        except HTTPError as exc:
            msg = f"HTTP {exc.code} POST {url}: {exc.reason}"
            if exc.code in RETRYABLE_STATUSES and attempt < MAX_RETRIES - 1:
                wait = RETRY_BACKOFF * (2**attempt)
                logger.debug("HTTP %d POST %s, retrying in %.1fs (attempt %d/%d)",
                             exc.code, url, wait, attempt + 1, MAX_RETRIES)
                time.sleep(wait)
                last_error = OSError(msg)
                continue
            body = exc.read().decode("utf-8", errors="replace")
            raise OSError(f"{msg}: {body}") from exc
        except URLError as exc:
            msg = f"URL error POST {url}: {exc.reason}"
            if attempt < MAX_RETRIES - 1:
                wait = RETRY_BACKOFF * (2**attempt)
                logger.debug("URL error POST %s, retrying in %.1fs (attempt %d/%d)",
                             url, wait, attempt + 1, MAX_RETRIES)
                time.sleep(wait)
                last_error = OSError(msg)
                continue
            raise OSError(msg) from exc
    if last_error is not None:
        raise last_error
    raise OSError(f"Failed to POST {url} after {MAX_RETRIES} attempts.")


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

    If *txid_or_hex* looks like a 64-character transaction ID, the
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


def broadcast_transaction(
    tx_hex: str,
    *,
    provider: BlockchainProvider | None = None,
) -> str:
    """Broadcast a raw transaction to the Bitcoin network.

    Args:
        tx_hex: The raw transaction as a hex-encoded string.
        provider: A ``BlockchainProvider`` instance.  If ``None``,
            a ``BlockstreamProvider`` is created automatically.

    Returns:
        The txid of the broadcast transaction as a string.

    Raises:
        OSError: On network or HTTP errors.
        ValueError: If *tx_hex* is invalid or the network rejects it.
    """
    if provider is None:
        provider = BlockstreamProvider()
    return provider.broadcast_transaction(tx_hex)


async def async_enrich_transaction(
    tx_hex: str,
    *,
    provider: BaseBlockchainProvider | None = None,
) -> tuple[list[bytes], list[int]]:
    """Async version of :func:`enrich_transaction`.

    Uses ``asyncio.gather`` to fetch all UTXO scripts and values
    concurrently.
    """
    if provider is None:
        provider = BlockstreamProvider()

    raw = decode_hex(tx_hex.strip())
    tx, _ = parse_tx(raw)

    async def fetch_one(txin: Any) -> tuple[bytes, int]:
        prev_txid = encode_hex(txin.previous_output.txid)
        vout = txin.previous_output.vout
        script = await provider.async_get_utxo_script_pubkey(prev_txid, vout)
        value = await provider.async_get_utxo_value(prev_txid, vout)
        return script, value

    results = await asyncio.gather(*[fetch_one(txin) for txin in tx.inputs])
    scripts, values = zip(*results, strict=True) if results else ([], [])
    return list(scripts), list(values)


__all__ = [
    "BlockchainInfoProvider",
    "BlockchainProvider",
    "BlockstreamProvider",
    "MempoolSpaceProvider",
    "async_enrich_transaction",
    "broadcast_transaction",
    "enrich_transaction",
    "fetch_and_extract",
]
