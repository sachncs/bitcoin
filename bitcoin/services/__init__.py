# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Services — serialisation, blockchain data fetching, and batch operations.

Two complementary submodules:

- :mod:`bitcoin.services.serializer` – wire-format serialisation for
  SegWit and legacy transactions, JSON conversion, and the specialised
  sighash pre-image serializers used by
  :mod:`bitcoin.sighash.legacy` and :mod:`bitcoin.sighash.taproot`.
- :mod:`bitcoin.services.blockchain` – pluggable blockchain data
  providers (Blockstream, blockchain.info, Mempool.space, generic
  HTTP), convenience enrichment helpers, and parallel/async batch
  fetchers.

These modules are intentionally isolated from the rest of the
library: they are the only modules that perform network I/O, so
they can be avoided entirely in air-gapped or test environments by
importing only the curve / signature / script layers.
"""

from bitcoin.services.blockchain import (
    BlockchainInfoProvider,
    BlockchainProvider,
    BlockstreamProvider,
    GenericHttpProvider,
    MempoolSpaceProvider,
    async_batch_fetch_transactions,
    async_enrich_transaction,
    batch_enrich_transactions,
    batch_fetch_transactions,
    broadcast_transaction,
    enrich_transaction,
    fetch_and_extract,
)
from bitcoin.services.serializer import (
    serialize_legacy_tx,
    serialize_tx,
    tx_to_json,
)

__all__ = [
    "BlockchainInfoProvider",
    "BlockchainProvider",
    "BlockstreamProvider",
    "GenericHttpProvider",
    "MempoolSpaceProvider",
    "async_batch_fetch_transactions",
    "async_enrich_transaction",
    "batch_enrich_transactions",
    "batch_fetch_transactions",
    "broadcast_transaction",
    "enrich_transaction",
    "fetch_and_extract",
    "serialize_legacy_tx",
    "serialize_tx",
    "tx_to_json",
]
