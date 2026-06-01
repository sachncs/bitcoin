"""Lightweight plugin registry for custom script-path extractors."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from bitcoin.signature.record import Record
from bitcoin.transaction.models import Tx, TxIn


@runtime_checkable
class ExtractorPlugin(Protocol):
    """Protocol for custom script-type extractors."""

    name: str

    def can_handle(self, script_type: str, is_segwit: bool) -> bool:
        """Return True if this plugin handles the given script type."""
        ...

    def extract(self, tx: Tx, vin: int, txin: TxIn, script_pubkey: bytes,
                value: int) -> list[Record]:
        """Extract signatures from this input."""
        ...


__registry: dict[str, ExtractorPlugin] = {}


def register_plugin(plugin: ExtractorPlugin) -> None:
    """Register a custom extractor plugin."""
    __registry[plugin.name] = plugin


def unregister_plugin(name: str) -> None:
    """Remove a plugin from the registry."""
    __registry.pop(name, None)


def get_plugin(name: str) -> ExtractorPlugin | None:
    """Retrieve a registered plugin by name."""
    return __registry.get(name)


def list_plugins() -> list[str]:
    """Return the names of all registered plugins."""
    return list(__registry)
