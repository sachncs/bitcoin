# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Lightweight plugin registry for custom script-path extractors.

Defines the :class:`ExtractorPlugin` :class:`~typing.Protocol` that
all extractor plugins must satisfy, plus a tiny in-memory registry:

- :data:`registry` – the underlying ``{name: plugin}`` mapping.
- :func:`register_plugin` – add a plugin by its ``name`` attribute.
- :func:`unregister_plugin` – remove a previously registered plugin.
- :func:`get_plugin` – look up a plugin by name.
- :func:`list_plugins` – return the names of all registered plugins.

The five built-in extractors (Legacy, P2WPKH, P2WSH, P2SH-SegWit,
Taproot) are registered automatically by
:func:`bitcoin.signature.extraction.engine.register_builtin_extractors`,
which is called by :func:`~bitcoin.signature.extraction.engine.extract_signatures`
on first use.  External code can register additional plugins to
support new script types without modifying this library.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from bitcoin.signature.record import Record
from bitcoin.transaction.models import Tx, TxIn


@runtime_checkable
class ExtractorPlugin(Protocol):
    """Protocol for custom script-type extractors.

    Implementations declare a ``name`` (used as the registry key) and
    two methods:

    - :meth:`can_handle` reports whether the plugin can process a
      given ``(script_type, is_segwit)`` pair.
    - :meth:`extract` performs the actual signature extraction for
      one input.
    """

    name: str

    def can_handle(self, script_type: str, is_segwit: bool) -> bool:
        """Return True if this plugin handles the given script type.

        Args:
            script_type: The classified script type (e.g. ``"p2pkh"``).
            is_segwit: Whether the input carries witness data.

        Returns:
            ``True`` if the plugin should handle this input.
        """
        ...

    def extract(
        self, tx: Tx, vin: int, txin: TxIn, script_pubkey: bytes, value: int
    ) -> list[Record]:
        """Extract signatures from this input.

        Args:
            tx: The parent transaction.
            vin: Index of the input being processed.
            txin: The ``TxIn`` providing scriptSig and witness data.
            script_pubkey: The previous output's ``scriptPubKey``.
            value: The UTXO value in satoshis (for SegWit sighash).

        Returns:
            A list of :class:`~bitcoin.signature.record.Record`
            instances.  Returning an empty list means "no signatures
            discovered" rather than "plugin does not apply".
        """
        ...


registry: dict[str, ExtractorPlugin] = {}
"""The process-wide extractor-plugin registry.

Keys are plugin ``name`` attributes; values are the plugin
instances.  Mutate only through :func:`register_plugin` and
:func:`unregister_plugin` to keep the registry consistent.
"""


def register_plugin(plugin: ExtractorPlugin) -> None:
    """Register a custom extractor plugin.

    The plugin's :attr:`ExtractorPlugin.name` is used as the registry
    key; registering a plugin whose name is already present
    overwrites the previous entry.

    Args:
        plugin: The plugin instance to register.
    """
    registry[plugin.name] = plugin


def unregister_plugin(name: str) -> None:
    """Remove a plugin from the registry.

    Args:
        name: The plugin name to remove.  Silently does nothing if
            no plugin is registered under that name.
    """
    registry.pop(name, None)


def get_plugin(name: str) -> ExtractorPlugin | None:
    """Retrieve a registered plugin by name.

    Args:
        name: The plugin name to look up.

    Returns:
        The plugin instance, or ``None`` if no plugin is registered
        under *name*.
    """
    return registry.get(name)


def list_plugins() -> list[str]:
    """Return the names of all registered plugins."""
    return list(registry)


__all__ = [
    "ExtractorPlugin",
    "get_plugin",
    "list_plugins",
    "register_plugin",
    "registry",
    "unregister_plugin",
]
