# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Library health check and capability introspection.

Three diagnostic functions used by the CLI's ``health`` command and
by external monitoring scripts:

- :func:`check_backend` – report the availability and callability of
  the pure-Python and ``coincurve``/libsecp256k1 backends.
- :func:`check_imports` – verify that every public sub-module can be
  imported without error.  Useful for catching optional-dependency
  regressions early.
- :func:`health` – aggregate everything into a single dict: package
  version, per-module import status, per-backend status, and a
  smoke test (``multiply(1, GENERATOR)``) that confirms the active
  backend can perform a real curve operation.

The aggregate report is suitable for direct JSON serialisation and
contains no sensitive material.
"""

from __future__ import annotations

import importlib.metadata
import logging
from typing import Any


def check_backend() -> dict[str, Any]:
    """Return status of curve backends."""
    from bitcoin.curve.backend.libsec import LibsecpBackend
    from bitcoin.curve.backend.native import NativeBackend

    status: dict[str, Any] = {}
    try:
        native = NativeBackend()
        status["native"] = {
            "available": True,
            "multiply": callable(native.multiply),
        }
    except Exception as exc:
        status["native"] = {"available": False, "error": str(exc)}

    try:
        libsec = LibsecpBackend()
        status["libsecp256k1"] = {
            "available": True,
            "multiply": callable(libsec.multiply),
        }
    except Exception as exc:
        status["libsecp256k1"] = {"available": False, "error": str(exc)}

    return status


def check_imports() -> dict[str, bool]:
    """Check that all submodules can be imported."""
    modules = [
        "bitcoin.curve",
        "bitcoin.encoding",
        "bitcoin.field",
        "bitcoin.script",
        "bitcoin.sighash",
        "bitcoin.signature",
        "bitcoin.transaction",
        "bitcoin.psbt",
        "bitcoin.services",
        "bitcoin.cli",
    ]
    import importlib

    logger = logging.getLogger(__name__)
    result: dict[str, bool] = {}
    for mod in modules:
        try:
            importlib.import_module(mod)
            result[mod] = True
        except Exception as exc:
            logger.warning("Module import failed: %s — %s", mod, exc)
            result[mod] = False
    return result


def health() -> dict[str, Any]:
    """Run all health checks and return a comprehensive status dict."""
    from bitcoin.curve import GENERATOR, multiply

    status: dict[str, Any] = {
        "version": importlib.metadata.version("bitcoin"),
        "imports": check_imports(),
        "backends": check_backend(),
    }

    try:
        p = multiply(1, GENERATOR)
        status["curve_operation"] = {
            "ok": not p.infinity and p.x is not None,
        }
    except Exception as exc:
        status["curve_operation"] = {"ok": False, "error": str(exc)}

    return status


__all__ = ["health", "check_backend", "check_imports"]
