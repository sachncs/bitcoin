# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""libsecp256k1 (coincurve) availability probe.

A thin module whose only public entry point, :func:`check`, raises
:exc:`ImportError` if the optional ``coincurve`` C extension is not
installed.  It exists as a separate module so that the
:class:`~bitcoin.curve.backend.libsec.LibsecpBackend` can probe for the
dependency before attempting to call into it, without forcing the
import to happen at package load time (which would break for users
who only want the pure-Python backend).
"""


def check() -> None:
    """Raise ``ImportError`` if ``coincurve`` is not installed."""
    import coincurve  # noqa: F401  # type: ignore[import-not-found]
