# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Application-wide settings singleton for the bitcoin package.

A small, mutable, thread-safe configuration holder exposed as the
module-level :data:`settings` instance.  Three knobs are currently
exposed:

- :attr:`Settings.strict_mode` – raise on non-fatal issues instead
  of returning ``None``/``INFINITY``.
- :attr:`Settings.default_backend` – preferred curve backend name
  (``"native"``, ``"libsecp"``, or ``None`` for auto-detect).
- :attr:`Settings.max_extraction_inputs` – upper limit on the number
  of transaction inputs processed during a single extraction.

All accessors are guarded by an internal lock so concurrent reads and
writes from multiple threads are safe.  The class uses ``__slots__``
to keep the per-instance memory footprint to a handful of bytes.
"""

from __future__ import annotations

import threading


class Settings:
    """Mutable singleton holding package-level configuration.

    Attributes:
        strict_mode: If True, raise exceptions on non-fatal issues.
        default_backend: Preferred curve backend name (``"native"`` or
            ``"libsecp"``), or ``None`` for auto-detect.
        max_extraction_inputs: Upper limit on transaction inputs processed
            during signature extraction.
    """

    __slots__ = (
        "__lock",
        "__strict_mode",
        "__default_backend",
        "__max_extraction_inputs",
    )

    def __init__(self) -> None:
        self.__lock = threading.Lock()
        self.__strict_mode: bool = False
        self.__default_backend: str | None = None
        self.__max_extraction_inputs: int = 100_000

    @property
    def strict_mode(self) -> bool:
        """Whether to raise exceptions on non-fatal issues."""
        with self.__lock:
            return self.__strict_mode

    @strict_mode.setter
    def strict_mode(self, value: bool) -> None:
        with self.__lock:
            self.__strict_mode = bool(value)

    @property
    def default_backend(self) -> str | None:
        """Preferred curve backend name, or ``None`` for auto-detect."""
        with self.__lock:
            return self.__default_backend

    @default_backend.setter
    def default_backend(self, value: str | None) -> None:
        allowed = (None, "native", "libsecp")
        if value not in allowed:
            raise ValueError(f"default_backend must be one of {allowed}.")
        with self.__lock:
            self.__default_backend = value

    @property
    def max_extraction_inputs(self) -> int:
        """Maximum transaction inputs to process during extraction."""
        with self.__lock:
            return self.__max_extraction_inputs

    @max_extraction_inputs.setter
    def max_extraction_inputs(self, value: int) -> None:
        if value < 1:
            raise ValueError("max_extraction_inputs must be >= 1.")
        with self.__lock:
            self.__max_extraction_inputs = value

    def __repr__(self) -> str:
        with self.__lock:
            return (
                f"Settings(strict_mode={self.__strict_mode}, "
                f"default_backend={self.__default_backend!r}, "
                f"max_extraction_inputs={self.__max_extraction_inputs})"
            )


settings = Settings()
