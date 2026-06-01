"""Application-wide settings singleton for the bitcoin package."""

from __future__ import annotations

from typing import Optional


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
        "__strict_mode",
        "__default_backend",
        "__max_extraction_inputs",
    )

    def __init__(self) -> None:
        self.__strict_mode: bool = False
        self.__default_backend: Optional[str] = None
        self.__max_extraction_inputs: int = 100_000

    @property
    def strict_mode(self) -> bool:
        """Whether to raise exceptions on non-fatal issues."""
        return self.__strict_mode

    @strict_mode.setter
    def strict_mode(self, value: bool) -> None:
        self.__strict_mode = bool(value)

    @property
    def default_backend(self) -> Optional[str]:
        """Preferred curve backend name, or ``None`` for auto-detect."""
        return self.__default_backend

    @default_backend.setter
    def default_backend(self, value: Optional[str]) -> None:
        allowed = (None, "native", "libsecp")
        if value not in allowed:
            raise ValueError(f"default_backend must be one of {allowed}.")
        self.__default_backend = value

    @property
    def max_extraction_inputs(self) -> int:
        """Maximum transaction inputs to process during extraction."""
        return self.__max_extraction_inputs

    @max_extraction_inputs.setter
    def max_extraction_inputs(self, value: int) -> None:
        if value < 1:
            raise ValueError("max_extraction_inputs must be >= 1.")
        self.__max_extraction_inputs = value

    def __repr__(self) -> str:
        return (f"Settings(strict_mode={self.__strict_mode}, "
                f"default_backend={self.__default_backend!r}, "
                f"max_extraction_inputs={self.__max_extraction_inputs})")


settings = Settings()
