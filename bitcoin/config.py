"""Configuration system supporting env vars and config files."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

ENV_PREFIX = "BITCOIN_"

__all__ = [
    "Config",
    "ENV_PREFIX",
    "coerce",
    "load_file",
]


@dataclass(frozen=True, slots=True)
class Config:
    """Package-wide configuration with env-var overrides.

    Environment variable mapping:
      ``BITCOIN_ECC_BACKEND``      → ``ecc_backend``
      ``BITCOIN_NETWORK``           → ``network``
      ``BITCOIN_FETCH_TIMEOUT``     → ``fetch_timeout``
      ``BITCOIN_STRICT_PARSING``    → ``strict_parsing``
    """

    ecc_backend: str = "python"
    network: str = "mainnet"
    fetch_timeout: int = 30
    strict_parsing: bool = True

    @classmethod
    def from_env(cls) -> Config:
        """Build Config from environment variables."""
        kwargs: dict[str, Any] = {}
        for f in fields(cls):
            env_key = ENV_PREFIX + f.name.upper()
            raw = os.environ.get(env_key)
            if raw is not None:
                kwargs[f.name] = coerce(raw, f.type)
        return cls(**kwargs)

    @classmethod
    def load(cls, path: str | None = None) -> Config:
        """Load config from file (JSON) with env-var overrides."""
        kwargs: dict[str, Any] = {}
        if path is not None:
            file_cfg = load_file(path)
            kwargs.update(file_cfg)
        # Env vars override file values
        for f in fields(cls):
            env_key = ENV_PREFIX + f.name.upper()
            raw = os.environ.get(env_key)
            if raw is not None:
                kwargs[f.name] = coerce(raw, f.type)
        return cls(**kwargs)


def coerce(raw: str, target: object) -> Any:
    if target is bool or target == "bool":
        return raw.lower() in ("1", "true", "yes")
    if target is int or target == "int":
        try:
            return int(raw)
        except ValueError:
            raise ValueError(
                f"Cannot coerce environment variable value {raw!r} to int."
            ) from None
    return raw


def load_file(path: str) -> dict[str, Any]:
    import json

    p = Path(path)
    if not p.exists():
        logger.error("Config file %s not found", path)
        return {}
    raw = p.read_text()
    if path.endswith(".json"):
        return json.loads(raw)
    logger.error("Unsupported config file format: %s", path)
    return {}
