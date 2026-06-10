# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
from pytest import fixture

from bitcoin.settings import settings


@fixture(autouse=True)
def reset_settings() -> None:
    """Reset the global settings singleton before each test.

    Prevents test-pollution when tests modify module-level
    ``bitcoin.settings.settings``.
    """
    settings.strict_mode = False
    settings.default_backend = None
    settings.max_extraction_inputs = 100_000
