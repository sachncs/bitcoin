# Copyright (c) 2026 secp contributors
# SPDX-License-Identifier: MIT
"""Command-line interface for the bitcoin package.

Re-exports the Typer :data:`app`, the :func:`main` console-script
entry point, and the small :func:`parse_input_values` helper used by
the ``extract`` command.  The actual command implementations live in
:mod:`bitcoin.cli.app`.

Commands exposed by the CLI:

- ``decode`` – parse a raw transaction and emit JSON.
- ``extract`` – extract signatures from a transaction.
- ``linearize`` – extract and sort signatures.
- ``broadcast`` – broadcast a raw transaction via a configured
  provider.
- ``health`` – run health checks and print a JSON status report.
- ``schema`` – print the JSON Schema for an output format.
- ``install_completion`` – show tab-completion instructions.
- ``version`` – print the installed package version.

The CLI is registered as the ``bitcoin`` console script by the
project's ``pyproject.toml`` (``[project.scripts]``).
"""

from bitcoin.cli.app import app, main, parse_input_values

__all__ = [
    "app",
    "main",
    "parse_input_values",
]
