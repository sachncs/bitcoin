#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_DIR"

echo "Creating virtual environment via uv..."
uv venv

echo "Syncing dependencies..."
uv sync --extra dev

echo "Running tests..."
uv run pytest tests/

echo "Done."
