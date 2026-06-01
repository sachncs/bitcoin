#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_DIR"

echo "Creating virtual environment..."
python3 -m venv .venv

echo "Activating virtual environment..."
# shellcheck source=/dev/null
source .venv/bin/activate || { echo "Failed to activate virtual environment."; exit 1; }

echo "Installing package in development mode with dev dependencies..."
pip install --upgrade pip
pip install -e ".[dev]"

echo "Installing pre-commit hooks..."
pre-commit install

echo "Running tests..."
python -m pytest tests/

echo "Done."
