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
.venv/bin/pip install --upgrade "pip>=24,<25"
.venv/bin/pip install -e ".[dev]"

echo "Installing pre-commit hooks..."
if [ -f .pre-commit-config.yaml ]; then
    pre-commit install
else
    echo "No .pre-commit-config.yaml found — skipping pre-commit setup."
fi

echo "Running tests..."
.venv/bin/python -m pytest tests/

echo "Done."
