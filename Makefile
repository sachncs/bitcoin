SHELL := /usr/bin/env bash

.PHONY: all setup venv lint typecheck test test-verbose test-cov docs clean

all: lint typecheck test

setup:
	./setup.sh

venv:
	uv venv && uv sync --extra dev

lint:
	uv run ruff check .

typecheck:
	uv run mypy -p bitcoin

test:
	uv run pytest

test-verbose:
	uv run pytest -v --tb=long

test-cov:
	uv run pytest --cov=bitcoin --cov-report=term-missing

docs:
	uv run sphinx-build -b html docs/source docs/build

clean:
	./cleanup.sh
