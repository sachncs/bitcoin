SHELL := /usr/bin/env bash

.PHONY: all setup venv lint typecheck test test-verbose test-cov clean

all: lint typecheck test

setup:
	./setup.sh

venv:
	python3 -m venv .venv && . .venv/bin/activate && pip install -e ".[dev]"

lint:
	ruff check .

typecheck:
	mypy -p bitcoin

test:
	python -m pytest

test-verbose:
	python -m pytest -v --tb=long

test-cov:
	python -m pytest --cov=bitcoin --cov-report=term-missing

clean:
	./cleanup.sh
