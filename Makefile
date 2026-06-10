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
	python3 -m pytest

test-verbose:
	python3 -m pytest -v --tb=long

test-cov:
	python3 -m pytest --cov=bitcoin --cov-report=term-missing

clean:
	./cleanup.sh
