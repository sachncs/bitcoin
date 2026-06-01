SHELL := /usr/bin/env bash

.PHONY: all setup lint typecheck test clean

all: lint typecheck test

setup:
	./setup.sh

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
