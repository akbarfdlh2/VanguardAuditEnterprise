.PHONY: install run cli lint format typecheck security test all

install:
	pip install -e ".[dev]"

run:
	python -m vanguard.main

cli:
	python -m vanguard.main --headless --url https://example.com --export-md

lint:
	ruff check src tests

format:
	ruff format src tests

typecheck:
	mypy src

security:
	bandit -c pyproject.toml -r src

test:
	pytest

all: format lint typecheck security test
