# Frost Gate Spear Makefile

.PHONY: help install dev test lint format type-check clean docker-build docker-up docker-down

# Default target
help:
	@echo "Frost Gate Spear - Development Commands"
	@echo ""
	@echo "Setup:"
	@echo "  make install      Install production dependencies"
	@echo "  make dev          Install development dependencies"
	@echo ""
	@echo "Development:"
	@echo "  make test         Run tests"
	@echo "  make lint         Run linter"
	@echo "  make format       Format code"
	@echo "  make type-check   Run type checker"
	@echo "  make check        Run all checks (lint, type-check, test)"
	@echo ""
	@echo "Docker:"
	@echo "  make docker-build Build Docker image"
	@echo "  make docker-up    Start all services"
	@echo "  make docker-down  Stop all services"
	@echo ""
	@echo "Other:"
	@echo "  make clean        Clean build artifacts"
	@echo "  make run          Run the server locally"

# Installation
install:
	pip install -e .

dev:
	pip install -e ".[dev]"
	pre-commit install

# Testing
test:
	pytest tests/ -v --cov=src --cov-report=term-missing

test-unit:
	pytest tests/test_core.py -v

test-integration:
	pytest tests/test_integration.py -v

# Code quality
lint:
	ruff check src tests

format:
	black src tests
	ruff check --fix src tests

type-check:
	mypy src

check: lint type-check test

# Cleaning
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .coverage
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete

# Docker
docker-build:
	docker build -t frostgate-spear:latest .

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f frostgate

# Running
run:
	python -m src.cli server --host 0.0.0.0 --port 8080

run-dev:
	python -m src.cli server --host 0.0.0.0 --port 8080 --log-level DEBUG

# Validation
validate-policies:
	opa check policy/*.rego
	opa test policy/ -v

validate-schemas:
	python -c "import json; json.load(open('policy/policy_envelope.schema.json'))"
	python -c "import json; json.load(open('scenarios/schema.json'))"
	python -c "import json; json.load(open('adversary_personas/schema.json'))"

# Simulation
simulate:
	python -m src.cli simulate \
		--envelope examples/mission_envelope.json \
		--scenario scenarios/examples/web_app_compromise.json \
		--iterations 100

# Database
db-init:
	docker-compose exec postgres psql -U frostgate -d frostgate -f /docker-entrypoint-initdb.d/init.sql

db-shell:
	docker-compose exec postgres psql -U frostgate -d frostgate
