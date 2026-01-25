# Makefile for Katran Control Plane

.PHONY: all install dev test unit-test integration-test lint format clean docker-build docker-test docker-debug help

PYTHON := python3
PYTEST := pytest
DOCKER_COMPOSE := docker compose -f docker-compose.test.yml

# Default target
all: help

# Install package
install:
	$(PYTHON) -m pip install -e .

# Install with development dependencies
dev:
	$(PYTHON) -m pip install -e ".[dev]"

# Run all tests (unit only, integration requires Docker)
test: unit-test

# Run unit tests
unit-test:
	$(PYTEST) tests/unit/ -v

# Run unit tests with coverage
unit-test-cov:
	$(PYTEST) tests/unit/ -v --cov=src/katran --cov-report=html --cov-report=term

# Run integration tests (uses shell script for proper orchestration)
integration-test:
	./tests/integration/run-tests.sh

# Run integration tests with debug output
integration-test-debug:
	./tests/integration/run-tests.sh --debug

# Lint code
lint:
	ruff check src/ tests/
	mypy src/

# Format code
format:
	ruff format src/ tests/
	ruff check --fix src/ tests/

# Clean build artifacts
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf src/*.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	rm -rf htmlcov/
	rm -rf .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

# Docker targets

# Build Docker image for integration tests
docker-build:
	$(DOCKER_COMPOSE) build

# Run integration tests via shell script (recommended)
docker-test: integration-test

# Run integration tests with verbose output
docker-test-verbose: integration-test-debug

# Start interactive debug shell in container
docker-debug:
	./tests/integration/run-tests.sh --shell

# Stop all Docker services
docker-stop:
	$(DOCKER_COMPOSE) down -v

# Clean Docker resources
docker-clean:
	$(DOCKER_COMPOSE) down --rmi local -v

# Help
help:
	@echo "Katran Control Plane - Available targets:"
	@echo ""
	@echo "Development:"
	@echo "  install          Install package"
	@echo "  dev              Install with dev dependencies"
	@echo "  lint             Run linters (ruff, mypy)"
	@echo "  format           Format code with ruff"
	@echo "  clean            Clean build artifacts"
	@echo ""
	@echo "Testing:"
	@echo "  test             Run unit tests"
	@echo "  unit-test        Run unit tests"
	@echo "  unit-test-cov    Run unit tests with coverage"
	@echo "  integration-test Run integration tests (Docker)"
	@echo ""
	@echo "Docker (for integration tests):"
	@echo "  docker-build         Build test Docker image"
	@echo "  docker-test          Run integration tests"
	@echo "  docker-test-verbose  Run tests with verbose output"
	@echo "  docker-debug         Start interactive debug shell"
	@echo "  docker-stop          Stop Docker services"
	@echo "  docker-clean         Clean Docker resources"
	@echo ""
	@echo "Examples:"
	@echo "  make dev                      # Install for development"
	@echo "  make unit-test                # Run unit tests"
	@echo "  make integration-test         # Run integration tests"
	@echo "  make integration-test-debug   # Run with debug output"
