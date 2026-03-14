# Makefile for Katran Control Plane

.PHONY: all install dev test unit-test e2e-test integration-test lint format clean \
        docker-build docker-test docker-debug docker-stop docker-clean \
        e2e-multi e2e-multi-debug e2e-multi-shell e2e-multi-stop e2e-multi-clean \
        ci-local ci-local-lint ci-local-unit ci-local-integration ci-local-e2e help

VENV := .venv/bin
PYTHON := $(VENV)/python3
PYTEST := $(PYTHON) -m pytest
PIP := $(PYTHON) -m pip
DOCKER_COMPOSE := docker compose -f docker-compose.test.yml
E2E_COMPOSE := docker compose -f docker-compose.e2e.yml

# Default target
all: help

# ─── Setup ───────────────────────────────────────────────────────────────────

# Create venv and install package in editable mode with dev deps
venv:
	python3 -m venv .venv
	$(PIP) install -e ".[dev]"

# Install package (editable)
install:
	$(PIP) install -e .

# Install with development dependencies
dev:
	$(PIP) install -e ".[dev]"

# ─── Testing ─────────────────────────────────────────────────────────────────

# Run all local tests (unit only; integration/e2e require Docker)
test: unit-test

# Run unit tests
unit-test:
	$(PYTEST) tests/unit/ -v

# Run unit tests with coverage
unit-test-cov:
	$(PYTEST) tests/unit/ -v --cov=src/katran --cov-report=html --cov-report=term

# Run e2e tests (requires BPF environment — use inside Docker or via integration-test)
e2e-test:
	$(PYTEST) tests/e2e/ -v

# Run integration + e2e tests (uses shell script for Docker orchestration)
integration-test:
	./tests/integration/run-tests.sh

# Run integration tests with debug output
integration-test-debug:
	./tests/integration/run-tests.sh --debug

# ─── Quality ─────────────────────────────────────────────────────────────────

# Lint code
lint:
	$(VENV)/ruff check src/ tests/
	$(VENV)/mypy src/

# Format code
format:
	$(VENV)/ruff format src/ tests/
	$(VENV)/ruff check --fix src/ tests/

# Validate config files load without errors
check-config:
	$(PYTHON) -c "from katran.core.config import KatranConfig; c = KatranConfig.from_yaml('config/katran.yaml'); print('flat  :', c.interface.name, c.maps.ring_size)"
	$(PYTHON) -c "from katran.core.config import KatranConfig; c = KatranConfig.from_yaml('config/katran-nested.yaml'); print('nested:', c.interface.name, c.maps.ring_size)"

# ─── Cleanup ─────────────────────────────────────────────────────────────────

# Clean build artifacts
clean:
	rm -rf build/ dist/ *.egg-info/ src/*.egg-info/
	rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/
	rm -rf htmlcov/ .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete

# ─── Docker ──────────────────────────────────────────────────────────────────

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

# ─── E2E Multi-Container ────────────────────────────────────────────────

# Run multi-container E2E tests (XDP traffic forwarding)
e2e-multi:
	./tests/e2e/run-e2e.sh

# Run multi-container E2E tests with debug output
e2e-multi-debug:
	./tests/e2e/run-e2e.sh --debug

# Start interactive shell in test-client container
e2e-multi-shell:
	./tests/e2e/run-e2e.sh --shell

# Stop E2E containers
e2e-multi-stop:
	$(E2E_COMPOSE) down -v

# Clean E2E Docker resources
e2e-multi-clean:
	$(E2E_COMPOSE) down --rmi local -v

# ─── Local CI (via act) ───────────────────────────────────────────────────

# Run full CI locally via act (requires: https://github.com/nektos/act)
ci-local:
	act push --privileged

# Run individual CI jobs locally
ci-local-lint:
	act push --privileged -j lint

ci-local-unit:
	act push --privileged -j unit-test

ci-local-integration:
	act push --privileged -j integration-test

ci-local-e2e:
	act push --privileged -j e2e-test

# ─── Help ────────────────────────────────────────────────────────────────────

help:
	@echo "Katran Control Plane - Available targets:"
	@echo ""
	@echo "Setup:"
	@echo "  venv             Create .venv and install dev deps"
	@echo "  install          Install package (editable)"
	@echo "  dev              Install with dev dependencies"
	@echo ""
	@echo "Testing:"
	@echo "  test             Run unit tests (alias)"
	@echo "  unit-test        Run unit tests"
	@echo "  unit-test-cov    Run unit tests with coverage"
	@echo "  e2e-test         Run e2e tests (needs BPF env)"
	@echo "  integration-test Run integration + e2e tests (Docker)"
	@echo ""
	@echo "Quality:"
	@echo "  lint             Run linters (ruff, mypy)"
	@echo "  format           Format code with ruff"
	@echo "  check-config     Validate YAML config files"
	@echo "  clean            Clean build artifacts"
	@echo ""
	@echo "Docker (single-container integration):"
	@echo "  docker-build         Build test Docker image"
	@echo "  docker-test          Run integration tests"
	@echo "  docker-test-verbose  Run tests with verbose output"
	@echo "  docker-debug         Start interactive debug shell"
	@echo "  docker-stop          Stop Docker services"
	@echo "  docker-clean         Clean Docker resources"
	@echo ""
	@echo "E2E Multi-Container (XDP traffic forwarding):"
	@echo "  e2e-multi            Run multi-container E2E tests"
	@echo "  e2e-multi-debug      Run with verbose/debug output"
	@echo "  e2e-multi-shell      Shell into test-client container"
	@echo "  e2e-multi-stop       Stop E2E containers"
	@echo "  e2e-multi-clean      Clean E2E Docker resources"
	@echo ""
	@echo "Local CI (requires act - https://github.com/nektos/act):"
	@echo "  ci-local             Run full CI locally"
	@echo "  ci-local-lint        Run lint job locally"
	@echo "  ci-local-unit        Run unit tests locally"
	@echo "  ci-local-integration Run integration tests locally"
	@echo "  ci-local-e2e         Run E2E tests locally"
