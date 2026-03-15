#!/bin/bash
#
# Multi-container E2E test orchestrator for Katran control plane.
#
# Usage:
#   ./tests/e2e/run-e2e.sh             # Run all E2E tests
#   ./tests/e2e/run-e2e.sh --debug     # Run with verbose output
#   ./tests/e2e/run-e2e.sh --shell     # Start shell in test-client container
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.e2e.yml"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

DEBUG=0
SHELL_MODE=0
for arg in "$@"; do
    case "$arg" in
        --debug) DEBUG=1 ;;
        --shell) SHELL_MODE=1 ;;
    esac
done

cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
}

echo -e "\n${BLUE}=== Katran Multi-Container E2E Tests ===${NC}\n"

# Build and start all containers
echo "Building images..."
cd "$PROJECT_DIR"
docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
docker compose -f "$COMPOSE_FILE" up -d --build

echo "Waiting for services to become healthy..."

# Wait for LB health check (up to 120s for XDP load + map pinning)
echo -n "  katran-lb: "
for i in $(seq 1 60); do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' katran-e2e-lb 2>/dev/null || echo "unknown")
    if [ "$STATUS" = "healthy" ]; then
        echo -e "${GREEN}ready${NC}"
        break
    fi
    if [ "$STATUS" = "unhealthy" ] || [ "$STATUS" = "unknown" ]; then
        if [ "$i" -eq 60 ]; then
            echo -e "${RED}failed${NC}"
            echo "LB container logs:"
            docker logs katran-e2e-lb 2>&1 | tail -50
            cleanup
            exit 1
        fi
    fi
    echo -n "."
    sleep 2
done

# Wait for backends
for backend in katran-e2e-backend-1 katran-e2e-backend-2 katran-e2e-backend-3 katran-e2e-hc-target; do
    echo -n "  $backend: "
    for i in $(seq 1 20); do
        STATUS=$(docker inspect --format='{{.State.Health.Status}}' "$backend" 2>/dev/null || echo "unknown")
        if [ "$STATUS" = "healthy" ]; then
            echo -e "${GREEN}ready${NC}"
            break
        fi
        if [ "$i" -eq 20 ]; then
            echo -e "${RED}failed${NC}"
            echo "Backend logs:"
            docker logs "$backend" 2>&1 | tail -20
            cleanup
            exit 1
        fi
        echo -n "."
        sleep 1
    done
done

echo ""

# Shell mode: drop into test-client container
if [ "$SHELL_MODE" -eq 1 ]; then
    echo -e "${YELLOW}Starting interactive shell in test-client...${NC}"
    echo "  API:     http://katran-lb:8080"
    echo "  VIP:     http://10.200.0.10:80"
    echo "  Run:     pytest tests/e2e/ -v"
    docker exec -it katran-e2e-client bash
    cleanup
    exit 0
fi

trap cleanup EXIT

# Run tests
echo -e "${BLUE}Running E2E tests...${NC}\n"

PYTEST_ARGS="-v --tb=short"
[ "$DEBUG" -eq 1 ] && PYTEST_ARGS="-vv --tb=long -s"

if docker exec katran-e2e-client pytest tests/e2e/ $PYTEST_ARGS 2>&1; then
    echo -e "\n${GREEN}=== All E2E tests passed ===${NC}"
    EXIT_CODE=0
else
    echo -e "\n${RED}=== Some E2E tests failed ===${NC}"
    EXIT_CODE=1
fi

# Show container logs on failure or debug
if [ "$EXIT_CODE" -ne 0 ] || [ "$DEBUG" -eq 1 ]; then
    echo -e "\n${YELLOW}--- LB logs ---${NC}"
    docker logs katran-e2e-lb 2>&1 | tail -30
    echo -e "\n${YELLOW}--- Backend-1 logs ---${NC}"
    docker logs katran-e2e-backend-1 2>&1 | tail -10
    echo -e "\n${YELLOW}--- Backend-2 logs ---${NC}"
    docker logs katran-e2e-backend-2 2>&1 | tail -10
    echo -e "\n${YELLOW}--- Backend-3 logs ---${NC}"
    docker logs katran-e2e-backend-3 2>&1 | tail -10
    echo -e "\n${YELLOW}--- HC Target logs ---${NC}"
    docker logs katran-e2e-hc-target 2>&1 | tail -10
fi

exit $EXIT_CODE
