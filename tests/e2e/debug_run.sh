#!/bin/bash
#
# Launch e2e environment and run debug test script
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

cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
}

trap cleanup EXIT

echo -e "${BLUE}=== Katran E2E Debug Environment ===${NC}\n"

# Build and start
echo "Building and starting containers..."
cd "$PROJECT_DIR"
docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
docker compose -f "$COMPOSE_FILE" up -d --build

# Wait for LB
echo -n "Waiting for katran-lb: "
for i in $(seq 1 60); do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' katran-e2e-lb 2>/dev/null || echo "unknown")
    if [ "$STATUS" = "healthy" ]; then
        echo -e "${GREEN}ready${NC}"
        break
    fi
    if [ "$i" -eq 60 ]; then
        echo -e "${RED}failed${NC}"
        exit 1
    fi
    echo -n "."
    sleep 2
done

# Wait for backends
for backend in katran-e2e-backend-1 katran-e2e-backend-2; do
    echo -n "Waiting for $backend: "
    for i in $(seq 1 20); do
        STATUS=$(docker inspect --format='{{.State.Health.Status}}' "$backend" 2>/dev/null || echo "unknown")
        if [ "$STATUS" = "healthy" ]; then
            echo -e "${GREEN}ready${NC}"
            break
        fi
        if [ "$i" -eq 20 ]; then
            echo -e "${RED}failed${NC}"
            exit 1
        fi
        echo -n "."
        sleep 1
    done
done

echo ""
echo -e "${GREEN}All services ready!${NC}\n"
echo -e "${BLUE}Running debug test...${NC}\n"

# Run the debug script
if docker exec katran-e2e-client python3 /app/tests/e2e/debug_test.py; then
    echo -e "\n${GREEN}✓ Debug test completed${NC}"
    EXIT_CODE=0
else
    echo -e "\n${RED}✗ Debug test failed${NC}"
    EXIT_CODE=1
fi

# Show LB logs
echo -e "\n${YELLOW}=== LB Logs (last 50 lines) ===${NC}"
docker logs katran-e2e-lb 2>&1 | tail -50

exit $EXIT_CODE
