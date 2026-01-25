#!/bin/bash
#
# Katran Control Plane Integration Tests
#
# Usage:
#   ./run-tests.sh           # Run all tests
#   ./run-tests.sh --debug   # Run with verbose output
#   ./run-tests.sh --shell   # Start interactive shell in container
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$PROJECT_DIR/docker-compose.test.yml"

CONTAINER_NAME="katran-target"
BPF_PROGRAM="/app/katran-bpfs/balancer.bpf.o"
PIN_PATH="/sys/fs/bpf/katran"
INTERFACE="eth0"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

DEBUG="${DEBUG:-0}"
[ "$1" = "--debug" ] && DEBUG=1

print_section() { echo -e "\n${YELLOW}--- $1 ---${NC}"; }
print_test() { echo -e "${YELLOW}[TEST]${NC} $1"; }
print_pass() { echo -e "${GREEN}[PASS]${NC} $1"; TESTS_PASSED=$((TESTS_PASSED + 1)); }
print_fail() { echo -e "${RED}[FAIL]${NC} $1"; TESTS_FAILED=$((TESTS_FAILED + 1)); }
run_test() { TESTS_RUN=$((TESTS_RUN + 1)); }

docker_exec() { docker exec "$CONTAINER_NAME" "$@"; }

cleanup() {
    echo "Cleaning up..."
    docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
}

echo -e "\n${BLUE}=== Katran Control Plane Integration Tests ===${NC}\n"

# Start containers
echo "Starting test container..."
cd "$PROJECT_DIR"
docker compose -f "$COMPOSE_FILE" down -v 2>/dev/null || true
docker compose -f "$COMPOSE_FILE" up -d --build

echo "Waiting for container..."
sleep 3

if ! docker ps | grep -q "$CONTAINER_NAME"; then
    echo -e "${RED}Container not running${NC}"
    docker compose -f "$COMPOSE_FILE" logs
    exit 1
fi

# Shell mode
if [ "$1" = "--shell" ]; then
    echo "Starting shell. Run: xdp-loader load -m skb -p $PIN_PATH $INTERFACE $BPF_PROGRAM"
    docker exec -it "$CONTAINER_NAME" bash
    exit 0
fi

trap cleanup EXIT

# Test 1: BPF Environment
print_section "Test 1: Verify BPF Environment"
run_test
print_test "Checking BPF filesystem and tools"

docker_exec test -d /sys/fs/bpf && echo "  BPF filesystem: OK" || { print_fail "BPF filesystem not accessible"; exit 1; }
docker_exec which xdp-loader > /dev/null 2>&1 && echo "  xdp-loader: OK" || { print_fail "xdp-loader not found"; exit 1; }
docker_exec test -f "$BPF_PROGRAM" && echo "  BPF program: OK" || { print_fail "BPF program not found"; exit 1; }
print_pass "BPF environment verified"

# Test 2: Load XDP Program
print_section "Test 2: Load XDP Program"
run_test
print_test "Loading Katran balancer XDP program"

docker_exec xdp-loader unload "$INTERFACE" --all 2>/dev/null || true
docker_exec rm -rf "$PIN_PATH" 2>/dev/null || true
docker_exec mkdir -p "$PIN_PATH"
docker_exec sysctl -w net.ipv4.conf.all.rp_filter=0 > /dev/null 2>&1 || true

if docker_exec xdp-loader load -m skb -p "$PIN_PATH" "$INTERFACE" "$BPF_PROGRAM" 2>&1; then
    sleep 2
    MAPS=$(docker_exec ls "$PIN_PATH" 2>&1)
    echo "  Pinned maps: $MAPS"
    print_pass "XDP program loaded"
else
    print_fail "Failed to load XDP program"
    exit 1
fi

# Test 3: Python Tests
print_section "Test 3: Python Integration Tests"
run_test
print_test "Running pytest"

PYTEST_OUT=$(docker_exec pytest tests/integration/test_bpf_maps.py -v --tb=short 2>&1) || true
PASSED=$(echo "$PYTEST_OUT" | grep -c " PASSED") || PASSED=0
FAILED=$(echo "$PYTEST_OUT" | grep -c " FAILED") || FAILED=0
echo "  Results: $PASSED passed, $FAILED failed"
[ "$DEBUG" = "1" ] && echo "$PYTEST_OUT"
[ "$FAILED" -eq 0 ] && [ "$PASSED" -gt 0 ] && print_pass "Python tests passed" || print_fail "Python tests failed"

# Test 4: Cleanup
print_section "Test 4: Cleanup"
run_test
docker_exec xdp-loader unload "$INTERFACE" --all 2>/dev/null && print_pass "Cleanup done" || print_fail "Cleanup failed"

# Summary
echo -e "\n${BLUE}=== Summary ===${NC}"
echo "Tests: $TESTS_RUN | Passed: $TESTS_PASSED | Failed: $TESTS_FAILED"
[ $TESTS_FAILED -eq 0 ] && echo -e "${GREEN}All tests passed!${NC}" && exit 0
echo -e "${RED}Some tests failed${NC}" && exit 1
