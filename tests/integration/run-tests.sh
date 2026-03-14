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

if docker_exec xdp-loader load -m skb "$INTERFACE" "$BPF_PROGRAM" 2>&1; then
    sleep 2

    # Pin BPF maps to expected location
    # Maps are created by the XDP program but not automatically pinned
    echo "  Pinning BPF maps..."

    # Find map IDs owned by the current XDP program and pin them.
    # Multiple maps with the same name may exist from previous loads;
    # we must pin the ones the active program uses.
    docker_exec bash -c '
        PROG_ID=$(bpftool prog list | grep "name balancer_ingress" | tail -1 | cut -d: -f1)
        PROG_MAP_IDS=$(bpftool prog show id "$PROG_ID" 2>/dev/null | grep map_ids | sed "s/.*map_ids //" | tr "," " ")
        for map_name in vip_map reals ch_rings stats ctl_array fallback_cache; do
            map_id=""
            for candidate in $(bpftool map list | grep -w "name $map_name" | cut -d: -f1); do
                for mid in $PROG_MAP_IDS; do
                    [ "$candidate" = "$mid" ] && map_id="$candidate" && break 2
                done
            done
            if [ -n "$map_id" ]; then
                bpftool map pin id "$map_id" '"$PIN_PATH"'/"$map_name" 2>/dev/null || true
            fi
        done
    ' 2>&1 | grep -v "Error: bpf obj already pinned" || true

    MAPS=$(docker_exec ls "$PIN_PATH" 2>&1 | tr '\n' ' ')
    echo "  Pinned maps: $MAPS"

    if [ -z "$MAPS" ] || [ "$MAPS" = " " ]; then
        print_fail "No maps were pinned"
        exit 1
    fi

    print_pass "XDP program loaded and maps pinned"
else
    print_fail "Failed to load XDP program"
    exit 1
fi

# Test 3: Python Tests
print_section "Test 3: Python Integration Tests"
run_test
print_test "Running pytest"

# Run with more verbose output
PYTEST_ARGS="-v --tb=short -s"
[ "$DEBUG" = "1" ] && PYTEST_ARGS="-vv --tb=long -s"

PYTEST_OUT=$(docker_exec pytest tests/integration/ tests/e2e/ $PYTEST_ARGS 2>&1) || true

# Parse pytest summary line (e.g., "====== 41 passed in 89.61s ======")
# Match any summary containing passed, failed, error, or skipped
SUMMARY_LINE=$(echo "$PYTEST_OUT" | grep -E "^=+.*(passed|failed|error|no tests).*=+$" | tail -1)
PASSED=$(echo "$SUMMARY_LINE" | grep -oP '\d+(?= passed)' || echo "0")
FAILED=$(echo "$SUMMARY_LINE" | grep -oP '\d+(?= failed)' || echo "0")
ERRORS=$(echo "$SUMMARY_LINE" | grep -oP '\d+(?= error)' || echo "0")

echo "  Results: $PASSED passed, $FAILED failed, $ERRORS errors"

# Show output if there are failures, errors, or no tests collected
if [ "$FAILED" -gt 0 ] || [ "$ERRORS" -gt 0 ] || [ "$PASSED" -eq 0 ]; then
    echo -e "${RED}Test output:${NC}"
    echo "$PYTEST_OUT"
elif [ "$DEBUG" = "1" ]; then
    echo "$PYTEST_OUT"
fi

[ "$FAILED" -eq 0 ] && [ "$ERRORS" -eq 0 ] && [ "$PASSED" -gt 0 ] && print_pass "Python tests passed" || print_fail "Python tests failed"

# Test 4: Cleanup
print_section "Test 4: Cleanup"
run_test
docker_exec xdp-loader unload "$INTERFACE" --all 2>/dev/null && print_pass "Cleanup done" || print_fail "Cleanup failed"

# Summary
echo -e "\n${BLUE}=== Summary ===${NC}"
echo "Tests: $TESTS_RUN | Passed: $TESTS_PASSED | Failed: $TESTS_FAILED"
[ $TESTS_FAILED -eq 0 ] && echo -e "${GREEN}All tests passed!${NC}" && exit 0
echo -e "${RED}Some tests failed${NC}" && exit 1
