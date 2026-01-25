# Katran Control Plane Integration Tests

Docker Compose-based integration tests for the Katran Python control plane.
Tests verify that the control plane can correctly manage BPF maps when
actual Katran BPF programs are loaded via **xdp-loader**.

## Test Methodology

These tests focus on **control plane operations**, not packet forwarding:

1. **BPF Program Loading**: Uses xdp-loader to load `balancer.bpf.o`
2. **Map Discovery**: Verifies expected maps are pinned
3. **Map Operations**: Tests Python control plane read/write to maps
4. **Data Serialization**: Verifies structs serialize to match BPF format
5. **Maglev Integration**: Tests hash ring generation and map writes

## Prerequisites

- Docker and Docker Compose installed
- BPF programs compiled (`katran-bpfs/*.o` files)
- Linux host with BPF support (kernel 5.10+)

## Running Tests

### Quick Start

```bash
cd katran-control-plane
./tests/integration/run-tests.sh
```

### With Debug Output

```bash
./tests/integration/run-tests.sh --debug
```

### Interactive Shell

```bash
./tests/integration/run-tests.sh --shell
```

### Using Make

```bash
make integration-test        # Run all integration tests
make docker-test-verbose     # Run with verbose output
make docker-debug            # Start interactive shell
```

## Test Structure

```
tests/integration/
├── Dockerfile          # Test container with xdp-tools, bpftool, Python
├── docker-compose.yml  # Container orchestration (in parent dir)
├── run-tests.sh        # Test orchestration script (runs from host)
├── conftest.py         # Pytest fixtures
├── test_bpf_maps.py    # Control plane map operation tests
└── README.md           # This file
```

## Test Execution Flow

The `run-tests.sh` script orchestrates tests from the HOST:

1. **Start Container**: `docker compose up -d --build`
2. **Verify BPF Environment**: Check xdp-loader, bpftool, BPF filesystem
3. **Load XDP Program**: `xdp-loader load -m skb -p /sys/fs/bpf/katran eth0 balancer.bpf.o`
4. **Verify Maps**: Check expected maps are pinned
5. **Run Python Tests**: `pytest tests/integration/test_bpf_maps.py`
6. **Test Direct Map Operations**: Using bpftool
7. **Cleanup**: Unload XDP program, stop container

## Test Categories

### Map Discovery Tests
- Verify maps are pinned after program load
- Check expected map names (vip_map, reals, ch_rings, stats, ctl_array)

### VIP Map Tests
- Open/close pinned map
- Add/remove VIP entries
- Serialization roundtrip verification

### Reals Map Tests
- Backend index allocation
- RealDefinition serialization
- Index management

### CH Rings Map Tests
- Ring size verification
- Ring read/write (when enabled)

### Stats Map Tests
- Per-CPU stats aggregation
- LbStats serialization

### Ctl Array Tests
- MAC address operations
- Interface index operations

### Maglev Integration Tests
- Ring generation
- Minimal disruption verification

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KATRAN_BPF_PATH` | `/app/katran-bpfs` | Path to BPF program files |
| `KATRAN_PIN_PATH` | `/sys/fs/bpf/katran` | Path for pinned BPF maps |
| `KATRAN_INTERFACE` | `eth0` | Network interface for XDP |
| `DEBUG` | `0` | Enable verbose output |

## Troubleshooting

### "BPF filesystem not accessible"

The BPF filesystem should be mounted from the host:
```yaml
volumes:
  - /sys/fs/bpf:/sys/fs/bpf:rw
```

### "xdp-loader not found"

The Dockerfile builds xdp-tools from source. If build fails:
```bash
docker compose build --no-cache
```

### "Failed to load XDP program"

Check kernel compatibility:
```bash
docker exec katran-target uname -r
docker exec katran-target xdp-loader --version
```

For kernel 6.14+, xdp-tools 1.5.5+ is required.

### "No maps pinned"

Verify the BPF program loaded:
```bash
docker exec katran-target xdp-loader status eth0
docker exec katran-target ls -la /sys/fs/bpf/katran/
```

### Inspect Map Contents

```bash
# List all maps
docker exec katran-target bpftool map list

# Show specific map
docker exec katran-target bpftool map show pinned /sys/fs/bpf/katran/vip_map

# Dump map contents
docker exec katran-target bpftool map dump pinned /sys/fs/bpf/katran/vip_map
```

## Manual Testing

Start container and shell in:
```bash
./tests/integration/run-tests.sh --shell

# Inside container:
xdp-loader load -m skb -p /sys/fs/bpf/katran eth0 /app/katran-bpfs/balancer.bpf.o
ls /sys/fs/bpf/katran/
pytest tests/integration/ -v -s
```

## CI/CD Integration

```bash
#!/bin/bash
set -e

# Build BPF programs (if not pre-built)
# make -C katran-bpfs

# Run integration tests
cd katran-control-plane
./tests/integration/run-tests.sh

# Exit code 0 = all tests passed
```
