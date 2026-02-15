# Katran Control Plane

Python control plane for the [Katran](https://github.com/facebookincubator/katran) L4 XDP load balancer.

## Overview

This package provides a Python-based control plane for managing Katran's BPF maps, VIPs, and backend servers. It implements type-safe wrappers around Katran's BPF data structures, Maglev consistent hashing, and a REST API for configuring the load balancer at runtime.

The control plane writes directly to the BPF maps used by Katran's XDP program, enabling full packet-path load balancing: client traffic arrives at the XDP program, gets IPIP-encapsulated to a selected backend via Maglev consistent hashing, and the backend responds directly to the client (DSR).

## Features

- **Core Data Structures** (`core/types.py`): Type-safe Python representations of all Katran BPF structures with correct serialization (network byte order for ports, packed addresses)
- **BPF Map Wrappers** (`bpf/maps/`): Thread-safe CRUD access to all 7 Katran BPF maps (VipMap, RealsMap, ChRingsMap, StatsMap, CtlArray, HcRealsMap, LruMap)
- **Maglev Consistent Hashing** (`lb/maglev.py`): V2 algorithm with true proportional weighted distribution across backends
- **VIP & Backend Management** (`lb/vip_manager.py`, `lb/real_manager.py`): High-level managers for VIP lifecycle, backend add/remove/drain, and automatic CH ring rebuilds
- **Configuration** (`core/config.py`): YAML config with Pydantic v2 validation, supporting both flat and nested formats
- **REST API** (`api/minimal.py`): FastAPI HTTP API for VIP/backend CRUD, health checks, and drain operations
- **Service Coordinator** (`service.py`): Lifecycle management wiring maps, managers, and API together
- **Multi-Container E2E Tests**: Full packet-path validation through XDP with IPIP encap/decap and DSR

## Requirements

- Python 3.11+
- Linux kernel with BPF support
- Katran BPF programs loaded (`balancer.bpf.o`)
- Docker & Docker Compose (for integration/E2E tests)

## Installation

```bash
# Development installation (includes test dependencies)
pip install -e ".[dev]"

# Production installation
pip install .
```

## Quick Start

### Programmatic usage

```python
from katran.core.config import KatranConfig
from katran.service import KatranService

# Load configuration
config = KatranConfig.from_yaml("config/katran.yaml")

# Start the service (opens BPF maps, initializes managers)
service = KatranService(config)
service.start()

# Add a VIP
vip = service.vip_manager.add_vip(
    address="10.200.1.1", port=80, protocol="TCP"
)

# Add a backend
real = service.real_manager.add_real(
    vip, address="10.0.0.50", weight=100
)

# Drain a backend (sets weight to 0, rebuilds CH ring)
service.real_manager.drain_real(vip, address="10.0.0.50")

# Stop the service
service.stop()
```

### REST API

```bash
# Start the API server
uvicorn katran.api.minimal:create_app --host 0.0.0.0 --port 8080

# Health check
curl http://localhost:8080/health

# Add a VIP
curl -X POST http://localhost:8080/api/v1/vips \
  -H "Content-Type: application/json" \
  -d '{"address": "10.200.1.1", "port": 80, "protocol": "tcp"}'

# Add a backend
curl -X POST http://localhost:8080/api/v1/vips/10.200.1.1/80/tcp/backends \
  -H "Content-Type: application/json" \
  -d '{"address": "10.0.0.50", "weight": 100}'

# List VIPs
curl http://localhost:8080/api/v1/vips

# Get VIP details (includes backends)
curl http://localhost:8080/api/v1/vips/10.200.1.1/80/tcp

# Drain a backend
curl -X PUT http://localhost:8080/api/v1/vips/10.200.1.1/80/tcp/backends/10.0.0.50/drain

# Remove a backend
curl -X DELETE http://localhost:8080/api/v1/vips/10.200.1.1/80/tcp/backends/10.0.0.50

# Remove a VIP
curl -X DELETE http://localhost:8080/api/v1/vips/10.200.1.1/80/tcp
```

## Configuration

Configuration supports both flat and nested YAML formats. See `config/katran.yaml` (flat) and `config/katran-nested.yaml` (nested).

### Nested format (recommended)

```yaml
interface:
  name: eth0
  xdp_mode: native        # native, generic, offload, or skb
  default_gateway_mac: "aa:bb:cc:dd:ee:ff"

bpf:
  xdp_program: /usr/share/katran/balancer.o
  hc_program: /usr/share/katran/healthchecking_ipip.o
  pin_path: /sys/fs/bpf/katran

maps:
  max_vips: 512
  max_reals: 4096
  lru_size: 1000000
  ring_size: 65537         # Must be prime

api:
  grpc_port: 50051
  rest_port: 8080
  prometheus_port: 9100

logging:
  level: INFO              # DEBUG, INFO, WARNING, ERROR, CRITICAL
  format: json             # json or console
```

### Key parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `maps.max_vips` | 512 | Maximum number of VIPs |
| `maps.max_reals` | 4096 | Maximum number of backend servers |
| `maps.ring_size` | 65537 | Maglev hash ring size (must be prime) |
| `maps.lru_size` | 1000 | LRU flow cache entries |
| `bpf.pin_path` | `/sys/fs/bpf/katran` | BPF map pin directory |

## Project Structure

```
katran-control-plane/
├── src/katran/
│   ├── core/                  # Core types, constants, config
│   │   ├── types.py           # BPF data structures (VipKey, RealDefinition, etc.)
│   │   ├── constants.py       # Enums & constants matching BPF headers
│   │   ├── config.py          # YAML configuration with Pydantic validation
│   │   ├── exceptions.py      # Custom exception hierarchy
│   │   └── logging.py         # Structured logging setup
│   ├── bpf/                   # BPF map management
│   │   ├── map_manager.py     # Base BpfMap class, IndexAllocator
│   │   └── maps/              # Individual map wrappers
│   │       ├── vip_map.py     # VIP hash map (address:port:proto -> flags, vip_num)
│   │       ├── reals_map.py   # Backend array (index -> address, flags)
│   │       ├── ch_rings_map.py # Consistent hash rings (vip_num*ring_size entries)
│   │       ├── stats_map.py   # Per-CPU statistics
│   │       ├── ctl_array.py   # Global config (gateway MAC, etc.)
│   │       ├── hc_reals_map.py # Healthcheck routing (optional)
│   │       └── lru_map.py     # Flow cache (optional)
│   ├── lb/                    # Load balancer logic
│   │   ├── maglev.py          # Maglev V2 consistent hashing
│   │   ├── vip_manager.py     # VIP lifecycle management
│   │   └── real_manager.py    # Backend management + CH ring rebuilds
│   ├── api/
│   │   └── minimal.py         # FastAPI REST API
│   └── service.py             # Service coordinator (lifecycle, wiring)
├── tests/
│   ├── unit/                  # 218 unit tests (no BPF required)
│   ├── integration/           # Single-container BPF integration tests
│   └── e2e/                   # Multi-container XDP traffic forwarding tests
│       ├── scripts/           # Container entrypoint & helper scripts
│       ├── test_control_plane.py    # API CRUD tests over real HTTP
│       └── test_traffic_forwarding.py # XDP packet path verification
├── config/
│   ├── katran.yaml            # Flat config format
│   └── katran-nested.yaml     # Nested config format
├── katran-bpfs/               # Pre-compiled BPF programs
├── docker-compose.test.yml    # Single-container integration tests
└── docker-compose.e2e.yml     # Multi-container E2E tests
```

## Testing

### Unit tests (no BPF/Docker required)

```bash
make unit-test              # 218 tests
make unit-test-cov          # With coverage report
```

### Integration tests (single container, BPF maps only)

```bash
make integration-test       # Load XDP, pin maps, run pytest
make integration-test-debug # Verbose output
```

### E2E tests (multi-container, full packet path)

The E2E test suite validates the complete traffic flow: client -> XDP load balancer (IPIP encap) -> backend (IPIP decap) -> DSR response to client.

```
Docker bridge: katran-e2e-net (10.200.0.0/24)

┌──────────────┐  HTTP to VIP  ┌──────────────┐  IPIP encap  ┌──────────────┐
│  test-client │ ────────────▶ │   katran-lb  │ ──────────▶  │  backend-1   │
│ 10.200.0.100 │               │ 10.200.0.10  │              │ 10.200.0.20  │
│ pytest runner│ ◀──────────── │ XDP + API    │              ├──────────────┤
│              │  DSR response │              │              │  backend-2   │
│              │               │              │              │ 10.200.0.21  │
└──────────────┘               └──────────────┘              └──────────────┘
```

```bash
make e2e-multi              # Build, start, test, teardown
make e2e-multi-debug        # Verbose output + container logs
make e2e-multi-shell        # Interactive shell in test-client
make e2e-multi-stop         # Stop containers
make e2e-multi-clean        # Remove images
```

E2E tests cover:
- Control plane API health, VIP CRUD, backend CRUD, error codes (404/409)
- Single backend traffic forwarding through XDP
- Multi-backend load distribution
- Drain shifts traffic to remaining backends
- Backend removal redistributes traffic
- VIP with no backends drops connections

## Architecture

### Packet flow

1. Client sends TCP SYN to VIP address (e.g., `10.200.0.10:80`)
2. Packet arrives at LB's `eth0` -> XDP program intercepts
3. XDP: VIP lookup in `vip_map` -> Maglev hash via `ch_rings` -> select backend from `reals`
4. IPIP encapsulate: outer `dst = backend_ip`, inner = original packet
5. Set `dst_mac = gateway_mac` (from `ctl_array[0]`), return `XDP_TX`
6. Backend kernel decapsulates IPIP via `tunl0`, delivers to HTTP server
7. DSR: backend replies directly to client with `src = VIP_IP`

### Maglev consistent hashing

The Maglev V2 algorithm provides:
- **Minimal disruption**: Adding/removing a backend only remaps ~1/N of connections
- **Weighted distribution**: Backend weight directly controls traffic share (proportional, not V1 reset-to-1)
- **Ring-based**: 65537-entry lookup table per VIP for O(1) backend selection
- **Automatic rebuild**: CH ring is rebuilt on any backend change (add/remove/drain/weight update)

### BPF map byte order conventions

- **IP addresses**: Network byte order (big-endian) - `IPv4Address.packed`
- **Ports**: Network byte order (big-endian) - `struct.pack("!H", port)` (BPF reads raw packet header bytes without byte-swap)
- **Integers** (flags, vip_num, indices): Host byte order (little-endian on x86) - `struct.pack("<I", value)`

## Development Status

- [x] Phase 1: Foundation & BPF Infrastructure (13/13)
- [x] Phase 2: Core Load Balancing Logic (11/11)
- [x] Phase 2.1: Control Plane Service & E2E Testing (15/15)
- [x] Phase 3: Multi-Container E2E with XDP Traffic Forwarding (11/11)
- [ ] Phase 4: XDP/TC Program Loading
- [ ] Phase 5: Statistics & Monitoring
- [ ] Phase 6: Healthcheck Management
- [ ] Phase 7: Full API Layer (gRPC + REST)
- [ ] Phase 8: CLI Tool
- [ ] Phase 9: Production Hardening
- [ ] Phase 10: Documentation & Deployment

## License

Apache 2.0
