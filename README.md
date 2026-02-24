# Katran Control Plane

Python control plane for [Katran](https://github.com/facebookincubator/katran), Meta's L4 XDP-based load balancer.

Provides a management layer over Katran's BPF maps, enabling VIP and backend management, consistent hashing, statistics collection, and a REST API -- all from userspace Python.

## Features

- **VIP management** -- add, remove, and modify virtual IPs with automatic index allocation and BPF map synchronization
- **Backend pool management** -- reference-counted backend servers with weighted load distribution
- **Maglev V2 consistent hashing** -- minimal disruption during topology changes with true proportional weight distribution
- **Type-safe BPF map wrappers** -- abstractions for all Katran kernel maps (VIP, reals, CH rings, stats, control array)
- **REST API** -- FastAPI-based HTTP interface for load balancer control
- **Prometheus metrics** -- real-time per-VIP and global statistics scraped directly from BPF maps
- **IPv4 and IPv6** -- full dual-stack support
- **YAML configuration** -- flat and nested config formats with Pydantic v2 validation

## Requirements

- Linux kernel 5.10+ with BPF support
- Python 3.11 or 3.12
- Compiled Katran BPF programs (`.o` files)

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Or using the Makefile:

```bash
make venv
```

## Configuration

Configuration is loaded from YAML. Two formats are supported -- flat and nested.

Flat format (`config/katran.yaml`):

```yaml
interface: eth0
xdp_mode: native
xdp_program: /usr/share/katran/balancer.o
pin_path: /sys/fs/bpf/katran
max_vips: 512
max_reals: 4096
ring_size: 65537
rest_port: 8080
```

Validate configuration with:

```bash
make check-config
```

## Usage

### REST API

The REST API binds to the configured port and exposes endpoints for VIP and backend management:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Service health |
| POST | `/vips` | Add a VIP |
| GET | `/vips` | List all VIPs |
| POST | `/vips/{id}/delete` | Remove a VIP |
| POST | `/backends` | Add backend to a VIP |
| DELETE | `/backends` | Remove backend |
| PUT | `/backends/weight` | Update backend weight |
| GET | `/stats` | VIP statistics |
| GET | `/metrics` | Prometheus metrics |

### Prometheus Metrics

Metrics are scraped in real time from BPF maps on each request -- no caching, no stale data.

- `katran_vip_packets` / `katran_vip_bytes` -- per-VIP counters
- `katran_stats_*` -- global counters

## Testing

```bash
# Unit tests
make unit-test

# Unit tests with coverage
make unit-test-cov

# Integration tests (Docker + real BPF)
make integration-test

# Multi-container E2E with traffic forwarding
make e2e-multi
```

## Development

```bash
make format        # Auto-format code
make lint          # Ruff + mypy
make unit-test     # Fast feedback loop
```

## License

Apache-2.0
