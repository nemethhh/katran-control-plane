# Katran Control Plane

Python control plane for [Katran](https://github.com/facebookincubator/katran), Meta's L4 XDP-based load balancer.

Provides a management layer over Katran's BPF maps, enabling VIP and backend management, consistent hashing, statistics collection, and a REST API -- all from userspace Python.

## Features

- **VIP management** -- add, remove, and modify virtual IPs with automatic index allocation and BPF map synchronization
- **Backend pool management** -- reference-counted backend servers with weighted load distribution
- **Maglev V2 consistent hashing** -- minimal disruption during topology changes with true proportional weight distribution
- **Source-based routing** -- LPM trie maps for routing traffic by source CIDR prefix
- **Inline decapsulation** -- manage decap destination addresses for tunneled traffic
- **QUIC server ID routing** -- map QUIC connection IDs to backend servers with invalidation/revalidation support
- **Health checking** -- direct health check program coordination (destinations, keys, source IPs/MACs, interface binding)
- **LRU introspection** -- search, list, purge, and analyze per-CPU and fallback LRU maps
- **Per-VIP down real tracking** -- HASH_OF_MAPS-based per-VIP backend health state
- **Feature flags** -- config-driven feature enablement (`KatranFeature` bitflags) with runtime gating
- **Type-safe BPF map wrappers** -- abstractions for all Katran kernel maps (24 map types including per-CPU stats, LPM tries, and HASH_OF_MAPS)
- **REST API** -- FastAPI-based HTTP interface with 60+ endpoints covering all features
- **Prometheus metrics** -- real-time per-VIP, per-real, global, QUIC, and HC statistics scraped directly from BPF maps
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
features:
  - src_routing
  - inline_decap
  - direct_healthchecking
tunnel_based_hc: true
```

The `features` field accepts either an integer bitmask or a list of feature names. Available features: `src_routing`, `inline_decap`, `introspection`, `gue_encap`, `direct_healthchecking`, `local_delivery_optimization`, `flow_debug`.

Validate configuration with:

```bash
make check-config
```

## Usage

### REST API

The REST API binds to the configured port. All endpoints use `/api/v1/` prefix. IP addresses are passed in request bodies, never URL paths.

**Core:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Service health |
| GET | `/api/v1/features` | Enabled feature flags |
| POST | `/api/v1/vips` | Add a VIP |
| GET | `/api/v1/vips` | List all VIPs |
| POST | `/api/v1/vips/delete` | Remove a VIP |
| POST | `/api/v1/backends` | Add backend to a VIP |
| POST | `/api/v1/backends/delete` | Remove backend |
| POST | `/api/v1/backends/weight` | Update backend weight |

**Source Routing** (requires `src_routing` feature):

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/src-routing/add` | Add source routing rules |
| POST | `/api/v1/src-routing/remove` | Remove rules |
| POST | `/api/v1/src-routing/clear` | Clear all rules |
| GET | `/api/v1/src-routing` | List rules |

**Inline Decap** (requires `inline_decap` feature):

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/decap/dst/add` | Add decap destination |
| POST | `/api/v1/decap/dst/remove` | Remove decap destination |
| GET | `/api/v1/decap/dst` | List destinations |

**QUIC:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/quic/mapping` | Add/remove server ID mappings |
| GET | `/api/v1/quic/mapping` | List mappings |
| POST | `/api/v1/quic/invalidate` | Invalidate server IDs |
| POST | `/api/v1/quic/revalidate` | Revalidate server IDs |

**Health Checking** (requires `direct_healthchecking` feature):

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/hc/dst/add` | Add HC destination |
| POST | `/api/v1/hc/dst/remove` | Remove HC destination |
| GET | `/api/v1/hc/dst` | List HC destinations |
| POST | `/api/v1/hc/key/add` | Add HC key |
| POST | `/api/v1/hc/key/remove` | Remove HC key |
| GET | `/api/v1/hc/keys` | List HC keys |
| POST | `/api/v1/hc/src-ip` | Set HC source IP |
| POST | `/api/v1/hc/src-mac` | Set HC source MAC |
| POST | `/api/v1/hc/dst-mac` | Set HC destination MAC |
| POST | `/api/v1/hc/interface` | Set HC interface |
| GET | `/api/v1/hc/stats` | HC program stats |
| GET | `/api/v1/hc/stats/key` | Per-key packet count |

**LRU:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/lru/search` | Search LRU entries |
| POST | `/api/v1/lru/list` | List LRU entries for VIP |
| POST | `/api/v1/lru/delete` | Delete LRU entries |
| POST | `/api/v1/lru/purge-vip` | Purge all entries for VIP |
| POST | `/api/v1/lru/purge-real` | Purge entries for real |
| GET | `/api/v1/lru/analyze` | Analyze LRU age distribution |

**Down Reals:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/down-reals/add` | Mark real as down |
| POST | `/api/v1/down-reals/remove` | Mark real as up |
| POST | `/api/v1/down-reals/remove-vip` | Clear down reals for VIP |
| POST | `/api/v1/down-reals/check` | Check if real is down |

**Statistics:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/stats/vip` | Per-VIP stats |
| GET | `/api/v1/stats/real` | Per-real stats |
| GET | `/api/v1/stats/global` | All global counters |
| GET | `/api/v1/stats/quic` | QUIC packet stats |
| GET | `/api/v1/stats/hc` | HC program stats |
| GET | `/api/v1/stats/per-cpu` | Per-CPU packet counts |
| GET | `/metrics` | Prometheus metrics |

### Prometheus Metrics

Metrics are scraped in real time from BPF maps on each request -- no caching, no stale data.

- `katran_vip_packets` / `katran_vip_bytes` -- per-VIP counters
- `katran_real_packets_total` / `katran_real_bytes_total` -- per-backend counters
- `katran_stats_*` -- global counters (LRU, XDP actions, new connections)
- `katran_ch_drops_total`, `katran_encap_failures_total` -- error counters
- `katran_quic_ch_routed_total`, `katran_quic_cid_routed_total` -- QUIC routing stats
- `katran_hc_packets_processed_total` -- health check program stats

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
