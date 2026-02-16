# Statistics & Monitoring for Katran Load Balancer

## Context

The BPF map layer for statistics (`StatsMap`, `VipStatistics`, `GlobalStatistics`) is fully implemented. `KatranService` owns `self.stats_map` but exposes **no stats methods**. The REST API has **no stats/metrics endpoints**. The `src/katran/stats/__init__.py` placeholder says "Phase 4". This plan bridges the existing BPF stats infrastructure to a Prometheus `/metrics` endpoint — the sole monitoring interface.

## Files to Modify/Create

| File | Action |
|------|--------|
| `src/katran/stats/collector.py` | **New** — Prometheus custom collector |
| `src/katran/stats/__init__.py` | Update exports |
| `src/katran/api/rest/app.py` | Mount `/metrics` endpoint |
| `tests/unit/test_collector.py` | **New** — collector unit tests (~14 tests) |
| `tests/e2e/test_control_plane.py` | Add metrics e2e tests (~4 tests) |

## Existing Code to Reuse (read-only)

- `StatsMap` methods: `get_vip_stats(vip_num)`, `get_global_stats()`, `get_xdp_action_stats()`, `get_counter_per_cpu(index)` — `src/katran/bpf/maps/stats_map.py`
- `VipStatistics`, `GlobalStatistics` dataclasses — same file
- `StatsCounterIndex` enum (20 counters) — `src/katran/core/constants.py`
- `LbStats` — `src/katran/core/types.py`
- `Vip.active_reals` property — `src/katran/core/types.py:745`
- `VipManager.list_vips()`, `get_vip_count()` — `src/katran/lb/vip_manager.py`
- `prometheus-client>=0.17.0` already in `pyproject.toml` dependencies

---

## Step 1: Prometheus Collector — `src/katran/stats/collector.py` (new)

Custom Prometheus collector that reads BPF stats fresh on each scrape. Uses `CounterMetricFamily` for monotonically increasing BPF counters, `GaugeMetricFamily` for point-in-time state.

The collector reads directly from `service.stats_map` and `service.vip_manager` (public attributes on `KatranService`). No service-layer pass-through methods needed.

**Class: `KatranMetricsCollector`**
- `__init__(service: KatranService)` — stores service reference
- `describe() -> []` — unchecked collector (dynamic VIP label sets)
- `collect()` — yields metric families, delegates to sub-methods:
  - `_collect_service_info()` — `katran_vips_configured` gauge
  - `_collect_vip_stats()` — per-VIP metrics (labels: address, port, protocol)
  - `_collect_global_stats()` — global counters
  - `_collect_xdp_stats()` — XDP action counters (label: action)
  - `_collect_per_cpu_stats()` — per-CPU packet counters (label: cpu)

Each `_collect_*` method catches exceptions internally so one failing subsystem doesn't block others.

### Metrics Exposed

**Service state (Gauge):**
| Metric | Description |
|--------|-------------|
| `katran_up` | 1 if service running, 0 otherwise |
| `katran_vips_configured` | Number of configured VIPs |

**Per-VIP (Counter, labels: address, port, protocol):**
| Metric | Description |
|--------|-------------|
| `katran_vip_packets_total` | Packets forwarded |
| `katran_vip_bytes_total` | Bytes forwarded |
| `katran_vip_lru_hits_total` | LRU cache hits |
| `katran_vip_lru_misses_total` | LRU cache misses |

**Per-VIP (Gauge, labels: address, port, protocol):**
| Metric | Description |
|--------|-------------|
| `katran_vip_backends` | Number of active backends |

**Global (Counter, no labels):**
| Metric | Description |
|--------|-------------|
| `katran_packets_total` | Total packets processed |
| `katran_bytes_total` | Total bytes processed |
| `katran_lru_hits_total` | Global LRU hits |
| `katran_lru_misses_total` | Global LRU misses |
| `katran_vip_misses_total` | Packets matching no VIP |
| `katran_icmp_toobig_total` | ICMP too-big messages |
| `katran_new_connections_total` | New connections |

**XDP actions (Counter, label: action):**
| Metric | Description |
|--------|-------------|
| `katran_xdp_packets_total` | Packets per XDP action (total/tx/drop/pass) |

**Per-CPU (Counter, label: cpu):**
| Metric | Description |
|--------|-------------|
| `katran_cpu_packets_total` | Packets processed per CPU core |

**Design rationale:** BPF counters are monotonically increasing → `CounterMetricFamily`. VIPs are dynamic → unchecked collector with `describe()=[]`. No `hit_ratio` metric — computed in PromQL from raw counters.

Update `src/katran/stats/__init__.py` to export `KatranMetricsCollector`.

---

## Step 2: Mount `/metrics` — `src/katran/api/rest/app.py`

```python
from prometheus_client import CollectorRegistry, make_asgi_app
from katran.stats.collector import KatranMetricsCollector

# In create_app(), after exception handler:
if service is not None:
    registry = CollectorRegistry()
    registry.register(KatranMetricsCollector(service))
    app.mount("/metrics", make_asgi_app(registry=registry))
```

Uses custom `CollectorRegistry` (not global default) to expose only katran metrics.

---

## Step 3: Unit Tests — Collector (`tests/unit/test_collector.py`, new)

~14 tests using mock service:
- `test_service_down_emits_up_zero` / `test_service_up_emits_up_one`
- `test_vip_stats_basic` — 2 VIPs, verify all 4 per-VIP counter families + backends gauge
- `test_vip_backends_gauge` — reflects `len(vip.active_reals)`
- `test_no_vips_configured` — VIP metrics yielded with zero samples
- `test_global_stats` — verify all 7 global counters
- `test_xdp_stats` — 4 action labels
- `test_per_cpu_stats` — 4 CPU labels
- `test_ipv6_vip_labels` — IPv6 address formats correctly
- `test_vip_stats_error_graceful` — one VIP fails, others still report
- `test_global_stats_error_graceful` — skips global, other subsystems still emit
- `test_describe_returns_empty`
- `test_metrics_endpoint_returns_200` — httpx ASGI, verify content-type
- `test_metrics_no_service_returns_404`

## Step 4: E2E Tests (`tests/e2e/test_control_plane.py`, extend)

~4 tests:
- `TestMetricsE2E.test_metrics_endpoint` — scrape `/metrics`, verify `katran_up 1`, verify Prometheus text format content-type
- `TestMetricsE2E.test_global_metrics_present` — verify `katran_packets_total`, `katran_lru_hits_total` etc. appear
- `TestMetricsE2E.test_vip_metrics` — create VIP + backends, verify `katran_vip_packets_total{address="...",port="...",protocol="..."}` appears with correct labels
- `TestMetricsE2E.test_per_cpu_metrics` — verify `katran_cpu_packets_total{cpu="0"}` appears

---

## Verification

1. After steps 1-2: `.venv/bin/python3 -m pytest tests/unit/test_collector.py -v`
2. All unit tests: `.venv/bin/python3 -m pytest tests/unit/ -v`
3. E2E: Run multi-container e2e test suite
4. Manual: `curl http://localhost:8080/metrics` → verify Prometheus text format output

## Out of Scope (future work)

- JSON stats REST API endpoints
- Per-real stats (requires new `reals_stats` BPF map)
- Flood detection (`is_under_flood()`)
- Dedicated Prometheus metrics port (config already has `prometheus_port` field)
