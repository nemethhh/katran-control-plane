# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Python control plane for Meta's [Katran](https://github.com/facebookincubator/katran) L4 XDP-based load balancer. Manages BPF maps from userspace to control VIP routing, backend pools, and consistent hashing.

## Commands

```bash
# Setup
make venv                  # Create .venv + install editable with dev deps

# Testing
make unit-test             # Run unit tests
make unit-test-cov         # Unit tests + coverage report
make integration-test      # Docker-based integration tests (real BPF)
make e2e-multi             # Multi-container E2E with XDP traffic

# Single test
.venv/bin/python3 -m pytest tests/unit/test_vip_manager.py -v
.venv/bin/python3 -m pytest tests/unit/test_maglev.py::TestMaglevHashRing::test_build_ring -v

# Quality
make lint                  # ruff check + mypy
make format                # ruff format + fix
```

All commands use `.venv/bin/python3` (the venv shebang is broken — always invoke via full path).

## Architecture

**Layered design:** BPF maps → Managers → Service → API

### KatranService (`src/katran/service.py`)
Main coordinator. `start()` opens BPF maps and initializes managers; `stop()` tears down. Required maps: VipMap, RealsMap, ChRingsMap, StatsMap, CtlArray. Optional: HcRealsMap, LruMap.

### Managers (`src/katran/lb/`)
- **VipManager** — VIP CRUD, index allocation via IndexAllocator, BPF vip_map sync
- **RealManager** — Backend CRUD, reference counting (backends shared across VIPs), hash ring rebuild on changes
- Both are thread-safe (RLock)

### BPF Map Wrappers (`src/katran/bpf/`)
- **BpfMap[K, V]** — Generic base with `open/close/get/set/delete/items`, ctypes-based BPF syscalls
- **PerCpuBpfMap** — Extends BpfMap; uses `_percpu_value_size` (value aligned to 8 bytes × num_cpus) for kernel buffer reads
- **IndexAllocator** — `available_count` is a `@property`, not a method
- Maps are pinned at `{pin_path}/{map_name}` on the BPF filesystem

### Consistent Hashing (`src/katran/lb/maglev.py`)
Maglev V2 algorithm with MurmurHash3. Ring size 65537 (prime). True proportional weighted distribution.

### REST API (`src/katran/api/rest/`)
FastAPI app. IPv6-safe design (addresses in request bodies, never URL paths).

### Prometheus Metrics (`src/katran/stats/collector.py`)
Custom collector scraping BPF stats maps in real time. Per-VIP at index `vip_num` (not `vip_num*2`); global counters at `MAX_VIPS + StatsCounterIndex`.

## Critical Implementation Details

- **Port byte order**: VipKey/FlowKey ports stored in network byte order (`struct.pack("!H", port)`) — BPF reads raw packet bytes
- **BpfMap truthiness trap**: Never use `not map_obj` or `if map_obj:` — triggers `__len__()` → full map iteration → segfault on per-CPU maps. Always use `is None` / `is not None`
- **Per-CPU map iteration**: Base class `_iterate_raw()` uses `_value_size`; per-CPU maps override with `_percpu_value_size` (kernel writes `num_cpus × aligned_value_size` bytes)
- **Map pinning**: Use program's `map_ids` (from `bpftool prog show`) to pin correct maps; stale maps can linger on `/sys/fs/bpf`
- **VipFlags enum**: Uses `NO_SRC_PORT` (not `NO_SPORT`)
- **Protocol parsing**: `Protocol[name.upper()]` for string-to-enum conversion

## Code Style

- Python 3.11+, type hints required (`mypy disallow_untyped_defs`)
- Line length: 100 (ruff), E501 ignored
- Linting rules: E, F, W, I, N, B, C4, SIM
- Structured logging via `structlog`
- Exception hierarchy rooted at `KatranError` in `src/katran/core/exceptions.py`
