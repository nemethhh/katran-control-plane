# Test Coverage Improvement Design

**Date:** 2026-03-15
**Goal:** Reach 85% overall coverage; 100% on critical path files.

---

## Context

Current overall coverage is 79% (3,262 / 4,126 lines). The project needs 245 more covered lines to reach 85%. Five files are designated critical path and must reach 100%.

---

## Coverage Targets

| File | Current | Target |
|---|---|---|
| `src/katran/bpf/maps/vip_map.py` | 36% | 100% |
| `src/katran/bpf/maps/reals_map.py` | 37% | 100% |
| `src/katran/lb/vip_manager.py` | 91% | 100% |
| `src/katran/lb/maglev.py` | 99% | 100% |
| `src/katran/lb/real_manager.py` | 99% | 100% |
| `src/katran/bpf/maps/ctl_array.py` | 44% | ~100% |
| `src/katran/service.py` | 68% | ~85% |
| `src/katran/bpf/maps/stats_map.py` | 55% | ~85% |
| **Overall** | **79%** | **≥85%** |

---

## Approach

Option A: critical path to 100% first, then highest-ROI non-critical files.

All new tests are pure unit tests using `unittest.mock` — no BPF kernel, no Docker required. Each source module is mocked at the BpfMap parent-class level (`get`, `set`, `delete`, `items`), allowing business logic in the map wrappers and managers to be tested in isolation.

---

## Phase 1: Critical Path (→ 100%)

### `tests/unit/test_vip_map.py` (new file)

Mock `BpfMap` methods on `VipMap`. Cover every public method:

- `add_vip`: happy path assigns index and writes to BPF; duplicate VIP raises `VipExistsError`; allocator exhaustion raises `ResourceExhaustedError`
- `remove_vip`: happy path frees index and deletes from BPF; missing VIP raises `VipNotFoundError`
- `get_vip`: cache hit returns without BPF call; cache miss falls back to BPF; missing returns `None`
- `update_flags`: found VIP updates flags in cache and BPF; missing VIP raises `VipNotFoundError`
- `list_vips`: empty map returns empty list; populated map returns all keys
- `get_all_vips`: returns dict mapping VipKey → VipMeta
- `sync_from_map`: restores allocator state from existing BPF entries; cache populated correctly
- Properties: `vip_count` reflects current allocation; `available_vip_slots` decreases on add and increases on remove

### `tests/unit/test_reals_map.py` (new file)

Mock `BpfMap` methods on `RealsMap`. Cover every public method:

- `add_real`: allocates index, writes to BPF, updates `Real.index`; duplicate raises `RealExistsError`
- `remove_real`: frees index, deletes from BPF; missing real raises `RealNotFoundError`
- `allocate_index` / `free_index`: sequential allocation; exhaustion raises `ResourceExhaustedError`; index 0 is reserved and never allocated; freed indices are reused
- `get_real`: cache hit; BPF fallback; missing returns `None`
- `list_allocated_indices`: excludes index 0; returns all active indices
- `get_all_reals`: consistent with `list_allocated_indices`
- `sync_from_map`: zero-address entries (all-zero packed bytes) are skipped; non-zero entries restore allocator state
- Properties: `allocated_count` excludes reserved index 0; `available_count` is inverse

### `tests/unit/test_vip_manager.py` (extend existing, 91% → 100%)

Identify and cover the 11 missing lines. Likely gaps:
- Error path in `update_vip_flags` when VIP not found
- Edge cases in `list_vips` with empty allocator state
- Any branch in `get_vip` that returns `None`

### `tests/unit/test_maglev.py` (extend existing, 99% → 100%)

Cover the 2 missing lines — likely an edge case in weight normalization or an unreachable error branch. Inspect with `coverage report --show-missing`.

### `tests/unit/test_real_manager.py` (extend existing, 99% → 100%)

Cover the 2 missing lines — similar approach.

---

## Phase 2: High-ROI Non-Critical Files

### `tests/unit/test_ctl_array.py` (new file, 44% → ~100%)

Mock `BpfMap` methods on `CtlArray`. Cover:

- `set_mac` / `get_mac` / `get_mac_bytes`: valid 6-byte MAC string and bytes; index not found returns `None`
- `set_ifindex` / `get_ifindex`: valid ifindex; missing returns `None`
- `set_u64` / `get_u64`: boundary values (0, `2**64 - 1`)
- `configure_gateway`: sets both MAC and ifindex; verify both calls made
- `get_configuration`: both values present; one `None`; both `None`

### `tests/unit/test_service.py` (extend existing, 68% → ~85%)

Mock all managers at construction time. Cover:

- **19 delegation methods** in groups by feature manager:
  - Each feature-guarded method raises `FeatureNotEnabledError` when the feature flag is absent
  - Happy path: call delegates to the correct manager method with correct arguments
- `_open_feature_maps`: each conditional branch — feature enabled opens the map; feature disabled skips it
- `_try_open`: exception during optional map open is caught and logged; map remains `None`
- `_initialize_feature_managers`: each manager initialized when its maps are present

### `tests/unit/test_stats_map.py` (new or extended, 55% → ~85%)

Mock `PerCpuBpfMap` on `StatsMap`. Cover:

- `_aggregate_values`: single CPU (list of one); multi-CPU sum (packets + bytes summed); empty list returns zero `LbStats`
- `get_vip_stats`: per-CPU values aggregated correctly; boundary `vip_num` (0 and `MAX_VIPS - 1`)
- `get_global_stats`: all `StatsCounterIndex` enum values present in result
- `get_xdp_action_stats`: all XDP action entries returned
- `reset_counter` / `reset_vip_stats`: verify zero `LbStats` written to all CPUs
- `VipStatistics.hit_ratio`: zero hits+misses returns 0.0 (no division by zero); partial (0.5); perfect (1.0)

---

## Test Infrastructure Notes

- All unit tests use `unittest.mock.MagicMock` / `patch`; no BPF filesystem access
- Mock target for map wrappers: patch at the method level on the instance (`mock_instance.get = MagicMock(...)`) or patch `BpfMap` methods via `spec=`
- Follow existing patterns in `test_vip_manager.py` and `test_real_manager.py` for mock setup
- Run with: `.venv/bin/python3 -m pytest tests/unit/ -v --cov=src/katran --cov-report=term-missing`

---

## Success Criteria

1. `make unit-test-cov` reports ≥85% overall
2. All five critical path files show 100% coverage
3. No new tests require Docker, BPF, or root privileges
4. All existing tests continue to pass
