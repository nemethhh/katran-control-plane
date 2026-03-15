# Test Coverage Improvement Design

**Date:** 2026-03-15
**Goal:** Reach 85% overall coverage; 100% on critical path files.

---

## Context

Current overall coverage is 79% (3,262 / 4,126 lines). The project needs 245 more covered lines to reach 85%. Five files are designated critical path and must reach 100%.

Uncovered lines per file (basis for phase sizing):
- `vip_map.py`: 47 missing
- `reals_map.py`: 52 missing
- `vip_manager.py`: 11 missing
- `maglev.py`: 2 missing
- `real_manager.py`: 2 missing
- `ctl_array.py`: 32 missing
- `service.py`: 94 missing (target ~40 of these)
- `stats_map.py`: 36 missing (target ~25 of these)

Phase 1 total: ~114 lines. Phase 2 target: ~97 lines (`ctl_array` +32, `service.py` +40, `stats_map` +25). Combined: ~211 lines. The remaining ~34 lines to reach 245 will emerge naturally from coverage of adjacent branches in the same files (e.g. `lru_manager.py` at 77%, `ch_rings_map.py` at 69%) as the new tests exercise shared code paths. The ≥85% target is achievable; exact line counts will be confirmed by running `make unit-test-cov` after Phase 2.

---

## Coverage Targets

| File | Current | Missing Lines | Target |
|---|---|---|---|
| `src/katran/bpf/maps/vip_map.py` | 36% | 47 | 100% |
| `src/katran/bpf/maps/reals_map.py` | 37% | 52 | 100% |
| `src/katran/lb/vip_manager.py` | 91% | 11 | 100% |
| `src/katran/lb/maglev.py` | 99% | 2 | 100% |
| `src/katran/lb/real_manager.py` | 99% | 2 | 100% |
| `src/katran/bpf/maps/ctl_array.py` | 44% | 32 | ~100% |
| `src/katran/service.py` | 68% | 94 | ~85% |
| `src/katran/bpf/maps/stats_map.py` | 55% | 36 | ~85% |
| **Overall** | **79%** | **245 target** | **≥85%** |

---

## Approach

Option A: critical path to 100% first, then highest-ROI non-critical files.

All new tests are pure unit tests using `unittest.mock` — no BPF kernel, no Docker required. Each source module is mocked at the BpfMap parent-class level (`get`, `set`, `delete`, `items`), allowing business logic in the map wrappers and managers to be tested in isolation.

---

## Phase 1: Critical Path (→ 100%)

### `tests/unit/test_vip_map.py` (new file)

Mock `BpfMap` methods on `VipMap`. Cover every public method:

- `add_vip`: takes a single `Vip` object (bundles key, flags, and mutable `vip_num`); happy path assigns index and writes to BPF; duplicate VIP raises `VipExistsError`; allocator exhaustion raises `ResourceExhaustedError`
- `remove_vip`: happy path frees index and deletes from BPF; missing VIP (meta is None) returns `False`; BPF delete failure (key present but `delete()` returns False) returns `False` — both branches must be tested
- `get_vip`: cache hit returns without BPF call; cache miss falls back to BPF; missing returns `None`
- `update_flags`: found VIP updates flags in cache and BPF; missing VIP returns `False` (does not raise)
- `list_vips`: empty map returns empty list; populated map returns all keys. Note: reads directly from BPF via `self.keys()` — mock must configure `keys()`, not `_vip_cache`
- `get_all_vips`: returns dict mapping VipKey → VipMeta. Note: calls `dict(self.items())` — reads BPF map directly, not cache; mock must configure `items()`
- `sync_from_map`: restores allocator state from existing BPF entries; cache populated correctly
- Properties: `vip_count` reflects current allocation; `available_vip_slots` decreases on add and increases on remove

### `tests/unit/test_reals_map.py` (new file)

Mock `BpfMap` methods on `RealsMap`. Cover every public method:

- `add_real`: allocates index via `allocate_and_set`, writes to BPF, updates `Real.index` on the passed object
- `remove_real`: calls `free_index()` and returns `True`; does NOT call `BpfMap.delete()` (entries are intentionally left in the map for in-flight connections). Missing real (index not allocated per `is_index_allocated`) returns `False`. Mock `is_index_allocated` and `free_index` — do not mock `delete()`.
- `allocate_and_set`: acquires lock, calls `allocate_index`, calls `set`, updates cache; test directly as primary write path
- `allocate_index` / `free_index`: sequential allocation; exhaustion raises `ResourceExhaustedError`; index 0 is reserved and never allocated; freed indices are reused
- `is_index_allocated`: returns `True` for allocated index, `False` for free index, `False` for reserved index 0
- `get_real`: cache hit; BPF fallback; missing returns `None`
- `list_allocated_indices`: excludes index 0; returns all active indices
- `get_all_reals`: consistent with `list_allocated_indices`
- `sync_from_map`: IPv4 zero-address entries (`b"\x00" * 4`) are skipped; non-zero entries restore allocator state. Note: the zero-address check is IPv4-only — an IPv6 zero-address (`b"\x00" * 16`) would not be filtered. This is a known limitation; add a test documenting current IPv4-only behavior.
- Properties: `allocated_count` excludes reserved index 0; `available_count` is inverse

### `tests/unit/test_vip_manager.py` (extend existing, 91% → 100%)

Identify and cover the 11 missing lines via `coverage report --show-missing`. Likely gaps:
- Error path in `update_vip_flags` when VIP not found (returns `False`)
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

- `start()`: happy path calls four internal methods in sequence (`_open_maps`, `_open_feature_maps`, `_initialize_managers`, `_initialize_feature_managers`); "already running" guard raises `RuntimeError`; exception triggers cleanup (`_close_maps`, managers set to `None`)
- `stop()`: early return when not running; nulls all feature managers on success
- `is_running` / `is_healthy`: property values in running and stopped states; `is_healthy` compound boolean
- **Delegation methods** in groups by feature manager:
  - Each feature-guarded method raises `FeatureNotEnabledError` when the feature flag is absent
  - Happy path: call delegates to the correct manager method with correct arguments
- `set_src_ip_for_encap`: IPv4 vs IPv6 branching; `_pckt_srcs_map is None` path
- `_open_maps`: two separate error handling zones — (a) required maps raise on failure; (b) optional maps (`hc_reals_map`, `lru_map`) are opened via an **inline `try/except` loop** that catches exceptions and logs, leaving the attribute unset. This loop is distinct from `_try_open`. Test both: required map failure propagates; optional map failure is swallowed and the attribute remains absent.
- `_open_feature_maps`: each conditional branch — feature enabled opens the map via `_try_open`; feature disabled skips it
- `_try_open`: used only in `_open_feature_maps`; exception during map open is caught and returns `None`
- `_initialize_managers`: `assert` statements raise `AssertionError` if required maps are `None` — test the happy path (assertions pass); error path is low-priority
- `_initialize_feature_managers`: each manager initialized when its maps are present
- `_close_maps`: exception during individual `close()` is handled without aborting the loop

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
