# Improve VIP Management and Stats Based on Original Katran Implementation

## Context

Comparing the original C++ katran control plane (`samples/katran/katran/lib/KatranLb.cpp`) with our Python implementation reveals several gaps in VIP management and stats reading. The most critical is that VIP deletion does not cascade to clean up associated backends - a resource leak bug. Additionally, stats are only exposed via Prometheus scrape with no REST API, batch real operations are missing, and flag modification lacks set/unset semantics.

---

## Phase 1: VIP Deletion Cascade (Critical Bug Fix)

**Problem**: `VipManager.remove_vip()` removes the VIP from BPF map and frees the vip_num but never cleans up the VIP's backends. Real ref counts become permanently stale, real indices leak, BPF reals_map entries linger. In C++ `delVip` (KatranLb.cpp:1087-1109), all associated reals have their ref counts decremented before VIP removal.

**Root cause**: VipManager and RealManager are separate classes with no coordination mechanism.

**Solution**: Callback pattern - VipManager invokes an optional `on_vip_delete` callback before deletion. KatranService wires `real_manager.remove_all_reals_for_vip` as the callback.

### Files to modify

**`src/katran/lb/real_manager.py`** - Add `remove_all_reals_for_vip(vip)` method:
- Iterate `vip.reals` (copy the list first), call `_decrease_ref_count()` for each
- Remove each from `vip.reals`
- Do NOT rebuild the hash ring (VIP is being deleted, matching C++ behavior)
- Return count of reals removed

**`src/katran/lb/vip_manager.py`** - Add callback support:
- Add `on_vip_delete: Optional[Callable] = None` to `__init__` params, store as `self._on_vip_delete`
- Add `set_on_vip_delete(callback)` setter method
- In `remove_vip()`, call `self._on_vip_delete(vip)` after finding the VIP but BEFORE the BPF map deletion (so if callback fails, VIP stays consistent)

**`src/katran/service.py`** - Wire the cascade in `_initialize_managers()`:
- After creating both managers, call `self.vip_manager.set_on_vip_delete(self.real_manager.remove_all_reals_for_vip)`

### Tests
- `tests/unit/test_real_manager.py`: `test_remove_all_reals_for_vip_cleans_all`, `test_remove_all_reals_shared_real_preserves_ref`, `test_remove_all_reals_frees_indices_at_zero_ref`, `test_remove_all_reals_empty_vip`, `test_remove_all_reals_does_not_rebuild_ring`
- `tests/unit/test_vip_manager.py`: `test_remove_vip_invokes_callback`, `test_remove_vip_callback_before_bpf_delete`, `test_remove_vip_no_callback_still_works`, `test_remove_nonexistent_vip_no_callback`
- `tests/unit/test_service.py`: `test_cascade_wiring`

---

## Phase 2: Set/Unset Flag Semantics

**Problem**: C++ `modifyVip` supports `set` mode (`flags |= new`) and `unset` mode (`flags &= ~flag`). Python `modify_flags` replaces flags entirely - callers must know current state to add/remove a single flag.

### Files to modify

**`src/katran/lb/vip_manager.py`** - Extend `modify_flags()`:
- Add `action: str = "replace"` parameter (values: `"replace"`, `"set"`, `"unset"`)
- `"replace"`: current behavior (backward compatible default)
- `"set"`: `vip.flags |= flags`
- `"unset"`: `vip.flags &= ~flags`

**`src/katran/api/rest/app.py`** - Add `POST /api/v1/vips/flags` endpoint:
- Request: `ModifyFlagsRequest(vip: VipId, flags: int, action: str = "replace")`
- Response: Updated VipResponse

### Tests
- `tests/unit/test_vip_manager.py`: `test_modify_flags_set_adds_flag`, `test_modify_flags_set_additive`, `test_modify_flags_unset_removes_flag`, `test_modify_flags_unset_absent_flag_noop`, `test_modify_flags_replace_backward_compat`, `test_modify_flags_invalid_action_raises`
- `tests/unit/test_rest_api.py`: `test_set_flag`, `test_unset_flag`, `test_modify_flags_vip_not_found`

---

## Phase 3: Batch Real Operations

**Problem**: C++ `modifyRealsForVip` processes a batch of real add/remove operations and rebuilds the ring ONCE. Python `add_real()` rebuilds the entire 65537-entry ring on every single backend addition. Adding N backends = N full ring rebuilds.

### Files to modify

**`src/katran/lb/real_manager.py`** - Add `modify_reals_for_vip()`:
- Accept `reals_to_add: list[dict]` and `reals_to_remove: list[str]`
- Process removals first (decrement ref counts), then additions (increment ref counts)
- Collect errors for individual failures (duplicate add, missing remove) without aborting batch
- Rebuild ring ONCE at the end if any changes were made
- Return `{"added": int, "removed": int, "errors": list[str]}`

**`src/katran/api/rest/app.py`** - Add `POST /api/v1/backends/batch` endpoint:
- Request: `BatchRealsRequest(vip: VipId, add: list[RealSpec], remove: list[str])`
- Response: batch result dict

### Tests
- `tests/unit/test_real_manager.py`: `test_batch_add_multiple_ring_rebuilt_once`, `test_batch_remove_multiple`, `test_batch_add_and_remove`, `test_batch_duplicate_add_in_errors`, `test_batch_missing_remove_in_errors`, `test_batch_empty_no_rebuild`, `test_batch_ref_counting`
- `tests/unit/test_rest_api.py`: `test_batch_add`, `test_batch_remove`, `test_batch_mixed`, `test_batch_vip_not_found`

---

## Phase 4: Stats REST API and Expanded GlobalStatistics

**Problem**: Stats only exposed via Prometheus `/metrics`. No REST API to query per-VIP stats, global stats, or XDP action stats. Additionally, `GlobalStatistics` is missing several counters that exist in the C++ implementation (fallback_lru, ch_drop, decap, etc.).

### Files to modify

**`src/katran/bpf/maps/stats_map.py`** - Expand `GlobalStatistics`:
- Add fields: `fallback_lru`, `lpm_src`, `remote_encap`, `global_lru`, `ch_drop`, `decap`, `quic_icmp`, `icmp_ptb_v6`, `icmp_ptb_v4`
- Update `get_global_stats()` to read these counters using existing `StatsCounterIndex` enum values (already defined in constants.py)

**`src/katran/api/rest/app.py`** - Add stats endpoints:
- `GET /api/v1/stats/vip?address=&port=&protocol=` → `VipStatsResponse(packets, bytes)`
- `GET /api/v1/stats/global` → `GlobalStatsResponse` (all fields from expanded GlobalStatistics)
- `GET /api/v1/stats/xdp` → XDP action breakdown dict
- `GET /api/v1/stats/summary` → combined: per-VIP + global + XDP
- Return 503 if `stats_map is None`

**`src/katran/stats/collector.py`** - Add Prometheus metrics for new GlobalStatistics counters:
- `katran_fallback_lru_total`, `katran_ch_drop_total`, `katran_decap_total`, `katran_global_lru_total`, `katran_lpm_src_total`, `katran_remote_encap_total`

### Tests
- `tests/unit/test_rest_api.py`: `test_get_vip_stats`, `test_get_vip_stats_not_found`, `test_get_global_stats`, `test_get_xdp_stats`, `test_get_stats_summary`, `test_stats_unavailable_503`
- `tests/unit/test_collector.py`: `test_new_global_counters_in_metrics`

---

## Phase 5: Ring Delta Optimization and Error Tracking

### 5a. Ring Delta Optimization

**Problem**: C++ caches the hash ring in memory and computes deltas; Python always writes all 65537 entries. `ChRingsMap.write_ring_incremental()` (ch_rings_map.py:259) already exists but is never used because the old ring isn't cached.

**`src/katran/core/types.py`** - Add to `Vip` dataclass:
- `_cached_ring: list[int] | None = field(default=None, repr=False, compare=False)`

**`src/katran/lb/real_manager.py`** - Modify `_rebuild_ring()`:
- If `vip._cached_ring` exists and has correct length, use `write_ring_incremental(vip_num, old_ring, new_ring)`
- Otherwise fall back to full `write_ring()`
- After write, update `vip._cached_ring = list(new_ring)`

### 5b. Internal Error Tracking

**Problem**: C++ tracks `bpfFailedCalls` and `addrValidationFailed` in `KatranLbStats`. Python has no error counters.

**`src/katran/service.py`** - Add `ServiceStats` dataclass:
- Fields: `bpf_failed_calls: int = 0`, `addr_validation_failed: int = 0`
- Add `self.service_stats = ServiceStats()` to `KatranService.__init__`
- Expose via stats summary endpoint

### Tests
- `tests/unit/test_real_manager.py`: `test_ring_delta_uses_cache`, `test_ring_first_build_writes_full`, `test_ring_cache_updated_after_rebuild`

---

## Verification

```bash
# Run all unit tests
.venv/bin/python3 -m pytest tests/unit/ -v

# Run specific test files for new code
.venv/bin/python3 -m pytest tests/unit/test_vip_manager.py tests/unit/test_real_manager.py tests/unit/test_rest_api.py tests/unit/test_service.py tests/unit/test_collector.py -v

# Verify no regressions in existing tests
.venv/bin/python3 -m pytest tests/unit/ -v --tb=short
```
