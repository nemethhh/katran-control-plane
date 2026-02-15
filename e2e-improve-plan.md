# Plan: Expand E2E Test Coverage for Katran Control Plane

## Context

The katran control plane has 11 existing e2e tests (6 API + 5 traffic forwarding) that cover the happy-path basics. Several API error paths, edge cases, and traffic scenarios are untested. This plan adds 18 new tests to bring total e2e coverage to 29 tests, plus fixes a bug where remove/drain operations on missing resources silently return 200 instead of 404.

## Step 1: Fix API bug in `minimal.py` (prerequisite)

**File:** `src/katran/api/minimal.py`

The `remove_vip`, `remove_backend`, and `drain_backend` endpoints catch `VipNotFoundError`/`RealNotFoundError` — but the underlying manager methods (`remove_vip`, `remove_real`, `drain_real`) return `False` instead of raising exceptions. The `try/except` blocks are dead code.

**Fix:** Check the boolean return value and raise 404 when `False`:

1. **`remove_vip`** (~line 149): Replace `try/except VipNotFoundError` with:
   ```python
   removed = svc.vip_manager.remove_vip(address=addr, port=port, protocol=protocol)
   if not removed:
       raise HTTPException(status_code=404, detail=f"VIP not found: {addr}:{port}/{proto}")
   ```

2. **`remove_backend`** (~line 199): Replace `try/except RealNotFoundError` with:
   ```python
   removed = svc.real_manager.remove_real(vip, address=backend_addr)
   if not removed:
       raise HTTPException(status_code=404, detail=f"Backend {backend_addr} not found")
   ```

3. **`drain_backend`** (~line 223): Replace `try/except RealNotFoundError` with:
   ```python
   drained = svc.real_manager.drain_real(vip, address=backend_addr)
   if not drained:
       raise HTTPException(status_code=404, detail=f"Backend {backend_addr} not found")
   ```

## Step 2: Add 15 tests to `test_control_plane.py`

Append 5 new classes after existing `TestBackendLifecycle`. All use unique `10.100.x.x` addresses to avoid collisions. Each test has `try/finally` cleanup.

### TestVipErrors (3 tests)
| Test | What it verifies |
|------|-----------------|
| `test_delete_nonexistent_vip_404` | DELETE missing VIP → 404 |
| `test_invalid_protocol_400` | POST VIP with `protocol="sctp"` → 400 |
| `test_get_vip_invalid_protocol_400` | GET VIP with bad protocol in URL → 400 |

### TestVipCreation (2 tests)
| Test | What it verifies |
|------|-----------------|
| `test_vip_with_flags` | Create VIP with `flags=1`, verify in POST and GET responses |
| `test_udp_vip_creation` | Create UDP VIP, verify protocol in response and GET |

### TestVipLifecycleExtended (2 tests)
| Test | What it verifies |
|------|-----------------|
| `test_vip_recreate_after_delete` | Delete VIP, recreate same → 201 (index recycling) |
| `test_multiple_vips_coexistence` | Create 3 VIPs, verify list count, delete one, verify count drops |

### TestBackendErrors (5 tests)
| Test | What it verifies |
|------|-----------------|
| `test_duplicate_backend_409` | Add same backend twice → 409 |
| `test_remove_backend_missing_vip_404` | Remove backend on non-existent VIP → 404 |
| `test_drain_backend_missing_vip_404` | Drain on non-existent VIP → 404 |
| `test_remove_missing_backend_from_existing_vip` | Remove non-existent backend → 404 (needs Step 1 fix) |
| `test_drain_missing_backend_from_existing_vip` | Drain non-existent backend → 404 (needs Step 1 fix) |

### TestBackendDetails (3 tests)
| Test | What it verifies |
|------|-----------------|
| `test_backend_weight_in_response` | Add with `weight=75`, verify in POST and GET |
| `test_multiple_backends_on_same_vip` | Add 2 backends, verify count and unique indices |
| `test_shared_backend_across_vips` | Same backend on 2 VIPs shares index; deleting VIP-A preserves backend on VIP-B |

## Step 3: Add 3 tests to `test_traffic_forwarding.py`

Append 3 new classes after existing `TestNoBackendDrops`. Uses existing helper functions.

| Class | Test | What it verifies |
|-------|------|-----------------|
| `TestVipRecreateTraffic` | `test_vip_recreate_traffic_resumes` | Teardown VIP+backend, recreate, traffic works again |
| `TestAllDrainedDrops` | `test_all_backends_drained_drops_traffic` | Drain all backends → connection fails (distinct from no-backends test) |
| `TestReaddBackendTraffic` | `test_readd_backend_after_removal_traffic_resumes` | Remove backend, re-add it, traffic still works |

## Files Modified

| File | Change |
|------|--------|
| `src/katran/api/minimal.py` | Fix 3 endpoints to check return values (lines ~149, ~199, ~223) |
| `tests/e2e/test_control_plane.py` | Add 15 tests in 5 new classes |
| `tests/e2e/test_traffic_forwarding.py` | Add 3 tests in 3 new classes |

No new files, fixtures, or dependencies needed.

## Verification

Run the full e2e suite:
```bash
./tests/e2e/run-e2e.sh
```
Expected: 29 tests pass (11 existing + 18 new).

For a quick unit-level check that the API fix doesn't break existing unit tests:
```bash
.venv/bin/python3 -m pytest tests/unit/test_minimal_api.py -v
```
