# Integration Test Error Output Examples

This document shows examples of the detailed error messages produced by the Phase 2 integration tests.

---

## Example 1: VIP Allocation Failure

**Test:** `test_add_ipv4_vip`

**Error Scenario:** VIP number allocation fails

```
======================================================================
TEST: test_add_ipv4_vip
======================================================================
  address: 10.200.1.100
  port: 8080
  protocol: TCP
======================================================================

VIP allocation failed:
  VIP: 10.200.1.100:8080/tcp
  Expected: vip_num >= 0 (allocated)
  Actual: vip_num = -1 (not allocated)
```

---

## Example 2: Backend Index Error

**Test:** `test_add_real_to_vip`

**Error Scenario:** Backend allocated with reserved index 0

```
======================================================================
TEST: test_add_real_to_vip
======================================================================
  vip: 10.200.1.200:80/tcp
  backend: 10.0.0.100
  weight: 100
======================================================================

Backend index is reserved value:
  Backend: 10.0.0.100
  Expected: index >= 1 (0 is reserved)
  Actual: index = 0
```

---

## Example 3: Ring Distribution Error

**Test:** `test_consistent_hash_ring_created`

**Error Scenario:** Uneven distribution with equal weights

```
======================================================================
TEST: test_consistent_hash_ring_created
======================================================================
  vip: 10.200.1.200:80/tcp
  backends: ['10.0.0.100', '10.0.0.101']
  weights: [100, 100]
  expected_distribution: 50/50 (equal weights)
======================================================================

  Backend 1: index=1, address=10.0.0.100
  Backend 2: index=2, address=10.0.0.101
  Ring distribution:
    Backend 1: 45000 positions (68.7%)
    Backend 2: 20537 positions (31.3%)
    Total: 65537 positions

Ring distribution - Uneven distribution:
  Backend 1:
    Expected: ~32768 positions (50.0%)
    Actual: 45000 positions (68.7%)
    Deviation: 12232 (max allowed: 3277)
  Full distribution: {1: 45000, 2: 20537}
```

---

## Example 4: Missing Backend in Ring

**Test:** `test_consistent_hash_ring_created`

**Error Scenario:** Backend index not found in ring

```
======================================================================
TEST: test_consistent_hash_ring_created
======================================================================
  vip: 10.200.1.200:80/tcp
  backends: ['10.0.0.100', '10.0.0.101']
  weights: [100, 100]
  expected_distribution: 50/50 (equal weights)
======================================================================

  Backend 1: index=1, address=10.0.0.100
  Backend 2: index=2, address=10.0.0.101

Backend 2 not found in ring:
  Backend: 10.0.0.101 (index=2)
  Ring unique values: {0, 1}
```

---

## Example 5: Weighted Distribution Error

**Test:** `test_weighted_hash_ring`

**Error Scenario:** Incorrect 2:1 weight ratio

```
======================================================================
TEST: test_weighted_hash_ring
======================================================================
  vip: 10.200.1.200:80/tcp
  backends: ['10.0.0.100', '10.0.0.101']
  weights: [100, 50]
  expected_ratio: 2:1 (weight 100:50)
======================================================================

  Backend 1: index=1, weight=100
  Backend 2: index=2, weight=50
  Ring distribution:
    Backend 1 (weight=100): 40000 positions (61.1%)
    Backend 2 (weight=50): 25537 positions (38.9%)
  Actual ratio: 1.57 (backend1/backend2)
  Expected ratio: 2.00

Weighted ring distribution - Incorrect weight distribution:
  Backend 1 (weight=100):
    Expected: 43691 positions (66.7%)
    Actual:   40000 positions (61.1%)
    Deviation: 5.6% (max: 13.3%)
  Backend 2 (weight=50):
    Expected: 21846 positions (33.3%)
    Actual:   25537 positions (38.9%)
    Deviation: 5.6% (max: 6.7%)
```

---

## Example 6: Reference Counting Error

**Test:** `test_real_reference_counting`

**Error Scenario:** Incorrect ref count after adding to multiple VIPs

```
======================================================================
TEST: test_real_reference_counting
======================================================================
  vip1: 10.200.1.201:80
  vip2: 10.200.1.202:80
  shared_backend: 10.0.0.100
  test: Backend sharing and reference counting
======================================================================

  VIP 1: 10.200.1.201:80/tcp (vip_num=0)
  VIP 2: 10.200.1.202:80/tcp (vip_num=1)

  Adding 10.0.0.100 to VIP 1...
    Allocated index: 1, ref_count: 1
  Adding 10.0.0.100 to VIP 2...
    Reused index: 1, ref_count: 1

Incorrect reference count after adding to 2 VIPs:
  Backend: 10.0.0.100
  Expected ref_count: 2
  Actual ref_count: 1
```

---

## Example 7: Backend Not Shared

**Test:** `test_real_reference_counting`

**Error Scenario:** Different indices for same backend on different VIPs

```
======================================================================
TEST: test_real_reference_counting
======================================================================
  vip1: 10.200.1.201:80
  vip2: 10.200.1.202:80
  shared_backend: 10.0.0.100
  test: Backend sharing and reference counting
======================================================================

  VIP 1: 10.200.1.201:80/tcp (vip_num=0)
  VIP 2: 10.200.1.202:80/tcp (vip_num=1)

  Adding 10.0.0.100 to VIP 1...
    Allocated index: 1, ref_count: 1
  Adding 10.0.0.100 to VIP 2...
    Reused index: 2, ref_count: 1

Backend not shared across VIPs:
  Backend: 10.0.0.100
  VIP 1 index: 1
  VIP 2 index: 2
  Expected: Same index (shared backend)
```

---

## Example 8: Ring Size Mismatch

**Test:** `test_consistent_hash_ring_created`

**Error Scenario:** Ring read from kernel has wrong size

```
Ring size mismatch:
  Expected: 65537
  Actual: 32768
```

---

## Example 9: Ring Not Fully Filled

**Test:** `test_consistent_hash_ring_created`

**Error Scenario:** Some ring positions not filled with backend indices

```
  Ring distribution:
    Backend 1: 40000 positions (61.1%)
    Backend 2: 20000 positions (30.5%)
    Total: 60000 positions

Ring not fully filled:
  Expected: 65537 positions filled
  Actual: 60000 positions filled
  Unfilled: 5537
  Unexpected values in ring: {0, 255}
```

---

## Example 10: Duplicate VIP Error

**Test:** `test_duplicate_vip_raises_error`

**Error Scenario:** Exception not raised on duplicate

```
======================================================================
TEST: test_duplicate_vip_raises_error
======================================================================
  address: 10.200.1.220
  port: 80
  expected: VipExistsError on duplicate add
======================================================================

  Adding VIP 10.200.1.220:80 (first time)...
    ✓ Added: vip_num=0
  Adding VIP 10.200.1.220:80 (duplicate, should fail)...

Duplicate VIP did not raise error:
  VIP: 10.200.1.220:80
  Expected: VipExistsError
  Actual: No exception raised
```

---

## Success Output Example

**Test:** `test_weighted_hash_ring` (passing)

```
======================================================================
TEST: test_weighted_hash_ring
======================================================================
  vip: 10.200.1.200:80/tcp
  backends: ['10.0.0.100', '10.0.0.101']
  weights: [100, 50]
  expected_ratio: 2:1 (weight 100:50)
======================================================================

  Backend 1: index=1, weight=100
  Backend 2: index=2, weight=50
  Ring distribution:
    Backend 1 (weight=100): 43691 positions (66.7%)
    Backend 2 (weight=50): 21846 positions (33.3%)
  Actual ratio: 2.00 (backend1/backend2)
  Expected ratio: 2.00
✓ Weighted distribution verified: 2.00:1 ratio (expected 2.00:1)

======================================================================
TEARDOWN: test_weighted_hash_ring
======================================================================
```

---

## Running Tests with Detailed Output

### Normal Mode
```bash
./tests/integration/run-tests.sh
```
- Shows test results summary
- Displays full output only on failures

### Debug Mode
```bash
./tests/integration/run-tests.sh --debug
```
- Shows all test output
- Verbose pytest output (`-vv --tb=long`)
- Displays all assertion details

### Example Output (Debug Mode)
```
--- Test 3: Python Integration Tests ---
[TEST] Running pytest
  Results: 7 passed, 0 failed

======================================================================
SETUP: test_vip_real_managers.py::TestVipManagerIntegration::test_add_ipv4_vip
======================================================================

======================================================================
TEST: test_add_ipv4_vip
======================================================================
  address: 10.200.1.100
  port: 8080
  protocol: TCP
======================================================================

✓ VIP added successfully: vip_num=0, address=10.200.1.100:8080

======================================================================
TEARDOWN: test_vip_real_managers.py::TestVipManagerIntegration::test_add_ipv4_vip
======================================================================

test_vip_real_managers.py::TestVipManagerIntegration::test_add_ipv4_vip PASSED
```

---

## Key Features of Enhanced Error Reporting

1. **Test Context Header**
   - Test name
   - Input parameters
   - Expected behavior

2. **Step-by-Step Progress**
   - Shows what the test is doing
   - Displays intermediate values
   - Confirms successful operations with ✓

3. **Detailed Error Messages**
   - Clear expected vs actual comparison
   - Relevant context (indices, counts, percentages)
   - Full distribution data when applicable

4. **Automatic Failure Output**
   - Test runner shows full output on any failure
   - No need to re-run with verbose flags

5. **Statistical Analysis**
   - Ring distribution percentages
   - Ratio calculations
   - Deviation from expected values
   - Tolerance thresholds

This makes debugging integration test failures much faster, as you can see exactly what went wrong without needing to add print statements or re-run tests.
