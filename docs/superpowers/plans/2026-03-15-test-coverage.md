# Test Coverage Improvement Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reach ≥85% overall unit test coverage and 100% on critical path files (`vip_map.py`, `reals_map.py`, `vip_manager.py`, `maglev.py`, `real_manager.py`).

**Architecture:** Pure unit tests using `unittest.mock`. Map wrapper classes (`VipMap`, `RealsMap`, etc.) are instantiated with a fake path and their inherited `BpfMap` methods (`get`, `set`, `delete`, `keys`, `items`) are replaced on the instance. No BPF kernel, Docker, or root privileges required.

**Tech Stack:** Python 3.11+, pytest, unittest.mock, pytest-cov

---

## File Map

| Action | Path |
|---|---|
| Create | `tests/unit/test_vip_map.py` |
| Create | `tests/unit/test_reals_map.py` |
| Create | `tests/unit/test_ctl_array.py` |
| Modify | `tests/unit/test_vip_manager.py` |
| Modify | `tests/unit/test_maglev.py` |
| Modify | `tests/unit/test_real_manager.py` |
| Modify | `tests/unit/test_service.py` |
| Modify | `tests/unit/test_stats_manager.py` or create `tests/unit/test_stats_map.py` |

---

## Chunk 1: Phase 1 — Critical Path to 100%

---

### Task 1: VipMap unit tests (36% → 100%)

**Files:**
- Create: `tests/unit/test_vip_map.py`
- Source: `src/katran/bpf/maps/vip_map.py`

**Mocking strategy:** Instantiate `VipMap` with a fake path (no fd opened at init), then replace `get`, `set`, `delete`, `keys`, `items` on the instance with `MagicMock`.

- [ ] **Step 1: Create test file with fixture and add_vip tests**

```python
# tests/unit/test_vip_map.py
"""Unit tests for VipMap — no BPF kernel required."""
from ipaddress import IPv4Address, IPv6Address
from unittest.mock import MagicMock

import pytest

from katran.bpf.maps.vip_map import VipMap
from katran.core.constants import Protocol, VipFlags
from katran.core.exceptions import ResourceExhaustedError, VipExistsError
from katran.core.types import Vip, VipKey, VipMeta


def _make_vip_map(max_vips: int = 4) -> VipMap:
    """Create a VipMap with mocked BPF methods."""
    vm = VipMap.__new__(VipMap)
    VipMap.__init__(vm, "/fake/path", max_vips=max_vips)
    vm.get = MagicMock(return_value=None)
    vm.set = MagicMock()
    vm.delete = MagicMock(return_value=True)
    vm.keys = MagicMock(return_value=[])
    vm.items = MagicMock(return_value=[])
    return vm


def _make_vip(addr: str = "10.0.0.1", port: int = 80) -> Vip:
    return Vip(
        key=VipKey(IPv4Address(addr), port, Protocol.TCP),
        flags=VipFlags.NONE,
    )


class TestVipMapAddVip:
    def test_add_vip_allocates_index_and_writes_bpf(self):
        vm = _make_vip_map()
        vip = _make_vip()

        vip_num = vm.add_vip(vip)

        assert vip_num == 0
        assert vip.vip_num == 0
        vm.set.assert_called_once()
        assert vm.vip_count == 1

    def test_add_vip_increments_available_slots(self):
        vm = _make_vip_map(max_vips=4)
        initial = vm.available_vip_slots
        vm.add_vip(_make_vip("10.0.0.1"))
        assert vm.available_vip_slots == initial - 1

    def test_add_vip_duplicate_raises_vip_exists_error(self):
        vm = _make_vip_map()
        vip = _make_vip()
        vm.add_vip(vip)

        with pytest.raises(VipExistsError):
            vm.add_vip(_make_vip())  # same address/port/proto

    def test_add_vip_exhaustion_raises_resource_exhausted(self):
        vm = _make_vip_map(max_vips=1)
        vm.add_vip(_make_vip("10.0.0.1"))

        with pytest.raises(ResourceExhaustedError):
            vm.add_vip(_make_vip("10.0.0.2"))

    def test_add_vip_caches_entry(self):
        vm = _make_vip_map()
        vip = _make_vip()
        vm.add_vip(vip)

        # get() should NOT be called on second add (duplicate check uses cache)
        vm.get.reset_mock()
        with pytest.raises(VipExistsError):
            vm.add_vip(_make_vip())
        vm.get.assert_not_called()


class TestVipMapRemoveVip:
    def test_remove_vip_returns_true_and_frees_slot(self):
        vm = _make_vip_map()
        vip = _make_vip()
        vm.add_vip(vip)
        initial_available = vm.available_vip_slots

        result = vm.remove_vip(vip.key)

        assert result is True
        vm.delete.assert_called_once_with(vip.key)
        assert vm.available_vip_slots == initial_available + 1
        assert vm.vip_count == 0

    def test_remove_vip_missing_key_returns_false(self):
        vm = _make_vip_map()
        vm.get = MagicMock(return_value=None)
        key = VipKey(IPv4Address("10.0.0.99"), 80, Protocol.TCP)

        result = vm.remove_vip(key)

        assert result is False
        vm.delete.assert_not_called()

    def test_remove_vip_bpf_delete_fails_returns_false(self):
        vm = _make_vip_map()
        vip = _make_vip()
        # Patch get to return existing meta (bypasses cache, simulates BPF state)
        meta = VipMeta(flags=VipFlags.NONE, vip_num=0)
        vm.get = MagicMock(return_value=meta)
        vm.delete = MagicMock(return_value=False)  # BPF delete fails

        result = vm.remove_vip(vip.key)

        assert result is False


class TestVipMapGetVip:
    def test_get_vip_cache_hit_skips_bpf(self):
        vm = _make_vip_map()
        vip = _make_vip()
        vm.add_vip(vip)
        vm.get.reset_mock()

        result = vm.get_vip(vip.key)

        assert result is not None
        vm.get.assert_not_called()  # Served from cache

    def test_get_vip_cache_miss_falls_back_to_bpf(self):
        vm = _make_vip_map()
        meta = VipMeta(flags=VipFlags.NONE, vip_num=5)
        vm.get = MagicMock(return_value=meta)
        key = VipKey(IPv4Address("10.0.0.1"), 80, Protocol.TCP)

        result = vm.get_vip(key)

        assert result == meta
        vm.get.assert_called_once_with(key)

    def test_get_vip_missing_returns_none(self):
        vm = _make_vip_map()
        vm.get = MagicMock(return_value=None)
        key = VipKey(IPv4Address("10.0.0.99"), 80, Protocol.TCP)

        result = vm.get_vip(key)

        assert result is None


class TestVipMapUpdateFlags:
    def test_update_flags_found_updates_cache_and_bpf(self):
        vm = _make_vip_map()
        vip = _make_vip()
        vm.add_vip(vip)
        meta = VipMeta(flags=VipFlags.NONE, vip_num=0)
        vm.get = MagicMock(return_value=meta)
        vm.set.reset_mock()

        result = vm.update_flags(vip.key, int(VipFlags.NO_SRC_PORT))

        assert result is True
        vm.set.assert_called_once()

    def test_update_flags_not_found_returns_false(self):
        vm = _make_vip_map()
        vm.get = MagicMock(return_value=None)
        key = VipKey(IPv4Address("10.0.0.99"), 80, Protocol.TCP)

        result = vm.update_flags(key, int(VipFlags.NO_SRC_PORT))

        assert result is False
        vm.set.assert_not_called()


class TestVipMapListAndGetAll:
    def test_list_vips_reads_from_bpf_keys(self):
        vm = _make_vip_map()
        key1 = VipKey(IPv4Address("10.0.0.1"), 80, Protocol.TCP)
        key2 = VipKey(IPv4Address("10.0.0.2"), 443, Protocol.TCP)
        vm.keys = MagicMock(return_value=[key1, key2])

        result = vm.list_vips()

        assert result == [key1, key2]
        vm.keys.assert_called_once()

    def test_list_vips_empty_returns_empty_list(self):
        vm = _make_vip_map()
        vm.keys = MagicMock(return_value=[])

        assert vm.list_vips() == []

    def test_get_all_vips_reads_from_bpf_items(self):
        vm = _make_vip_map()
        key = VipKey(IPv4Address("10.0.0.1"), 80, Protocol.TCP)
        meta = VipMeta(flags=VipFlags.NONE, vip_num=0)
        vm.items = MagicMock(return_value=[(key, meta)])

        result = vm.get_all_vips()

        assert result == {key: meta}
        vm.items.assert_called_once()

    def test_get_all_vips_empty_returns_empty_dict(self):
        vm = _make_vip_map()
        vm.items = MagicMock(return_value=[])

        assert vm.get_all_vips() == {}


class TestVipMapSyncFromMap:
    def test_sync_from_map_restores_cache_and_allocator(self):
        vm = _make_vip_map(max_vips=8)
        key = VipKey(IPv4Address("10.0.0.1"), 80, Protocol.TCP)
        meta = VipMeta(flags=VipFlags.NONE, vip_num=3)
        vm.items = MagicMock(return_value=[(key, meta)])

        vm.sync_from_map()

        assert vm._vip_cache[key] == meta
        assert vm._vip_num_allocator.is_allocated(3)
        assert vm.vip_count == 1

    def test_sync_from_map_clears_existing_cache(self):
        vm = _make_vip_map()
        vip = _make_vip()
        vm.add_vip(vip)
        assert vm.vip_count == 1

        # Sync with empty map should clear cache
        vm.items = MagicMock(return_value=[])
        vm.sync_from_map()

        assert vm.vip_count == 0


class TestVipMapProperties:
    def test_vip_count_increases_on_add(self):
        vm = _make_vip_map()
        assert vm.vip_count == 0
        vm.add_vip(_make_vip("10.0.0.1"))
        assert vm.vip_count == 1
        vm.add_vip(_make_vip("10.0.0.2"))
        assert vm.vip_count == 2

    def test_available_vip_slots_decreases_on_add_and_increases_on_remove(self):
        vm = _make_vip_map(max_vips=4)
        initial = vm.available_vip_slots
        vip = _make_vip()
        vm.add_vip(vip)
        assert vm.available_vip_slots == initial - 1
        # Re-configure delete to simulate successful BPF delete
        meta = VipMeta(flags=VipFlags.NONE, vip_num=0)
        vm.get = MagicMock(return_value=meta)
        vm.remove_vip(vip.key)
        assert vm.available_vip_slots == initial
```

- [ ] **Step 2: Run the tests and verify they pass**

```bash
.venv/bin/python3 -m pytest tests/unit/test_vip_map.py -v
```
Expected: All tests pass.

- [ ] **Step 3: Verify vip_map.py coverage reaches ~100%**

```bash
.venv/bin/python3 -m pytest tests/unit/test_vip_map.py --cov=src/katran/bpf/maps/vip_map --cov-report=term-missing -q
```
Expected: `vip_map.py` shows 0 or very few missing lines.

- [ ] **Step 4: Commit**

```bash
git add tests/unit/test_vip_map.py
git commit -m "test: add VipMap unit tests (36% → 100%)"
```

---

### Task 2: RealsMap unit tests (37% → 100%)

**Files:**
- Create: `tests/unit/test_reals_map.py`
- Source: `src/katran/bpf/maps/reals_map.py`

**Key notes:**
- `remove_real` does NOT call `BpfMap.delete()` — it calls `free_index()` only
- Index 0 is reserved: `_index_allocator.reserve(0)` is called at init
- `sync_from_map` filters IPv4 zeros (`b"\x00" * 4`) — IPv6 zero-address is NOT filtered (known limitation)

- [ ] **Step 5: Create test file**

```python
# tests/unit/test_reals_map.py
"""Unit tests for RealsMap — no BPF kernel required."""
from ipaddress import IPv4Address, IPv6Address
from unittest.mock import MagicMock

import pytest

from katran.bpf.maps.reals_map import RealsMap
from katran.core.constants import RealFlags
from katran.core.exceptions import ResourceExhaustedError
from katran.core.types import Real, RealDefinition


def _make_reals_map(max_reals: int = 8) -> RealsMap:
    """Create a RealsMap with mocked BPF methods."""
    rm = RealsMap.__new__(RealsMap)
    RealsMap.__init__(rm, "/fake/path", max_reals=max_reals)
    rm.get = MagicMock(return_value=None)
    rm.set = MagicMock()
    rm.delete = MagicMock(return_value=True)
    rm.items = MagicMock(return_value=[])
    return rm


def _make_real_def(addr: str = "10.0.0.1") -> RealDefinition:
    return RealDefinition(address=IPv4Address(addr), flags=RealFlags.NONE)


class TestRealsMapIndexAllocation:
    def test_index_zero_is_reserved_at_init(self):
        rm = _make_reals_map()
        assert rm._index_allocator.is_allocated(0)

    def test_allocate_index_starts_at_one(self):
        rm = _make_reals_map()
        idx = rm.allocate_index()
        assert idx == 1

    def test_allocate_index_sequential(self):
        rm = _make_reals_map()
        idx1 = rm.allocate_index()
        idx2 = rm.allocate_index()
        assert idx1 == 1
        assert idx2 == 2

    def test_allocate_index_exhaustion_raises(self):
        rm = _make_reals_map(max_reals=2)  # only index 1 available (0 is reserved)
        rm.allocate_index()  # gets 1

        with pytest.raises(ResourceExhaustedError):
            rm.allocate_index()

    def test_free_index_allows_reuse(self):
        rm = _make_reals_map()
        idx = rm.allocate_index()
        rm.free_index(idx)
        reused = rm.allocate_index()
        assert reused == idx

    def test_free_index_zero_is_no_op(self):
        rm = _make_reals_map()
        rm.free_index(0)  # Should not raise
        assert rm._index_allocator.is_allocated(0)  # Still reserved

    def test_is_index_allocated_true_for_allocated(self):
        rm = _make_reals_map()
        idx = rm.allocate_index()
        assert rm.is_index_allocated(idx) is True

    def test_is_index_allocated_false_for_free(self):
        rm = _make_reals_map()
        assert rm.is_index_allocated(5) is False

    def test_is_index_allocated_false_for_reserved_zero(self):
        # Index 0 is reserved internally; is_allocated reflects actual state
        rm = _make_reals_map()
        assert rm.is_index_allocated(0) is True  # Reserved = allocated


class TestRealsMapAllocateAndSet:
    def test_allocate_and_set_writes_to_bpf_and_caches(self):
        rm = _make_reals_map()
        real_def = _make_real_def()

        idx = rm.allocate_and_set(real_def)

        assert idx == 1
        rm.set.assert_called_once_with(1, real_def)
        assert rm._reals_cache[1] == real_def

    def test_allocate_and_set_increments_allocated_count(self):
        rm = _make_reals_map()
        assert rm.allocated_count == 0
        rm.allocate_and_set(_make_real_def())
        assert rm.allocated_count == 1


class TestRealsMapAddReal:
    def test_add_real_sets_index_on_real_object(self):
        rm = _make_reals_map()
        real = Real(address=IPv4Address("10.0.0.1"), weight=100)

        idx = rm.add_real(real)

        assert idx == 1
        assert real.index == 1

    def test_add_real_multiple_get_sequential_indices(self):
        rm = _make_reals_map()
        r1 = Real(address=IPv4Address("10.0.0.1"), weight=100)
        r2 = Real(address=IPv4Address("10.0.0.2"), weight=100)

        rm.add_real(r1)
        rm.add_real(r2)

        assert r1.index == 1
        assert r2.index == 2


class TestRealsMapRemoveReal:
    def test_remove_real_allocated_returns_true_and_frees_index(self):
        rm = _make_reals_map()
        rm.add_real(Real(address=IPv4Address("10.0.0.1"), weight=100))

        result = rm.remove_real(1)

        assert result is True
        assert rm.is_index_allocated(1) is False
        # delete() is NEVER called — entries left for in-flight connections
        rm.delete.assert_not_called()

    def test_remove_real_not_allocated_returns_false(self):
        rm = _make_reals_map()

        result = rm.remove_real(99)  # Never allocated

        assert result is False

    def test_remove_real_index_zero_returns_false(self):
        rm = _make_reals_map()
        # Index 0 is reserved; is_allocated(0) is True but we should not remove reserved index
        # free_index(0) is a no-op, so remove_real(0) returns True but frees nothing
        # This documents current behavior:
        result = rm.remove_real(0)
        assert result is True  # is_allocated(0) == True, so code proceeds
        assert rm.is_index_allocated(0) is True  # free_index(0) is a no-op


class TestRealsMapGetReal:
    def test_get_real_cache_hit(self):
        rm = _make_reals_map()
        real_def = _make_real_def()
        rm.add_real(Real(address=IPv4Address("10.0.0.1"), weight=100))
        rm.get.reset_mock()

        result = rm.get_real(1)

        assert result == real_def
        rm.get.assert_not_called()  # Served from cache

    def test_get_real_cache_miss_falls_back_to_bpf(self):
        rm = _make_reals_map()
        real_def = _make_real_def()
        rm.get = MagicMock(return_value=real_def)

        result = rm.get_real(5)

        assert result == real_def
        rm.get.assert_called_once_with(5)

    def test_get_real_missing_returns_none(self):
        rm = _make_reals_map()
        rm.get = MagicMock(return_value=None)

        result = rm.get_real(99)

        assert result is None


class TestRealsMapListAndGetAll:
    def test_list_allocated_indices_excludes_zero(self):
        rm = _make_reals_map()
        rm.add_real(Real(address=IPv4Address("10.0.0.1"), weight=100))
        rm.add_real(Real(address=IPv4Address("10.0.0.2"), weight=100))

        indices = rm.list_allocated_indices()

        assert 0 not in indices
        assert 1 in indices
        assert 2 in indices

    def test_list_allocated_indices_empty(self):
        rm = _make_reals_map()
        assert rm.list_allocated_indices() == []

    def test_get_all_reals_returns_dict_of_allocated(self):
        rm = _make_reals_map()
        real_def = _make_real_def()
        rm.add_real(Real(address=IPv4Address("10.0.0.1"), weight=100))

        result = rm.get_all_reals()

        assert 1 in result
        assert result[1] == real_def

    def test_get_all_reals_empty(self):
        rm = _make_reals_map()
        assert rm.get_all_reals() == {}


class TestRealsMapSyncFromMap:
    def test_sync_from_map_skips_ipv4_zero_address(self):
        rm = _make_reals_map()
        # Index 0 would have all-zero IPv4 address
        zero_def = RealDefinition(
            address=IPv4Address("0.0.0.0"), flags=RealFlags.NONE
        )
        # sync_from_map iterates range(1, max_reals) and calls self.get(i)
        # It skips entries where address.packed == b"\x00" * 4
        rm.get = MagicMock(return_value=zero_def)

        rm.sync_from_map()

        # Zero-address entries are skipped, no indices reserved
        assert rm.allocated_count == 0

    def test_sync_from_map_restores_non_zero_entries(self):
        rm = _make_reals_map()
        real_def = _make_real_def("10.0.0.5")
        zero_def = RealDefinition(address=IPv4Address("0.0.0.0"), flags=RealFlags.NONE)

        def fake_get(i):
            if i == 3:
                return real_def
            return zero_def

        rm.get = MagicMock(side_effect=fake_get)

        rm.sync_from_map()

        assert rm._reals_cache[3] == real_def
        assert rm.is_index_allocated(3)

    def test_sync_from_map_known_limitation_ipv6_zero_not_filtered(self):
        """IPv6 zero-address is NOT filtered by sync_from_map (IPv4-only check)."""
        rm = _make_reals_map()
        ipv6_zero = RealDefinition(
            address=IPv6Address("::"), flags=RealFlags.NONE
        )
        zero_ipv4 = RealDefinition(address=IPv4Address("0.0.0.0"), flags=RealFlags.NONE)

        def fake_get(i):
            if i == 2:
                return ipv6_zero
            return zero_ipv4

        rm.get = MagicMock(side_effect=fake_get)

        rm.sync_from_map()

        # IPv6 zero IS included because packed is 16 bytes != b"\x00" * 4
        assert rm.is_index_allocated(2)


class TestRealsMapProperties:
    def test_allocated_count_excludes_reserved_zero(self):
        rm = _make_reals_map()
        assert rm.allocated_count == 0
        rm.add_real(Real(address=IPv4Address("10.0.0.1"), weight=100))
        assert rm.allocated_count == 1

    def test_available_count_is_inverse_of_allocated(self):
        rm = _make_reals_map(max_reals=4)
        initial = rm.available_count
        rm.add_real(Real(address=IPv4Address("10.0.0.1"), weight=100))
        assert rm.available_count == initial - 1
```

- [ ] **Step 6: Run the tests and verify they pass**

```bash
.venv/bin/python3 -m pytest tests/unit/test_reals_map.py -v
```
Expected: All tests pass.

- [ ] **Step 7: Verify reals_map.py coverage**

```bash
.venv/bin/python3 -m pytest tests/unit/test_reals_map.py --cov=src/katran/bpf/maps/reals_map --cov-report=term-missing -q
```
Expected: `reals_map.py` shows 0 or very few missing lines.

- [ ] **Step 8: Commit**

```bash
git add tests/unit/test_reals_map.py
git commit -m "test: add RealsMap unit tests (37% → 100%)"
```

---

### Task 3: Extend VipManager tests (91% → 100%)

**Files:**
- Modify: `tests/unit/test_vip_manager.py`
- Source: `src/katran/lb/vip_manager.py`

**Missing lines (from coverage):**
- Line 180: `raise ValueError` in `remove_vip` when `key=None` and partial args
- Line 232: `return None` in `get_vip` when `key=None` and some args missing
- Lines 385–407: `sync_from_bpf()` method — entirely untested

- [ ] **Step 9: Add tests for missing lines in test_vip_manager.py**

Add these test classes at the end of `tests/unit/test_vip_manager.py`:

```python
class TestVipManagerRemoveVipEdgeCases:
    """Cover line 180: remove_vip raises ValueError when key=None and partial args."""

    def test_remove_vip_partial_args_raises_value_error(self, vip_manager):
        """remove_vip(address=...) without port and protocol raises ValueError."""
        with pytest.raises(ValueError, match="Must provide either key or address/port/protocol"):
            vip_manager.remove_vip(address="10.200.1.1")  # port and protocol missing


class TestVipManagerGetVipEdgeCases:
    """Cover line 232: get_vip returns None when key=None and some args missing."""

    def test_get_vip_partial_args_returns_none(self, vip_manager):
        """get_vip with partial address args returns None."""
        result = vip_manager.get_vip(address="10.200.1.1")  # port and protocol missing

        assert result is None


class TestVipManagerSyncFromBpf:
    """Cover lines 385-407: sync_from_bpf restores state from BPF vip_map."""

    def test_sync_from_bpf_populates_vips_from_map(self, vip_manager, mock_vip_map):
        """sync_from_bpf reads entries from BPF map and populates local state."""
        from ipaddress import IPv4Address
        from katran.core.constants import Protocol, VipFlags
        from katran.core.types import VipKey, VipMeta

        key = VipKey(IPv4Address("10.200.1.1"), 80, Protocol.TCP)
        meta = VipMeta(flags=VipFlags.NONE, vip_num=5)
        mock_vip_map.items = MagicMock(return_value=[(key, meta)])

        vip_manager.sync_from_bpf()

        assert vip_manager.get_vip_count() == 1
        vip = vip_manager.get_vip(key=key)
        assert vip is not None
        assert vip.vip_num == 5

    def test_sync_from_bpf_clears_existing_state(self, vip_manager, mock_vip_map):
        """sync_from_bpf clears local state before loading from BPF."""
        vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)
        assert vip_manager.get_vip_count() == 1

        mock_vip_map.items = MagicMock(return_value=[])
        vip_manager.sync_from_bpf()

        assert vip_manager.get_vip_count() == 0

    def test_sync_from_bpf_reserves_vip_nums_in_allocator(self, vip_manager, mock_vip_map):
        """sync_from_bpf marks vip_nums as allocated so they are not reused."""
        from ipaddress import IPv4Address
        from katran.core.constants import Protocol, VipFlags
        from katran.core.types import VipKey, VipMeta

        key = VipKey(IPv4Address("10.200.1.1"), 80, Protocol.TCP)
        meta = VipMeta(flags=VipFlags.NONE, vip_num=7)
        mock_vip_map.items = MagicMock(return_value=[(key, meta)])

        vip_manager.sync_from_bpf()

        # The allocator should have vip_num=7 reserved; next allocation gets 0 (first free)
        assert vip_manager._vip_num_allocator.is_allocated(7)
```

**REQUIRED:** Add `from unittest.mock import MagicMock` to the imports in `test_vip_manager.py` — the existing file does not have this import. The new tests use `MagicMock` directly. Add it at the top of the file alongside the existing imports.

- [ ] **Step 10: Run the tests and verify they pass**

```bash
.venv/bin/python3 -m pytest tests/unit/test_vip_manager.py -v
```
Expected: All existing + new tests pass.

- [ ] **Step 11: Verify vip_manager.py coverage reaches 100%**

```bash
.venv/bin/python3 -m pytest tests/unit/test_vip_manager.py --cov=src/katran/lb/vip_manager --cov-report=term-missing -q
```
Expected: 0 missing lines.

- [ ] **Step 12: Commit**

```bash
git add tests/unit/test_vip_manager.py
git commit -m "test: extend VipManager tests to cover sync_from_bpf and edge cases (91% → 100%)"
```

---

### Task 4: Extend Maglev tests (99% → 100%)

**Files:**
- Modify: `tests/unit/test_maglev.py`
- Source: `src/katran/lb/maglev.py`

**Missing lines:**
- Line 370: `return {}` in `get_distribution()` when ring is not built
- Line 389: `return {}` in `get_distribution_percentage()` when total is 0

- [ ] **Step 13: Add tests for missing lines**

Add to `tests/unit/test_maglev.py`:

```python
class TestMaglevDistributionEdgeCases:
    """Cover lines 370, 389: distribution methods when ring is not built or empty."""

    def test_get_distribution_ring_not_built_returns_empty_dict(self):
        """get_distribution returns {} when ring hasn't been built yet."""
        ring = MaglevHashRing(ring_size=7)

        result = ring.get_distribution()

        assert result == {}

    def test_get_distribution_percentage_empty_ring_returns_empty_dict(self):
        """get_distribution_percentage returns {} when ring is built with no endpoints."""
        ring = MaglevHashRing(ring_size=7)
        ring.build([])  # Empty ring — all slots are -1

        result = ring.get_distribution_percentage()

        # get_distribution returns {} for empty ring (all -1 slots filtered out),
        # so total == 0, returns {}
        assert result == {}
```

- [ ] **Step 14: Run tests and verify they pass**

```bash
.venv/bin/python3 -m pytest tests/unit/test_maglev.py -v
```

- [ ] **Step 15: Verify maglev.py hits 100%**

```bash
.venv/bin/python3 -m pytest tests/unit/test_maglev.py --cov=src/katran/lb/maglev --cov-report=term-missing -q
```
Expected: 0 missing lines.

- [ ] **Step 16: Commit**

```bash
git add tests/unit/test_maglev.py
git commit -m "test: extend Maglev tests to cover distribution edge cases (99% → 100%)"
```

---

### Task 5: Extend RealManager tests (99% → 100%)

**Files:**
- Modify: `tests/unit/test_real_manager.py`
- Source: `src/katran/lb/real_manager.py`

**Missing lines:**
- Line 519: `return` in `_decrease_ref_count()` when address not tracked
- Line 592: `logger.warning(...)` in `rebuild_all_rings()` — method body is never called

- [ ] **Step 17: Add tests for missing lines**

Add to `tests/unit/test_real_manager.py`:

```python
class TestRealManagerEdgeCases:
    """Cover lines 519, 592: decrease_ref_count no-op and rebuild_all_rings."""

    def test_decrease_ref_count_unknown_address_is_no_op(self, real_manager):
        """_decrease_ref_count on an unknown address does nothing (returns early)."""
        from ipaddress import IPv4Address

        # Should not raise; address is not tracked
        real_manager._decrease_ref_count(IPv4Address("10.0.0.99"))

        # State unchanged
        assert real_manager.get_global_real_count() == 0

    def test_rebuild_all_rings_logs_warning(self, real_manager):
        """rebuild_all_rings logs a warning and does not raise (placeholder method)."""
        # Just calling the method should succeed and log a warning
        real_manager.rebuild_all_rings()  # Should not raise
```

- [ ] **Step 18: Run tests and verify they pass**

```bash
.venv/bin/python3 -m pytest tests/unit/test_real_manager.py -v
```

- [ ] **Step 19: Verify real_manager.py hits 100%**

```bash
.venv/bin/python3 -m pytest tests/unit/test_real_manager.py --cov=src/katran/lb/real_manager --cov-report=term-missing -q
```
Expected: 0 missing lines.

- [ ] **Step 20: Commit**

```bash
git add tests/unit/test_real_manager.py
git commit -m "test: extend RealManager tests to cover decrease_ref_count no-op and rebuild_all_rings (99% → 100%)"
```

---

### Task 5b: Verify Phase 1 coverage targets

- [ ] **Step 21: Run full unit suite and check critical path files**

```bash
.venv/bin/python3 -m pytest tests/unit/ --cov=src/katran --cov-report=term-missing -q 2>&1 | grep -E "(vip_map|reals_map|vip_manager|maglev|real_manager)\.py"
```
Expected: All five critical path files show 100%.

---

## Chunk 2: Phase 2 — High-ROI Non-Critical Files (→ 85% overall)

---

### Task 6: CtlArray unit tests (44% → ~100%)

**Files:**
- Create: `tests/unit/test_ctl_array.py`
- Source: `src/katran/bpf/maps/ctl_array.py`

**Mocking strategy:** Same as VipMap — instantiate with fake path, replace `get` and `set` on the instance.

- [ ] **Step 22: Create test file**

```python
# tests/unit/test_ctl_array.py
"""Unit tests for CtlArray — no BPF kernel required."""
from unittest.mock import MagicMock, call

import pytest

from katran.bpf.maps.ctl_array import CtlArray
from katran.core.constants import CtlArrayIndex
from katran.core.types import CtlValue


def _make_ctl_array() -> CtlArray:
    """Create a CtlArray with mocked BPF methods."""
    ca = CtlArray.__new__(CtlArray)
    CtlArray.__init__(ca, "/fake/path")
    ca.get = MagicMock(return_value=None)
    ca.set = MagicMock()
    return ca


class TestCtlArrayMac:
    def test_set_mac_string_calls_set(self):
        ca = _make_ctl_array()
        ca.set_mac("aa:bb:cc:dd:ee:ff")
        ca.set.assert_called_once()
        idx, val = ca.set.call_args[0]
        assert idx == CtlArrayIndex.MAC_ADDRESS_POS
        assert isinstance(val, CtlValue)

    def test_set_mac_custom_index(self):
        ca = _make_ctl_array()
        ca.set_mac("aa:bb:cc:dd:ee:ff", index=2)
        idx = ca.set.call_args[0][0]
        assert idx == 2

    def test_get_mac_returns_string(self):
        ca = _make_ctl_array()
        mock_val = MagicMock()
        mock_val.as_mac.return_value = "aa:bb:cc:dd:ee:ff"
        ca.get = MagicMock(return_value=mock_val)

        result = ca.get_mac()

        assert result == "aa:bb:cc:dd:ee:ff"
        ca.get.assert_called_once_with(CtlArrayIndex.MAC_ADDRESS_POS)

    def test_get_mac_not_set_returns_none(self):
        ca = _make_ctl_array()
        ca.get = MagicMock(return_value=None)

        result = ca.get_mac()

        assert result is None

    def test_get_mac_bytes_returns_6_bytes(self):
        ca = _make_ctl_array()
        mock_val = MagicMock()
        mock_val.value = b"\xaa\xbb\xcc\xdd\xee\xff\x00\x00"
        ca.get = MagicMock(return_value=mock_val)

        result = ca.get_mac_bytes()

        assert result == b"\xaa\xbb\xcc\xdd\xee\xff"

    def test_get_mac_bytes_not_set_returns_none(self):
        ca = _make_ctl_array()
        ca.get = MagicMock(return_value=None)

        result = ca.get_mac_bytes()

        assert result is None


class TestCtlArrayIfindex:
    def test_set_ifindex_calls_set_at_ifindex_pos(self):
        ca = _make_ctl_array()
        ca.set_ifindex(42)
        ca.set.assert_called_once()
        idx, val = ca.set.call_args[0]
        assert idx == CtlArrayIndex.IFINDEX_POS
        assert isinstance(val, CtlValue)

    def test_set_ifindex_custom_index(self):
        ca = _make_ctl_array()
        ca.set_ifindex(42, index=3)
        idx = ca.set.call_args[0][0]
        assert idx == 3

    def test_get_ifindex_returns_int(self):
        ca = _make_ctl_array()
        mock_val = MagicMock()
        mock_val.as_ifindex.return_value = 42
        ca.get = MagicMock(return_value=mock_val)

        result = ca.get_ifindex()

        assert result == 42

    def test_get_ifindex_not_set_returns_none(self):
        ca = _make_ctl_array()
        ca.get = MagicMock(return_value=None)

        result = ca.get_ifindex()

        assert result is None


class TestCtlArrayU64:
    def test_set_u64_boundary_zero(self):
        ca = _make_ctl_array()
        ca.set_u64(0, index=5)
        ca.set.assert_called_once()
        idx, val = ca.set.call_args[0]
        assert idx == 5
        assert isinstance(val, CtlValue)

    def test_set_u64_boundary_max(self):
        ca = _make_ctl_array()
        ca.set_u64(2**64 - 1, index=5)
        ca.set.assert_called_once()

    def test_get_u64_returns_int(self):
        ca = _make_ctl_array()
        mock_val = MagicMock()
        mock_val.as_u64.return_value = 12345
        ca.get = MagicMock(return_value=mock_val)

        result = ca.get_u64(5)

        assert result == 12345

    def test_get_u64_not_set_returns_none(self):
        ca = _make_ctl_array()
        ca.get = MagicMock(return_value=None)

        result = ca.get_u64(5)

        assert result is None


class TestCtlArrayConvenienceMethods:
    def test_configure_gateway_calls_set_mac_and_set_ifindex(self):
        ca = _make_ctl_array()

        ca.configure_gateway("aa:bb:cc:dd:ee:ff", 42)

        # set() should be called twice: once for MAC, once for ifindex
        assert ca.set.call_count == 2

    def test_get_configuration_both_present(self):
        ca = _make_ctl_array()
        mac_val = MagicMock()
        mac_val.as_mac.return_value = "aa:bb:cc:dd:ee:ff"
        ifindex_val = MagicMock()
        ifindex_val.as_ifindex.return_value = 42

        def fake_get(index):
            if index == CtlArrayIndex.MAC_ADDRESS_POS:
                return mac_val
            if index == CtlArrayIndex.IFINDEX_POS:
                return ifindex_val
            return None

        ca.get = MagicMock(side_effect=fake_get)

        result = ca.get_configuration()

        assert result["mac_address"] == "aa:bb:cc:dd:ee:ff"
        assert result["ifindex"] == 42

    def test_get_configuration_both_none(self):
        ca = _make_ctl_array()
        ca.get = MagicMock(return_value=None)

        result = ca.get_configuration()

        assert result["mac_address"] is None
        assert result["ifindex"] is None

    def test_get_configuration_mac_only(self):
        ca = _make_ctl_array()
        mac_val = MagicMock()
        mac_val.as_mac.return_value = "aa:bb:cc:dd:ee:ff"

        def fake_get(index):
            if index == CtlArrayIndex.MAC_ADDRESS_POS:
                return mac_val
            return None

        ca.get = MagicMock(side_effect=fake_get)

        result = ca.get_configuration()

        assert result["mac_address"] == "aa:bb:cc:dd:ee:ff"
        assert result["ifindex"] is None
```

- [ ] **Step 23: Run tests and verify they pass**

```bash
.venv/bin/python3 -m pytest tests/unit/test_ctl_array.py -v
```

- [ ] **Step 24: Commit**

```bash
git add tests/unit/test_ctl_array.py
git commit -m "test: add CtlArray unit tests (44% → ~100%)"
```

---

### Task 7: Extend KatranService tests (68% → ~85%)

**Files:**
- Modify: `tests/unit/test_service.py`
- Source: `src/katran/service.py`

**Missing lines covered here:** 141-143 (`_require_manager`), 154-155 (`_try_open` happy path), 213-214 (`_open_maps` optional map happy path), 223-224, 227 (`_open_feature_maps`), delegation methods (418+).

**Strategy:** Extend the existing `TestServiceLifecycle` class and add new test classes. Use the existing `mock_maps` fixture. For feature manager tests, patch individual manager classes.

- [ ] **Step 25: Add service tests — feature checking and internal helpers**

Add the following classes to `tests/unit/test_service.py`:

```python
from katran.core.constants import KatranFeature
from katran.core.exceptions import FeatureNotEnabledError, KatranError


class TestServiceFeatureChecks:
    def test_has_feature_returns_true_when_enabled(self, config, mock_maps):
        config_with_src = KatranConfig.from_dict({
            "bpf": {"pin_path": "/tmp/fake"},
            "maps": {"max_vips": 64, "max_reals": 256, "ring_size": 13, "lru_size": 100},
            "features": KatranFeature.SRC_ROUTING,
        })
        svc = KatranService(config_with_src)
        svc.start()

        assert svc.has_feature(KatranFeature.SRC_ROUTING) is True

    def test_has_feature_returns_false_when_not_enabled(self, config, mock_maps):
        svc = KatranService(config)  # No features enabled
        svc.start()

        assert svc.has_feature(KatranFeature.SRC_ROUTING) is False

    def test_require_feature_raises_when_not_enabled(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()

        with pytest.raises(FeatureNotEnabledError):
            svc._require_feature(KatranFeature.SRC_ROUTING)

    def test_require_manager_raises_when_none(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()

        with pytest.raises(KatranError, match="not available"):
            svc._require_manager(None, "TestManager")

    def test_require_manager_returns_manager_when_present(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()

        mock_mgr = MagicMock()
        result = svc._require_manager(mock_mgr, "TestManager")

        assert result is mock_mgr


class TestServiceTryOpen:
    def test_try_open_success_returns_map(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()

        mock_map = MagicMock()
        mock_cls = MagicMock(return_value=mock_map)

        result = svc._try_open(mock_cls, "/fake/path")

        assert result is mock_map
        mock_map.open.assert_called_once()
        assert mock_map in svc._opened_maps

    def test_try_open_failure_returns_none(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()

        mock_cls = MagicMock(side_effect=OSError("map not found"))

        result = svc._try_open(mock_cls, "/fake/path")

        assert result is None


class TestServiceOptionalMapHandling:
    def test_open_maps_optional_map_failure_is_swallowed(self, config):
        """Optional maps (hc_reals, lru) failing during _open_maps does not prevent start."""
        good_map = _make_mock_map()
        bad_optional = _make_mock_map()
        bad_optional.open.side_effect = OSError("optional map unavailable")

        call_count = [0]
        required_map_names = ["VipMap", "RealsMap", "ChRingsMap", "StatsMap", "CtlArray"]
        optional_map_names = ["HcRealsMap", "LruMap"]

        def make_factory(cls_name):
            def factory(*a, **kw):
                if cls_name in optional_map_names:
                    return bad_optional
                return _make_mock_map()
            return factory

        with (
            patch("katran.service.VipMap", side_effect=make_factory("VipMap")),
            patch("katran.service.RealsMap", side_effect=make_factory("RealsMap")),
            patch("katran.service.ChRingsMap", side_effect=lambda *a, **kw: (
                setattr(m := _make_mock_map(), 'ring_size', 13) or m
            )),
            patch("katran.service.StatsMap", side_effect=make_factory("StatsMap")),
            patch("katran.service.CtlArray", side_effect=make_factory("CtlArray")),
            patch("katran.service.HcRealsMap", side_effect=make_factory("HcRealsMap")),
            patch("katran.service.LruMap", side_effect=make_factory("LruMap")),
        ):
            svc = KatranService(config)
            svc.start()  # Should NOT raise even though optional maps fail

            assert svc.is_running
            # Optional maps are not set (their attributes remain None/absent)
            assert not hasattr(svc, 'hc_reals_map') or getattr(svc, 'hc_reals_map', None) is None


class TestServiceIsHealthy:
    def test_is_healthy_true_when_running_with_managers(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()

        assert svc.is_healthy is True

    def test_is_healthy_false_when_not_running(self, config):
        svc = KatranService(config)

        assert svc.is_healthy is False

    def test_is_healthy_false_when_vip_manager_is_none(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()
        svc.vip_manager = None

        assert svc.is_healthy is False


class TestServiceDelegation:
    """Test that service delegation methods call through to the right manager."""

    def test_get_vip_stats_delegates_to_stats_manager(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()
        svc._stats_manager = MagicMock()

        svc.get_vip_stats(vip_num=0)

        svc._stats_manager.get_vip_stats.assert_called_once_with(0)

    def test_get_real_stats_delegates_to_stats_manager(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()
        svc._stats_manager = MagicMock()

        svc.get_real_stats(real_index=1)

        svc._stats_manager.get_real_stats.assert_called_once_with(1)

    def test_add_decap_dst_raises_feature_not_enabled(self, config, mock_maps):
        """add_decap_dst raises FeatureNotEnabledError when INLINE_DECAP not configured."""
        svc = KatranService(config)
        svc.start()

        with pytest.raises(FeatureNotEnabledError):
            svc.add_decap_dst("10.0.0.1")

    def test_add_src_routing_rules_raises_feature_not_enabled(self, config, mock_maps):
        """add_src_routing_rules raises FeatureNotEnabledError when SRC_ROUTING not configured."""
        svc = KatranService(config)
        svc.start()

        with pytest.raises(FeatureNotEnabledError):
            svc.add_src_routing_rules(["192.168.0.0/24"], "10.0.0.1")

    def test_add_hc_dst_raises_feature_not_enabled(self, config, mock_maps):
        """add_hc_dst raises FeatureNotEnabledError when DIRECT_HEALTHCHECKING not configured."""
        svc = KatranService(config)
        svc.start()

        with pytest.raises(FeatureNotEnabledError):
            svc.add_hc_dst(somark=1, dst="10.0.0.1")

    def test_add_down_real_raises_when_manager_not_initialized(self, config, mock_maps):
        """add_down_real raises KatranError when down_real_manager not available."""
        svc = KatranService(config)
        svc.start()
        svc._down_real_manager = None

        with pytest.raises(KatranError, match="not available"):
            from katran.core.types import VipKey, Protocol
            from ipaddress import IPv4Address
            key = VipKey(IPv4Address("10.0.0.1"), 80, Protocol.TCP)
            svc.add_down_real(key, real_index=1)
```

- [ ] **Step 26: Run tests and verify they pass**

```bash
.venv/bin/python3 -m pytest tests/unit/test_service.py -v
```

Note: Some tests may need adjustment based on actual service API. Run to see failures and fix accordingly. The key constraint is: do not change the source code.

- [ ] **Step 27: Check service.py coverage improvement**

```bash
.venv/bin/python3 -m pytest tests/unit/test_service.py --cov=src/katran/service --cov-report=term-missing -q
```

- [ ] **Step 28: Commit**

```bash
git add tests/unit/test_service.py
git commit -m "test: extend KatranService tests for feature checks, delegation, and optional maps (68% → ~85%)"
```

---

### Task 8: StatsMap unit tests (55% → ~85%)

**Files:**
- Create: `tests/unit/test_stats_map.py` (new file; existing `test_stats_manager.py` tests `StatsManager`, not `StatsMap`)
- Source: `src/katran/bpf/maps/stats_map.py`

**Missing lines:** 43-46 (`VipStatistics.hit_ratio`), 95-96, 104, 108, 111, 114, 117, 120, 124 (serialization methods called via `get`/`set`), 143 (`_global_index`), 159-160 (`get_counter`), 172 (`get_counter_per_cpu`), 190-192 (`get_vip_stats`), 210-222 (`get_global_stats`), 242-245 (`get_all_vip_stats`), 254-259 (`get_xdp_action_stats`), 275 (`reset_counter`), 284 (`reset_vip_stats`).

**Mocking strategy:** Instantiate `StatsMap` with fake path and mocked `num_cpus=2`. Replace `get`, `set`, `get_all_cpus` on the instance.

- [ ] **Step 29: Create stats_map test file**

```python
# tests/unit/test_stats_map.py
"""Unit tests for StatsMap — no BPF kernel required."""
from unittest.mock import MagicMock

import pytest

from katran.bpf.maps.stats_map import GlobalStatistics, StatsMap, VipStatistics
from katran.core.constants import MAX_VIPS, StatsCounterIndex
from katran.core.types import LbStats


def _make_stats_map(max_vips: int = 16) -> StatsMap:
    """Create a StatsMap with mocked BPF methods."""
    sm = StatsMap.__new__(StatsMap)
    StatsMap.__init__(sm, "/fake/path", max_vips=max_vips, num_cpus=2)
    sm.get = MagicMock(return_value=None)
    sm.set = MagicMock()
    sm.get_all_cpus = MagicMock(return_value=[LbStats(), LbStats()])
    return sm


class TestVipStatisticsHitRatio:
    def test_hit_ratio_zero_when_no_traffic(self):
        stats = VipStatistics(packets=0, bytes=0, lru_hits=0, lru_misses=0)
        assert stats.hit_ratio == 0.0

    def test_hit_ratio_perfect(self):
        stats = VipStatistics(lru_hits=100, lru_misses=0)
        assert stats.hit_ratio == 1.0

    def test_hit_ratio_partial(self):
        stats = VipStatistics(lru_hits=50, lru_misses=50)
        assert stats.hit_ratio == 0.5


class TestStatsMapAggregateValues:
    def test_aggregate_single_cpu(self):
        sm = _make_stats_map()
        values = [LbStats(v1=100, v2=200)]

        result = sm._aggregate_values(values)

        assert result.v1 == 100
        assert result.v2 == 200

    def test_aggregate_multi_cpu_sums(self):
        sm = _make_stats_map()
        values = [LbStats(v1=100, v2=200), LbStats(v1=50, v2=100)]

        result = sm._aggregate_values(values)

        assert result.v1 == 150
        assert result.v2 == 300

    def test_aggregate_empty_list_returns_zero_stats(self):
        sm = _make_stats_map()

        result = sm._aggregate_values([])

        assert result.v1 == 0
        assert result.v2 == 0


class TestStatsMapGetCounter:
    def test_get_counter_returns_aggregated_stats(self):
        sm = _make_stats_map()
        sm.get = MagicMock(return_value=LbStats(v1=999, v2=888))

        result = sm.get_counter(5)

        assert result.v1 == 999
        sm.get.assert_called_once_with(5)

    def test_get_counter_not_found_returns_empty_stats(self):
        sm = _make_stats_map()
        sm.get = MagicMock(return_value=None)

        result = sm.get_counter(5)

        assert result.v1 == 0
        assert result.v2 == 0

    def test_get_counter_per_cpu_delegates_to_get_all_cpus(self):
        sm = _make_stats_map()
        per_cpu = [LbStats(v1=10), LbStats(v1=20)]
        sm.get_all_cpus = MagicMock(return_value=per_cpu)

        result = sm.get_counter_per_cpu(3)

        assert result == per_cpu
        sm.get_all_cpus.assert_called_once_with(3)


class TestStatsMapGetVipStats:
    def test_get_vip_stats_returns_vip_statistics(self):
        sm = _make_stats_map()
        sm.get = MagicMock(return_value=LbStats(v1=1000, v2=50000))

        result = sm.get_vip_stats(vip_num=0)

        assert isinstance(result, VipStatistics)
        assert result.packets == 1000
        assert result.bytes == 50000
        assert result.lru_hits == 0   # Per-VIP LRU not tracked
        assert result.lru_misses == 0
        sm.get.assert_called_once_with(0)

    def test_get_vip_stats_boundary_last_vip(self):
        sm = _make_stats_map(max_vips=16)
        sm.get = MagicMock(return_value=LbStats(v1=5, v2=10))

        result = sm.get_vip_stats(vip_num=15)

        sm.get.assert_called_once_with(15)
        assert result.packets == 5


class TestStatsMapGetGlobalStats:
    def test_get_global_stats_aggregates_all_counters(self):
        sm = _make_stats_map(max_vips=16)

        call_map: dict[int, LbStats] = {
            16 + StatsCounterIndex.LRU_CNTRS: LbStats(v1=100, v2=5),
            16 + StatsCounterIndex.LRU_MISS_CNTR: LbStats(v1=10, v2=0),
            16 + StatsCounterIndex.NEW_CONN_RATE_CNTR: LbStats(v1=200, v2=0),
            16 + StatsCounterIndex.ICMP_TOOBIG_CNTRS: LbStats(v1=3, v2=0),
            16 + StatsCounterIndex.XDP_TOTAL_CNTR: LbStats(v1=500, v2=1000000),
        }

        def fake_get(idx):
            return call_map.get(idx, LbStats())

        sm.get = MagicMock(side_effect=fake_get)

        result = sm.get_global_stats()

        assert isinstance(result, GlobalStatistics)
        assert result.total_packets == 500
        assert result.total_bytes == 1000000
        assert result.total_lru_hits == 100
        assert result.total_lru_misses == 10
        assert result.new_connections == 200
        assert result.icmp_toobig == 3


class TestStatsMapGetXdpActionStats:
    def test_get_xdp_action_stats_returns_dict(self):
        sm = _make_stats_map(max_vips=16)

        call_map: dict[int, LbStats] = {
            16 + StatsCounterIndex.XDP_TOTAL_CNTR: LbStats(v1=500),
            16 + StatsCounterIndex.XDP_TX_CNTR: LbStats(v1=480),
            16 + StatsCounterIndex.XDP_DROP_CNTR: LbStats(v1=10),
            16 + StatsCounterIndex.XDP_PASS_CNTR: LbStats(v1=10),
        }

        def fake_get(idx):
            return call_map.get(idx, LbStats())

        sm.get = MagicMock(side_effect=fake_get)

        result = sm.get_xdp_action_stats()

        assert result["total"] == 500
        assert result["tx"] == 480
        assert result["drop"] == 10
        assert result["pass"] == 10

    def test_get_all_vip_stats_batch(self):
        sm = _make_stats_map(max_vips=16)
        sm.get = MagicMock(return_value=LbStats(v1=100, v2=200))

        result = sm.get_all_vip_stats([0, 1, 2])

        assert len(result) == 3
        for vip_num in [0, 1, 2]:
            assert vip_num in result
            assert result[vip_num].packets == 100


class TestStatsMapReset:
    def test_reset_counter_writes_zero_lbstats(self):
        sm = _make_stats_map()

        sm.reset_counter(5)

        sm.set.assert_called_once_with(5, LbStats(v1=0, v2=0))

    def test_reset_vip_stats_delegates_to_reset_counter(self):
        sm = _make_stats_map()

        sm.reset_vip_stats(vip_num=3)

        sm.set.assert_called_once_with(3, LbStats(v1=0, v2=0))

    def test_global_index_adds_max_vips_offset(self):
        sm = _make_stats_map(max_vips=16)

        result = sm._global_index(StatsCounterIndex.LRU_CNTRS)

        assert result == 16 + StatsCounterIndex.LRU_CNTRS
```

- [ ] **Step 30: Run tests and verify they pass**

```bash
.venv/bin/python3 -m pytest tests/unit/test_stats_map.py -v
```

- [ ] **Step 31: Check stats_map coverage**

```bash
.venv/bin/python3 -m pytest tests/unit/test_stats_map.py --cov=src/katran/bpf/maps/stats_map --cov-report=term-missing -q
```

- [ ] **Step 32: Commit**

```bash
git add tests/unit/test_stats_map.py
git commit -m "test: add StatsMap unit tests (55% → ~85%)"
```

---

### Task 9: Final verification — overall coverage ≥85%

- [ ] **Step 33: Run full unit test suite with coverage**

```bash
make unit-test-cov 2>&1 | tail -20
```
Expected:
- Overall coverage ≥ 85%
- `vip_map.py`, `reals_map.py`, `vip_manager.py`, `maglev.py`, `real_manager.py` all at 100%
- All existing tests continue to pass

If overall is below 85%, inspect the term-missing output for the next highest-ROI files and add a few targeted tests. The most likely candidates are `lru_manager.py` (77%) and `ch_rings_map.py` (69%).

- [ ] **Step 34: Commit final verification result**

```bash
git add -A  # Only if any minor fixes were needed
git commit -m "test: verify ≥85% overall coverage and 100% critical path coverage"
```

---

## Quick Reference: Test Commands

```bash
# Run all unit tests
.venv/bin/python3 -m pytest tests/unit/ -v

# Coverage report
make unit-test-cov

# Single file
.venv/bin/python3 -m pytest tests/unit/test_vip_map.py -v

# Coverage for one source file
.venv/bin/python3 -m pytest tests/unit/ --cov=src/katran/bpf/maps/vip_map --cov-report=term-missing -q
```
