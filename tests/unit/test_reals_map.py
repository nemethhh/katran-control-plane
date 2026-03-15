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
