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
        # remove_vip calls self.get() (BPF, not cache) to retrieve meta
        meta = VipMeta(flags=VipFlags.NONE, vip_num=0)
        vm.get = MagicMock(return_value=meta)

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
