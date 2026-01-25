"""
Unit tests for VipManager.

Tests VIP lifecycle management including CRUD operations,
index allocation, and state synchronization.
"""

import pytest
from ipaddress import IPv4Address, IPv6Address
from unittest.mock import Mock, MagicMock, call

from katran.lb.vip_manager import VipManager
from katran.core.constants import Protocol, VipFlags, MAX_VIPS
from katran.core.types import Vip, VipKey, VipMeta
from katran.core.exceptions import (
    VipExistsError,
    ResourceExhaustedError,
)


class TestVipManagerInit:
    """Test VipManager initialization."""

    def test_init_defaults(self, mock_vip_map, mock_ch_rings_map):
        """Test VipManager initialization with default parameters."""
        mgr = VipManager(mock_vip_map, mock_ch_rings_map)

        assert mgr._max_vips == MAX_VIPS
        assert len(mgr._vips) == 0
        assert mgr.get_vip_count() == 0

    def test_init_custom_max_vips(self, mock_vip_map, mock_ch_rings_map):
        """Test VipManager initialization with custom max_vips."""
        mgr = VipManager(mock_vip_map, mock_ch_rings_map, max_vips=256)

        assert mgr._max_vips == 256
        assert mgr.get_available_vip_count() == 256


class TestVipManagerAddVip:
    """Test VIP addition."""

    def test_add_vip_ipv4_tcp(self, vip_manager):
        """Test adding IPv4 TCP VIP."""
        vip = vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)

        assert vip.key.address == IPv4Address("10.200.1.1")
        assert vip.key.port == 80
        assert vip.key.protocol == Protocol.TCP
        assert vip.vip_num == 0  # First allocated
        assert vip.flags == VipFlags.NONE
        assert vip.is_allocated

        assert vip_manager.get_vip_count() == 1
        assert vip_manager.vip_exists(vip.key)

    def test_add_vip_ipv6_udp(self, vip_manager):
        """Test adding IPv6 UDP VIP."""
        vip = vip_manager.add_vip("2001:db8::1", 53, "udp")

        assert vip.key.address == IPv6Address("2001:db8::1")
        assert vip.key.protocol == Protocol.UDP
        assert vip.is_allocated

    def test_add_vip_with_flags(self, vip_manager):
        """Test adding VIP with flags."""
        vip = vip_manager.add_vip(
            "10.200.1.1",
            80,
            Protocol.TCP,
            flags=VipFlags.NO_SPORT | VipFlags.NO_LRU,
        )

        assert vip.flags == (VipFlags.NO_SPORT | VipFlags.NO_LRU)

    def test_add_multiple_vips(self, vip_manager):
        """Test adding multiple VIPs."""
        vip1 = vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)
        vip2 = vip_manager.add_vip("10.200.1.2", 443, Protocol.TCP)
        vip3 = vip_manager.add_vip("10.200.1.1", 8080, Protocol.TCP)

        assert vip1.vip_num == 0
        assert vip2.vip_num == 1
        assert vip3.vip_num == 2
        assert vip_manager.get_vip_count() == 3

    def test_add_duplicate_vip_raises_error(self, vip_manager):
        """Test adding duplicate VIP raises VipExistsError."""
        vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)

        with pytest.raises(VipExistsError) as exc_info:
            vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)

        assert "10.200.1.1" in str(exc_info.value)
        assert "80" in str(exc_info.value)

    def test_add_vip_initializes_empty_ring(
        self, vip_manager, mock_ch_rings_map
    ):
        """Test adding VIP initializes empty hash ring."""
        vip = vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)

        # Check write_ring was called with empty ring
        mock_ch_rings_map.write_ring.assert_called_once()
        call_args = mock_ch_rings_map.write_ring.call_args
        assert call_args[0][0] == vip.vip_num  # vip_num
        ring = call_args[0][1]
        assert len(ring) == mock_ch_rings_map.ring_size
        assert all(val == 0 for val in ring)  # All zeros

    def test_add_vip_updates_bpf_map(self, vip_manager, mock_vip_map):
        """Test adding VIP updates BPF vip_map."""
        vip = vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)

        mock_vip_map.add_vip.assert_called_once()
        call_args = mock_vip_map.add_vip.call_args[0][0]
        assert call_args.key == vip.key
        assert call_args.vip_num == vip.vip_num

    def test_add_vip_invalid_port_raises_error(self, vip_manager):
        """Test adding VIP with invalid port raises ValueError."""
        with pytest.raises(ValueError):
            vip_manager.add_vip("10.200.1.1", 70000, Protocol.TCP)


class TestVipManagerRemoveVip:
    """Test VIP removal."""

    def test_remove_vip_by_key(self, vip_manager):
        """Test removing VIP by key."""
        vip = vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)

        result = vip_manager.remove_vip(key=vip.key)

        assert result is True
        assert vip_manager.get_vip_count() == 0
        assert not vip_manager.vip_exists(vip.key)

    def test_remove_vip_by_address_port_protocol(self, vip_manager):
        """Test removing VIP by address/port/protocol."""
        vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)

        result = vip_manager.remove_vip(
            address="10.200.1.1", port=80, protocol="tcp"
        )

        assert result is True
        assert vip_manager.get_vip_count() == 0

    def test_remove_nonexistent_vip_returns_false(self, vip_manager):
        """Test removing nonexistent VIP returns False."""
        key = VipKey(IPv4Address("10.200.1.1"), 80, Protocol.TCP)

        result = vip_manager.remove_vip(key=key)

        assert result is False

    def test_remove_vip_frees_vip_num(self, vip_manager):
        """Test removing VIP frees vip_num for reuse."""
        vip1 = vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)
        vip_num1 = vip1.vip_num

        vip_manager.remove_vip(key=vip1.key)

        # Add new VIP should reuse freed vip_num
        vip2 = vip_manager.add_vip("10.200.1.2", 80, Protocol.TCP)
        assert vip2.vip_num == vip_num1

    def test_remove_vip_updates_bpf_map(self, vip_manager, mock_vip_map):
        """Test removing VIP updates BPF vip_map."""
        vip = vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)
        mock_vip_map.reset_mock()

        vip_manager.remove_vip(key=vip.key)

        mock_vip_map.remove_vip.assert_called_once_with(vip.key)


class TestVipManagerGetVip:
    """Test VIP retrieval."""

    def test_get_vip_by_key(self, vip_manager):
        """Test getting VIP by key."""
        vip_added = vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)

        vip = vip_manager.get_vip(key=vip_added.key)

        assert vip is not None
        assert vip.key == vip_added.key
        assert vip.vip_num == vip_added.vip_num

    def test_get_vip_by_address_port_protocol(self, vip_manager):
        """Test getting VIP by address/port/protocol."""
        vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)

        vip = vip_manager.get_vip(
            address="10.200.1.1", port=80, protocol="tcp"
        )

        assert vip is not None
        assert vip.key.address == IPv4Address("10.200.1.1")

    def test_get_nonexistent_vip_returns_none(self, vip_manager):
        """Test getting nonexistent VIP returns None."""
        vip = vip_manager.get_vip(
            address="10.200.1.1", port=80, protocol="tcp"
        )

        assert vip is None


class TestVipManagerListVips:
    """Test VIP listing."""

    def test_list_vips_empty(self, vip_manager):
        """Test listing VIPs when empty."""
        vips = vip_manager.list_vips()

        assert vips == []

    def test_list_vips_multiple(self, vip_manager):
        """Test listing multiple VIPs."""
        vip1 = vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)
        vip2 = vip_manager.add_vip("10.200.1.2", 443, Protocol.TCP)

        vips = vip_manager.list_vips()

        assert len(vips) == 2
        assert vip1 in vips
        assert vip2 in vips


class TestVipManagerModifyFlags:
    """Test VIP flags modification."""

    def test_modify_flags(self, vip_manager):
        """Test modifying VIP flags."""
        vip = vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)

        result = vip_manager.modify_flags(
            vip.key, VipFlags.NO_SPORT | VipFlags.NO_LRU
        )

        assert result is True
        assert vip.flags == (VipFlags.NO_SPORT | VipFlags.NO_LRU)

    def test_modify_flags_updates_bpf_map(
        self, vip_manager, mock_vip_map
    ):
        """Test modifying flags updates BPF map."""
        vip = vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)
        mock_vip_map.reset_mock()

        vip_manager.modify_flags(vip.key, VipFlags.NO_SPORT)

        # Check set was called with updated meta
        mock_vip_map.set.assert_called_once()
        call_args = mock_vip_map.set.call_args[0]
        assert call_args[0] == vip.key
        assert call_args[1].flags == VipFlags.NO_SPORT

    def test_modify_flags_nonexistent_vip_returns_false(self, vip_manager):
        """Test modifying flags for nonexistent VIP returns False."""
        key = VipKey(IPv4Address("10.200.1.1"), 80, Protocol.TCP)

        result = vip_manager.modify_flags(key, VipFlags.NO_SPORT)

        assert result is False


class TestVipManagerQueries:
    """Test VIP query methods."""

    def test_vip_exists(self, vip_manager):
        """Test vip_exists method."""
        vip = vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)

        assert vip_manager.vip_exists(vip.key)
        assert not vip_manager.vip_exists(
            VipKey(IPv4Address("10.200.1.2"), 80, Protocol.TCP)
        )

    def test_get_vip_count(self, vip_manager):
        """Test get_vip_count method."""
        assert vip_manager.get_vip_count() == 0

        vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)
        assert vip_manager.get_vip_count() == 1

        vip_manager.add_vip("10.200.1.2", 80, Protocol.TCP)
        assert vip_manager.get_vip_count() == 2

    def test_get_available_vip_count(self, vip_manager):
        """Test get_available_vip_count method."""
        initial = vip_manager.get_available_vip_count()

        vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)

        assert vip_manager.get_available_vip_count() == initial - 1

    def test_get_vip_by_num(self, vip_manager):
        """Test get_vip_by_num reverse lookup."""
        vip = vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)

        found = vip_manager.get_vip_by_num(vip.vip_num)

        assert found is not None
        assert found.vip_num == vip.vip_num
        assert found.key == vip.key

    def test_get_vip_by_num_not_found(self, vip_manager):
        """Test get_vip_by_num returns None if not found."""
        found = vip_manager.get_vip_by_num(999)

        assert found is None


class TestVipManagerStateManagement:
    """Test VIP state management."""

    def test_clear_all(self, vip_manager):
        """Test clearing all VIPs."""
        vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)
        vip_manager.add_vip("10.200.1.2", 443, Protocol.TCP)

        count = vip_manager.clear_all()

        assert count == 2
        assert vip_manager.get_vip_count() == 0

    def test_len(self, vip_manager):
        """Test __len__ magic method."""
        assert len(vip_manager) == 0

        vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)
        assert len(vip_manager) == 1

    def test_contains(self, vip_manager):
        """Test __contains__ magic method (in operator)."""
        vip = vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)

        assert vip.key in vip_manager
        assert VipKey(IPv4Address("10.200.1.2"), 80, Protocol.TCP) not in vip_manager

    def test_repr(self, vip_manager):
        """Test __repr__ method."""
        vip_manager.add_vip("10.200.1.1", 80, Protocol.TCP)

        repr_str = repr(vip_manager)

        assert "VipManager" in repr_str
        assert "vips=1" in repr_str


class TestVipManagerThreadSafety:
    """Test thread safety of VipManager operations."""

    def test_concurrent_add_vip(self, vip_manager):
        """Test concurrent VIP additions are serialized."""
        import threading

        results = []

        def add_vip(addr):
            try:
                vip = vip_manager.add_vip(addr, 80, Protocol.TCP)
                results.append(("success", vip.vip_num))
            except Exception as e:
                results.append(("error", str(e)))

        # Create threads
        threads = [
            threading.Thread(target=add_vip, args=(f"10.200.1.{i}",))
            for i in range(1, 11)
        ]

        # Start all threads
        for t in threads:
            t.start()

        # Wait for completion
        for t in threads:
            t.join()

        # Check results
        success_count = sum(1 for r in results if r[0] == "success")
        assert success_count == 10
        assert vip_manager.get_vip_count() == 10

        # Check vip_nums are unique
        vip_nums = [r[1] for r in results if r[0] == "success"]
        assert len(set(vip_nums)) == 10
