"""
Unit tests for RealManager.

Tests backend server management including reference counting,
index allocation, and consistent hash ring updates.
"""

import pytest
from ipaddress import IPv4Address, IPv6Address
from unittest.mock import Mock, MagicMock, call, patch

from katran.lb.real_manager import RealManager, RealMeta
from katran.lb.maglev import MaglevHashRing
from katran.core.constants import Protocol, VipFlags, MAX_REALS
from katran.core.types import Vip, VipKey, Real
from katran.core.exceptions import (
    RealExistsError,
    RealNotFoundError,
    ResourceExhaustedError,
)


class TestRealManagerInit:
    """Test RealManager initialization."""

    def test_init_defaults(self, mock_reals_map, mock_ch_rings_map):
        """Test RealManager initialization with default parameters."""
        mgr = RealManager(mock_reals_map, mock_ch_rings_map)

        assert mgr._max_reals == MAX_REALS
        assert len(mgr._reals) == 0
        assert mgr.get_global_real_count() == 0

    def test_init_custom_ring_builder(
        self, mock_reals_map, mock_ch_rings_map
    ):
        """Test RealManager initialization with custom ring builder."""
        custom_ring = MaglevHashRing(ring_size=65537)
        mgr = RealManager(
            mock_reals_map, mock_ch_rings_map, ring_builder=custom_ring
        )

        assert mgr._ring_builder is custom_ring


class TestRealManagerAddReal:
    """Test backend addition."""

    def test_add_real_to_vip(self, real_manager, sample_vip):
        """Test adding backend to VIP."""
        real = real_manager.add_real(sample_vip, "10.0.0.100", weight=100)

        assert real.address == IPv4Address("10.0.0.100")
        assert real.weight == 100
        assert real.index >= 1  # Index 0 is reserved
        assert real.is_allocated

        assert len(sample_vip.reals) == 1
        assert sample_vip.reals[0] == real

    def test_add_real_ipv6(self, real_manager, sample_vip):
        """Test adding IPv6 backend."""
        real = real_manager.add_real(sample_vip, "2001:db8::100", weight=100)

        assert real.address == IPv6Address("2001:db8::100")
        assert real.is_allocated

    def test_add_real_with_weight(self, real_manager, sample_vip):
        """Test adding backend with custom weight."""
        real = real_manager.add_real(sample_vip, "10.0.0.100", weight=50)

        assert real.weight == 50

    def test_add_multiple_reals_to_vip(self, real_manager, sample_vip):
        """Test adding multiple backends to VIP."""
        real1 = real_manager.add_real(sample_vip, "10.0.0.100")
        real2 = real_manager.add_real(sample_vip, "10.0.0.101")
        real3 = real_manager.add_real(sample_vip, "10.0.0.102")

        assert len(sample_vip.reals) == 3
        assert real1.index != real2.index != real3.index

    def test_add_duplicate_real_to_vip_raises_error(
        self, real_manager, sample_vip
    ):
        """Test adding duplicate backend to same VIP raises error."""
        real_manager.add_real(sample_vip, "10.0.0.100")

        with pytest.raises(RealExistsError) as exc_info:
            real_manager.add_real(sample_vip, "10.0.0.100")

        assert "10.0.0.100" in str(exc_info.value)

    def test_add_same_real_to_different_vips(self, real_manager, sample_vip):
        """Test adding same backend to different VIPs (reference counting)."""
        vip2 = Vip.create("10.200.1.2", 80, Protocol.TCP)
        vip2.vip_num = 1

        real1 = real_manager.add_real(sample_vip, "10.0.0.100")
        real2 = real_manager.add_real(vip2, "10.0.0.100")

        # Should have same index (shared backend)
        assert real1.index == real2.index

        # Reference count should be 2
        assert real_manager.get_real_ref_count("10.0.0.100") == 2

        # Global real count should be 1 (shared)
        assert real_manager.get_global_real_count() == 1

    def test_add_real_updates_bpf_map(
        self, real_manager, sample_vip, mock_reals_map
    ):
        """Test adding backend updates BPF reals map."""
        real = real_manager.add_real(sample_vip, "10.0.0.100")

        # Check that reals map was updated
        mock_reals_map.set.assert_called()
        call_args = mock_reals_map.set.call_args[0]
        assert call_args[0] == real.index
        assert call_args[1].address == real.address

    def test_add_real_triggers_ring_rebuild(
        self, real_manager, sample_vip, mock_ch_rings_map
    ):
        """Test adding backend triggers hash ring rebuild."""
        real_manager.add_real(sample_vip, "10.0.0.100")

        # Check that ring was written
        mock_ch_rings_map.write_ring.assert_called()
        call_args = mock_ch_rings_map.write_ring.call_args
        assert call_args[0][0] == sample_vip.vip_num


class TestRealManagerRemoveReal:
    """Test backend removal."""

    def test_remove_real_from_vip(self, real_manager, sample_vip):
        """Test removing backend from VIP."""
        real_manager.add_real(sample_vip, "10.0.0.100")

        result = real_manager.remove_real(sample_vip, "10.0.0.100")

        assert result is True
        assert len(sample_vip.reals) == 0

    def test_remove_nonexistent_real_returns_false(
        self, real_manager, sample_vip
    ):
        """Test removing nonexistent backend returns False."""
        result = real_manager.remove_real(sample_vip, "10.0.0.100")

        assert result is False

    def test_remove_real_decrements_ref_count(self, real_manager, sample_vip):
        """Test removing backend decrements reference count."""
        vip2 = Vip.create("10.200.1.2", 80, Protocol.TCP)
        vip2.vip_num = 1

        # Add to two VIPs (ref_count=2)
        real_manager.add_real(sample_vip, "10.0.0.100")
        real_manager.add_real(vip2, "10.0.0.100")

        assert real_manager.get_real_ref_count("10.0.0.100") == 2

        # Remove from one VIP (ref_count=1)
        real_manager.remove_real(sample_vip, "10.0.0.100")

        assert real_manager.get_real_ref_count("10.0.0.100") == 1
        assert real_manager.get_global_real_count() == 1

    def test_remove_real_deletes_when_ref_count_zero(
        self, real_manager, sample_vip, mock_reals_map
    ):
        """Test removing backend deletes when ref count reaches zero."""
        real = real_manager.add_real(sample_vip, "10.0.0.100")
        index = real.index

        real_manager.remove_real(sample_vip, "10.0.0.100")

        # Backend should be deleted
        assert real_manager.get_real_ref_count("10.0.0.100") == 0
        assert real_manager.get_global_real_count() == 0

        # Index should be freed
        mock_reals_map.free_index.assert_called_with(index)

    def test_remove_real_triggers_ring_rebuild(
        self, real_manager, sample_vip, mock_ch_rings_map
    ):
        """Test removing backend triggers hash ring rebuild."""
        real_manager.add_real(sample_vip, "10.0.0.100")
        mock_ch_rings_map.reset_mock()

        real_manager.remove_real(sample_vip, "10.0.0.100")

        # Ring should be rebuilt
        mock_ch_rings_map.write_ring.assert_called()


class TestRealManagerWeightManagement:
    """Test backend weight management."""

    def test_set_weight(self, real_manager, sample_vip):
        """Test setting backend weight."""
        real_manager.add_real(sample_vip, "10.0.0.100", weight=100)

        result = real_manager.set_weight(sample_vip, "10.0.0.100", weight=50)

        assert result is True
        real = real_manager.get_real(sample_vip, "10.0.0.100")
        assert real.weight == 50

    def test_set_weight_triggers_ring_rebuild(
        self, real_manager, sample_vip, mock_ch_rings_map
    ):
        """Test changing weight triggers hash ring rebuild."""
        real_manager.add_real(sample_vip, "10.0.0.100", weight=100)
        mock_ch_rings_map.reset_mock()

        real_manager.set_weight(sample_vip, "10.0.0.100", weight=50)

        # Ring should be rebuilt
        mock_ch_rings_map.write_ring.assert_called()

    def test_set_weight_same_value_rebuilds_ring(
        self, real_manager, sample_vip, mock_ch_rings_map
    ):
        """Test setting same weight still rebuilds ring."""
        real_manager.add_real(sample_vip, "10.0.0.100", weight=100)
        mock_ch_rings_map.reset_mock()

        real_manager.set_weight(sample_vip, "10.0.0.100", weight=100)

        # Ring should NOT be rebuilt if weight unchanged
        mock_ch_rings_map.write_ring.assert_not_called()

    def test_set_weight_nonexistent_real_returns_false(
        self, real_manager, sample_vip
    ):
        """Test setting weight for nonexistent backend returns False."""
        result = real_manager.set_weight(sample_vip, "10.0.0.100", weight=50)

        assert result is False

    def test_drain_real(self, real_manager, sample_vip):
        """Test draining backend (set weight to 0)."""
        real_manager.add_real(sample_vip, "10.0.0.100", weight=100)

        result = real_manager.drain_real(sample_vip, "10.0.0.100")

        assert result is True
        real = real_manager.get_real(sample_vip, "10.0.0.100")
        assert real.weight == 0
        assert real.is_drained

    def test_undrain_real(self, real_manager, sample_vip):
        """Test undraining backend (restore weight)."""
        real_manager.add_real(sample_vip, "10.0.0.100", weight=100)
        real_manager.drain_real(sample_vip, "10.0.0.100")

        result = real_manager.undrain_real(sample_vip, "10.0.0.100", weight=100)

        assert result is True
        real = real_manager.get_real(sample_vip, "10.0.0.100")
        assert real.weight == 100
        assert not real.is_drained


class TestRealManagerQueries:
    """Test backend query methods."""

    def test_get_real(self, real_manager, sample_vip):
        """Test getting backend from VIP."""
        real_manager.add_real(sample_vip, "10.0.0.100")

        real = real_manager.get_real(sample_vip, "10.0.0.100")

        assert real is not None
        assert real.address == IPv4Address("10.0.0.100")

    def test_get_real_not_found(self, real_manager, sample_vip):
        """Test getting nonexistent backend returns None."""
        real = real_manager.get_real(sample_vip, "10.0.0.100")

        assert real is None

    def test_real_exists(self, real_manager, sample_vip):
        """Test real_exists method."""
        real_manager.add_real(sample_vip, "10.0.0.100")

        assert real_manager.real_exists(sample_vip, "10.0.0.100")
        assert not real_manager.real_exists(sample_vip, "10.0.0.101")

    def test_get_real_count(self, real_manager, sample_vip):
        """Test get_real_count method."""
        assert real_manager.get_real_count(sample_vip) == 0

        real_manager.add_real(sample_vip, "10.0.0.100")
        assert real_manager.get_real_count(sample_vip) == 1

        real_manager.add_real(sample_vip, "10.0.0.101")
        assert real_manager.get_real_count(sample_vip) == 2

    def test_get_active_real_count(self, real_manager, sample_vip):
        """Test get_active_real_count method."""
        real_manager.add_real(sample_vip, "10.0.0.100", weight=100)
        real_manager.add_real(sample_vip, "10.0.0.101", weight=100)
        real_manager.add_real(sample_vip, "10.0.0.102", weight=0)  # drained

        assert real_manager.get_active_real_count(sample_vip) == 2

    def test_get_global_real_count(self, real_manager, sample_vip):
        """Test get_global_real_count method."""
        vip2 = Vip.create("10.200.1.2", 80, Protocol.TCP)
        vip2.vip_num = 1

        real_manager.add_real(sample_vip, "10.0.0.100")
        real_manager.add_real(sample_vip, "10.0.0.101")
        real_manager.add_real(vip2, "10.0.0.100")  # Shared backend

        # Should be 2 unique backends
        assert real_manager.get_global_real_count() == 2

    def test_get_real_ref_count(self, real_manager, sample_vip):
        """Test get_real_ref_count method."""
        vip2 = Vip.create("10.200.1.2", 80, Protocol.TCP)
        vip2.vip_num = 1

        real_manager.add_real(sample_vip, "10.0.0.100")
        assert real_manager.get_real_ref_count("10.0.0.100") == 1

        real_manager.add_real(vip2, "10.0.0.100")
        assert real_manager.get_real_ref_count("10.0.0.100") == 2

        # Nonexistent backend
        assert real_manager.get_real_ref_count("10.0.0.999") == 0


class TestRealManagerRingRebuild:
    """Test consistent hash ring rebuild."""

    def test_rebuild_ring_with_single_backend(
        self, real_manager, sample_vip, mock_ring_builder
    ):
        """Test rebuilding ring with single backend."""
        real_manager._ring_builder = mock_ring_builder
        real = real_manager.add_real(sample_vip, "10.0.0.100", weight=100)

        # Check ring builder was called
        mock_ring_builder.build.assert_called()
        endpoints = mock_ring_builder.build.call_args[0][0]
        assert len(endpoints) == 1
        assert endpoints[0].num == real.index
        assert endpoints[0].weight == 100

    def test_rebuild_ring_with_multiple_backends(
        self, real_manager, sample_vip, mock_ring_builder
    ):
        """Test rebuilding ring with multiple backends."""
        real_manager._ring_builder = mock_ring_builder
        real1 = real_manager.add_real(sample_vip, "10.0.0.100", weight=100)
        real2 = real_manager.add_real(sample_vip, "10.0.0.101", weight=50)

        # Last call should have both backends
        endpoints = mock_ring_builder.build.call_args[0][0]
        assert len(endpoints) == 2

        # Find endpoints by index
        ep_nums = {ep.num for ep in endpoints}
        assert real1.index in ep_nums
        assert real2.index in ep_nums

    def test_rebuild_ring_excludes_drained_backends(
        self, real_manager, sample_vip, mock_ring_builder
    ):
        """Test rebuilding ring excludes drained backends."""
        real_manager._ring_builder = mock_ring_builder
        real_manager.add_real(sample_vip, "10.0.0.100", weight=100)
        real_manager.add_real(sample_vip, "10.0.0.101", weight=0)  # drained

        # Should only have 1 active endpoint
        endpoints = mock_ring_builder.build.call_args[0][0]
        assert len(endpoints) == 1

    def test_rebuild_ring_all_drained_creates_empty_ring(
        self, real_manager, sample_vip, mock_ch_rings_map
    ):
        """Test rebuilding ring with all drained backends creates empty ring."""
        real_manager.add_real(sample_vip, "10.0.0.100", weight=0)
        real_manager.add_real(sample_vip, "10.0.0.101", weight=0)

        # Ring should be all zeros
        call_args = mock_ch_rings_map.write_ring.call_args
        ring = call_args[0][1]
        assert all(val == 0 for val in ring)


class TestRealManagerStateManagement:
    """Test backend state management."""

    def test_clear_all(self, real_manager, sample_vip):
        """Test clearing all backends."""
        real_manager.add_real(sample_vip, "10.0.0.100")
        real_manager.add_real(sample_vip, "10.0.0.101")

        count = real_manager.clear_all()

        assert count == 2
        assert real_manager.get_global_real_count() == 0

    def test_repr(self, real_manager, sample_vip):
        """Test __repr__ method."""
        real_manager.add_real(sample_vip, "10.0.0.100")

        repr_str = repr(real_manager)

        assert "RealManager" in repr_str
        assert "reals=1" in repr_str


class TestRealManagerThreadSafety:
    """Test thread safety of RealManager operations."""

    def test_concurrent_add_real(self, real_manager, sample_vip):
        """Test concurrent backend additions are serialized."""
        import threading

        results = []

        def add_real(addr):
            try:
                real = real_manager.add_real(sample_vip, addr, weight=100)
                results.append(("success", real.index))
            except Exception as e:
                results.append(("error", str(e)))

        # Create threads
        threads = [
            threading.Thread(target=add_real, args=(f"10.0.0.{i}",))
            for i in range(100, 110)
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
        assert real_manager.get_real_count(sample_vip) == 10

        # Check indices are unique
        indices = [r[1] for r in results if r[0] == "success"]
        assert len(set(indices)) == 10
