"""
Integration tests for BPF map operations via Python control plane.

These tests verify that the Python control plane can correctly
read/write BPF maps when Katran BPF programs are loaded.

Prerequisites:
- XDP program loaded via xdp-loader
- Maps pinned at /sys/fs/bpf/katran

Run via: ./tests/integration/run-tests.sh
"""

from ipaddress import IPv4Address
from pathlib import Path

import pytest

from katran.core.constants import Protocol, RealFlags
from katran.core.types import (
    REAL_DEFINITION_SIZE,
    VIP_KEY_SIZE,
    CtlValue,
    LbStats,
    RealDefinition,
    Vip,
    VipKey,
)


class TestMapDiscovery:
    """Tests for discovering pinned BPF maps."""

    def test_maps_are_pinned(self, pin_path: Path, pinned_map_names: list[str]) -> None:
        """Verify BPF maps are pinned after program load."""
        assert pin_path.exists(), f"Pin path {pin_path} does not exist"
        assert len(pinned_map_names) > 0, "No maps were pinned"

        # Log discovered maps
        print(f"\nDiscovered {len(pinned_map_names)} pinned maps at {pin_path}:")
        for name in sorted(pinned_map_names):
            print(f"  - {name}")

    def test_core_maps_exist(self, pinned_map_names: list[str]) -> None:
        """Check for expected Katran map names."""
        # These are the core maps we expect from balancer.bpf.o
        expected_patterns = ["vip", "real", "ch", "stat", "ctl"]

        found = []
        missing = []

        for pattern in expected_patterns:
            if any(pattern in name.lower() for name in pinned_map_names):
                found.append(pattern)
            else:
                missing.append(pattern)

        print(f"\nFound map patterns: {found}")
        if missing:
            print(f"Missing map patterns: {missing}")

        # At least some core maps should be present
        assert len(found) >= 2, f"Too few core maps found. Available: {pinned_map_names}"


class TestVipMapOperations:
    """Integration tests for VIP map operations."""

    @pytest.fixture
    def vip_map(self, pin_path: Path):
        """Create VipMap instance if vip_map exists."""
        from katran.bpf.maps.vip_map import VipMap

        vip_map = VipMap(str(pin_path))
        try:
            vip_map.open()
            yield vip_map
        except Exception as e:
            pytest.skip(f"Could not open vip_map: {e}")
        finally:
            vip_map.close()

    def test_vip_map_open(self, vip_map) -> None:
        """Can open pinned VIP map."""
        assert vip_map.is_open

    def test_vip_add_and_remove(self, vip_map, test_vip_ipv4: Vip) -> None:
        """Test VIP create and delete cycle."""
        # Add VIP
        vip_num = vip_map.add_vip(test_vip_ipv4)
        assert vip_num >= 0, "Should allocate valid vip_num"

        # Verify exists
        meta = vip_map.get_vip(test_vip_ipv4.key)
        assert meta is not None, "VIP should exist after add"
        assert meta.vip_num == vip_num

        # Remove
        removed = vip_map.remove_vip(test_vip_ipv4.key)
        assert removed, "VIP removal should succeed"

        # Verify gone
        meta_after = vip_map.get_vip(test_vip_ipv4.key)
        assert meta_after is None, "VIP should not exist after delete"

    def test_vip_serialization(self, pin_path: Path) -> None:
        """Verify VIP key serialization matches expected BPF format."""
        key = VipKey(
            address=IPv4Address("192.168.100.50"),
            port=8443,
            protocol=Protocol.TCP,
        )

        data = key.to_bytes()
        assert len(data) == VIP_KEY_SIZE

        # Verify roundtrip
        restored = VipKey.from_bytes(data)
        assert restored.address == key.address
        assert restored.port == key.port
        assert restored.protocol == key.protocol


class TestRealsMapOperations:
    """Integration tests for reals (backend) map operations."""

    @pytest.fixture
    def reals_map(self, pin_path: Path):
        """Create RealsMap instance if reals map exists."""
        from katran.bpf.maps.reals_map import RealsMap

        reals_map = RealsMap(str(pin_path))
        try:
            reals_map.open()
            yield reals_map
        except Exception as e:
            pytest.skip(f"Could not open reals map: {e}")
        finally:
            reals_map.close()

    def test_reals_map_open(self, reals_map) -> None:
        """Can open pinned reals map."""
        assert reals_map.is_open

    def test_backend_allocation(self, reals_map) -> None:
        """Test backend index allocation."""
        # Allocate indices
        idx1 = reals_map.allocate_index()
        idx2 = reals_map.allocate_index()

        # Indices should be unique and positive
        assert idx1 > 0
        assert idx2 > 0
        assert idx1 != idx2

        # Free them
        reals_map.free_index(idx1)
        reals_map.free_index(idx2)

    def test_real_serialization(self) -> None:
        """Verify RealDefinition serialization."""
        real = RealDefinition(
            address=IPv4Address("10.0.0.100"),
            flags=RealFlags(0),
        )

        data = real.to_bytes()
        assert len(data) == REAL_DEFINITION_SIZE

        # Roundtrip
        restored = RealDefinition.from_bytes(data)
        assert restored.address == real.address


class TestChRingsMapOperations:
    """Integration tests for consistent hash rings map."""

    @pytest.fixture
    def ch_map(self, pin_path: Path):
        """Create ChRingsMap instance."""
        from katran.bpf.maps.ch_rings_map import ChRingsMap

        ch_map = ChRingsMap(str(pin_path))
        try:
            ch_map.open()
            yield ch_map
        except Exception as e:
            pytest.skip(f"Could not open ch_rings map: {e}")
        finally:
            ch_map.close()

    def test_ch_rings_map_open(self, ch_map) -> None:
        """Can open pinned CH rings map."""
        assert ch_map.is_open

    def test_ring_size(self, ch_map) -> None:
        """Verify ring size is as expected."""
        # Default Katran ring size is 65537
        assert ch_map.ring_size > 0
        print(f"Ring size: {ch_map.ring_size}")


class TestStatsMapOperations:
    """Integration tests for statistics map."""

    @pytest.fixture
    def stats_map(self, pin_path: Path):
        """Create StatsMap instance."""
        from katran.bpf.maps.stats_map import StatsMap

        stats_map = StatsMap(str(pin_path))
        try:
            stats_map.open()
            yield stats_map
        except Exception as e:
            pytest.skip(f"Could not open stats map: {e}")
        finally:
            stats_map.close()

    def test_stats_map_open(self, stats_map) -> None:
        """Can open pinned stats map."""
        assert stats_map.is_open

    def test_lb_stats_serialization(self) -> None:
        """Verify LbStats serialization."""
        stats = LbStats(v1=1000, v2=50000)

        data = stats.to_bytes()
        restored = LbStats.from_bytes(data)

        assert restored.v1 == stats.v1
        assert restored.v2 == stats.v2

    def test_stats_aggregation(self) -> None:
        """Test stats aggregation logic."""
        stats_list = [
            LbStats(v1=100, v2=1000),
            LbStats(v1=200, v2=2000),
            LbStats(v1=300, v2=3000),
        ]

        aggregated = LbStats.aggregate(stats_list)
        assert aggregated.v1 == 600
        assert aggregated.v2 == 6000


class TestCtlArrayOperations:
    """Integration tests for control array map."""

    @pytest.fixture
    def ctl_array(self, pin_path: Path):
        """Create CtlArray instance."""
        from katran.bpf.maps.ctl_array import CtlArray

        ctl = CtlArray(str(pin_path))
        try:
            ctl.open()
            yield ctl
        except Exception as e:
            pytest.skip(f"Could not open ctl_array: {e}")
        finally:
            ctl.close()

    def test_ctl_array_open(self, ctl_array) -> None:
        """Can open pinned ctl_array map."""
        assert ctl_array.is_open

    def test_ctl_value_mac(self) -> None:
        """Test CtlValue MAC address handling."""
        mac_str = "aa:bb:cc:dd:ee:ff"
        value = CtlValue.from_mac(mac_str)

        assert value.as_mac() == mac_str

    def test_ctl_value_ifindex(self) -> None:
        """Test CtlValue interface index handling."""
        value = CtlValue.from_ifindex(42)
        assert value.as_ifindex() == 42


class TestMaglevIntegration:
    """Integration tests for Maglev hash ring with BPF maps."""

    def test_maglev_ring_generation(self) -> None:
        """Test Maglev ring can be generated."""
        from katran.lb.maglev import Endpoint, MaglevHashRing, hash_endpoint_address

        ring = MaglevHashRing(ring_size=1009)
        endpoints = [
            Endpoint(num=1, weight=100, hash=hash_endpoint_address("10.0.0.100")),
            Endpoint(num=2, weight=100, hash=hash_endpoint_address("10.0.0.101")),
            Endpoint(num=3, weight=100, hash=hash_endpoint_address("10.0.0.102")),
        ]

        result = ring.build(endpoints)

        assert len(result) == 1009
        assert ring.is_built

        # All positions should be filled
        assert all(v >= 0 for v in result)

        # All backends should have positions
        dist = ring.get_distribution()
        assert len(dist) == 3

    def test_maglev_minimal_disruption(self) -> None:
        """Test Maglev minimal disruption property."""
        from katran.lb.maglev import (
            Endpoint,
            MaglevHashRing,
            compute_ring_changes,
            hash_endpoint_address,
        )

        # Build initial ring
        ring1 = MaglevHashRing(ring_size=1009)
        endpoints1 = [
            Endpoint(num=i, weight=100, hash=hash_endpoint_address(f"10.0.0.{i}"))
            for i in range(1, 4)
        ]
        old_ring = ring1.build(endpoints1)

        # Add a backend
        ring2 = MaglevHashRing(ring_size=1009)
        endpoints2 = endpoints1 + [
            Endpoint(num=4, weight=100, hash=hash_endpoint_address("10.0.0.4"))
        ]
        new_ring = ring2.build(endpoints2)

        # Check disruption
        changed, pct = compute_ring_changes(old_ring, new_ring)

        # Adding 1 of 4 backends should change ~25%
        assert pct < 40, f"Too much disruption: {pct}%"
        assert pct > 10, f"Too little change: {pct}%"
