"""
Integration tests for VipManager and RealManager (Phase 2).

These tests verify that VIP and backend management works correctly
with actual BPF maps when Katran BPF programs are loaded.

Prerequisites:
- XDP program loaded via xdp-loader
- Maps pinned at /sys/fs/bpf/katran
- Root privileges / BPF capabilities

Run via: ./tests/integration/run-tests.sh
"""

import sys
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

import pytest

from katran.bpf.maps.ch_rings_map import ChRingsMap
from katran.bpf.maps.reals_map import RealsMap
from katran.bpf.maps.vip_map import VipMap
from katran.core.constants import RING_SIZE, Protocol, VipFlags
from katran.core.types import Real, Vip
from katran.lb.maglev import MaglevHashRing
from katran.lb.real_manager import RealManager
from katran.lb.vip_manager import VipManager

# =============================================================================
# Test Utilities for Detailed Error Reporting
# =============================================================================


def assert_vip_allocated(vip: Vip, description: str = "VIP"):
    """Assert VIP is properly allocated with detailed error message."""
    if not vip.is_allocated:
        pytest.fail(
            f"\n{description} allocation failed:\n"
            f"  VIP: {vip.key}\n"
            f"  Expected: vip_num >= 0 (allocated)\n"
            f"  Actual: vip_num = {vip.vip_num} (not allocated)\n"
        )


def assert_vip_num_valid(vip_num: int, description: str = "vip_num"):
    """Assert vip_num is valid (>= 0)."""
    if vip_num < 0:
        pytest.fail(f"\n{description} is invalid:\n  Expected: >= 0\n  Actual: {vip_num}\n")


def assert_real_allocated(real: Real, description: str = "Backend"):
    """Assert backend is properly allocated with detailed error message."""
    if not real.is_allocated:
        pytest.fail(
            f"\n{description} allocation failed:\n"
            f"  Address: {real.address}\n"
            f"  Expected: index >= 1 (allocated, 0 is reserved)\n"
            f"  Actual: index = {real.index} (not allocated)\n"
        )


def assert_ring_distribution(
    ring: list[int],
    expected_indices: list[int],
    tolerance: float = 0.1,
    description: str = "Ring distribution",
):
    """
    Assert hash ring contains expected backend indices with detailed stats.

    Args:
        ring: The hash ring (list of backend indices)
        expected_indices: Backend indices that should be in ring
        tolerance: Allowed deviation from uniform distribution (default: 10%)
        description: Description for error messages
    """
    ring_size = len(ring)

    # Count occurrences
    counts = {}
    for idx in expected_indices:
        counts[idx] = ring.count(idx)

    # Check all expected indices are present
    missing = [idx for idx in expected_indices if counts[idx] == 0]
    if missing:
        pytest.fail(
            f"\n{description} - Missing backend indices:\n"
            f"  Expected indices: {expected_indices}\n"
            f"  Missing: {missing}\n"
            f"  Ring distribution: {counts}\n"
        )

    # Check distribution is reasonable
    sum(counts.values())
    expected_per_backend = ring_size // len(expected_indices)
    max_deviation = expected_per_backend * tolerance

    for idx, count in counts.items():
        deviation = abs(count - expected_per_backend)
        if deviation > max_deviation:
            pytest.fail(
                f"\n{description} - Uneven distribution:\n"
                f"  Backend {idx}:\n"
                f"    Expected: ~{expected_per_backend} positions ({100 / len(expected_indices):.1f}%)\n"
                f"    Actual: {count} positions ({100 * count / ring_size:.1f}%)\n"
                f"    Deviation: {deviation} (max allowed: {max_deviation:.0f})\n"
                f"  Full distribution: {counts}\n"
            )


def assert_weighted_distribution(
    ring: list[int],
    backend_weights: dict[int, int],
    tolerance: float = 0.2,
    description: str = "Weighted ring distribution",
):
    """
    Assert hash ring has correct weighted distribution.

    Args:
        ring: The hash ring
        backend_weights: Dict mapping backend index to weight
        tolerance: Allowed deviation from expected ratio (default: 20%)
        description: Description for error messages
    """
    ring_size = len(ring)
    total_weight = sum(backend_weights.values())

    # Count actual distribution
    counts = {idx: ring.count(idx) for idx in backend_weights}

    # Calculate expected vs actual
    results = []
    for idx, weight in backend_weights.items():
        expected_count = (weight * ring_size) // total_weight
        actual_count = counts[idx]
        expected_pct = (weight / total_weight) * 100
        actual_pct = (actual_count / ring_size) * 100
        deviation = abs(actual_pct - expected_pct)

        results.append(
            {
                "index": idx,
                "weight": weight,
                "expected_count": expected_count,
                "actual_count": actual_count,
                "expected_pct": expected_pct,
                "actual_pct": actual_pct,
                "deviation": deviation,
            }
        )

        # Check if within tolerance
        max_deviation = expected_pct * tolerance
        if deviation > max_deviation:
            error_lines = [f"\n{description} - Incorrect weight distribution:"]
            for r in results:
                error_lines.append(
                    f"  Backend {r['index']} (weight={r['weight']}):\n"
                    f"    Expected: {r['expected_count']} positions ({r['expected_pct']:.1f}%)\n"
                    f"    Actual:   {r['actual_count']} positions ({r['actual_pct']:.1f}%)\n"
                    f"    Deviation: {r['deviation']:.1f}% (max: {max_deviation:.1f}%)"
                )
            pytest.fail("\n".join(error_lines))


def print_test_info(test_name: str, **kwargs):
    """Print detailed test information for debugging."""
    print(f"\n{'=' * 70}")
    print(f"TEST: {test_name}")
    print(f"{'=' * 70}")
    for key, value in kwargs.items():
        print(f"  {key}: {value}")
    print(f"{'=' * 70}\n")
    sys.stdout.flush()


# =============================================================================
# Manager Fixtures
# =============================================================================


@pytest.fixture
def vip_map(pin_path: Path):
    """VipMap connected to real BPF map."""
    vip_map = VipMap(str(pin_path))
    try:
        vip_map.open()
        yield vip_map
    except Exception as e:
        pytest.skip(f"Could not open vip_map: {e}")
    finally:
        vip_map.close()


@pytest.fixture
def reals_map(pin_path: Path):
    """RealsMap connected to real BPF map."""
    reals_map = RealsMap(str(pin_path))
    try:
        reals_map.open()
        yield reals_map
    except Exception as e:
        pytest.skip(f"Could not open reals map: {e}")
    finally:
        reals_map.close()


@pytest.fixture
def ch_rings_map(pin_path: Path):
    """ChRingsMap connected to real BPF map."""
    ch_rings_map = ChRingsMap(str(pin_path))
    try:
        ch_rings_map.open()
        yield ch_rings_map
    except Exception as e:
        pytest.skip(f"Could not open ch_rings map: {e}")
    finally:
        ch_rings_map.close()


@pytest.fixture
def vip_manager(vip_map, ch_rings_map):
    """VipManager with real BPF maps."""

    # Clean up test VIPs from BPF maps before creating manager
    # Scan BPF map directly since manager starts with empty state
    all_vips = vip_map.get_all_vips()
    for key, _meta in all_vips.items():
        addr_str = str(key.address)
        if "10.200.1." in addr_str or "2001:db8:" in addr_str:
            vip_map.remove_vip(key)

    mgr = VipManager(vip_map, ch_rings_map, max_vips=512)

    yield mgr

    # Clean up after tests - use manager's list since it tracked adds/removes
    for vip in mgr.list_vips():
        addr_str = str(vip.key.address)
        if "10.200.1." in addr_str or "2001:db8:" in addr_str:
            try:
                mgr.remove_vip(key=vip.key)
            except Exception as e:
                print(f"Warning: Failed to cleanup VIP {vip.key}: {e}")


@pytest.fixture
def real_manager(reals_map, ch_rings_map):
    """RealManager with real BPF maps."""
    ring_builder = MaglevHashRing(ring_size=RING_SIZE)
    mgr = RealManager(reals_map, ch_rings_map, ring_builder=ring_builder, max_reals=4096)

    yield mgr

    # Clean up is handled by VIP cleanup (reference counting)


# =============================================================================
# VipManager Integration Tests
# =============================================================================


class TestVipManagerIntegration:
    """Integration tests for VipManager with real BPF maps."""

    def test_add_ipv4_vip(self, vip_manager):
        """Test adding IPv4 VIP updates BPF map."""
        test_addr = "10.200.1.100"
        test_port = 8080

        print_test_info("test_add_ipv4_vip", address=test_addr, port=test_port, protocol="TCP")

        vip = vip_manager.add_vip(test_addr, test_port, Protocol.TCP)

        # Detailed assertions
        assert_vip_num_valid(vip.vip_num, "VIP number for 10.200.1.100:8080")
        assert_vip_allocated(vip, "VIP 10.200.1.100:8080")

        # Verify address
        if vip.key.address != IPv4Address(test_addr):
            pytest.fail(
                f"\nVIP address mismatch:\n  Expected: {test_addr}\n  Actual: {vip.key.address}\n"
            )

        # Verify port
        if vip.key.port != test_port:
            pytest.fail(
                f"\nVIP port mismatch:\n  Expected: {test_port}\n  Actual: {vip.key.port}\n"
            )

        # Verify it exists in manager
        if not vip_manager.vip_exists(vip.key):
            pytest.fail(
                f"\nVIP not found in manager after add:\n"
                f"  VIP: {vip.key}\n"
                f"  Manager VIP count: {vip_manager.get_vip_count()}\n"
            )

        print(
            f"✓ VIP added successfully: vip_num={vip.vip_num}, address={vip.key.address}:{vip.key.port}"
        )
        sys.stdout.flush()

    def test_add_ipv6_vip(self, vip_manager):
        """Test adding IPv6 VIP updates BPF map."""
        vip = vip_manager.add_vip("2001:db8::100", 443, "tcp", VipFlags.NO_SRC_PORT)

        assert vip.is_allocated
        assert vip.key.address == IPv6Address("2001:db8::100")
        assert vip.flags == VipFlags.NO_SRC_PORT

    def test_add_multiple_vips(self, vip_manager):
        """Test adding multiple VIPs allocates different vip_nums."""
        vip1 = vip_manager.add_vip("10.200.1.101", 80, Protocol.TCP)
        vip2 = vip_manager.add_vip("10.200.1.102", 80, Protocol.TCP)
        vip3 = vip_manager.add_vip("10.200.1.103", 443, Protocol.TCP)

        # All should have unique vip_nums
        vip_nums = {vip1.vip_num, vip2.vip_num, vip3.vip_num}
        assert len(vip_nums) == 3

        # All should be listed
        vips = vip_manager.list_vips()
        keys = {v.key for v in vips}
        assert vip1.key in keys
        assert vip2.key in keys
        assert vip3.key in keys

    def test_remove_vip(self, vip_manager):
        """Test removing VIP updates BPF map."""
        vip = vip_manager.add_vip("10.200.1.104", 80, Protocol.TCP)
        vip_num = vip.vip_num

        # Remove
        result = vip_manager.remove_vip(key=vip.key)
        assert result is True

        # Should not exist
        assert not vip_manager.vip_exists(vip.key)
        assert vip_manager.get_vip(key=vip.key) is None

        # vip_num should be reusable
        vip2 = vip_manager.add_vip("10.200.1.105", 80, Protocol.TCP)
        assert vip2.vip_num == vip_num  # Recycled

    def test_modify_vip_flags(self, vip_manager):
        """Test modifying VIP flags updates BPF map."""
        vip = vip_manager.add_vip("10.200.1.106", 80, Protocol.TCP)

        # Modify flags
        result = vip_manager.modify_flags(vip.key, VipFlags.NO_SRC_PORT | VipFlags.NO_LRU)
        assert result is True

        # Verify updated
        vip_retrieved = vip_manager.get_vip(key=vip.key)
        assert vip_retrieved.flags == (VipFlags.NO_SRC_PORT | VipFlags.NO_LRU)

    def test_get_vip_by_num(self, vip_manager):
        """Test reverse lookup by vip_num."""
        vip = vip_manager.add_vip("10.200.1.107", 80, Protocol.TCP)

        found = vip_manager.get_vip_by_num(vip.vip_num)
        assert found is not None
        assert found.key == vip.key

    def test_vip_with_multiple_ports(self, vip_manager):
        """Test same IP with different ports creates separate VIPs."""
        vip1 = vip_manager.add_vip("10.200.1.108", 80, Protocol.TCP)
        vip2 = vip_manager.add_vip("10.200.1.108", 443, Protocol.TCP)
        vip3 = vip_manager.add_vip("10.200.1.108", 8080, Protocol.TCP)

        assert vip1.vip_num != vip2.vip_num != vip3.vip_num
        assert vip_manager.get_vip_count() >= 3


# =============================================================================
# RealManager Integration Tests
# =============================================================================


class TestRealManagerIntegration:
    """Integration tests for RealManager with real BPF maps."""

    @pytest.fixture
    def test_vip(self, vip_manager):
        """Create a test VIP for backend tests."""
        vip = vip_manager.add_vip("10.200.1.200", 80, Protocol.TCP)
        return vip

    def test_add_real_to_vip(self, real_manager, test_vip):
        """Test adding backend to VIP updates reals and ch_rings maps."""
        backend_addr = "10.0.0.100"
        backend_weight = 100

        print_test_info(
            "test_add_real_to_vip",
            vip=str(test_vip.key),
            backend=backend_addr,
            weight=backend_weight,
        )

        real = real_manager.add_real(test_vip, backend_addr, weight=backend_weight)

        # Verify allocation
        assert_real_allocated(real, f"Backend {backend_addr}")

        # Verify index (0 is reserved)
        if real.index < 1:
            pytest.fail(
                f"\nBackend index is reserved value:\n"
                f"  Backend: {backend_addr}\n"
                f"  Expected: index >= 1 (0 is reserved)\n"
                f"  Actual: index = {real.index}\n"
            )

        # Verify weight
        if real.weight != backend_weight:
            pytest.fail(
                f"\nBackend weight mismatch:\n"
                f"  Expected: {backend_weight}\n"
                f"  Actual: {real.weight}\n"
            )

        # Verify VIP's backend list
        if len(test_vip.reals) != 1:
            pytest.fail(
                f"\nVIP backend list incorrect:\n"
                f"  Expected: 1 backend\n"
                f"  Actual: {len(test_vip.reals)} backends\n"
                f"  Backends: {[str(r.address) for r in test_vip.reals]}\n"
            )

        # Verify backend is in list
        if test_vip.reals[0].address != IPv4Address(backend_addr):
            pytest.fail(
                f"\nBackend address mismatch in VIP list:\n"
                f"  Expected: {backend_addr}\n"
                f"  Actual: {test_vip.reals[0].address}\n"
            )

        print(f"✓ Backend added: index={real.index}, address={real.address}, weight={real.weight}")
        sys.stdout.flush()

    def test_add_multiple_reals(self, real_manager, test_vip):
        """Test adding multiple backends allocates unique indices."""
        real1 = real_manager.add_real(test_vip, "10.0.0.100", weight=100)
        real2 = real_manager.add_real(test_vip, "10.0.0.101", weight=100)
        real3 = real_manager.add_real(test_vip, "10.0.0.102", weight=50)

        # All should have unique indices
        indices = {real1.index, real2.index, real3.index}
        assert len(indices) == 3

        # VIP should have all backends
        assert len(test_vip.reals) == 3

    def test_remove_real_from_vip(self, real_manager, test_vip):
        """Test removing backend from VIP."""
        real_manager.add_real(test_vip, "10.0.0.100", weight=100)

        # Remove
        result = real_manager.remove_real(test_vip, "10.0.0.100")
        assert result is True

        # Should not be in VIP's list
        assert len(test_vip.reals) == 0

        # Reference count should be 0
        assert real_manager.get_real_ref_count("10.0.0.100") == 0

    def test_real_reference_counting(self, real_manager, vip_manager):
        """Test backend shared across multiple VIPs (reference counting)."""
        vip1_addr = "10.200.1.201"
        vip2_addr = "10.200.1.202"
        shared_backend = "10.0.0.100"

        print_test_info(
            "test_real_reference_counting",
            vip1=f"{vip1_addr}:80",
            vip2=f"{vip2_addr}:80",
            shared_backend=shared_backend,
            test="Backend sharing and reference counting",
        )

        vip1 = vip_manager.add_vip(vip1_addr, 80, Protocol.TCP)
        vip2 = vip_manager.add_vip(vip2_addr, 80, Protocol.TCP)

        print(f"  VIP 1: {vip1.key} (vip_num={vip1.vip_num})")
        print(f"  VIP 2: {vip2.key} (vip_num={vip2.vip_num})")

        # Add same backend to both VIPs
        print(f"\n  Adding {shared_backend} to VIP 1...")
        real1 = real_manager.add_real(vip1, shared_backend, weight=100)
        ref_count_1 = real_manager.get_real_ref_count(shared_backend)
        print(f"    Allocated index: {real1.index}, ref_count: {ref_count_1}")

        print(f"  Adding {shared_backend} to VIP 2...")
        real2 = real_manager.add_real(vip2, shared_backend, weight=100)
        ref_count_2 = real_manager.get_real_ref_count(shared_backend)
        print(f"    Reused index: {real2.index}, ref_count: {ref_count_2}")

        # Verify same index (shared)
        if real1.index != real2.index:
            pytest.fail(
                f"\nBackend not shared across VIPs:\n"
                f"  Backend: {shared_backend}\n"
                f"  VIP 1 index: {real1.index}\n"
                f"  VIP 2 index: {real2.index}\n"
                f"  Expected: Same index (shared backend)\n"
            )

        # Verify reference count is 2
        if ref_count_2 != 2:
            pytest.fail(
                f"\nIncorrect reference count after adding to 2 VIPs:\n"
                f"  Backend: {shared_backend}\n"
                f"  Expected ref_count: 2\n"
                f"  Actual ref_count: {ref_count_2}\n"
            )

        print(f"  ✓ Backend shared: index={real1.index}, ref_count=2")

        # Remove from one VIP
        print(f"\n  Removing {shared_backend} from VIP 1...")
        real_manager.remove_real(vip1, shared_backend)
        ref_count_after_1 = real_manager.get_real_ref_count(shared_backend)
        print(f"    ref_count after removal: {ref_count_after_1}")

        # Reference count should be 1
        if ref_count_after_1 != 1:
            pytest.fail(
                f"\nIncorrect reference count after removing from 1 VIP:\n"
                f"  Backend: {shared_backend}\n"
                f"  Expected ref_count: 1 (still used by VIP 2)\n"
                f"  Actual ref_count: {ref_count_after_1}\n"
            )

        # Remove from second VIP
        print(f"  Removing {shared_backend} from VIP 2...")
        real_manager.remove_real(vip2, shared_backend)
        ref_count_final = real_manager.get_real_ref_count(shared_backend)
        print(f"    ref_count after removal: {ref_count_final}")

        # Reference count should be 0 (deleted)
        if ref_count_final != 0:
            pytest.fail(
                f"\nBackend not deleted when ref_count reached 0:\n"
                f"  Backend: {shared_backend}\n"
                f"  Expected ref_count: 0 (deleted)\n"
                f"  Actual ref_count: {ref_count_final}\n"
            )

        print("  ✓ Backend deleted when ref_count=0")
        print("\n✓ Reference counting verified: 2 → 1 → 0")
        sys.stdout.flush()

    def test_set_backend_weight(self, real_manager, test_vip):
        """Test changing backend weight triggers ring rebuild."""
        real_manager.add_real(test_vip, "10.0.0.100", weight=100)

        # Change weight
        result = real_manager.set_weight(test_vip, "10.0.0.100", weight=50)
        assert result is True

        # Verify updated
        real = real_manager.get_real(test_vip, "10.0.0.100")
        assert real.weight == 50

    def test_drain_backend(self, real_manager, test_vip):
        """Test draining backend (weight=0)."""
        real_manager.add_real(test_vip, "10.0.0.100", weight=100)

        # Drain
        result = real_manager.drain_real(test_vip, "10.0.0.100")
        assert result is True

        # Verify drained
        real = real_manager.get_real(test_vip, "10.0.0.100")
        assert real.is_drained
        assert real.weight == 0

        # Active count should be 0
        assert real_manager.get_active_real_count(test_vip) == 0

    def test_undrain_backend(self, real_manager, test_vip):
        """Test undraining backend."""
        real_manager.add_real(test_vip, "10.0.0.100", weight=100)
        real_manager.drain_real(test_vip, "10.0.0.100")

        # Undrain
        result = real_manager.undrain_real(test_vip, "10.0.0.100", weight=100)
        assert result is True

        # Verify undrained
        real = real_manager.get_real(test_vip, "10.0.0.100")
        assert not real.is_drained
        assert real.weight == 100

        # Active count should be 1
        assert real_manager.get_active_real_count(test_vip) == 1

    def test_consistent_hash_ring_created(self, real_manager, test_vip, ch_rings_map):
        """Test that adding backends creates consistent hash ring."""
        backend1 = "10.0.0.100"
        backend2 = "10.0.0.101"

        print_test_info(
            "test_consistent_hash_ring_created",
            vip=str(test_vip.key),
            backends=[backend1, backend2],
            weights=[100, 100],
            expected_distribution="50/50 (equal weights)",
        )

        real1 = real_manager.add_real(test_vip, backend1, weight=100)
        real2 = real_manager.add_real(test_vip, backend2, weight=100)

        print(f"  Backend 1: index={real1.index}, address={real1.address}")
        print(f"  Backend 2: index={real2.index}, address={real2.address}")

        # Read ring from BPF map
        ring = ch_rings_map.read_ring(test_vip.vip_num)

        # Verify ring size
        if len(ring) != RING_SIZE:
            pytest.fail(f"\nRing size mismatch:\n  Expected: {RING_SIZE}\n  Actual: {len(ring)}\n")

        # Verify backends are in ring
        if real1.index not in ring:
            pytest.fail(
                f"\nBackend 1 not found in ring:\n"
                f"  Backend: {backend1} (index={real1.index})\n"
                f"  Ring unique values: {set(ring)}\n"
            )

        if real2.index not in ring:
            pytest.fail(
                f"\nBackend 2 not found in ring:\n"
                f"  Backend: {backend2} (index={real2.index})\n"
                f"  Ring unique values: {set(ring)}\n"
            )

        # Count distribution
        count_real1 = ring.count(real1.index)
        count_real2 = ring.count(real2.index)
        total = count_real1 + count_real2

        print("  Ring distribution:")
        print(
            f"    Backend {real1.index}: {count_real1} positions ({100 * count_real1 / RING_SIZE:.1f}%)"
        )
        print(
            f"    Backend {real2.index}: {count_real2} positions ({100 * count_real2 / RING_SIZE:.1f}%)"
        )
        print(f"    Total: {total} positions")

        # Verify all positions filled
        if total != RING_SIZE:
            unfilled = RING_SIZE - total
            other_values = [x for x in ring if x not in [real1.index, real2.index]]
            pytest.fail(
                f"\nRing not fully filled:\n"
                f"  Expected: {RING_SIZE} positions filled\n"
                f"  Actual: {total} positions filled\n"
                f"  Unfilled: {unfilled}\n"
                f"  Unexpected values in ring: {set(other_values)}\n"
            )

        # Use helper for distribution check
        assert_ring_distribution(
            ring,
            [real1.index, real2.index],
            tolerance=0.1,
            description=f"Ring for VIP {test_vip.key} with equal weights",
        )

        print("✓ Ring distribution verified: ~50/50 split")
        sys.stdout.flush()

    def test_weighted_hash_ring(self, real_manager, test_vip, ch_rings_map):
        """Test that weighted backends get proportional ring positions."""
        backend1 = "10.0.0.100"
        backend2 = "10.0.0.101"
        weight1 = 100
        weight2 = 50

        print_test_info(
            "test_weighted_hash_ring",
            vip=str(test_vip.key),
            backends=[backend1, backend2],
            weights=[weight1, weight2],
            expected_ratio="2:1 (weight 100:50)",
        )

        real1 = real_manager.add_real(test_vip, backend1, weight=weight1)
        real2 = real_manager.add_real(test_vip, backend2, weight=weight2)

        print(f"  Backend 1: index={real1.index}, weight={weight1}")
        print(f"  Backend 2: index={real2.index}, weight={weight2}")

        # Read ring
        ring = ch_rings_map.read_ring(test_vip.vip_num)

        count_real1 = ring.count(real1.index)
        count_real2 = ring.count(real2.index)

        pct_real1 = (count_real1 / RING_SIZE) * 100
        pct_real2 = (count_real2 / RING_SIZE) * 100

        print("  Ring distribution:")
        print(
            f"    Backend {real1.index} (weight={weight1}): {count_real1} positions ({pct_real1:.1f}%)"
        )
        print(
            f"    Backend {real2.index} (weight={weight2}): {count_real2} positions ({pct_real2:.1f}%)"
        )

        # Check ratio
        if count_real2 == 0:
            pytest.fail(
                f"\nBackend 2 has zero positions in ring:\n"
                f"  Backend 1: {count_real1} positions\n"
                f"  Backend 2: {count_real2} positions\n"
                f"  This indicates ring build failure\n"
            )

        ratio = count_real1 / count_real2
        expected_ratio = weight1 / weight2

        print(f"  Actual ratio: {ratio:.2f} (backend1/backend2)")
        print(f"  Expected ratio: {expected_ratio:.2f}")

        # Use helper for weighted distribution check
        assert_weighted_distribution(
            ring,
            {real1.index: weight1, real2.index: weight2},
            tolerance=0.2,
            description=f"Weighted ring for VIP {test_vip.key}",
        )

        print(
            f"✓ Weighted distribution verified: {ratio:.2f}:1 ratio (expected {expected_ratio:.2f}:1)"
        )
        sys.stdout.flush()


# =============================================================================
# Combined Manager Tests
# =============================================================================


class TestVipRealManagersCombined:
    """Tests for VipManager and RealManager working together."""

    def test_full_vip_lifecycle(self, vip_manager, real_manager):
        """Test complete VIP lifecycle: add VIP, add backends, remove all."""
        # Create VIP
        vip = vip_manager.add_vip("10.200.1.210", 80, Protocol.TCP)
        assert vip.is_allocated

        # Add backends
        real_manager.add_real(vip, "10.0.0.100", weight=100)
        real_manager.add_real(vip, "10.0.0.101", weight=100)
        real_manager.add_real(vip, "10.0.0.102", weight=100)

        assert len(vip.reals) == 3

        # Remove backends
        real_manager.remove_real(vip, "10.0.0.100")
        real_manager.remove_real(vip, "10.0.0.101")
        real_manager.remove_real(vip, "10.0.0.102")

        assert len(vip.reals) == 0

        # Remove VIP
        vip_manager.remove_vip(key=vip.key)
        assert not vip_manager.vip_exists(vip.key)

    def test_multiple_vips_shared_backends(self, vip_manager, real_manager):
        """Test multiple VIPs sharing backends."""
        # Create VIPs
        vip1 = vip_manager.add_vip("10.200.1.211", 80, Protocol.TCP)
        vip2 = vip_manager.add_vip("10.200.1.212", 80, Protocol.TCP)

        # Add shared backends
        real1_vip1 = real_manager.add_real(vip1, "10.0.0.100", weight=100)
        real_manager.add_real(vip1, "10.0.0.101", weight=100)

        real1_vip2 = real_manager.add_real(vip2, "10.0.0.100", weight=100)  # Shared
        real_manager.add_real(vip2, "10.0.0.102", weight=100)

        # Verify sharing
        assert real1_vip1.index == real1_vip2.index  # Same backend
        assert real_manager.get_real_ref_count("10.0.0.100") == 2

        # Each VIP should have its backends
        assert len(vip1.reals) == 2
        assert len(vip2.reals) == 2

        # Global real count should be 3 unique backends
        assert real_manager.get_global_real_count() == 3

    def test_graceful_backend_draining(self, vip_manager, real_manager, ch_rings_map):
        """Test graceful backend draining workflow."""
        # Setup VIP with 3 backends
        vip = vip_manager.add_vip("10.200.1.213", 80, Protocol.TCP)
        real_manager.add_real(vip, "10.0.0.100", weight=100)
        real_manager.add_real(vip, "10.0.0.101", weight=100)
        real_manager.add_real(vip, "10.0.0.102", weight=100)

        # Drain one backend
        real_manager.drain_real(vip, "10.0.0.100")

        # Check active count
        assert real_manager.get_active_real_count(vip) == 2

        # Ring should only have 2 backends
        ring = ch_rings_map.read_ring(vip.vip_num)
        real1 = real_manager.get_real(vip, "10.0.0.100")
        real2 = real_manager.get_real(vip, "10.0.0.101")
        real3 = real_manager.get_real(vip, "10.0.0.102")

        # Drained backend should not be in ring
        assert real1.index not in ring
        assert real2.index in ring
        assert real3.index in ring

        # After drain period, remove backend
        real_manager.remove_real(vip, "10.0.0.100")
        assert len(vip.reals) == 2


# =============================================================================
# Error Handling Tests
# =============================================================================


class TestErrorHandling:
    """Test error handling in managers."""

    def test_duplicate_vip_raises_error(self, vip_manager):
        """Test adding duplicate VIP raises VipExistsError."""
        from katran.core.exceptions import VipExistsError

        test_addr = "10.200.1.220"
        test_port = 80

        print_test_info(
            "test_duplicate_vip_raises_error",
            address=test_addr,
            port=test_port,
            expected="VipExistsError on duplicate add",
        )

        # Add first VIP
        print(f"  Adding VIP {test_addr}:{test_port} (first time)...")
        vip1 = vip_manager.add_vip(test_addr, test_port, Protocol.TCP)
        print(f"    ✓ Added: vip_num={vip1.vip_num}")

        # Try to add duplicate
        print(f"  Adding VIP {test_addr}:{test_port} (duplicate, should fail)...")
        try:
            vip_manager.add_vip(test_addr, test_port, Protocol.TCP)
            pytest.fail(
                f"\nDuplicate VIP did not raise error:\n"
                f"  VIP: {test_addr}:{test_port}\n"
                f"  Expected: VipExistsError\n"
                f"  Actual: No exception raised\n"
            )
        except VipExistsError as e:
            print(f"    ✓ VipExistsError raised as expected: {e}")
            sys.stdout.flush()

    def test_duplicate_real_raises_error(self, vip_manager, real_manager):
        """Test adding duplicate backend to same VIP raises error."""
        from katran.core.exceptions import RealExistsError

        vip = vip_manager.add_vip("10.200.1.221", 80, Protocol.TCP)
        real_manager.add_real(vip, "10.0.0.100")

        with pytest.raises(RealExistsError):
            real_manager.add_real(vip, "10.0.0.100")

    def test_remove_nonexistent_vip_returns_false(self, vip_manager):
        """Test removing nonexistent VIP returns False."""
        from katran.core.types import VipKey

        key = VipKey(IPv4Address("10.200.1.250"), 80, Protocol.TCP)
        result = vip_manager.remove_vip(key=key)

        assert result is False

    def test_remove_nonexistent_real_returns_false(self, vip_manager, real_manager):
        """Test removing nonexistent backend returns False."""
        vip = vip_manager.add_vip("10.200.1.222", 80, Protocol.TCP)

        result = real_manager.remove_real(vip, "10.0.0.250")

        assert result is False
