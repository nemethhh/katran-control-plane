"""
Unit tests for Maglev consistent hashing implementation.

Tests verify:
- Ring size prime validation
- MurmurHash3 correctness
- Uniform distribution across backends
- Weighted distribution
- Minimal disruption when adding/removing backends
- Deterministic ring generation
"""


import pytest

from katran.core.constants import RING_SIZE
from katran.lb.maglev import (
    Endpoint,
    MaglevHashRing,
    _is_prime,
    compute_ring_changes,
    compute_ring_updates,
    hash_endpoint_address,
    murmur_hash3_x64_64,
)


class TestPrimeValidation:
    """Tests for prime number validation."""

    def test_ring_size_must_be_prime(self) -> None:
        """Non-prime ring size raises ValueError."""
        with pytest.raises(ValueError, match="must be prime"):
            MaglevHashRing(ring_size=100)

    def test_valid_prime_ring_sizes(self) -> None:
        """Valid prime ring sizes are accepted."""
        # Small primes for testing
        for size in [7, 11, 13, 17, 19, 23, 101, 1009]:
            ring = MaglevHashRing(ring_size=size)
            assert ring.ring_size == size

    def test_default_ring_size_is_prime(self) -> None:
        """Default ring size (65537) is prime."""
        assert _is_prime(RING_SIZE)
        ring = MaglevHashRing()  # Uses default
        assert ring.ring_size == RING_SIZE

    def test_is_prime_function(self) -> None:
        """_is_prime correctly identifies primes."""
        primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 65537]
        non_primes = [0, 1, 4, 6, 8, 9, 10, 12, 15, 100, 65536]

        for p in primes:
            assert _is_prime(p), f"{p} should be prime"

        for np in non_primes:
            assert not _is_prime(np), f"{np} should not be prime"


class TestMurmurHash3:
    """Tests for MurmurHash3 implementation."""

    def test_hash_is_deterministic(self) -> None:
        """Same inputs always produce same hash."""
        for _ in range(100):
            h1 = murmur_hash3_x64_64(12345, 67890, 42)
            h2 = murmur_hash3_x64_64(12345, 67890, 42)
            assert h1 == h2

    def test_different_inputs_different_hashes(self) -> None:
        """Different inputs produce different hashes."""
        h1 = murmur_hash3_x64_64(1, 2, 0)
        h2 = murmur_hash3_x64_64(1, 3, 0)
        h3 = murmur_hash3_x64_64(2, 2, 0)
        h4 = murmur_hash3_x64_64(1, 2, 1)

        assert len({h1, h2, h3, h4}) == 4

    def test_hash_distribution(self) -> None:
        """Hash values are well distributed."""
        hashes = []
        for i in range(1000):
            h = murmur_hash3_x64_64(i, i * 2, 0)
            hashes.append(h % 1000)

        # Check that we see a reasonable spread of values
        unique = len(set(hashes))
        assert unique > 500, f"Only {unique} unique values in 1000 hashes"


class TestMaglevRingBuild:
    """Tests for ring building."""

    def test_empty_endpoints(self) -> None:
        """Empty endpoints list produces all-negative ring."""
        ring = MaglevHashRing(ring_size=101)
        result = ring.build([])

        assert len(result) == 101
        assert all(v == -1 for v in result)

    def test_single_endpoint(self) -> None:
        """Single endpoint fills entire ring."""
        ring = MaglevHashRing(ring_size=101)
        endpoint = Endpoint(num=42, weight=100, hash=12345)
        result = ring.build([endpoint])

        assert len(result) == 101
        assert all(v == 42 for v in result)

    def test_ring_is_built_flag(self) -> None:
        """is_built reflects ring state."""
        ring = MaglevHashRing(ring_size=101)
        assert not ring.is_built

        ring.build([Endpoint(num=1, weight=1, hash=1)])
        assert ring.is_built

    def test_ring_completely_filled(self) -> None:
        """Ring has no empty slots after build."""
        ring = MaglevHashRing(ring_size=101)
        endpoints = [
            Endpoint(num=1, weight=1, hash=111),
            Endpoint(num=2, weight=1, hash=222),
            Endpoint(num=3, weight=1, hash=333),
        ]
        result = ring.build(endpoints)

        assert len(result) == 101
        assert all(v >= 0 for v in result)
        assert all(v in [1, 2, 3] for v in result)

    def test_deterministic_build(self) -> None:
        """Same inputs always produce same ring."""
        endpoints = [
            Endpoint(num=1, weight=100, hash=12345),
            Endpoint(num=2, weight=100, hash=67890),
            Endpoint(num=3, weight=100, hash=11111),
        ]

        ring1 = MaglevHashRing(ring_size=1009)
        ring2 = MaglevHashRing(ring_size=1009)

        result1 = ring1.build(endpoints)
        result2 = ring2.build(endpoints)

        assert result1 == result2


class TestUniformDistribution:
    """Tests for distribution uniformity."""

    def test_equal_weight_distribution(self) -> None:
        """Equal weights produce roughly equal distribution."""
        ring = MaglevHashRing(ring_size=10009)  # Larger ring for better stats
        endpoints = [
            Endpoint(num=i, weight=100, hash=hash_endpoint_address(f"10.0.0.{i}")) for i in range(5)
        ]
        ring.build(endpoints)

        dist = ring.get_distribution()

        # With equal weights, each should have ~20% of ring
        expected = 10009 / 5
        for num, count in dist.items():
            deviation = abs(count - expected) / expected
            assert deviation < 0.05, f"Backend {num} has {count}, expected ~{expected}"

    def test_weighted_distribution(self) -> None:
        """MaglevV2 provides proportional weighted distribution."""
        ring = MaglevHashRing(ring_size=10009)
        endpoints = [
            Endpoint(num=1, weight=200, hash=11111),  # 2x weight
            Endpoint(num=2, weight=100, hash=22222),  # 1x weight
        ]
        ring.build(endpoints)

        dist = ring.get_distribution()

        # MaglevV2 uses cumulative weight tracking for true proportional distribution.
        # With weights 200:100 the ratio should be close to 2:1.
        ratio = dist[1] / dist[2]
        assert ratio > 1.8, f"Higher weight backend should have ~2x more, got ratio {ratio}"
        assert ratio < 2.2, f"Ratio too far from 2:1: {ratio}"

    def test_zero_weight_excluded(self) -> None:
        """Zero weight backends get no ring positions."""
        ring = MaglevHashRing(ring_size=101)
        endpoints = [
            Endpoint(num=1, weight=100, hash=11111),
            Endpoint(num=2, weight=0, hash=22222),  # Zero weight
            Endpoint(num=3, weight=100, hash=33333),
        ]
        ring.build(endpoints)

        dist = ring.get_distribution()

        # Backend 2 should not appear (or have very few entries)
        assert 2 not in dist or dist[2] == 0


class TestMinimalDisruption:
    """Tests for minimal disruption property."""

    def test_adding_backend_minimal_disruption(self) -> None:
        """Adding a backend causes minimal key changes."""
        # Initial ring with 3 backends
        ring1 = MaglevHashRing(ring_size=10009)
        endpoints1 = [
            Endpoint(num=i, weight=100, hash=hash_endpoint_address(f"10.0.0.{i}")) for i in range(3)
        ]
        old_ring = ring1.build(endpoints1)

        # Add 4th backend
        ring2 = MaglevHashRing(ring_size=10009)
        endpoints2 = endpoints1 + [
            Endpoint(num=3, weight=100, hash=hash_endpoint_address("10.0.0.3"))
        ]
        new_ring = ring2.build(endpoints2)

        changed, pct = compute_ring_changes(old_ring, new_ring)

        # Adding 1 of 4 backends should change ~25% of keys
        # Allow some tolerance
        assert pct < 35, f"Changed {pct}%, expected <35%"
        assert pct > 15, f"Changed {pct}%, expected >15%"

    def test_removing_backend_minimal_disruption(self) -> None:
        """Removing a backend causes minimal key changes."""
        # Initial ring with 4 backends
        ring1 = MaglevHashRing(ring_size=10009)
        endpoints1 = [
            Endpoint(num=i, weight=100, hash=hash_endpoint_address(f"10.0.0.{i}")) for i in range(4)
        ]
        old_ring = ring1.build(endpoints1)

        # Remove 1 backend
        ring2 = MaglevHashRing(ring_size=10009)
        endpoints2 = endpoints1[:3]  # Remove last one
        new_ring = ring2.build(endpoints2)

        changed, pct = compute_ring_changes(old_ring, new_ring)

        # Removing 1 of 4 backends should change ~25% of keys
        assert pct < 35, f"Changed {pct}%, expected <35%"
        assert pct > 15, f"Changed {pct}%, expected >15%"

    def test_weight_change_minimal_disruption(self) -> None:
        """Changing weight causes moderate disruption with MaglevV2 proportional weights."""
        ring1 = MaglevHashRing(ring_size=10009)
        endpoints1 = [
            Endpoint(num=1, weight=100, hash=11111),
            Endpoint(num=2, weight=100, hash=22222),
        ]
        old_ring = ring1.build(endpoints1)

        # Double backend 1's weight
        ring2 = MaglevHashRing(ring_size=10009)
        endpoints2 = [
            Endpoint(num=1, weight=200, hash=11111),  # 2x weight now
            Endpoint(num=2, weight=100, hash=22222),
        ]
        new_ring = ring2.build(endpoints2)

        changed, pct = compute_ring_changes(old_ring, new_ring)

        # MaglevV2 uses true proportional weights, so doubling one backend's
        # weight shifts ~1/6 of total ring positions (from 50/50 to 66/33).
        # Expect ~17% disruption.
        assert pct < 25, f"Changed {pct}%, expected <25% for weight doubling"


class TestLookup:
    """Tests for ring lookup."""

    def test_lookup_requires_built_ring(self) -> None:
        """Lookup before build raises RuntimeError."""
        ring = MaglevHashRing(ring_size=101)

        with pytest.raises(RuntimeError, match="not built"):
            ring.lookup(12345)

    def test_lookup_consistent(self) -> None:
        """Same hash always maps to same backend."""
        ring = MaglevHashRing(ring_size=1009)
        endpoints = [
            Endpoint(num=1, weight=100, hash=11111),
            Endpoint(num=2, weight=100, hash=22222),
        ]
        ring.build(endpoints)

        # Same hash should always return same backend
        for hash_val in [100, 200, 300, 12345, 99999]:
            backend1 = ring.lookup(hash_val)
            backend2 = ring.lookup(hash_val)
            assert backend1 == backend2

    def test_lookup_uses_modulo(self) -> None:
        """Lookup uses modulo for hash values larger than ring."""
        ring = MaglevHashRing(ring_size=101)
        endpoints = [Endpoint(num=1, weight=100, hash=11111)]
        ring.build(endpoints)

        # These should all map to same position
        assert ring.lookup(5) == ring.lookup(5 + 101) == ring.lookup(5 + 101 * 100)


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_hash_endpoint_address(self) -> None:
        """hash_endpoint_address produces consistent hashes."""
        h1 = hash_endpoint_address("10.0.0.1")
        h2 = hash_endpoint_address("10.0.0.1")
        h3 = hash_endpoint_address("10.0.0.2")

        assert h1 == h2  # Same address = same hash
        assert h1 != h3  # Different address = different hash

    def test_compute_ring_changes(self) -> None:
        """compute_ring_changes correctly counts differences."""
        ring1 = [1, 2, 3, 4, 5]
        ring2 = [1, 2, 9, 4, 9]  # 2 changes

        changed, pct = compute_ring_changes(ring1, ring2)

        assert changed == 2
        assert pct == 40.0

    def test_compute_ring_changes_size_mismatch(self) -> None:
        """compute_ring_changes raises on size mismatch."""
        with pytest.raises(ValueError, match="same size"):
            compute_ring_changes([1, 2, 3], [1, 2])

    def test_get_ring_returns_copy(self) -> None:
        """get_ring returns a copy, not the internal ring."""
        ring = MaglevHashRing(ring_size=101)
        ring.build([Endpoint(num=1, weight=1, hash=1)])

        copy = ring.get_ring()
        copy[0] = 999

        # Internal ring should be unchanged
        assert ring.lookup(0) == 1

    def test_get_distribution_percentage(self) -> None:
        """get_distribution_percentage returns correct percentages."""
        ring = MaglevHashRing(ring_size=101)
        endpoints = [
            Endpoint(num=1, weight=100, hash=11111),
            Endpoint(num=2, weight=100, hash=22222),
        ]
        ring.build(endpoints)

        pct = ring.get_distribution_percentage()

        # Total should be ~100%
        total = sum(pct.values())
        assert 99.9 < total < 100.1


class TestLargeRing:
    """Tests with production-sized ring."""

    def test_default_ring_size_builds(self) -> None:
        """Can build ring with default size (65537)."""
        ring = MaglevHashRing()  # Uses default RING_SIZE
        endpoints = [
            Endpoint(num=i, weight=100, hash=hash_endpoint_address(f"10.0.0.{i}"))
            for i in range(10)
        ]

        result = ring.build(endpoints)

        assert len(result) == RING_SIZE
        assert ring.is_built

    def test_many_backends(self) -> None:
        """Works with many backends."""
        ring = MaglevHashRing(ring_size=10009)
        endpoints = [
            Endpoint(num=i, weight=100, hash=hash_endpoint_address(f"10.0.{i // 256}.{i % 256}"))
            for i in range(100)
        ]

        result = ring.build(endpoints)

        dist = ring.get_distribution()
        assert len(dist) == 100  # All backends present


class TestRingRebuildOptimization:
    """Tests for ring rebuild optimization (minimal writes)."""

    def test_rebuild_returns_changes(self) -> None:
        """rebuild() returns both new ring and changes from previous."""
        ring = MaglevHashRing(ring_size=1009)

        # Initial build
        endpoints1 = [
            Endpoint(num=1, weight=100, hash=11111),
            Endpoint(num=2, weight=100, hash=22222),
        ]
        ring.build(endpoints1)

        # Rebuild with additional backend
        endpoints2 = endpoints1 + [Endpoint(num=3, weight=100, hash=33333)]
        new_ring, changes = ring.rebuild(endpoints2)

        # Should have changes
        assert len(changes) > 0
        assert len(changes) < 1009  # Not all positions changed
        assert len(new_ring) == 1009

        # Changes should be a dict mapping position -> (old, new)
        for pos, (old_val, new_val) in changes.items():
            assert 0 <= pos < 1009
            assert old_val in [1, 2]  # Old backends
            assert new_val in [1, 2, 3]  # All backends
            assert old_val != new_val  # Must have actually changed

    def test_rebuild_no_previous_ring(self) -> None:
        """rebuild() on fresh ring returns empty changes."""
        ring = MaglevHashRing(ring_size=101)
        endpoints = [Endpoint(num=1, weight=100, hash=11111)]

        new_ring, changes = ring.rebuild(endpoints)

        assert len(new_ring) == 101
        assert len(changes) == 0  # No previous ring to compare

    def test_rebuild_preserves_old_ring(self) -> None:
        """rebuild() correctly identifies unchanged positions."""
        ring = MaglevHashRing(ring_size=1009)

        # Build initial ring
        endpoints1 = [
            Endpoint(num=1, weight=100, hash=11111),
            Endpoint(num=2, weight=100, hash=22222),
            Endpoint(num=3, weight=100, hash=33333),
        ]
        old_ring = ring.build(endpoints1)

        # Rebuild with one backend removed
        endpoints2 = endpoints1[:2]  # Remove backend 3
        new_ring, changes = ring.rebuild(endpoints2)

        # Verify: unchanged positions should be preserved
        for pos in range(1009):
            if pos not in changes:
                # Position didn't change - should be same in both rings
                assert old_ring[pos] == new_ring[pos]
            else:
                # Position changed - should be different
                old_val, new_val = changes[pos]
                assert old_ring[pos] == old_val
                assert new_ring[pos] == new_val

    def test_rebuild_minimal_disruption(self) -> None:
        """rebuild() with small backend change has minimal disruption."""
        ring = MaglevHashRing(ring_size=10009)

        # Initial 3 backends
        endpoints1 = [
            Endpoint(num=i, weight=100, hash=hash_endpoint_address(f"10.0.0.{i}")) for i in range(3)
        ]
        ring.build(endpoints1)

        # Add 1 backend (4 total)
        endpoints2 = endpoints1 + [
            Endpoint(num=3, weight=100, hash=hash_endpoint_address("10.0.0.3"))
        ]
        new_ring, changes = ring.rebuild(endpoints2)

        # Adding 1 of 4 backends should change ~25% of positions
        pct_changed = (len(changes) / 10009) * 100
        assert 15 < pct_changed < 35, f"Changed {pct_changed}%, expected 15-35%"

    def test_compute_ring_updates_helper(self) -> None:
        """compute_ring_updates correctly identifies changed positions."""
        old = [1, 1, 2, 2, 3, 3]
        new = [1, 2, 2, 2, 3, 1]  # Positions 1 and 5 changed

        updates = compute_ring_updates(old, new)

        assert len(updates) == 2
        assert updates[1] == 2  # Position 1: 1 -> 2
        assert updates[5] == 1  # Position 5: 3 -> 1

    def test_compute_ring_updates_no_changes(self) -> None:
        """compute_ring_updates returns empty dict when nothing changed."""
        ring1 = [1, 2, 3, 4, 5]
        ring2 = [1, 2, 3, 4, 5]

        updates = compute_ring_updates(ring1, ring2)

        assert len(updates) == 0

    def test_compute_ring_updates_all_changed(self) -> None:
        """compute_ring_updates handles all positions changing."""
        ring1 = [1, 1, 1, 1]
        ring2 = [2, 2, 2, 2]

        updates = compute_ring_updates(ring1, ring2)

        assert len(updates) == 4
        assert all(v == 2 for v in updates.values())

    def test_compute_ring_updates_size_mismatch(self) -> None:
        """compute_ring_updates raises on size mismatch."""
        with pytest.raises(ValueError, match="same size"):
            compute_ring_updates([1, 2, 3], [1, 2])

    def test_rebuild_deterministic(self) -> None:
        """rebuild() produces same results as separate builds."""
        endpoints1 = [
            Endpoint(num=1, weight=100, hash=11111),
            Endpoint(num=2, weight=100, hash=22222),
        ]
        endpoints2 = endpoints1 + [Endpoint(num=3, weight=100, hash=33333)]

        # Method 1: Use rebuild
        ring1 = MaglevHashRing(ring_size=1009)
        ring1.build(endpoints1)
        new_ring_rebuild, _ = ring1.rebuild(endpoints2)

        # Method 2: Separate builds
        ring2 = MaglevHashRing(ring_size=1009)
        old_ring_separate = ring2.build(endpoints1)
        ring3 = MaglevHashRing(ring_size=1009)
        new_ring_separate = ring3.build(endpoints2)

        # Results should match
        assert new_ring_rebuild == new_ring_separate
