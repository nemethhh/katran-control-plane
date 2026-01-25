"""
Maglev consistent hashing implementation.

This module implements Google's Maglev consistent hashing algorithm as used
in Katran. The implementation matches katran/lib/MaglevHash.cpp exactly,
including the MurmurHash3 variant used for permutation generation.

Reference: http://research.google.com/pubs/pub44824.html (Section 3.4)

Key Properties:
- Minimal disruption: Adding/removing backends affects minimal keys
- Uniform distribution: Keys distributed evenly across backends (weighted)
- O(1) lookup after ring construction
- Deterministic: Same inputs always produce same ring
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from katran.core.constants import RING_SIZE


# =============================================================================
# MurmurHash3 Implementation
# =============================================================================

# Hash constants matching katran/lib/MurmurHash3.cpp
_C1 = 0x87C37B91114253D5
_C2 = 0x4CF5AD432745937F
_FMIX_C1 = 0xFF51AFD7ED558CCD
_FMIX_C2 = 0xC4CEB9FE1A85EC53
_MASK64 = 0xFFFFFFFFFFFFFFFF


def _rotl64(x: int, r: int) -> int:
    """64-bit rotate left."""
    return ((x << r) | (x >> (64 - r))) & _MASK64


def _fmix64(k: int) -> int:
    """MurmurHash3 finalization mix."""
    k ^= k >> 33
    k = (k * _FMIX_C1) & _MASK64
    k ^= k >> 33
    k = (k * _FMIX_C2) & _MASK64
    k ^= k >> 33
    return k


def murmur_hash3_x64_64(a: int, b: int, seed: int) -> int:
    """
    MurmurHash3 x64 128-bit variant, returning lower 64 bits.

    This matches katran/lib/MurmurHash3.cpp exactly.

    Args:
        a: First 64-bit input value
        b: Second 64-bit input value
        seed: 32-bit seed value

    Returns:
        64-bit hash value
    """
    h1 = seed & _MASK64
    h2 = seed & _MASK64

    # Body
    k1 = a & _MASK64
    k2 = b & _MASK64

    k1 = (k1 * _C1) & _MASK64
    k1 = _rotl64(k1, 31)
    k1 = (k1 * _C2) & _MASK64
    h1 ^= k1

    h1 = _rotl64(h1, 27)
    h1 = (h1 + h2) & _MASK64
    h1 = (h1 * 5 + 0x52DCE729) & _MASK64

    k2 = (k2 * _C2) & _MASK64
    k2 = _rotl64(k2, 33)
    k2 = (k2 * _C1) & _MASK64
    h2 ^= k2

    h2 = _rotl64(h2, 31)
    h2 = (h2 + h1) & _MASK64
    h2 = (h2 * 5 + 0x38495AB5) & _MASK64

    # Finalization
    h1 ^= 16
    h2 ^= 16

    h1 = (h1 + h2) & _MASK64
    h2 = (h2 + h1) & _MASK64

    h1 = _fmix64(h1)
    h2 = _fmix64(h2)

    h1 = (h1 + h2) & _MASK64

    return h1


# =============================================================================
# Maglev Hash Ring
# =============================================================================

# Hash seeds matching katran/lib/MaglevBase.cpp
_HASH_SEED_0 = 0
_HASH_SEED_1 = 2307
_HASH_SEED_2 = 42
_HASH_SEED_3 = 2718281828


@dataclass
class Endpoint:
    """
    Backend endpoint for consistent hashing.

    Attributes:
        num: Backend index/identifier (used in the resulting ring)
        weight: Weight for load distribution (higher = more ring positions)
        hash: Unique hash value for this endpoint (seed for permutation)
    """

    num: int
    weight: int
    hash: int


def _is_prime(n: int) -> bool:
    """
    Check if a number is prime.

    Args:
        n: Number to check

    Returns:
        True if prime, False otherwise
    """
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(n**0.5) + 1, 2):
        if n % i == 0:
            return False
    return True


def _gen_maglev_permutation(endpoint: Endpoint, ring_size: int) -> tuple[int, int]:
    """
    Generate Maglev permutation (offset, skip) for an endpoint.

    This matches katran/lib/MaglevBase.cpp::genMaglevPermutation exactly.

    Args:
        endpoint: Endpoint to generate permutation for
        ring_size: Size of the hash ring (must be prime)

    Returns:
        Tuple of (offset, skip) values
    """
    offset_hash = murmur_hash3_x64_64(endpoint.hash, _HASH_SEED_2, _HASH_SEED_0)
    offset = offset_hash % ring_size

    skip_hash = murmur_hash3_x64_64(endpoint.hash, _HASH_SEED_3, _HASH_SEED_1)
    skip = (skip_hash % (ring_size - 1)) + 1

    return offset, skip


class MaglevHashRing:
    """
    Maglev consistent hashing implementation.

    This class builds a hash ring using Google's Maglev algorithm, which
    provides minimal disruption when backends are added or removed.

    The implementation matches katran/lib/MaglevHash.cpp exactly.

    Example:
        >>> ring = MaglevHashRing(ring_size=65537)
        >>> endpoints = [
        ...     Endpoint(num=1, weight=100, hash=hash_backend("10.0.0.1")),
        ...     Endpoint(num=2, weight=100, hash=hash_backend("10.0.0.2")),
        ...     Endpoint(num=3, weight=50, hash=hash_backend("10.0.0.3")),
        ... ]
        >>> result = ring.build(endpoints)
        >>> backend = ring.lookup(flow_hash)
    """

    def __init__(self, ring_size: int = RING_SIZE) -> None:
        """
        Initialize Maglev hash ring.

        Args:
            ring_size: Size of the hash ring (must be prime, default: 65537)

        Raises:
            ValueError: If ring_size is not prime
        """
        if not _is_prime(ring_size):
            raise ValueError(f"Ring size must be prime, got {ring_size}")

        self._ring_size = ring_size
        self._ring: list[int] = []

    @property
    def ring_size(self) -> int:
        """Size of the hash ring."""
        return self._ring_size

    @property
    def is_built(self) -> bool:
        """Check if ring has been built."""
        return len(self._ring) == self._ring_size

    def build(self, endpoints: Sequence[Endpoint]) -> list[int]:
        """
        Build Maglev ring from endpoints.

        This matches katran/lib/MaglevHash.cpp::generateHashRing exactly.

        Args:
            endpoints: List of Endpoint objects with num, weight, and hash

        Returns:
            Ring as list of endpoint numbers (num values)
        """
        # Initialize result with -1 (empty slots)
        result = [-1] * self._ring_size

        if len(endpoints) == 0:
            self._ring = result
            return result

        if len(endpoints) == 1:
            # Single endpoint fills entire ring
            result = [endpoints[0].num] * self._ring_size
            self._ring = result
            return result

        # Make a mutable copy of endpoints to track weights
        eps = [Endpoint(num=e.num, weight=e.weight, hash=e.hash) for e in endpoints]

        # Generate permutations for all endpoints
        permutations: list[tuple[int, int]] = []
        for ep in eps:
            offset, skip = _gen_maglev_permutation(ep, self._ring_size)
            permutations.append((offset, skip))

        # Track next position to try for each endpoint
        next_pos = [0] * len(eps)

        # Fill the ring
        runs = 0
        while True:
            for i, ep in enumerate(eps):
                offset, skip = permutations[i]

                # Weighted Maglev: each endpoint claims 'weight' positions per round
                for _ in range(ep.weight):
                    # Find next empty slot in this endpoint's permutation
                    cur = (offset + next_pos[i] * skip) % self._ring_size
                    while result[cur] >= 0:
                        next_pos[i] += 1
                        cur = (offset + next_pos[i] * skip) % self._ring_size

                    # Claim this slot
                    result[cur] = ep.num
                    next_pos[i] += 1
                    runs += 1

                    if runs == self._ring_size:
                        self._ring = result
                        return result

                # Reset weight to 1 after first round (Katran behavior)
                eps[i].weight = 1

        # Should never reach here
        self._ring = result
        return result

    def lookup(self, hash_value: int) -> int:
        """
        Lookup backend for given hash value.

        Args:
            hash_value: Hash of the flow/request

        Returns:
            Backend number (endpoint.num) for this hash

        Raises:
            RuntimeError: If ring has not been built
        """
        if not self.is_built:
            raise RuntimeError("Ring not built - call build() first")

        return self._ring[hash_value % self._ring_size]

    def get_ring(self) -> list[int]:
        """
        Get a copy of the current ring contents.

        Returns:
            Copy of ring as list of endpoint numbers
        """
        return self._ring.copy()

    def get_distribution(self) -> dict[int, int]:
        """
        Get the distribution of endpoints in the ring.

        Returns:
            Dictionary mapping endpoint number to count in ring
        """
        if not self.is_built:
            return {}

        distribution: dict[int, int] = {}
        for num in self._ring:
            if num >= 0:
                distribution[num] = distribution.get(num, 0) + 1

        return distribution

    def get_distribution_percentage(self) -> dict[int, float]:
        """
        Get the distribution of endpoints as percentages.

        Returns:
            Dictionary mapping endpoint number to percentage of ring
        """
        distribution = self.get_distribution()
        total = sum(distribution.values())
        if total == 0:
            return {}

        return {num: (count / total) * 100 for num, count in distribution.items()}


# =============================================================================
# Helper Functions
# =============================================================================


def hash_endpoint_address(address: str) -> int:
    """
    Generate a hash value for an endpoint address.

    This creates a consistent hash from an IP address string that can
    be used as the Endpoint.hash value.

    Args:
        address: IP address string (e.g., "10.0.0.1")

    Returns:
        64-bit hash value
    """
    # Use Python's built-in hash as base, then mix with MurmurHash3
    # for better distribution
    base_hash = hash(address) & _MASK64
    return murmur_hash3_x64_64(base_hash, len(address), 0)


def compute_ring_changes(
    old_ring: list[int], new_ring: list[int]
) -> tuple[int, float]:
    """
    Compute the number of positions that changed between two rings.

    Useful for measuring disruption when backends change.

    Args:
        old_ring: Previous ring
        new_ring: New ring

    Returns:
        Tuple of (changed_count, changed_percentage)
    """
    if len(old_ring) != len(new_ring):
        raise ValueError("Rings must be the same size")

    changed = sum(1 for o, n in zip(old_ring, new_ring) if o != n)
    percentage = (changed / len(old_ring)) * 100 if old_ring else 0.0

    return changed, percentage
