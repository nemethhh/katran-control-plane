"""
LRU map wrapper for BPF LRU hash maps.

Katran uses per-CPU LRU hash maps to cache backend selection decisions
for existing flows. This avoids recalculating the consistent hash for
every packet of an established connection.

The lru_mapping map is an array of maps (BPF_MAP_TYPE_ARRAY_OF_MAPS)
where each entry points to a per-CPU LRU hash map.

For simpler configurations, the fallback_cache is a single LRU hash map.

BPF Map Definitions:
    fallback_cache:
        Type: BPF_MAP_TYPE_LRU_HASH
        Key: struct flow_key (40 bytes)
        Value: struct real_pos_lru (16 bytes)
        Max Entries: DEFAULT_LRU_SIZE (1000)

    lru_mapping (per-CPU):
        Type: BPF_MAP_TYPE_ARRAY_OF_MAPS
        Key: __u32 (CPU index)
        Value: fd to LRU hash map
"""

from __future__ import annotations

from typing import Any

from katran.bpf.map_manager import BpfMap
from katran.core.constants import DEFAULT_LRU_SIZE
from katran.core.types import (
    FLOW_KEY_SIZE,
    REAL_POS_LRU_SIZE,
    FlowKey,
    RealPosLru,
)


class LruMap(BpfMap[FlowKey, RealPosLru]):
    """
    Wrapper for LRU hash map (fallback_cache).

    Provides flow lookup cache operations. This is the fallback LRU
    used for testing or simple configurations.

    In production, Katran uses per-CPU LRU maps (lru_mapping) for
    better performance, which requires more complex handling.

    Example:
        >>> with LruMap("/sys/fs/bpf/katran") as lru:
        ...     # Lookup cached backend for flow
        ...     flow = FlowKey(
        ...         src_addr=IPv4Address("192.168.1.100"),
        ...         dst_addr=IPv4Address("10.200.1.1"),
        ...         src_port=54321,
        ...         dst_port=80,
        ...         protocol=Protocol.TCP
        ...     )
        ...     cached = lru.get(flow)
        ...     if cached:
        ...         print(f"Cached backend: {cached.pos}")
    """

    MAP_NAME = "fallback_cache"

    def __init__(
        self,
        pin_base_path: str,
        map_name: str | None = None,
        max_entries: int = DEFAULT_LRU_SIZE,
    ) -> None:
        """
        Initialize LRU map wrapper.

        Args:
            pin_base_path: Base path where maps are pinned
            map_name: Map name (defaults to "fallback_cache")
            max_entries: Maximum LRU entries
        """
        super().__init__(pin_base_path, map_name)
        self._max_entries = max_entries

    # -------------------------------------------------------------------------
    # Serialization methods
    # -------------------------------------------------------------------------

    @property
    def _key_size(self) -> int:
        return FLOW_KEY_SIZE

    @property
    def _value_size(self) -> int:
        return REAL_POS_LRU_SIZE

    def _serialize_key(self, key: FlowKey) -> bytes:
        return key.to_bytes()

    def _deserialize_key(self, data: bytes) -> FlowKey:
        return FlowKey.from_bytes(data)

    def _serialize_value(self, value: RealPosLru) -> bytes:
        return value.to_bytes()

    def _deserialize_value(self, data: bytes) -> RealPosLru:
        return RealPosLru.from_bytes(data)

    # -------------------------------------------------------------------------
    # LRU operations
    # -------------------------------------------------------------------------

    def lookup_flow(self, flow: FlowKey) -> int | None:
        """
        Lookup cached backend for a flow.

        Args:
            flow: 5-tuple flow key

        Returns:
            Backend index (pos) if cached, None otherwise
        """
        cached = self.get(flow)
        if cached is None:
            return None
        return cached.pos

    def cache_flow(self, flow: FlowKey, real_index: int, atime: int = 0) -> None:
        """
        Cache backend selection for a flow.

        Args:
            flow: 5-tuple flow key
            real_index: Selected backend index
            atime: Access time in nanoseconds (default: 0)
        """
        entry = RealPosLru(pos=real_index, atime=atime)
        self.set(flow, entry)

    def invalidate_flow(self, flow: FlowKey) -> bool:
        """
        Remove flow from cache.

        Args:
            flow: 5-tuple flow key

        Returns:
            True if removed, False if not found
        """
        return self.delete(flow)

    def invalidate_backend(self, real_index: int) -> int:
        """
        Invalidate all cache entries for a backend.

        Used when draining or removing a backend to force
        new backend selection for affected flows.

        Note: This is expensive as it iterates all entries.
        Consider using this sparingly or implementing a more
        efficient invalidation strategy.

        Args:
            real_index: Backend index to invalidate

        Returns:
            Number of entries invalidated
        """
        count = 0
        flows_to_delete = []

        # Collect flows to delete (can't modify while iterating)
        for flow, cached in self.items():
            if cached.pos == real_index:
                flows_to_delete.append(flow)

        # Delete collected flows
        for flow in flows_to_delete:
            if self.delete(flow):
                count += 1

        return count

    def get_cache_stats(self) -> dict[str, Any]:
        """
        Get LRU cache statistics.

        Returns:
            Dictionary with entry count and backend distribution
        """
        backend_counts: dict[int, int] = {}
        total = 0

        for _flow, cached in self.items():
            total += 1
            backend_counts[cached.pos] = backend_counts.get(cached.pos, 0) + 1

        return {
            "total_entries": total,
            "unique_backends": len(backend_counts),
            "backend_distribution": backend_counts,
        }

    def clear_all(self) -> int:
        """
        Clear all entries from the LRU cache.

        Note: LRU maps don't support iteration-safe deletion,
        so this may not remove all entries atomically.

        Returns:
            Number of entries removed
        """
        count = 0
        flows_to_delete = list(self.keys())

        for flow in flows_to_delete:
            if self.delete(flow):
                count += 1

        return count


class PerCpuLruMap:
    """
    Wrapper for per-CPU LRU map array (lru_mapping).

    This is a more complex wrapper that handles the array-of-maps
    structure used for per-CPU LRU caches.

    Note: Full implementation requires handling BPF_MAP_TYPE_ARRAY_OF_MAPS
    which involves opening inner maps. This is a simplified placeholder.
    """

    MAP_NAME = "lru_mapping"

    def __init__(
        self,
        pin_base_path: str,
        map_name: str | None = None,
        num_cpus: int | None = None,
    ) -> None:
        """
        Initialize per-CPU LRU map wrapper.

        Args:
            pin_base_path: Base path where maps are pinned
            map_name: Map name (defaults to "lru_mapping")
            num_cpus: Number of CPUs (auto-detected if None)
        """
        self._pin_base_path = pin_base_path
        self._map_name = map_name or self.MAP_NAME
        self._num_cpus = num_cpus or self._detect_num_cpus()
        self._cpu_maps: dict[int, LruMap] = {}

    @staticmethod
    def _detect_num_cpus() -> int:
        """Detect number of possible CPUs."""
        import os

        try:
            with open("/sys/devices/system/cpu/possible") as f:
                cpus_str = f.read().strip()
                if "-" in cpus_str:
                    parts = cpus_str.split("-")
                    return int(parts[-1]) + 1
                else:
                    return len(cpus_str.split(","))
        except Exception:
            return os.cpu_count() or 1

    def lookup_flow_all_cpus(self, flow: FlowKey) -> list[int | None]:
        """
        Lookup cached backend across all per-CPU LRU maps.

        This is primarily for debugging/introspection. In normal
        operation, each CPU only accesses its own LRU map.

        Args:
            flow: 5-tuple flow key

        Returns:
            List of backend indices (one per CPU, None if not cached)
        """
        # Placeholder - would need to open inner maps from array-of-maps
        raise NotImplementedError("Per-CPU LRU map access requires array-of-maps handling")
