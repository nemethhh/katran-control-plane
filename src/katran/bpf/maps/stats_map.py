"""
Statistics map wrapper for BPF stats per-CPU array.

The stats map stores per-CPU statistics counters. Each entry is an lb_stats
structure containing two 64-bit counters (typically packets and bytes).

Map layout (matches BPF balancer_consts.h):
- Indices 0..MAX_VIPS-1: per-VIP stats (one entry per VIP, v1=packets, v2=bytes)
- Indices MAX_VIPS+offset: global counters (LRU, XDP actions, etc.)

BPF Map Definition:
    Type: BPF_MAP_TYPE_PERCPU_ARRAY
    Key: __u32 (counter index, 4 bytes)
    Value: struct lb_stats (16 bytes per CPU)
    Max Entries: STATS_MAP_SIZE (MAX_VIPS * 2 = 1024)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from katran.bpf.map_manager import PerCpuBpfMap
from katran.core.constants import (
    MAX_VIPS,
    StatsCounterIndex,
)
from katran.core.types import LB_STATS_SIZE, LbStats


@dataclass
class VipStatistics:
    """Aggregated statistics for a VIP."""

    packets: int = 0
    bytes: int = 0
    lru_hits: int = 0
    lru_misses: int = 0

    @property
    def hit_ratio(self) -> float:
        """LRU cache hit ratio (0.0 to 1.0)."""
        total = self.lru_hits + self.lru_misses
        if total == 0:
            return 0.0
        return self.lru_hits / total


@dataclass
class GlobalStatistics:
    """Aggregated global statistics."""

    total_packets: int = 0
    total_bytes: int = 0
    total_lru_hits: int = 0
    total_lru_misses: int = 0
    vip_misses: int = 0
    icmp_toobig: int = 0
    new_connections: int = 0


class StatsMap(PerCpuBpfMap[int, LbStats]):
    """
    Wrapper for stats BPF per-CPU array map.

    Provides statistics collection with automatic CPU aggregation.

    Example:
        >>> with StatsMap("/sys/fs/bpf/katran") as stats:
        ...     # Get stats for VIP 0
        ...     vip_stats = stats.get_vip_stats(vip_num=0)
        ...     print(f"Packets: {vip_stats.packets}")
        ...     # Get global stats
        ...     global_stats = stats.get_global_stats()
    """

    MAP_NAME = "stats"

    def __init__(
        self,
        pin_base_path: str,
        map_name: str | None = None,
        max_vips: int = MAX_VIPS,
        num_cpus: int | None = None,
    ) -> None:
        """
        Initialize statistics map wrapper.

        Args:
            pin_base_path: Base path where maps are pinned
            map_name: Map name (defaults to "stats")
            max_vips: Maximum number of VIPs
            num_cpus: Number of CPUs (auto-detected if None)
        """
        super().__init__(pin_base_path, map_name, num_cpus)
        self._max_vips = max_vips

    # -------------------------------------------------------------------------
    # Serialization methods
    # -------------------------------------------------------------------------

    @property
    def _key_size(self) -> int:
        return 4  # __u32

    @property
    def _value_size(self) -> int:
        return LB_STATS_SIZE

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return struct.unpack("<I", data)[0]

    def _serialize_value(self, value: LbStats) -> bytes:
        return value.to_bytes()

    def _deserialize_value(self, data: bytes) -> LbStats:
        return LbStats.from_bytes(data)

    def _aggregate_values(self, values: list[LbStats]) -> LbStats:
        """Sum all per-CPU LbStats values."""
        return LbStats.aggregate(values)

    # -------------------------------------------------------------------------
    # Index calculation
    # -------------------------------------------------------------------------

    def _global_index(self, offset: int) -> int:
        """
        Get stats map index for a global counter.

        The BPF program stores global counters at MAX_VIPS + offset,
        after the per-VIP entries (0..MAX_VIPS-1).

        Args:
            offset: Counter offset (StatsCounterIndex value)

        Returns:
            Absolute index in stats array
        """
        return self._max_vips + offset

    # -------------------------------------------------------------------------
    # Statistics collection
    # -------------------------------------------------------------------------

    def get_counter(self, index: int) -> LbStats:
        """
        Get aggregated counter by index.

        Args:
            index: Counter index

        Returns:
            Aggregated LbStats from all CPUs
        """
        result = self.get(index)
        return result if result is not None else LbStats()

    def get_counter_per_cpu(self, index: int) -> list[LbStats]:
        """
        Get counter values from each CPU.

        Args:
            index: Counter index

        Returns:
            List of LbStats, one per CPU
        """
        return self.get_all_cpus(index)

    def get_vip_stats(self, vip_num: int) -> VipStatistics:
        """
        Get aggregated statistics for a VIP.

        The BPF program stores one lb_stats entry per VIP at index vip_num:
          v1 = packets forwarded, v2 = bytes forwarded.

        Per-VIP LRU stats are not tracked in the BPF program (LRU
        counters are global only), so lru_hits/lru_misses are always 0.

        Args:
            vip_num: VIP index number

        Returns:
            VipStatistics with aggregated values
        """
        stats = self.get_counter(vip_num)

        return VipStatistics(
            packets=stats.v1,
            bytes=stats.v2,
            lru_hits=0,
            lru_misses=0,
        )

    def get_global_stats(self) -> GlobalStatistics:
        """
        Get aggregated global statistics.

        Global counters live at index MAX_VIPS + offset in the stats map,
        after all the per-VIP entries.

        Returns:
            GlobalStatistics with aggregated values
        """
        # LRU counters
        lru = self.get_counter(self._global_index(StatsCounterIndex.LRU_CNTRS))
        lru_miss = self.get_counter(self._global_index(StatsCounterIndex.LRU_MISS_CNTR))

        # New connection rate
        new_conn = self.get_counter(self._global_index(StatsCounterIndex.NEW_CONN_RATE_CNTR))

        # ICMP too big
        icmp = self.get_counter(self._global_index(StatsCounterIndex.ICMP_TOOBIG_CNTRS))

        # XDP counters
        xdp_total = self.get_counter(self._global_index(StatsCounterIndex.XDP_TOTAL_CNTR))

        return GlobalStatistics(
            total_packets=xdp_total.v1,
            total_bytes=xdp_total.v2,
            total_lru_hits=lru.v1,
            total_lru_misses=lru_miss.v1,
            vip_misses=lru.v2,
            icmp_toobig=icmp.v1,
            new_connections=new_conn.v1,
        )

    def get_all_vip_stats(self, vip_nums: list[int]) -> dict[int, VipStatistics]:
        """
        Get statistics for multiple VIPs.

        Args:
            vip_nums: List of VIP index numbers

        Returns:
            Dictionary mapping vip_num to VipStatistics
        """
        result = {}
        for vip_num in vip_nums:
            result[vip_num] = self.get_vip_stats(vip_num)
        return result

    def get_xdp_action_stats(self) -> dict[str, int]:
        """
        Get XDP action statistics.

        Returns:
            Dictionary with XDP action counts
        """
        total = self.get_counter(self._global_index(StatsCounterIndex.XDP_TOTAL_CNTR))
        tx = self.get_counter(self._global_index(StatsCounterIndex.XDP_TX_CNTR))
        drop = self.get_counter(self._global_index(StatsCounterIndex.XDP_DROP_CNTR))
        pass_cnt = self.get_counter(self._global_index(StatsCounterIndex.XDP_PASS_CNTR))

        return {
            "total": total.v1,
            "tx": tx.v1,
            "drop": drop.v1,
            "pass": pass_cnt.v1,
        }

    def reset_counter(self, index: int) -> None:
        """
        Reset a counter to zero.

        Note: This sets the counter for all CPUs to zero.

        Args:
            index: Counter index
        """
        self.set(index, LbStats(v1=0, v2=0))

    def reset_vip_stats(self, vip_num: int) -> None:
        """
        Reset statistics for a VIP.

        Args:
            vip_num: VIP index number
        """
        self.reset_counter(vip_num)
