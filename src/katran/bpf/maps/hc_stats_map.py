"""HC program stats: key 0 -> HealthCheckProgStats (per-CPU)."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import PerCpuBpfMap
from katran.core.types import HealthCheckProgStats

HC_STATS_VALUE_SIZE = 40  # 5 u64 fields


class HcStatsMap(PerCpuBpfMap[int, HealthCheckProgStats]):
    """hc_stats_map BPF per-CPU array: key 0 -> HealthCheckProgStats."""

    MAP_NAME = "hc_stats_map"

    def __init__(
        self,
        pin_base_path: str,
        map_name: str | None = None,
        num_cpus: int | None = None,
    ) -> None:
        super().__init__(pin_base_path, map_name, num_cpus)

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return HC_STATS_VALUE_SIZE

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: HealthCheckProgStats) -> bytes:
        return struct.pack(
            "<5Q",
            value.packets_processed,
            value.packets_dropped,
            value.packets_skipped,
            value.packets_too_big,
            value.packets_dst_matched,
        )

    def _deserialize_value(self, data: bytes) -> HealthCheckProgStats:
        vals = struct.unpack("<5Q", data[:HC_STATS_VALUE_SIZE])
        return HealthCheckProgStats(
            packets_processed=vals[0],
            packets_dropped=vals[1],
            packets_skipped=vals[2],
            packets_too_big=vals[3],
            packets_dst_matched=vals[4],
        )

    def _aggregate_values(self, values: list[HealthCheckProgStats]) -> HealthCheckProgStats:
        result = HealthCheckProgStats()
        for v in values:
            result.packets_processed += v.packets_processed
            result.packets_dropped += v.packets_dropped
            result.packets_skipped += v.packets_skipped
            result.packets_too_big += v.packets_too_big
            result.packets_dst_matched += v.packets_dst_matched
        return result
