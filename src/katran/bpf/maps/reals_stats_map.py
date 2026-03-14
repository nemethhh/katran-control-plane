"""Per-real statistics: real_index (u32) -> LbStats (per-CPU)."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import PerCpuBpfMap
from katran.core.constants import MAX_REALS
from katran.core.types import LB_STATS_SIZE, LbStats


class RealsStatsMap(PerCpuBpfMap[int, LbStats]):
    """reals_stats BPF per-CPU array: real_index -> LbStats."""

    MAP_NAME = "reals_stats"

    def __init__(
        self,
        pin_base_path: str,
        map_name: str | None = None,
        max_entries: int = MAX_REALS,
        num_cpus: int | None = None,
    ) -> None:
        super().__init__(pin_base_path, map_name, num_cpus)
        self._max_entries = max_entries

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return LB_STATS_SIZE

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: LbStats) -> bytes:
        return value.to_bytes()

    def _deserialize_value(self, data: bytes) -> LbStats:
        return LbStats.from_bytes(data)

    def _aggregate_values(self, values: list[LbStats]) -> LbStats:
        return LbStats.aggregate(values)
