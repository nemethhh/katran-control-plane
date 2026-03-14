"""Per-HC-key packet counts: hc_key_index (u32) -> count (u64, per-CPU)."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import PerCpuBpfMap
from katran.core.constants import MAX_VIPS


class PerHcKeyStatsMap(PerCpuBpfMap[int, int]):
    """per_hckey_stats BPF per-CPU array: hc_key_index -> count (u64)."""

    MAP_NAME = "per_hckey_stats"

    def __init__(
        self,
        pin_base_path: str,
        map_name: str | None = None,
        max_entries: int = MAX_VIPS,
        num_cpus: int | None = None,
    ) -> None:
        super().__init__(pin_base_path, map_name, num_cpus)
        self._max_entries = max_entries

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return 8

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: int) -> bytes:
        return struct.pack("<Q", value)

    def _deserialize_value(self, data: bytes) -> int:
        return int(struct.unpack("<Q", data)[0])

    def _aggregate_values(self, values: list[int]) -> int:
        return sum(values)
