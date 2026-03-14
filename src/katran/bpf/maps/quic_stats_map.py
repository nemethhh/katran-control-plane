"""QUIC packet stats: key 0 (u32) -> QuicPacketStats (per-CPU)."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import PerCpuBpfMap
from katran.core.types import QuicPacketStats

QUIC_STATS_SIZE = 104  # 13 u64 fields


class QuicStatsMap(PerCpuBpfMap[int, QuicPacketStats]):
    """quic_stats_map BPF per-CPU array: key 0 -> QuicPacketStats."""

    MAP_NAME = "quic_stats_map"

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
        return QUIC_STATS_SIZE

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: QuicPacketStats) -> bytes:
        return struct.pack(
            "<13Q",
            value.ch_routed,
            value.cid_initial,
            value.cid_invalid_server_id,
            value.cid_invalid_server_id_sample,
            value.cid_routed,
            value.cid_unknown_real_dropped,
            value.cid_v0,
            value.cid_v1,
            value.cid_v2,
            value.cid_v3,
            value.dst_match_in_lru,
            value.dst_mismatch_in_lru,
            value.dst_not_found_in_lru,
        )

    def _deserialize_value(self, data: bytes) -> QuicPacketStats:
        vals = struct.unpack("<13Q", data[:QUIC_STATS_SIZE])
        return QuicPacketStats(
            ch_routed=vals[0],
            cid_initial=vals[1],
            cid_invalid_server_id=vals[2],
            cid_invalid_server_id_sample=vals[3],
            cid_routed=vals[4],
            cid_unknown_real_dropped=vals[5],
            cid_v0=vals[6],
            cid_v1=vals[7],
            cid_v2=vals[8],
            cid_v3=vals[9],
            dst_match_in_lru=vals[10],
            dst_mismatch_in_lru=vals[11],
            dst_not_found_in_lru=vals[12],
        )

    def _aggregate_values(self, values: list[QuicPacketStats]) -> QuicPacketStats:
        result = QuicPacketStats()
        for v in values:
            result.ch_routed += v.ch_routed
            result.cid_initial += v.cid_initial
            result.cid_invalid_server_id += v.cid_invalid_server_id
            result.cid_invalid_server_id_sample = v.cid_invalid_server_id_sample
            result.cid_routed += v.cid_routed
            result.cid_unknown_real_dropped += v.cid_unknown_real_dropped
            result.cid_v0 += v.cid_v0
            result.cid_v1 += v.cid_v1
            result.cid_v2 += v.cid_v2
            result.cid_v3 += v.cid_v3
            result.dst_match_in_lru += v.dst_match_in_lru
            result.dst_mismatch_in_lru += v.dst_mismatch_in_lru
            result.dst_not_found_in_lru += v.dst_not_found_in_lru
        return result
