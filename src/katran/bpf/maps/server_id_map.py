"""QUIC server ID map: server_id (u32) -> real_index (u32)."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import BpfMap
from katran.core.constants import MAX_QUIC_REALS


class ServerIdMap(BpfMap[int, int]):
    """server_id_map BPF map: server_id (u32) -> real_index (u32)."""

    MAP_NAME = "server_id_map"

    def __init__(
        self,
        pin_base_path: str,
        map_name: str | None = None,
        max_entries: int = MAX_QUIC_REALS,
    ) -> None:
        super().__init__(pin_base_path, map_name)
        self._max_entries = max_entries

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return 4

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: int) -> bytes:
        return struct.pack("<I", value)

    def _deserialize_value(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])
