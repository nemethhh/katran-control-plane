"""HC control array: index (u32) -> value (u32)."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import BpfMap
from katran.core.constants import HC_CTRL_MAP_SIZE


class HcCtrlMap(BpfMap[int, int]):
    """hc_ctrl_map BPF array: index (u32) -> value (u32)."""

    MAP_NAME = "hc_ctrl_map"

    def __init__(self, pin_base_path: str, map_name: str | None = None) -> None:
        super().__init__(pin_base_path, map_name)

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
