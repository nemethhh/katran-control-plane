"""HC packet source IPs: index (0=v4, 1=v6) -> RealDefinition."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import BpfMap
from katran.core.types import REAL_DEFINITION_SIZE, RealDefinition


class HcPcktSrcsMap(BpfMap[int, RealDefinition]):
    """hc_pckt_srcs_map BPF array: index (0=v4, 1=v6) -> RealDefinition (20 bytes)."""

    MAP_NAME = "hc_pckt_srcs_map"

    def __init__(self, pin_base_path: str, map_name: str | None = None) -> None:
        super().__init__(pin_base_path, map_name)

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return REAL_DEFINITION_SIZE

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: RealDefinition) -> bytes:
        return value.to_bytes()

    def _deserialize_value(self, data: bytes) -> RealDefinition:
        return RealDefinition.from_bytes(data)
