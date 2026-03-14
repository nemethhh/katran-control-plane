"""HC packet MACs: index (0=src, 1=dst) -> HcMac."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import BpfMap
from katran.core.types import HcMac

HC_MAC_VALUE_SIZE = 8  # 6 bytes MAC + 2 padding


class HcPcktMacsMap(BpfMap[int, HcMac]):
    """hc_pckt_macs BPF array: index (0=src, 1=dst) -> HcMac (8 bytes)."""

    MAP_NAME = "hc_pckt_macs"

    def __init__(self, pin_base_path: str, map_name: str | None = None) -> None:
        super().__init__(pin_base_path, map_name)

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return HC_MAC_VALUE_SIZE

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: HcMac) -> bytes:
        return value.to_bytes()

    def _deserialize_value(self, data: bytes) -> HcMac:
        return HcMac.from_bytes(data)
