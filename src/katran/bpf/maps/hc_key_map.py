"""HC key map: VipKey (hc_key struct, same layout) -> index (u32)."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import BpfMap
from katran.core.constants import MAX_VIPS
from katran.core.types import VIP_KEY_SIZE, VipKey


class HcKeyMap(BpfMap[VipKey, int]):
    """hc_key_map BPF hash: VipKey -> HC key index (u32)."""

    MAP_NAME = "hc_key_map"

    def __init__(
        self,
        pin_base_path: str,
        map_name: str | None = None,
        max_entries: int = MAX_VIPS,
    ) -> None:
        super().__init__(pin_base_path, map_name)
        self._max_entries = max_entries

    @property
    def _key_size(self) -> int:
        return VIP_KEY_SIZE

    @property
    def _value_size(self) -> int:
        return 4

    def _serialize_key(self, key: VipKey) -> bytes:
        return key.to_bytes()

    def _deserialize_key(self, data: bytes) -> VipKey:
        return VipKey.from_bytes(data)

    def _serialize_value(self, value: int) -> bytes:
        return struct.pack("<I", value)

    def _deserialize_value(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])
