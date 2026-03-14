"""VIP-to-down-reals HASH_OF_MAPS wrapper.

Outer map: VipKey -> inner_map_id (u32).
Inner maps: BPF_MAP_TYPE_HASH with real_index (u32) -> dummy (u8).
Inner map lifecycle managed by DownRealManager.
"""

from __future__ import annotations

import struct

from katran.bpf.map_manager import BpfMap
from katran.core.constants import MAX_VIPS
from katran.core.types import VIP_KEY_SIZE, VipKey


class VipToDownRealsMap(BpfMap[VipKey, int]):
    """vip_to_down_reals BPF HASH_OF_MAPS: VipKey -> inner map ID (u32)."""

    MAP_NAME = "vip_to_down_reals"

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
