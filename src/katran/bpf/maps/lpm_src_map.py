"""LPM trie map wrappers for source-based routing.

NOTE: LPM_TRIE maps do not support get_next_key (EOPNOTSUPP).
Do not call items()/keys()/values() -- SrcRoutingManager uses in-memory state.
"""

from __future__ import annotations

import struct

from katran.bpf.map_manager import BpfMap
from katran.core.constants import MAX_LPM_SRC
from katran.core.types import V4_LPM_KEY_SIZE, V6_LPM_KEY_SIZE, V4LpmKey, V6LpmKey


class LpmSrcV4Map(BpfMap[V4LpmKey, int]):
    """lpm_src_v4 BPF LPM trie: V4LpmKey -> real_index (u32)."""

    MAP_NAME = "lpm_src_v4"

    def __init__(
        self,
        pin_base_path: str,
        map_name: str | None = None,
        max_entries: int = MAX_LPM_SRC,
    ) -> None:
        super().__init__(pin_base_path, map_name)
        self._max_entries = max_entries

    @property
    def _key_size(self) -> int:
        return V4_LPM_KEY_SIZE

    @property
    def _value_size(self) -> int:
        return 4

    def _serialize_key(self, key: V4LpmKey) -> bytes:
        return key.to_bytes()

    def _deserialize_key(self, data: bytes) -> V4LpmKey:
        return V4LpmKey.from_bytes(data)

    def _serialize_value(self, value: int) -> bytes:
        return struct.pack("<I", value)

    def _deserialize_value(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])


class LpmSrcV6Map(BpfMap[V6LpmKey, int]):
    """lpm_src_v6 BPF LPM trie: V6LpmKey -> real_index (u32)."""

    MAP_NAME = "lpm_src_v6"

    def __init__(
        self,
        pin_base_path: str,
        map_name: str | None = None,
        max_entries: int = MAX_LPM_SRC,
    ) -> None:
        super().__init__(pin_base_path, map_name)
        self._max_entries = max_entries

    @property
    def _key_size(self) -> int:
        return V6_LPM_KEY_SIZE

    @property
    def _value_size(self) -> int:
        return 4

    def _serialize_key(self, key: V6LpmKey) -> bytes:
        return key.to_bytes()

    def _deserialize_key(self, data: bytes) -> V6LpmKey:
        return V6LpmKey.from_bytes(data)

    def _serialize_value(self, value: int) -> bytes:
        return struct.pack("<I", value)

    def _deserialize_value(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])
