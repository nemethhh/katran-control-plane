"""Decap destination map: 16-byte address -> flags (u32)."""

from __future__ import annotations

import struct
from ipaddress import IPv4Address, IPv6Address, ip_address

from katran.bpf.map_manager import BpfMap
from katran.core.constants import MAX_DECAP_DST


class DecapDstMap(BpfMap[str, int]):
    """decap_dst BPF hash map: address (16 bytes) -> flags (u32)."""

    MAP_NAME = "decap_dst"

    def __init__(
        self,
        pin_base_path: str,
        map_name: str | None = None,
        max_entries: int = MAX_DECAP_DST,
    ) -> None:
        super().__init__(pin_base_path, map_name)
        self._max_entries = max_entries

    @property
    def _key_size(self) -> int:
        return 16

    @property
    def _value_size(self) -> int:
        return 4

    def _serialize_key(self, key: str) -> bytes:
        addr = ip_address(key)
        if isinstance(addr, IPv6Address):
            return addr.packed
        return addr.packed + b"\x00" * 12

    def _deserialize_key(self, data: bytes) -> str:
        if any(data[4:16]):
            return str(IPv6Address(data[:16]))
        return str(IPv4Address(data[:4]))

    def _serialize_value(self, value: int) -> bytes:
        return struct.pack("<I", value)

    def _deserialize_value(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])
