"""Healthcheck reals map: SO_MARK (u32) -> HcRealDefinition (20 bytes).

The BPF hc_reals_map stores the actual backend IP address (not an index)
in hc_real_definition format: 16-byte address + 1-byte flags + 3 padding.
"""

from __future__ import annotations

import struct

from katran.bpf.map_manager import BpfMap
from katran.core.constants import MAX_REALS
from katran.core.types import HC_REAL_DEFINITION_SIZE, HcRealDefinition


class HcRealsMap(BpfMap[int, HcRealDefinition]):
    """hc_reals_map BPF hash: SO_MARK (u32) -> HcRealDefinition (20 bytes)."""

    MAP_NAME = "hc_reals_map"

    def __init__(
        self,
        pin_base_path: str,
        map_name: str | None = None,
        max_reals: int = MAX_REALS,
        tunnel_based_hc: bool = True,
    ) -> None:
        super().__init__(pin_base_path, map_name)
        self._max_reals = max_reals
        self._tunnel_based_hc = tunnel_based_hc

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return HC_REAL_DEFINITION_SIZE

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: HcRealDefinition) -> bytes:
        return value.to_bytes(tunnel_based_hc=self._tunnel_based_hc)

    def _deserialize_value(self, data: bytes) -> HcRealDefinition:
        return HcRealDefinition.from_bytes(data, tunnel_based_hc=self._tunnel_based_hc)
