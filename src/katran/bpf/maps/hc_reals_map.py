"""
Healthcheck reals map wrapper for BPF hc_reals_map.

The hc_reals_map is a hash map that maps SO_MARK values to backend indices.
This allows external health checkers to send packets with a specific SO_MARK
that get forwarded to the appropriate backend.

The TC BPF program (healthchecking_ipip) looks up the SO_MARK from the
packet's skb->mark and forwards it to the corresponding backend.

BPF Map Definition:
    Type: BPF_MAP_TYPE_HASH
    Key: __u32 (SO_MARK value, 4 bytes)
    Value: __u32 (real_index, 4 bytes)
    Max Entries: MAX_REALS (4096)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from katran.bpf.map_manager import BpfMap
from katran.core.constants import MAX_REALS


@dataclass
class HealthcheckMapping:
    """Mapping of SO_MARK to backend information."""

    mark: int
    real_index: int


class HcRealsMap(BpfMap[int, int]):
    """
    Wrapper for hc_reals_map BPF hash map.

    Maps SO_MARK values to backend indices for healthcheck routing.

    External health checkers set SO_MARK on their sockets, and the TC
    program routes packets to the appropriate backend via IPIP tunnel.

    Example:
        >>> with HcRealsMap("/sys/fs/bpf/katran") as hc:
        ...     # Add healthcheck destination
        ...     hc.add_healthcheck_dst(mark=1000, real_index=5)
        ...     # List all mappings
        ...     for mapping in hc.list_mappings():
        ...         print(f"Mark {mapping.mark} -> Backend {mapping.real_index}")
    """

    MAP_NAME = "hc_reals_map"

    def __init__(
        self,
        pin_base_path: str,
        map_name: str | None = None,
        max_reals: int = MAX_REALS,
    ) -> None:
        """
        Initialize healthcheck reals map wrapper.

        Args:
            pin_base_path: Base path where maps are pinned
            map_name: Map name (defaults to "hc_reals_map")
            max_reals: Maximum number of entries
        """
        super().__init__(pin_base_path, map_name)
        self._max_reals = max_reals
        self._mappings_cache: dict[int, int] = {}

    # -------------------------------------------------------------------------
    # Serialization methods
    # -------------------------------------------------------------------------

    @property
    def _key_size(self) -> int:
        return 4  # __u32

    @property
    def _value_size(self) -> int:
        return 4  # __u32

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return struct.unpack("<I", data)[0]

    def _serialize_value(self, value: int) -> bytes:
        return struct.pack("<I", value)

    def _deserialize_value(self, data: bytes) -> int:
        return struct.unpack("<I", data)[0]

    # -------------------------------------------------------------------------
    # Healthcheck mapping operations
    # -------------------------------------------------------------------------

    def add_healthcheck_dst(self, mark: int, real_index: int) -> None:
        """
        Add healthcheck routing for SO_MARK to backend.

        Args:
            mark: SO_MARK value used by health checker
            real_index: Backend index in reals array

        Raises:
            ValueError: If mark or real_index is invalid
        """
        if mark <= 0:
            raise ValueError(f"SO_MARK must be positive, got {mark}")
        if real_index <= 0:
            raise ValueError(f"real_index must be positive, got {real_index}")

        with self._lock:
            self.set(mark, real_index)
            self._mappings_cache[mark] = real_index

    def remove_healthcheck_dst(self, mark: int) -> bool:
        """
        Remove healthcheck routing for SO_MARK.

        Args:
            mark: SO_MARK value to remove

        Returns:
            True if removed, False if not found
        """
        with self._lock:
            if self.delete(mark):
                self._mappings_cache.pop(mark, None)
                return True
            return False

    def get_healthcheck_dst(self, mark: int) -> int | None:
        """
        Get backend index for SO_MARK.

        Args:
            mark: SO_MARK value

        Returns:
            real_index or None if not found
        """
        # Check cache first
        if mark in self._mappings_cache:
            return self._mappings_cache[mark]

        return self.get(mark)

    def list_mappings(self) -> list[HealthcheckMapping]:
        """
        List all SO_MARK to backend mappings.

        Returns:
            List of HealthcheckMapping
        """
        mappings = []
        for mark, real_index in self.items():
            mappings.append(HealthcheckMapping(mark=mark, real_index=real_index))
        return mappings

    def get_marks_for_real(self, real_index: int) -> list[int]:
        """
        Get all SO_MARK values mapped to a specific backend.

        Args:
            real_index: Backend index

        Returns:
            List of SO_MARK values
        """
        marks = []
        for mark, idx in self.items():
            if idx == real_index:
                marks.append(mark)
        return marks

    def clear_all(self) -> int:
        """
        Remove all healthcheck mappings.

        Returns:
            Number of mappings removed
        """
        count = 0
        with self._lock:
            # Collect all marks first to avoid modifying while iterating
            marks = list(self.keys())
            for mark in marks:
                if self.delete(mark):
                    count += 1
            self._mappings_cache.clear()
        return count

    def sync_from_map(self) -> None:
        """
        Synchronize internal cache from BPF map.

        Reads all entries and updates the internal cache.
        """
        with self._lock:
            self._mappings_cache.clear()
            for mark, real_index in self.items():
                self._mappings_cache[mark] = real_index

    @property
    def mapping_count(self) -> int:
        """Number of configured healthcheck mappings."""
        return len(self._mappings_cache)
