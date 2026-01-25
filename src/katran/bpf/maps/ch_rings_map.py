"""
Consistent hash rings map wrapper for BPF ch_rings array.

The ch_rings array stores Maglev consistent hash rings for all VIPs.
Each VIP has RING_SIZE (65537) entries, and the total array is
MAX_VIPS * RING_SIZE entries.

Each entry contains a backend index (real_index) that packets matching
that hash position should be forwarded to.

BPF Map Definition:
    Type: BPF_MAP_TYPE_ARRAY
    Key: __u32 (index = vip_num * RING_SIZE + position, 4 bytes)
    Value: __u32 (real_index, 4 bytes)
    Max Entries: CH_RINGS_SIZE (MAX_VIPS * RING_SIZE = 512 * 65537)
"""

from __future__ import annotations

import struct
from typing import Sequence

from katran.bpf.map_manager import BpfMap
from katran.core.constants import RING_SIZE, MAX_VIPS, CH_RINGS_SIZE


class ChRingsMap(BpfMap[int, int]):
    """
    Wrapper for ch_rings BPF array map.

    Manages consistent hash rings for VIPs. Each VIP has a ring of
    RING_SIZE entries containing backend indices.

    The ring index for a VIP is: vip_num * RING_SIZE + position

    Example:
        >>> with ChRingsMap("/sys/fs/bpf/katran") as rings:
        ...     # Write ring for VIP 0
        ...     ring = [1, 2, 1, 2, 1, ...]  # alternating backends
        ...     rings.write_ring(vip_num=0, ring=ring)
        ...     # Read ring
        ...     ring = rings.read_ring(vip_num=0)
    """

    MAP_NAME = "ch_rings"

    def __init__(
        self,
        pin_base_path: str,
        map_name: str | None = None,
        ring_size: int = RING_SIZE,
        max_vips: int = MAX_VIPS,
    ) -> None:
        """
        Initialize consistent hash rings map wrapper.

        Args:
            pin_base_path: Base path where maps are pinned
            map_name: Map name (defaults to "ch_rings")
            ring_size: Size of each VIP's ring (default: 65537)
            max_vips: Maximum number of VIPs (default: 512)
        """
        super().__init__(pin_base_path, map_name)
        self._ring_size = ring_size
        self._max_vips = max_vips

    @property
    def ring_size(self) -> int:
        """Size of each VIP's hash ring."""
        return self._ring_size

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
    # Ring index calculation
    # -------------------------------------------------------------------------

    def get_ring_base(self, vip_num: int) -> int:
        """
        Get base index for VIP's ring in the array.

        Args:
            vip_num: VIP index number

        Returns:
            Base index in ch_rings array
        """
        return vip_num * self._ring_size

    def get_ring_index(self, vip_num: int, position: int) -> int:
        """
        Get array index for a specific ring position.

        Args:
            vip_num: VIP index number
            position: Position within the ring (0 to ring_size-1)

        Returns:
            Index in ch_rings array
        """
        return self.get_ring_base(vip_num) + position

    # -------------------------------------------------------------------------
    # Ring operations
    # -------------------------------------------------------------------------

    def write_ring(self, vip_num: int, ring: Sequence[int]) -> None:
        """
        Write complete ring for VIP.

        Args:
            vip_num: VIP index number
            ring: List of real_index values (must be ring_size length)

        Raises:
            ValueError: If ring length doesn't match ring_size
        """
        if len(ring) != self._ring_size:
            raise ValueError(
                f"Ring length {len(ring)} doesn't match ring_size {self._ring_size}"
            )

        base = self.get_ring_base(vip_num)

        with self._lock:
            for i, real_idx in enumerate(ring):
                self.set(base + i, real_idx)

    def write_ring_batch(self, vip_num: int, ring: Sequence[int]) -> None:
        """
        Write complete ring for VIP using batch operations if available.

        This is an optimized version that writes entries in batches
        for better performance. Falls back to write_ring if batch
        operations are not supported.

        Args:
            vip_num: VIP index number
            ring: List of real_index values
        """
        # For now, fall back to standard write
        # TODO: Implement batch update when supported
        self.write_ring(vip_num, ring)

    def read_ring(self, vip_num: int) -> list[int]:
        """
        Read complete ring for VIP.

        Args:
            vip_num: VIP index number

        Returns:
            List of real_index values
        """
        base = self.get_ring_base(vip_num)
        ring = []

        with self._lock:
            for i in range(self._ring_size):
                value = self.get(base + i)
                ring.append(value if value is not None else 0)

        return ring

    def lookup_ring_position(self, vip_num: int, position: int) -> int:
        """
        Lookup a single position in a VIP's ring.

        Args:
            vip_num: VIP index number
            position: Position within the ring

        Returns:
            real_index at that position, or 0 if not found
        """
        idx = self.get_ring_index(vip_num, position)
        value = self.get(idx)
        return value if value is not None else 0

    def clear_ring(self, vip_num: int) -> None:
        """
        Clear a VIP's ring (set all entries to 0).

        Args:
            vip_num: VIP index number
        """
        empty_ring = [0] * self._ring_size
        self.write_ring(vip_num, empty_ring)

    def update_ring_positions(
        self,
        vip_num: int,
        updates: dict[int, int],
    ) -> None:
        """
        Update specific positions in a VIP's ring.

        This is more efficient than writing the entire ring when
        only a few positions need to change.

        Args:
            vip_num: VIP index number
            updates: Dictionary mapping position to new real_index
        """
        base = self.get_ring_base(vip_num)

        with self._lock:
            for position, real_idx in updates.items():
                self.set(base + position, real_idx)

    def get_ring_stats(self, vip_num: int) -> dict[int, int]:
        """
        Get distribution statistics for a VIP's ring.

        Args:
            vip_num: VIP index number

        Returns:
            Dictionary mapping real_index to count in ring
        """
        ring = self.read_ring(vip_num)
        stats: dict[int, int] = {}
        for real_idx in ring:
            stats[real_idx] = stats.get(real_idx, 0) + 1
        return stats

    def validate_ring(self, vip_num: int, expected_reals: set[int]) -> list[str]:
        """
        Validate a VIP's ring contains only expected backends.

        Args:
            vip_num: VIP index number
            expected_reals: Set of valid real_index values

        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        ring = self.read_ring(vip_num)

        for i, real_idx in enumerate(ring):
            if real_idx != 0 and real_idx not in expected_reals:
                errors.append(
                    f"Position {i} has invalid real_index {real_idx}"
                )

        # Check if any expected reals are missing
        ring_reals = set(ring) - {0}
        missing = expected_reals - ring_reals
        if missing:
            errors.append(f"Missing backends in ring: {missing}")

        return errors
