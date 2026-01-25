"""
Reals map wrapper for BPF reals array.

The reals array stores backend server definitions indexed by real_index.
This index is used in the consistent hash rings to map hash values to backends.

BPF Map Definition:
    Type: BPF_MAP_TYPE_ARRAY
    Key: __u32 (index, 4 bytes)
    Value: struct real_definition (20 bytes)
    Max Entries: MAX_REALS (4096)
"""

from __future__ import annotations

import struct

from katran.bpf.map_manager import BpfMap, IndexAllocator
from katran.core.constants import MAX_REALS
from katran.core.types import (
    RealDefinition,
    Real,
    REAL_DEFINITION_SIZE,
)


class RealsMap(BpfMap[int, RealDefinition]):
    """
    Wrapper for reals BPF array map.

    Manages backend server entries with automatic index allocation.
    Index 0 is reserved (represents "no backend").

    Example:
        >>> with RealsMap("/sys/fs/bpf/katran") as reals:
        ...     # Allocate and add a backend
        ...     idx = reals.allocate_and_set(
        ...         RealDefinition(IPv4Address("10.0.0.100"))
        ...     )
        ...     print(f"Backend at index {idx}")
        ...     # Remove backend
        ...     reals.free_index(idx)
    """

    MAP_NAME = "reals"

    def __init__(
        self,
        pin_base_path: str,
        map_name: str | None = None,
        max_reals: int = MAX_REALS,
    ) -> None:
        """
        Initialize reals map wrapper.

        Args:
            pin_base_path: Base path where maps are pinned
            map_name: Map name (defaults to "reals")
            max_reals: Maximum number of backends
        """
        super().__init__(pin_base_path, map_name)
        self._max_reals = max_reals
        # Reserve index 0 (represents no backend)
        self._index_allocator = IndexAllocator(max_reals)
        self._index_allocator.reserve(0)
        self._reals_cache: dict[int, RealDefinition] = {}

    # -------------------------------------------------------------------------
    # Serialization methods
    # -------------------------------------------------------------------------

    @property
    def _key_size(self) -> int:
        return 4  # __u32

    @property
    def _value_size(self) -> int:
        return REAL_DEFINITION_SIZE

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return struct.unpack("<I", data)[0]

    def _serialize_value(self, value: RealDefinition) -> bytes:
        return value.to_bytes()

    def _deserialize_value(self, data: bytes) -> RealDefinition:
        return RealDefinition.from_bytes(data)

    # -------------------------------------------------------------------------
    # Index allocation
    # -------------------------------------------------------------------------

    def allocate_index(self) -> int:
        """
        Allocate the next available backend index.

        Returns:
            Allocated index (1 to max_reals-1, index 0 is reserved)

        Raises:
            ResourceExhaustedError: If no indices available
        """
        return self._index_allocator.allocate()

    def free_index(self, index: int) -> None:
        """
        Free a previously allocated backend index.

        Note: This only frees the index for reuse. The entry in the
        BPF array map is not cleared to allow existing connections
        to continue using the backend.

        Args:
            index: Index to free
        """
        if index != 0:  # Don't free reserved index 0
            self._index_allocator.free(index)
            self._reals_cache.pop(index, None)

    def is_index_allocated(self, index: int) -> bool:
        """Check if an index is currently allocated."""
        return self._index_allocator.is_allocated(index)

    # -------------------------------------------------------------------------
    # High-level backend operations
    # -------------------------------------------------------------------------

    def allocate_and_set(self, real_def: RealDefinition) -> int:
        """
        Allocate an index and set the backend definition.

        Args:
            real_def: Backend server definition

        Returns:
            Allocated index

        Raises:
            ResourceExhaustedError: If no indices available
        """
        with self._lock:
            idx = self.allocate_index()
            self.set(idx, real_def)
            self._reals_cache[idx] = real_def
            return idx

    def add_real(self, real: Real) -> int:
        """
        Add a backend server.

        Allocates an index and stores the backend definition.

        Args:
            real: Backend server to add

        Returns:
            Allocated index (also sets real.index)
        """
        real_def = real.to_real_definition()
        idx = self.allocate_and_set(real_def)
        real.index = idx
        return idx

    def remove_real(self, index: int) -> bool:
        """
        Remove a backend server by index.

        This frees the index but does NOT clear the map entry to allow
        existing connections to continue. The entry will be overwritten
        when the index is reallocated.

        Args:
            index: Backend index to remove

        Returns:
            True if removed, False if index was not allocated
        """
        if not self.is_index_allocated(index):
            return False

        self.free_index(index)
        return True

    def get_real(self, index: int) -> RealDefinition | None:
        """
        Get backend definition by index.

        Args:
            index: Backend index

        Returns:
            RealDefinition if found, None otherwise
        """
        # Check cache first
        if index in self._reals_cache:
            return self._reals_cache[index]

        return self.get(index)

    def list_allocated_indices(self) -> list[int]:
        """
        List all allocated backend indices.

        Returns:
            List of allocated indices (excluding reserved index 0)
        """
        indices = []
        for i in range(1, self._max_reals):
            if self.is_index_allocated(i):
                indices.append(i)
        return indices

    def get_all_reals(self) -> dict[int, RealDefinition]:
        """
        Get all backends with their indices.

        Returns:
            Dictionary mapping index to RealDefinition
        """
        result = {}
        for idx in self.list_allocated_indices():
            real_def = self.get_real(idx)
            if real_def is not None:
                result[idx] = real_def
        return result

    def sync_from_map(self) -> None:
        """
        Synchronize internal state from BPF map.

        Reads all non-zero entries from the BPF map and updates
        the cache and allocator state.
        """
        with self._lock:
            self._reals_cache.clear()

            for i in range(1, self._max_reals):
                real_def = self.get(i)
                if real_def is not None:
                    # Check if entry is non-zero (has valid address)
                    if real_def.address.packed != b"\x00" * 4:
                        self._reals_cache[i] = real_def
                        self._index_allocator.reserve(i)

    @property
    def allocated_count(self) -> int:
        """Number of allocated backend slots (excluding reserved index 0)."""
        return self._index_allocator.allocated_count - 1  # Subtract reserved index 0

    @property
    def available_count(self) -> int:
        """Number of available backend slots."""
        return self._index_allocator.available_count
