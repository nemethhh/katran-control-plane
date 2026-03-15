"""
Unit tests for BPF map manager and index allocator.
"""

import ctypes

import pytest

from katran.bpf.map_manager import BpfMapType, BpfMapUpdateFlags, IndexAllocator
from katran.core.exceptions import ResourceExhaustedError


class TestIndexAllocator:
    """Tests for IndexAllocator."""

    def test_allocate_returns_sequential(self) -> None:
        """Allocates indices starting from 0."""
        allocator = IndexAllocator(max_index=10)

        idx1 = allocator.allocate()
        idx2 = allocator.allocate()
        idx3 = allocator.allocate()

        assert idx1 == 0
        assert idx2 == 1
        assert idx3 == 2

    def test_free_and_reuse(self) -> None:
        """Freed indices can be reused."""
        allocator = IndexAllocator(max_index=10)

        idx1 = allocator.allocate()
        allocator.allocate()

        allocator.free(idx1)

        # Next allocation should reuse freed index
        idx3 = allocator.allocate()
        assert idx3 == idx1

    def test_exhaustion_raises(self) -> None:
        """ResourceExhaustedError when all indices used."""
        allocator = IndexAllocator(max_index=3)

        allocator.allocate()
        allocator.allocate()
        allocator.allocate()

        with pytest.raises(ResourceExhaustedError):
            allocator.allocate()

    def test_is_allocated(self) -> None:
        """is_allocated correctly tracks state."""
        allocator = IndexAllocator(max_index=10)

        assert not allocator.is_allocated(0)

        idx = allocator.allocate()
        assert allocator.is_allocated(idx)

        allocator.free(idx)
        assert not allocator.is_allocated(idx)

    def test_reserve(self) -> None:
        """Can reserve specific indices."""
        allocator = IndexAllocator(max_index=10)

        assert allocator.reserve(5)
        assert allocator.is_allocated(5)

        # Can't reserve again
        assert not allocator.reserve(5)

        # Other indices still available
        idx = allocator.allocate()
        assert idx != 5

    def test_counts(self) -> None:
        """available_count and allocated_count are accurate."""
        allocator = IndexAllocator(max_index=10)

        assert allocator.available_count == 10
        assert allocator.allocated_count == 0

        allocator.allocate()
        allocator.allocate()

        assert allocator.available_count == 8
        assert allocator.allocated_count == 2

    def test_free_unallocated_is_noop(self) -> None:
        """Freeing unallocated index doesn't cause issues."""
        allocator = IndexAllocator(max_index=10)

        # Should not raise
        allocator.free(5)
        allocator.free(999)  # Out of range

        # Counts unchanged
        assert allocator.available_count == 10

    def test_thread_safety(self) -> None:
        """Basic thread safety test."""
        import threading

        allocator = IndexAllocator(max_index=1000)
        allocated = []
        lock = threading.Lock()

        def allocate_many() -> None:
            for _ in range(100):
                idx = allocator.allocate()
                with lock:
                    allocated.append(idx)

        threads = [threading.Thread(target=allocate_many) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # All indices should be unique
        assert len(allocated) == 500
        assert len(set(allocated)) == 500


class TestBpfMapType:
    """Tests for BpfMapType enum."""

    def test_common_types(self) -> None:
        """Common map types have expected values."""
        assert BpfMapType.HASH == 1
        assert BpfMapType.ARRAY == 2
        assert BpfMapType.PERCPU_HASH == 5
        assert BpfMapType.PERCPU_ARRAY == 6
        assert BpfMapType.LRU_HASH == 9
        assert BpfMapType.ARRAY_OF_MAPS == 12


class TestBpfMapUpdateFlags:
    """Tests for BpfMapUpdateFlags enum."""

    def test_flag_values(self) -> None:
        """Update flags have expected values."""
        assert BpfMapUpdateFlags.ANY == 0
        assert BpfMapUpdateFlags.NOEXIST == 1
        assert BpfMapUpdateFlags.EXIST == 2


class TestBpfMapCreate:
    def test_bpf_attr_map_create_struct(self):
        from katran.bpf.map_manager import BpfAttrMapCreate
        attr = BpfAttrMapCreate()
        attr.map_type = 1
        attr.key_size = 4
        attr.value_size = 4
        attr.max_entries = 100
        attr.map_flags = 0
        assert ctypes.sizeof(attr) == 20

    def test_bpf_attr_get_id_struct(self):
        from katran.bpf.map_manager import BpfAttrGetId
        attr = BpfAttrGetId()
        attr.map_id = 42
        assert ctypes.sizeof(attr) >= 4

    def test_bpf_cmd_get_fd_by_id(self):
        from katran.bpf.map_manager import BpfCmd
        assert BpfCmd.MAP_GET_FD_BY_ID == 14
