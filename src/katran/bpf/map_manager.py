"""
Base class for BPF map operations.

Provides type-safe interface for interacting with BPF maps via pinned paths.
Uses ctypes and libc directly for BPF syscalls.

BPF Map Operations:
- Maps are pinned at /sys/fs/bpf/katran/<map_name>
- Operations use BPF_MAP_* commands via bpf() syscall
- Per-CPU maps aggregate values from all CPUs
"""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import os
from abc import ABC, abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from threading import RLock
from typing import Callable, Generic, TypeVar

from katran.core.exceptions import (
    BpfMapError,
    MapNotFoundError,
    MapOperationError,
    ResourceExhaustedError,
)

# Type variables for generic map wrapper
K = TypeVar("K")  # Key type
V = TypeVar("V")  # Value type


# =============================================================================
# BPF Syscall Constants and Structures
# =============================================================================


class BpfMapType(IntEnum):
    """BPF map types (from linux/bpf.h)."""

    UNSPEC = 0
    HASH = 1
    ARRAY = 2
    PROG_ARRAY = 3
    PERF_EVENT_ARRAY = 4
    PERCPU_HASH = 5
    PERCPU_ARRAY = 6
    STACK_TRACE = 7
    CGROUP_ARRAY = 8
    LRU_HASH = 9
    LRU_PERCPU_HASH = 10
    LPM_TRIE = 11
    ARRAY_OF_MAPS = 12
    HASH_OF_MAPS = 13


class BpfCmd(IntEnum):
    """BPF syscall commands (from linux/bpf.h)."""

    MAP_CREATE = 0
    MAP_LOOKUP_ELEM = 1
    MAP_UPDATE_ELEM = 2
    MAP_DELETE_ELEM = 3
    MAP_GET_NEXT_KEY = 4
    PROG_LOAD = 5
    OBJ_PIN = 6
    OBJ_GET = 7
    MAP_LOOKUP_AND_DELETE_ELEM = 17
    MAP_FREEZE = 22
    MAP_LOOKUP_BATCH = 24
    MAP_LOOKUP_AND_DELETE_BATCH = 25
    MAP_UPDATE_BATCH = 26
    MAP_DELETE_BATCH = 27


class BpfMapUpdateFlags(IntEnum):
    """Flags for BPF map update operations."""

    ANY = 0  # Create new or update existing
    NOEXIST = 1  # Create new only if it doesn't exist
    EXIST = 2  # Update existing only


# BPF syscall number varies by architecture
BPF_SYSCALL = {
    "x86_64": 321,
    "aarch64": 280,
    "arm64": 280,
}


def get_bpf_syscall() -> int:
    """Get the BPF syscall number for current architecture."""
    import platform

    machine = platform.machine()
    if machine in BPF_SYSCALL:
        return BPF_SYSCALL[machine]
    raise RuntimeError(f"Unsupported architecture: {machine}")


# =============================================================================
# libc Interface
# =============================================================================


def _load_libc() -> ctypes.CDLL:
    """Load libc for syscall access."""
    libc_path = ctypes.util.find_library("c")
    if libc_path is None:
        raise RuntimeError("Could not find libc")
    return ctypes.CDLL(libc_path, use_errno=True)


_libc = _load_libc()


def _bpf_syscall(cmd: int, attr: ctypes.Structure, size: int) -> int:
    """Make BPF syscall."""
    syscall_nr = get_bpf_syscall()
    result = _libc.syscall(syscall_nr, cmd, ctypes.byref(attr), size)
    if result < 0:
        err = ctypes.get_errno()
        return -err
    return result


# =============================================================================
# BPF Attribute Structures
# =============================================================================


class BpfAttrMapElem(ctypes.Structure):
    """Structure for BPF map element operations."""

    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value_or_next_key", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    ]


class BpfAttrObjGet(ctypes.Structure):
    """Structure for BPF object get operations."""

    _fields_ = [
        ("pathname", ctypes.c_uint64),
        ("bpf_fd", ctypes.c_uint32),
        ("file_flags", ctypes.c_uint32),
    ]


class BpfMapInfo(ctypes.Structure):
    """Structure for BPF map info."""

    _fields_ = [
        ("type", ctypes.c_uint32),
        ("id", ctypes.c_uint32),
        ("key_size", ctypes.c_uint32),
        ("value_size", ctypes.c_uint32),
        ("max_entries", ctypes.c_uint32),
        ("map_flags", ctypes.c_uint32),
        ("name", ctypes.c_char * 16),
    ]


# =============================================================================
# Index Allocator
# =============================================================================


class IndexAllocator:
    """
    Thread-safe index allocator for VIPs and reals.

    Manages allocation and freeing of integer indices within a range.
    """

    def __init__(self, max_index: int) -> None:
        """
        Initialize allocator.

        Args:
            max_index: Maximum index value (exclusive)
        """
        self._max_index = max_index
        self._free_indices: set[int] = set(range(max_index))
        self._allocated: set[int] = set()
        self._lock = RLock()

    def allocate(self) -> int:
        """
        Allocate the next available index.

        Returns:
            Allocated index

        Raises:
            ResourceExhaustedError: If no indices available
        """
        with self._lock:
            if not self._free_indices:
                raise ResourceExhaustedError("indices", self._max_index)

            # Get lowest available index for predictability
            idx = min(self._free_indices)
            self._free_indices.remove(idx)
            self._allocated.add(idx)
            return idx

    def free(self, index: int) -> None:
        """
        Free a previously allocated index.

        Args:
            index: Index to free
        """
        with self._lock:
            if index in self._allocated:
                self._allocated.remove(index)
                self._free_indices.add(index)

    def is_allocated(self, index: int) -> bool:
        """Check if an index is currently allocated."""
        with self._lock:
            return index in self._allocated

    def reserve(self, index: int) -> bool:
        """
        Reserve a specific index.

        Args:
            index: Index to reserve

        Returns:
            True if reserved, False if already allocated
        """
        with self._lock:
            if index in self._free_indices:
                self._free_indices.remove(index)
                self._allocated.add(index)
                return True
            return False

    @property
    def available_count(self) -> int:
        """Number of available indices."""
        with self._lock:
            return len(self._free_indices)

    @property
    def allocated_count(self) -> int:
        """Number of allocated indices."""
        with self._lock:
            return len(self._allocated)


# =============================================================================
# BPF Map Base Class
# =============================================================================


@dataclass
class MapInfo:
    """Information about a BPF map."""

    map_type: BpfMapType
    key_size: int
    value_size: int
    max_entries: int
    name: str


class BpfMap(ABC, Generic[K, V]):
    """
    Abstract base class for BPF map wrappers.

    Provides type-safe interface for map operations using pinned paths.
    Subclasses implement serialization/deserialization for specific types.

    Example:
        >>> class MyMap(BpfMap[int, str]):
        ...     def _serialize_key(self, key): return key.to_bytes(4, 'little')
        ...     # ... other methods
        >>>
        >>> with MyMap("/sys/fs/bpf/katran", "my_map") as m:
        ...     m.set(1, "hello")
        ...     print(m.get(1))
    """

    MAP_NAME: str = ""  # Override in subclasses

    def __init__(self, pin_base_path: str, map_name: str | None = None) -> None:
        """
        Initialize map wrapper.

        Args:
            pin_base_path: Base path where maps are pinned (e.g., /sys/fs/bpf/katran)
            map_name: Map name (defaults to MAP_NAME class attribute)
        """
        self._map_name = map_name or self.MAP_NAME
        self._pin_base_path = Path(pin_base_path)
        self._map_path = self._pin_base_path / self._map_name
        self._fd: int | None = None
        self._info: MapInfo | None = None
        self._lock = RLock()

    @property
    def map_name(self) -> str:
        """Name of the BPF map."""
        return self._map_name

    @property
    def map_path(self) -> Path:
        """Full path to the pinned map."""
        return self._map_path

    @property
    def is_open(self) -> bool:
        """Check if map is currently open."""
        return self._fd is not None

    @property
    def fd(self) -> int:
        """File descriptor of open map."""
        if self._fd is None:
            raise BpfMapError(f"Map '{self._map_name}' is not open")
        return self._fd

    # -------------------------------------------------------------------------
    # Abstract methods - implement in subclasses
    # -------------------------------------------------------------------------

    @abstractmethod
    def _serialize_key(self, key: K) -> bytes:
        """Convert typed key to bytes for BPF."""
        pass

    @abstractmethod
    def _deserialize_key(self, data: bytes) -> K:
        """Convert bytes from BPF to typed key."""
        pass

    @abstractmethod
    def _serialize_value(self, value: V) -> bytes:
        """Convert typed value to bytes for BPF."""
        pass

    @abstractmethod
    def _deserialize_value(self, data: bytes) -> V:
        """Convert bytes from BPF to typed value."""
        pass

    @property
    @abstractmethod
    def _key_size(self) -> int:
        """Size of key in bytes."""
        pass

    @property
    @abstractmethod
    def _value_size(self) -> int:
        """Size of value in bytes."""
        pass

    # -------------------------------------------------------------------------
    # Map lifecycle methods
    # -------------------------------------------------------------------------

    def open(self) -> None:
        """
        Open the pinned BPF map.

        Raises:
            MapNotFoundError: If map file doesn't exist
            MapOperationError: If opening fails
        """
        with self._lock:
            if self._fd is not None:
                return  # Already open

            if not self._map_path.exists():
                raise MapNotFoundError(self._map_name, str(self._map_path))

            # Convert path to null-terminated C string
            path_bytes = str(self._map_path).encode() + b"\x00"
            path_buf = ctypes.create_string_buffer(path_bytes)

            attr = BpfAttrObjGet()
            attr.pathname = ctypes.cast(path_buf, ctypes.c_void_p).value or 0
            attr.bpf_fd = 0
            attr.file_flags = 0

            result = _bpf_syscall(BpfCmd.OBJ_GET, attr, ctypes.sizeof(attr))

            if result < 0:
                raise MapOperationError(
                    "open", self._map_name, error_code=-result, message=os.strerror(-result)
                )

            self._fd = result

    def close(self) -> None:
        """Close the map file descriptor."""
        with self._lock:
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None

    def __enter__(self) -> BpfMap[K, V]:
        """Context manager entry - opens the map."""
        self.open()
        return self

    def __exit__(self, *args: object) -> None:
        """Context manager exit - closes the map."""
        self.close()

    # -------------------------------------------------------------------------
    # Map operations
    # -------------------------------------------------------------------------

    def get(self, key: K) -> V | None:
        """
        Lookup value by key.

        Args:
            key: Key to lookup

        Returns:
            Value if found, None otherwise
        """
        with self._lock:
            key_bytes = self._serialize_key(key)
            value_bytes = self._lookup_raw(key_bytes)
            if value_bytes is None:
                return None
            return self._deserialize_value(value_bytes)

    def set(self, key: K, value: V, flags: BpfMapUpdateFlags = BpfMapUpdateFlags.ANY) -> None:
        """
        Insert or update key-value pair.

        Args:
            key: Key to insert/update
            value: Value to set
            flags: Update flags (ANY, NOEXIST, EXIST)

        Raises:
            MapOperationError: If operation fails
        """
        with self._lock:
            key_bytes = self._serialize_key(key)
            value_bytes = self._serialize_value(value)
            self._update_raw(key_bytes, value_bytes, flags)

    def delete(self, key: K) -> bool:
        """
        Delete key from map.

        Args:
            key: Key to delete

        Returns:
            True if deleted, False if key not found
        """
        with self._lock:
            key_bytes = self._serialize_key(key)
            return self._delete_raw(key_bytes)

    def items(self) -> Iterator[tuple[K, V]]:
        """
        Iterate over all key-value pairs.

        Yields:
            Tuples of (key, value)
        """
        with self._lock:
            for key_bytes, value_bytes in self._iterate_raw():
                key = self._deserialize_key(key_bytes)
                value = self._deserialize_value(value_bytes)
                yield key, value

    def keys(self) -> Iterator[K]:
        """Iterate over all keys."""
        for key, _ in self.items():
            yield key

    def values(self) -> Iterator[V]:
        """Iterate over all values."""
        for _, value in self.items():
            yield value

    def __bool__(self) -> bool:
        """Map is truthy when the FD is open."""
        return self._fd >= 0

    def __contains__(self, key: K) -> bool:
        """Check if key exists in map."""
        return self.get(key) is not None

    def __len__(self) -> int:
        """Return number of entries (for hash maps)."""
        count = 0
        for _ in self.keys():
            count += 1
        return count

    # -------------------------------------------------------------------------
    # Raw BPF operations
    # -------------------------------------------------------------------------

    def _lookup_raw(self, key: bytes) -> bytes | None:
        """Raw lookup operation."""
        key_buf = ctypes.create_string_buffer(key)
        value_buf = ctypes.create_string_buffer(self._value_size)

        attr = BpfAttrMapElem()
        attr.map_fd = self.fd
        attr.key = ctypes.cast(key_buf, ctypes.c_void_p).value or 0
        attr.value_or_next_key = ctypes.cast(value_buf, ctypes.c_void_p).value or 0
        attr.flags = 0

        result = _bpf_syscall(BpfCmd.MAP_LOOKUP_ELEM, attr, ctypes.sizeof(attr))

        if result < 0:
            if -result == errno.ENOENT:
                return None
            raise MapOperationError(
                "lookup", self._map_name, error_code=-result, message=os.strerror(-result)
            )

        return value_buf.raw

    def _update_raw(self, key: bytes, value: bytes, flags: BpfMapUpdateFlags) -> None:
        """Raw update operation."""
        key_buf = ctypes.create_string_buffer(key)
        value_buf = ctypes.create_string_buffer(value)

        attr = BpfAttrMapElem()
        attr.map_fd = self.fd
        attr.key = ctypes.cast(key_buf, ctypes.c_void_p).value or 0
        attr.value_or_next_key = ctypes.cast(value_buf, ctypes.c_void_p).value or 0
        attr.flags = flags

        result = _bpf_syscall(BpfCmd.MAP_UPDATE_ELEM, attr, ctypes.sizeof(attr))

        if result < 0:
            raise MapOperationError(
                "update", self._map_name, error_code=-result, message=os.strerror(-result)
            )

    def _delete_raw(self, key: bytes) -> bool:
        """Raw delete operation."""
        key_buf = ctypes.create_string_buffer(key)

        attr = BpfAttrMapElem()
        attr.map_fd = self.fd
        attr.key = ctypes.cast(key_buf, ctypes.c_void_p).value or 0
        attr.value_or_next_key = 0
        attr.flags = 0

        result = _bpf_syscall(BpfCmd.MAP_DELETE_ELEM, attr, ctypes.sizeof(attr))

        if result < 0:
            if -result == errno.ENOENT:
                return False
            raise MapOperationError(
                "delete", self._map_name, error_code=-result, message=os.strerror(-result)
            )

        return True

    def _iterate_raw(self) -> Iterator[tuple[bytes, bytes]]:
        """Raw iteration using get_next_key."""
        key_buf = ctypes.create_string_buffer(self._key_size)
        next_key_buf = ctypes.create_string_buffer(self._key_size)
        value_buf = ctypes.create_string_buffer(self._value_size)

        # Start with NULL key to get first key
        attr = BpfAttrMapElem()
        attr.map_fd = self.fd
        attr.key = 0  # NULL for first key
        attr.value_or_next_key = ctypes.cast(next_key_buf, ctypes.c_void_p).value or 0
        attr.flags = 0

        result = _bpf_syscall(BpfCmd.MAP_GET_NEXT_KEY, attr, ctypes.sizeof(attr))

        while result >= 0:
            # Copy next_key to key for lookup and next iteration
            ctypes.memmove(key_buf, next_key_buf, self._key_size)

            # Lookup value for current key
            attr2 = BpfAttrMapElem()
            attr2.map_fd = self.fd
            attr2.key = ctypes.cast(key_buf, ctypes.c_void_p).value or 0
            attr2.value_or_next_key = ctypes.cast(value_buf, ctypes.c_void_p).value or 0
            attr2.flags = 0

            lookup_result = _bpf_syscall(BpfCmd.MAP_LOOKUP_ELEM, attr2, ctypes.sizeof(attr2))
            if lookup_result >= 0:
                yield bytes(key_buf.raw), bytes(value_buf.raw)

            # Get next key
            attr.key = ctypes.cast(key_buf, ctypes.c_void_p).value or 0
            result = _bpf_syscall(BpfCmd.MAP_GET_NEXT_KEY, attr, ctypes.sizeof(attr))


# =============================================================================
# Per-CPU BPF Map Base Class
# =============================================================================


class PerCpuBpfMap(BpfMap[K, V]):
    """
    Base class for per-CPU BPF maps.

    Per-CPU maps store separate values for each CPU. This class provides
    methods to read values from all CPUs and aggregate them.
    """

    def __init__(
        self, pin_base_path: str, map_name: str | None = None, num_cpus: int | None = None
    ) -> None:
        """
        Initialize per-CPU map wrapper.

        Args:
            pin_base_path: Base path where maps are pinned
            map_name: Map name
            num_cpus: Number of CPUs (auto-detected if None)
        """
        super().__init__(pin_base_path, map_name)
        self._num_cpus = num_cpus or self._detect_num_cpus()

    @staticmethod
    def _detect_num_cpus() -> int:
        """Detect number of possible CPUs."""
        try:
            # Read from /sys/devices/system/cpu/possible
            with open("/sys/devices/system/cpu/possible") as f:
                cpus_str = f.read().strip()
                # Parse format like "0-127" or "0,1,2,3"
                if "-" in cpus_str:
                    parts = cpus_str.split("-")
                    return int(parts[-1]) + 1
                else:
                    return len(cpus_str.split(","))
        except Exception:
            # Fallback to online CPUs
            return os.cpu_count() or 1

    @property
    def _percpu_value_size(self) -> int:
        """Total size of per-CPU values array."""
        # Per-CPU values are stored in an array with 8-byte alignment per CPU
        aligned_size = (self._value_size + 7) & ~7  # Round up to 8 bytes
        return aligned_size * self._num_cpus

    def get_all_cpus(self, key: K) -> list[V]:
        """
        Get values from all CPUs.

        Args:
            key: Key to lookup

        Returns:
            List of values, one per CPU
        """
        with self._lock:
            key_bytes = self._serialize_key(key)
            value_bytes = self._lookup_percpu_raw(key_bytes)

            if value_bytes is None:
                return []

            # Parse per-CPU array
            aligned_size = (self._value_size + 7) & ~7
            values = []
            for i in range(self._num_cpus):
                offset = i * aligned_size
                cpu_value_bytes = value_bytes[offset : offset + self._value_size]
                values.append(self._deserialize_value(cpu_value_bytes))

            return values

    def aggregate(self, key: K, aggregator: Callable[[list[V]], V]) -> V:
        """
        Aggregate per-CPU values using provided function.

        Args:
            key: Key to lookup
            aggregator: Function to aggregate values

        Returns:
            Aggregated value
        """
        values = self.get_all_cpus(key)
        return aggregator(values)

    def _lookup_percpu_raw(self, key: bytes) -> bytes | None:
        """Raw lookup for per-CPU map."""
        key_buf = ctypes.create_string_buffer(key)
        value_buf = ctypes.create_string_buffer(self._percpu_value_size)

        attr = BpfAttrMapElem()
        attr.map_fd = self.fd
        attr.key = ctypes.cast(key_buf, ctypes.c_void_p).value or 0
        attr.value_or_next_key = ctypes.cast(value_buf, ctypes.c_void_p).value or 0
        attr.flags = 0

        result = _bpf_syscall(BpfCmd.MAP_LOOKUP_ELEM, attr, ctypes.sizeof(attr))

        if result < 0:
            if -result == errno.ENOENT:
                return None
            raise MapOperationError(
                "lookup_percpu", self._map_name, error_code=-result, message=os.strerror(-result)
            )

        return value_buf.raw

    # Override get to aggregate by default
    def get(self, key: K) -> V | None:
        """
        Get aggregated value for key.

        For per-CPU maps, this aggregates values from all CPUs by summing
        numeric fields. Override _aggregate_values for custom aggregation.
        """
        values = self.get_all_cpus(key)
        if not values:
            return None
        return self._aggregate_values(values)

    def _iterate_raw(self) -> Iterator[tuple[bytes, bytes]]:
        """
        Raw iteration for per-CPU maps.

        Overrides base class to use _percpu_value_size for the value buffer.
        The base class uses _value_size which is the single-CPU size; for
        per-CPU maps the kernel writes num_cpus * aligned_value_size bytes
        into the buffer, causing a heap overflow if the buffer is too small.
        """
        key_buf = ctypes.create_string_buffer(self._key_size)
        next_key_buf = ctypes.create_string_buffer(self._key_size)
        value_buf = ctypes.create_string_buffer(self._percpu_value_size)

        # Start with NULL key to get first key
        attr = BpfAttrMapElem()
        attr.map_fd = self.fd
        attr.key = 0  # NULL for first key
        attr.value_or_next_key = ctypes.cast(next_key_buf, ctypes.c_void_p).value or 0
        attr.flags = 0

        result = _bpf_syscall(BpfCmd.MAP_GET_NEXT_KEY, attr, ctypes.sizeof(attr))

        while result >= 0:
            ctypes.memmove(key_buf, next_key_buf, self._key_size)

            attr2 = BpfAttrMapElem()
            attr2.map_fd = self.fd
            attr2.key = ctypes.cast(key_buf, ctypes.c_void_p).value or 0
            attr2.value_or_next_key = ctypes.cast(value_buf, ctypes.c_void_p).value or 0
            attr2.flags = 0

            lookup_result = _bpf_syscall(BpfCmd.MAP_LOOKUP_ELEM, attr2, ctypes.sizeof(attr2))
            if lookup_result >= 0:
                yield bytes(key_buf.raw), bytes(value_buf.raw)

            attr.key = ctypes.cast(key_buf, ctypes.c_void_p).value or 0
            result = _bpf_syscall(BpfCmd.MAP_GET_NEXT_KEY, attr, ctypes.sizeof(attr))

    def _aggregate_values(self, values: list[V]) -> V:
        """
        Aggregate per-CPU values.

        Default implementation returns the first value.
        Override in subclasses for type-specific aggregation.
        """
        return values[0] if values else None  # type: ignore
