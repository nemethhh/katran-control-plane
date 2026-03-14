"""
VIP map wrapper for BPF vip_map.

The vip_map is a hash map that maps VIP definitions (address:port:proto)
to VIP metadata (flags and vip_num index).

BPF Map Definition:
    Type: BPF_MAP_TYPE_HASH
    Key: struct vip_definition (20 bytes)
    Value: struct vip_meta (8 bytes)
    Max Entries: MAX_VIPS (512)
"""

from __future__ import annotations

from katran.bpf.map_manager import BpfMap, IndexAllocator
from katran.core.constants import MAX_VIPS, VipFlags
from katran.core.exceptions import VipExistsError
from katran.core.types import (
    VIP_KEY_SIZE,
    VIP_META_SIZE,
    Vip,
    VipKey,
    VipMeta,
)


class VipMap(BpfMap[VipKey, VipMeta]):
    """
    Wrapper for vip_map BPF hash map.

    Provides VIP CRUD operations with automatic vip_num allocation.

    Example:
        >>> with VipMap("/sys/fs/bpf/katran") as vip_map:
        ...     # Add a VIP
        ...     vip_num = vip_map.add_vip(
        ...         VipKey(IPv4Address("10.200.1.1"), 80, Protocol.TCP),
        ...         VipFlags.NONE
        ...     )
        ...     # List VIPs
        ...     for vip_key in vip_map.list_vips():
        ...         print(vip_key)
    """

    MAP_NAME = "vip_map"

    def __init__(
        self,
        pin_base_path: str,
        map_name: str | None = None,
        max_vips: int = MAX_VIPS,
    ) -> None:
        """
        Initialize VIP map wrapper.

        Args:
            pin_base_path: Base path where maps are pinned
            map_name: Map name (defaults to "vip_map")
            max_vips: Maximum number of VIPs for index allocation
        """
        super().__init__(pin_base_path, map_name)
        self._vip_num_allocator = IndexAllocator(max_vips)
        self._vip_cache: dict[VipKey, VipMeta] = {}

    # -------------------------------------------------------------------------
    # Serialization methods
    # -------------------------------------------------------------------------

    @property
    def _key_size(self) -> int:
        return VIP_KEY_SIZE

    @property
    def _value_size(self) -> int:
        return VIP_META_SIZE

    def _serialize_key(self, key: VipKey) -> bytes:
        return key.to_bytes()

    def _deserialize_key(self, data: bytes) -> VipKey:
        return VipKey.from_bytes(data)

    def _serialize_value(self, value: VipMeta) -> bytes:
        return value.to_bytes()

    def _deserialize_value(self, data: bytes) -> VipMeta:
        return VipMeta.from_bytes(data)

    # -------------------------------------------------------------------------
    # High-level VIP operations
    # -------------------------------------------------------------------------

    def add_vip(self, vip: Vip) -> int:
        """
        Add VIP to the map.

        Allocates a vip_num and writes to the BPF map.

        Args:
            vip: VIP to add

        Returns:
            Allocated vip_num

        Raises:
            VipExistsError: If VIP already exists
            ResourceExhaustedError: If max VIPs reached
        """
        with self._lock:
            # Check if VIP already exists
            if vip.key in self._vip_cache or self.get(vip.key) is not None:
                raise VipExistsError(str(vip.key.address), vip.key.port, vip.key.protocol.name)

            # Allocate vip_num
            vip_num = self._vip_num_allocator.allocate()
            vip.vip_num = vip_num

            # Create metadata
            meta = VipMeta(flags=vip.flags, vip_num=vip_num)

            # Write to BPF map
            self.set(vip.key, meta)

            # Update cache
            self._vip_cache[vip.key] = meta

            return vip_num

    def remove_vip(self, key: VipKey) -> bool:
        """
        Remove VIP from the map.

        Frees the vip_num and removes from BPF map.

        Args:
            key: VIP key to remove

        Returns:
            True if removed, False if not found
        """
        with self._lock:
            # Get current metadata to free vip_num
            meta = self.get(key)
            if meta is None:
                return False

            # Delete from BPF map
            if not self.delete(key):
                return False

            # Free vip_num
            self._vip_num_allocator.free(meta.vip_num)

            # Remove from cache
            self._vip_cache.pop(key, None)

            return True

    def get_vip(self, key: VipKey) -> VipMeta | None:
        """
        Get VIP metadata by key.

        Args:
            key: VIP key to lookup

        Returns:
            VipMeta if found, None otherwise
        """
        # Check cache first
        if key in self._vip_cache:
            return self._vip_cache[key]

        # Lookup in BPF map
        return self.get(key)

    def list_vips(self) -> list[VipKey]:
        """
        List all configured VIPs.

        Returns:
            List of VipKey for all VIPs
        """
        return list(self.keys())

    def get_all_vips(self) -> dict[VipKey, VipMeta]:
        """
        Get all VIPs with their metadata.

        Returns:
            Dictionary mapping VipKey to VipMeta
        """
        return dict(self.items())

    def update_flags(self, key: VipKey, flags: int) -> bool:
        """
        Update VIP flags.

        Args:
            key: VIP key
            flags: New flags value

        Returns:
            True if updated, False if VIP not found
        """
        with self._lock:
            meta = self.get(key)
            if meta is None:
                return False

            # Update flags, keep vip_num
            new_meta = VipMeta(flags=VipFlags(flags), vip_num=meta.vip_num)
            self.set(key, new_meta)

            # Update cache
            self._vip_cache[key] = new_meta

            return True

    def sync_from_map(self) -> None:
        """
        Synchronize internal state from BPF map.

        Reads all entries from the BPF map and updates the cache
        and allocator state. Call this after loading programs to
        restore state.
        """
        with self._lock:
            self._vip_cache.clear()

            for key, meta in self.items():
                self._vip_cache[key] = meta
                # Mark vip_num as allocated
                self._vip_num_allocator.reserve(meta.vip_num)

    @property
    def vip_count(self) -> int:
        """Number of configured VIPs."""
        return len(self._vip_cache)

    @property
    def available_vip_slots(self) -> int:
        """Number of available VIP slots."""
        return self._vip_num_allocator.available_count
