"""
VIP lifecycle management for Katran load balancer.

This module implements the VipManager class which coordinates VIP configuration,
index allocation, and BPF map updates. It matches the functionality of KatranLb
in katran/lib/KatranLb.cpp.

Key responsibilities:
- VIP CRUD operations
- VIP number allocation/recycling
- BPF vip_map synchronization
- VIP state tracking
"""

from __future__ import annotations

import logging
from threading import RLock
from typing import Optional

from katran.bpf.map_manager import IndexAllocator
from katran.bpf.maps.vip_map import VipMap
from katran.bpf.maps.ch_rings_map import ChRingsMap
from katran.core.constants import MAX_VIPS, Protocol, VipFlags
from katran.core.types import Vip, VipKey, IpAddress, _parse_ip_address
from katran.core.exceptions import (
    VipExistsError,
    VipNotFoundError,
    ResourceExhaustedError,
)


logger = logging.getLogger(__name__)


class VipManager:
    """
    Manages VIP lifecycle and coordinates with BPF maps.

    The VipManager provides a high-level interface for VIP operations
    while maintaining synchronization with the underlying BPF maps.

    Thread-safety: All public methods are thread-safe via internal locking.

    Example:
        >>> vip_mgr = VipManager(vip_map, ch_rings_map)
        >>> vip = vip_mgr.add_vip("10.200.1.1", 80, Protocol.TCP)
        >>> print(f"Added VIP with vip_num={vip.vip_num}")
        >>> vip_mgr.modify_flags(vip.key, VipFlags.NO_SPORT)
        >>> vip_mgr.remove_vip(vip.key)
    """

    def __init__(
        self,
        vip_map: VipMap,
        ch_rings_map: ChRingsMap,
        max_vips: int = MAX_VIPS,
    ) -> None:
        """
        Initialize VIP manager.

        Args:
            vip_map: VIP map wrapper for BPF vip_map
            ch_rings_map: Consistent hash rings map wrapper
            max_vips: Maximum number of VIPs (default: 512)
        """
        self._vip_map = vip_map
        self._ch_rings_map = ch_rings_map
        self._max_vips = max_vips

        # VIP state tracking
        self._vips: dict[VipKey, Vip] = {}
        self._vip_num_allocator = IndexAllocator(max_vips)

        # Thread safety
        self._lock = RLock()

        logger.info(f"VipManager initialized with max_vips={max_vips}")

    # =========================================================================
    # VIP CRUD Operations
    # =========================================================================

    def add_vip(
        self,
        address: str | IpAddress,
        port: int,
        protocol: Protocol | str,
        flags: VipFlags = VipFlags.NONE,
    ) -> Vip:
        """
        Add new VIP.

        Allocates a vip_num, initializes empty hash ring, and writes
        to BPF vip_map.

        Args:
            address: VIP IP address (string or address object)
            port: VIP port number (1-65535)
            protocol: IP protocol (TCP, UDP, or string)
            flags: VIP behavior flags (default: NONE)

        Returns:
            Created Vip object with allocated vip_num

        Raises:
            VipExistsError: If VIP already exists
            ResourceExhaustedError: If max VIPs reached
            ValueError: If address/port/protocol invalid

        Example:
            >>> vip = vip_mgr.add_vip("10.200.1.1", 80, Protocol.TCP)
            >>> vip = vip_mgr.add_vip("10.200.1.2", 443, "tcp", VipFlags.NO_SPORT)
        """
        with self._lock:
            # Parse address if string
            if isinstance(address, str):
                address = _parse_ip_address(address)

            # Parse protocol if string
            if isinstance(protocol, str):
                protocol = Protocol[protocol.upper()]

            # Create VIP key
            key = VipKey(address=address, port=port, protocol=protocol)

            # Check if VIP already exists
            if key in self._vips:
                raise VipExistsError(
                    str(key.address), key.port, key.protocol.name
                )

            # Allocate vip_num
            vip_num = self._vip_num_allocator.allocate()

            # Create VIP object
            vip = Vip(key=key, flags=flags, vip_num=vip_num)

            # Initialize empty hash ring in ch_rings_map
            # (prevents lookups from returning garbage data)
            empty_ring = [0] * self._ch_rings_map.ring_size
            self._ch_rings_map.write_ring(vip_num, empty_ring, optimize=False)

            # Write to BPF vip_map
            self._vip_map.add_vip(vip)

            # Store in local state
            self._vips[key] = vip

            logger.info(
                f"Added VIP {key} with vip_num={vip_num}, flags={flags}"
            )

            return vip

    def remove_vip(
        self,
        key: VipKey | None = None,
        address: str | IpAddress | None = None,
        port: int | None = None,
        protocol: Protocol | str | None = None,
    ) -> bool:
        """
        Remove VIP and all associated backends.

        Can be called with either a VipKey or individual address/port/protocol.

        Args:
            key: VIP key to remove (if provided, other args ignored)
            address: VIP IP address (if key not provided)
            port: VIP port (if key not provided)
            protocol: IP protocol (if key not provided)

        Returns:
            True if removed, False if not found

        Example:
            >>> # Remove by key
            >>> vip_mgr.remove_vip(key=vip.key)
            >>> # Remove by address/port/protocol
            >>> vip_mgr.remove_vip(address="10.200.1.1", port=80, protocol="tcp")
        """
        with self._lock:
            # Build key if not provided
            if key is None:
                if address is None or port is None or protocol is None:
                    raise ValueError(
                        "Must provide either key or address/port/protocol"
                    )
                if isinstance(address, str):
                    address = _parse_ip_address(address)
                if isinstance(protocol, str):
                    protocol = Protocol[protocol.upper()]
                key = VipKey(address=address, port=port, protocol=protocol)

            # Check if VIP exists
            vip = self._vips.get(key)
            if vip is None:
                return False

            # Remove from BPF vip_map
            self._vip_map.remove_vip(key)

            # Free vip_num for reuse
            self._vip_num_allocator.free(vip.vip_num)

            # Remove from local state
            del self._vips[key]

            logger.info(f"Removed VIP {key} (vip_num={vip.vip_num})")

            return True

    def get_vip(
        self,
        key: VipKey | None = None,
        address: str | IpAddress | None = None,
        port: int | None = None,
        protocol: Protocol | str | None = None,
    ) -> Optional[Vip]:
        """
        Get VIP by key or address/port/protocol.

        Args:
            key: VIP key (if provided, other args ignored)
            address: VIP IP address (if key not provided)
            port: VIP port (if key not provided)
            protocol: IP protocol (if key not provided)

        Returns:
            Vip object if found, None otherwise

        Example:
            >>> vip = vip_mgr.get_vip(key=vip_key)
            >>> vip = vip_mgr.get_vip(address="10.200.1.1", port=80, protocol="tcp")
        """
        with self._lock:
            # Build key if not provided
            if key is None:
                if address is None or port is None or protocol is None:
                    return None
                if isinstance(address, str):
                    address = _parse_ip_address(address)
                if isinstance(protocol, str):
                    protocol = Protocol[protocol.upper()]
                key = VipKey(address=address, port=port, protocol=protocol)

            return self._vips.get(key)

    def list_vips(self) -> list[Vip]:
        """
        List all configured VIPs.

        Returns:
            List of all Vip objects

        Example:
            >>> for vip in vip_mgr.list_vips():
            ...     print(f"{vip.key}: {len(vip.reals)} backends")
        """
        with self._lock:
            return list(self._vips.values())

    def modify_flags(
        self,
        key: VipKey,
        flags: VipFlags,
    ) -> bool:
        """
        Modify VIP flags.

        Updates both local state and BPF vip_map.

        Args:
            key: VIP key
            flags: New flags value

        Returns:
            True if updated, False if VIP not found

        Example:
            >>> # Disable source port hashing
            >>> vip_mgr.modify_flags(vip.key, VipFlags.NO_SPORT)
            >>> # Combine flags
            >>> vip_mgr.modify_flags(vip.key, VipFlags.NO_SPORT | VipFlags.NO_LRU)
        """
        with self._lock:
            vip = self._vips.get(key)
            if vip is None:
                return False

            # Update local state
            vip.flags = flags

            # Sync to BPF map
            meta = vip.to_vip_meta()
            self._vip_map.set(key, meta)

            logger.info(f"Modified VIP {key} flags to {flags}")

            return True

    # =========================================================================
    # VIP Query Operations
    # =========================================================================

    def vip_exists(self, key: VipKey) -> bool:
        """
        Check if VIP exists.

        Args:
            key: VIP key to check

        Returns:
            True if VIP exists, False otherwise
        """
        with self._lock:
            return key in self._vips

    def get_vip_count(self) -> int:
        """
        Get total number of configured VIPs.

        Returns:
            Count of VIPs
        """
        with self._lock:
            return len(self._vips)

    def get_available_vip_count(self) -> int:
        """
        Get number of available VIP slots.

        Returns:
            Number of VIPs that can still be allocated
        """
        with self._lock:
            return self._vip_num_allocator.available_count()

    def get_vip_by_num(self, vip_num: int) -> Optional[Vip]:
        """
        Get VIP by vip_num (reverse lookup).

        Args:
            vip_num: VIP number to search for

        Returns:
            Vip object if found, None otherwise

        Note:
            This is O(n) as it searches all VIPs. Use sparingly.
        """
        with self._lock:
            for vip in self._vips.values():
                if vip.vip_num == vip_num:
                    return vip
            return None

    # =========================================================================
    # State Management
    # =========================================================================

    def clear_all(self) -> int:
        """
        Remove all VIPs.

        Warning: This is a destructive operation.

        Returns:
            Number of VIPs removed
        """
        with self._lock:
            count = len(self._vips)
            keys = list(self._vips.keys())

            for key in keys:
                self.remove_vip(key=key)

            logger.warning(f"Cleared all VIPs (removed {count})")

            return count

    def sync_from_bpf(self) -> None:
        """
        Synchronize local state from BPF vip_map.

        Rebuilds the local _vips dictionary by reading from the BPF map.
        Useful for recovering state after restart or detecting external changes.

        Note:
            This will not restore the backend lists - only VIP keys and metadata.
            Backend associations are managed by RealManager.
        """
        with self._lock:
            logger.info("Syncing VIP state from BPF vip_map")

            # Clear local state
            self._vips.clear()
            self._vip_num_allocator = IndexAllocator(self._max_vips)

            # Read all entries from BPF map
            for key, meta in self._vip_map.items():
                # Allocate the same vip_num (reserve it)
                self._vip_num_allocator.reserve(meta.vip_num)

                # Create Vip object
                vip = Vip(
                    key=key,
                    flags=meta.flags,
                    vip_num=meta.vip_num,
                )

                # Store in local state
                self._vips[key] = vip

            logger.info(f"Synced {len(self._vips)} VIPs from BPF map")

    def __len__(self) -> int:
        """Return number of configured VIPs."""
        return self.get_vip_count()

    def __contains__(self, key: VipKey) -> bool:
        """Check if VIP exists (supports 'in' operator)."""
        return self.vip_exists(key)

    def __repr__(self) -> str:
        """String representation of VipManager."""
        return (
            f"VipManager(vips={len(self._vips)}, "
            f"max={self._max_vips}, "
            f"available={self.get_available_vip_count()})"
        )
