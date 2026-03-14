"""
Backend (real) server management for Katran load balancer.

This module implements the RealManager class which coordinates backend configuration,
reference counting, and consistent hash ring updates. It matches the functionality
of KatranLb's real management in katran/lib/KatranLb.cpp.

Key responsibilities:
- Backend CRUD operations per VIP
- Reference counting (backends shared across VIPs)
- Backend index allocation/recycling
- Consistent hash ring rebuild and optimization
- BPF reals and ch_rings map synchronization
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from threading import RLock
from typing import TYPE_CHECKING, Optional

from katran.bpf.maps.ch_rings_map import ChRingsMap
from katran.bpf.maps.reals_map import RealsMap
from katran.core.constants import MAX_REALS, RealFlags
from katran.core.exceptions import (
    RealExistsError,
)
from katran.core.types import IpAddress, Real, RealDefinition, _parse_ip_address
from katran.lb.maglev import Endpoint, MaglevHashRing, hash_endpoint_address

if TYPE_CHECKING:
    from katran.core.types import Vip


logger = logging.getLogger(__name__)


@dataclass
class RealMeta:
    """
    Metadata for tracking backend servers.

    Matches the RealMeta structure in katran/lib/KatranLb.cpp.

    Attributes:
        num: Backend index in reals array
        ref_count: Number of VIPs using this backend
        flags: Backend flags
    """

    num: int
    ref_count: int = 1
    flags: int = 0


class RealManager:
    """
    Manages backend servers for VIPs.

    The RealManager provides a high-level interface for backend operations
    with reference counting, hash ring management, and BPF map synchronization.

    Thread-safety: All public methods are thread-safe via internal locking.

    Reference Counting:
        Backends are shared across multiple VIPs. Each backend maintains a
        reference count tracking how many VIPs use it. When the count reaches
        zero, the backend is deleted and its index is recycled.

    Hash Ring Updates:
        When backends are added/removed/weighted, the consistent hash ring
        is rebuilt using the Maglev algorithm. Only changed ring positions
        are written to the BPF ch_rings map for efficiency.

    Example:
        >>> real_mgr = RealManager(reals_map, ch_rings_map, ring_builder)
        >>> # Add backend to VIP
        >>> real = real_mgr.add_real(vip, "10.0.0.100", weight=100)
        >>> # Change weight (for draining)
        >>> real_mgr.set_weight(vip, "10.0.0.100", weight=0)
        >>> # Remove backend
        >>> real_mgr.remove_real(vip, "10.0.0.100")
    """

    def __init__(
        self,
        reals_map: RealsMap,
        ch_rings_map: ChRingsMap,
        ring_builder: Optional[MaglevHashRing] = None,
        max_reals: int = MAX_REALS,
    ) -> None:
        """
        Initialize real manager.

        Args:
            reals_map: Reals map wrapper for BPF reals array
            ch_rings_map: Consistent hash rings map wrapper
            ring_builder: Maglev hash ring builder (creates default if None)
            max_reals: Maximum number of backends (default: 4096)
        """
        self._reals_map = reals_map
        self._ch_rings_map = ch_rings_map
        self._ring_builder = ring_builder or MaglevHashRing()
        self._max_reals = max_reals

        # Backend state tracking
        # Maps IP address → RealMeta (index, ref count, flags)
        self._reals: dict[IpAddress, RealMeta] = {}

        # Reverse lookup: index → IP address
        self._num_to_reals: dict[int, IpAddress] = {}

        # Thread safety
        self._lock = RLock()

        logger.info(f"RealManager initialized with max_reals={max_reals}")

    # =========================================================================
    # Backend CRUD Operations
    # =========================================================================

    def add_real(
        self,
        vip: Vip,
        address: str | IpAddress,
        weight: int = 100,
    ) -> Real:
        """
        Add backend server to VIP.

        If the backend already exists globally, increments its reference count.
        Otherwise, allocates a new index and adds to reals map.

        After adding, rebuilds the VIP's consistent hash ring and updates
        the BPF ch_rings map.

        Args:
            vip: VIP to add backend to
            address: Backend IP address
            weight: Backend weight for load balancing (default: 100)

        Returns:
            Real object with allocated index

        Raises:
            RealExistsError: If backend already exists for this VIP
            ResourceExhaustedError: If max reals reached

        Example:
            >>> real = real_mgr.add_real(vip, "10.0.0.100", weight=100)
            >>> print(f"Backend at index {real.index}")
        """
        with self._lock:
            # Parse address if string
            if isinstance(address, str):
                address = _parse_ip_address(address)

            # Check if backend already exists for this VIP
            for existing_real in vip.reals:
                if existing_real.address == address:
                    raise RealExistsError(str(address), str(vip.key))

            # Increase reference count or create new backend
            real_meta = self._increase_ref_count(address)

            # Create Real object
            real = Real(
                address=address,
                weight=weight,
                index=real_meta.num,
                flags=RealFlags(real_meta.flags),
            )

            # Add to VIP's backend list
            vip.reals.append(real)

            # Rebuild consistent hash ring
            self._rebuild_ring(vip)

            logger.info(
                f"Added real {address} (index={real.index}, weight={weight}) "
                f"to VIP {vip.key}, ref_count={real_meta.ref_count}"
            )

            return real

    def remove_real(
        self,
        vip: Vip,
        address: str | IpAddress,
    ) -> bool:
        """
        Remove backend from VIP.

        Decrements the backend's reference count. If count reaches zero,
        the backend is deleted from the reals map and its index is recycled.

        After removal, rebuilds the VIP's consistent hash ring.

        Args:
            vip: VIP to remove backend from
            address: Backend IP address

        Returns:
            True if removed, False if not found

        Example:
            >>> real_mgr.remove_real(vip, "10.0.0.100")
        """
        with self._lock:
            # Parse address if string
            if isinstance(address, str):
                address = _parse_ip_address(address)

            # Find backend in VIP's real list
            real = None
            for r in vip.reals:
                if r.address == address:
                    real = r
                    break

            if real is None:
                return False

            # Remove from VIP's backend list
            vip.reals.remove(real)

            # Decrease reference count (may delete backend)
            self._decrease_ref_count(address)

            # Rebuild consistent hash ring
            self._rebuild_ring(vip)

            logger.info(f"Removed real {address} from VIP {vip.key}")

            return True

    def set_weight(
        self,
        vip: Vip,
        address: str | IpAddress,
        weight: int,
    ) -> bool:
        """
        Set backend weight.

        Weight determines the backend's share of the consistent hash ring.
        Weight 0 effectively drains the backend (no new connections).

        After changing weight, rebuilds the VIP's consistent hash ring.

        Args:
            vip: VIP containing the backend
            address: Backend IP address
            weight: New weight (0 = drained, >0 = active)

        Returns:
            True if updated, False if backend not found

        Example:
            >>> # Normal operation
            >>> real_mgr.set_weight(vip, "10.0.0.100", weight=100)
            >>> # Drain backend
            >>> real_mgr.set_weight(vip, "10.0.0.100", weight=0)
        """
        with self._lock:
            # Parse address if string
            if isinstance(address, str):
                address = _parse_ip_address(address)

            # Find backend in VIP's real list
            real = None
            for r in vip.reals:
                if r.address == address:
                    real = r
                    break

            if real is None:
                return False

            # Update weight
            old_weight = real.weight
            real.weight = weight

            # Rebuild ring if weight changed
            if old_weight != weight:
                self._rebuild_ring(vip)

                logger.info(
                    f"Changed weight for real {address} in VIP {vip.key}: {old_weight} → {weight}"
                )

            return True

    def drain_real(
        self,
        vip: Vip,
        address: str | IpAddress,
    ) -> bool:
        """
        Drain backend (set weight to 0).

        Convenience method for graceful backend removal.

        Args:
            vip: VIP containing the backend
            address: Backend IP address

        Returns:
            True if drained, False if backend not found

        Example:
            >>> real_mgr.drain_real(vip, "10.0.0.100")
        """
        return self.set_weight(vip, address, weight=0)

    def undrain_real(
        self,
        vip: Vip,
        address: str | IpAddress,
        weight: int = 100,
    ) -> bool:
        """
        Undrain backend (restore weight).

        Args:
            vip: VIP containing the backend
            address: Backend IP address
            weight: Weight to restore (default: 100)

        Returns:
            True if undrained, False if backend not found

        Example:
            >>> real_mgr.undrain_real(vip, "10.0.0.100", weight=100)
        """
        return self.set_weight(vip, address, weight=weight)

    # =========================================================================
    # Query Operations
    # =========================================================================

    def get_real(
        self,
        vip: Vip,
        address: str | IpAddress,
    ) -> Optional[Real]:
        """
        Get backend from VIP.

        Args:
            vip: VIP to search
            address: Backend IP address

        Returns:
            Real object if found, None otherwise
        """
        with self._lock:
            # Parse address if string
            if isinstance(address, str):
                address = _parse_ip_address(address)

            for real in vip.reals:
                if real.address == address:
                    return real

            return None

    def real_exists(
        self,
        vip: Vip,
        address: str | IpAddress,
    ) -> bool:
        """
        Check if backend exists for VIP.

        Args:
            vip: VIP to check
            address: Backend IP address

        Returns:
            True if backend exists for this VIP, False otherwise
        """
        return self.get_real(vip, address) is not None

    def get_real_count(self, vip: Vip) -> int:
        """
        Get number of backends for VIP.

        Args:
            vip: VIP to count backends for

        Returns:
            Count of backends
        """
        with self._lock:
            return len(vip.reals)

    def get_active_real_count(self, vip: Vip) -> int:
        """
        Get number of active (non-drained) backends for VIP.

        Args:
            vip: VIP to count active backends for

        Returns:
            Count of backends with weight > 0
        """
        with self._lock:
            return sum(1 for r in vip.reals if r.weight > 0)

    def get_global_real_count(self) -> int:
        """
        Get total number of unique backends across all VIPs.

        Returns:
            Count of globally allocated backends
        """
        with self._lock:
            return len(self._reals)

    def get_real_ref_count(self, address: str | IpAddress) -> int:
        """
        Get reference count for a backend.

        Args:
            address: Backend IP address

        Returns:
            Reference count (number of VIPs using this backend), or 0 if not found
        """
        with self._lock:
            if isinstance(address, str):
                address = _parse_ip_address(address)

            meta = self._reals.get(address)
            return meta.ref_count if meta else 0

    # =========================================================================
    # Public Reference Counting (for shared real tracking)
    # =========================================================================

    def increase_ref_count(self, address: str) -> int:
        """Increment ref count for a real, allocating if new. Returns real index."""
        with self._lock:
            ip_addr = _parse_ip_address(address)
            meta = self._increase_ref_count(ip_addr)
            return meta.num

    def decrease_ref_count(self, address: str) -> None:
        """Decrement ref count for a real, freeing if count reaches 0."""
        with self._lock:
            ip_addr = _parse_ip_address(address)
            self._decrease_ref_count(ip_addr)

    def get_index_for_real(self, address: str) -> int | None:
        """Get the current BPF array index for a real address, or None."""
        with self._lock:
            ip_addr = _parse_ip_address(address)
            meta = self._reals.get(ip_addr)
            return meta.num if meta is not None else None

    # =========================================================================
    # Reference Counting (Internal)
    # =========================================================================

    def _increase_ref_count(self, address: IpAddress) -> RealMeta:
        """
        Increase reference count for backend.

        If backend exists, increments ref count.
        If new backend, allocates index and adds to reals map.

        Args:
            address: Backend IP address

        Returns:
            RealMeta with index and ref count

        Raises:
            ResourceExhaustedError: If no indices available
        """
        meta = self._reals.get(address)

        if meta is not None:
            # Existing backend: increment ref count
            meta.ref_count += 1
            logger.debug(f"Increased ref_count for {address}: {meta.ref_count} (index={meta.num})")
            return meta
        else:
            # New backend: allocate index
            idx = self._reals_map.allocate_index()

            # Create metadata
            meta = RealMeta(num=idx, ref_count=1, flags=0)
            self._reals[address] = meta
            self._num_to_reals[idx] = address

            # Write to BPF reals array
            real_def = RealDefinition(address=address, flags=RealFlags(meta.flags))
            self._reals_map.set(idx, real_def)

            logger.debug(f"Allocated new backend {address} at index {idx}, ref_count=1")

            return meta

    def _decrease_ref_count(self, address: IpAddress) -> None:
        """
        Decrease reference count for backend.

        If ref count reaches zero, deletes backend and recycles index.

        Args:
            address: Backend IP address
        """
        meta = self._reals.get(address)
        if meta is None:
            return

        meta.ref_count -= 1

        if meta.ref_count == 0:
            # Delete backend when no VIPs use it
            idx = meta.num

            # Free index for reuse
            self._reals_map.free_index(idx)

            # Remove from tracking
            del self._reals[address]
            del self._num_to_reals[idx]

            logger.debug(f"Deleted backend {address} (index={idx}), ref_count=0")
        else:
            logger.debug(f"Decreased ref_count for {address}: {meta.ref_count} (index={meta.num})")

    # =========================================================================
    # Consistent Hash Ring Management
    # =========================================================================

    def _rebuild_ring(self, vip: Vip) -> None:
        """
        Rebuild consistent hash ring for VIP.

        Generates new ring using Maglev algorithm, computes delta from
        old ring, and updates only changed positions in ch_rings map.

        Args:
            vip: VIP to rebuild ring for
        """
        # Build list of active endpoints (weight > 0)
        endpoints: list[Endpoint] = []
        for real in vip.reals:
            if real.weight > 0:
                endpoint = Endpoint(
                    num=real.index,
                    weight=real.weight,
                    hash=hash_endpoint_address(str(real.address)),
                )
                endpoints.append(endpoint)

        # Generate new ring
        if len(endpoints) == 0:
            # All backends drained: use empty ring (index 0 = no backend)
            new_ring = [0] * self._ring_builder.ring_size
        else:
            new_ring = self._ring_builder.build(endpoints)

        # Write to BPF ch_rings map without optimization
        # Note: Unlike C++ version which caches old ring in memory, we would
        # need to read 65k entries from BPF to optimize. Just write all entries.
        self._ch_rings_map.write_ring(vip.vip_num, new_ring, optimize=False)

        logger.info(
            f"Rebuilt ring for VIP {vip.key}: "
            f"{len(endpoints)} active backends, "
            f"wrote {self._ring_builder.ring_size} positions"
        )

    def rebuild_all_rings(self) -> None:
        """
        Rebuild consistent hash rings for all VIPs.

        Note:
            This requires access to all VIPs, which is typically managed
            by VipManager. This method should be called with a list of VIPs
            passed in, or via a coordinator that has both managers.
        """
        # This is a placeholder - typically called by a higher-level
        # coordinator that has access to both VipManager and RealManager
        logger.warning("rebuild_all_rings called but VIPs not accessible from RealManager")

    # =========================================================================
    # State Management
    # =========================================================================

    def clear_all(self) -> int:
        """
        Remove all backend references and state.

        Warning: This is a destructive operation.

        Returns:
            Number of backends removed
        """
        with self._lock:
            count = len(self._reals)

            # Free all indices
            for meta in self._reals.values():
                self._reals_map.free_index(meta.num)

            # Clear state
            self._reals.clear()
            self._num_to_reals.clear()

            logger.warning(f"Cleared all backends (removed {count})")

            return count

    def __repr__(self) -> str:
        """String representation of RealManager."""
        return f"RealManager(reals={len(self._reals)}, max={self._max_reals})"
