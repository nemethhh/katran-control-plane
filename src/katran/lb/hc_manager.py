"""Health check manager coordinating all HC maps."""

from __future__ import annotations

import logging
from threading import RLock
from typing import TYPE_CHECKING

from katran.bpf.map_manager import IndexAllocator
from katran.core.constants import (
    HC_DST_MAC_POS,
    HC_MAIN_INTF_POSITION,
    HC_SRC_MAC_POS,
    MAX_VIPS,
    V4_SRC_INDEX,
    V6_SRC_INDEX,
)
from katran.core.exceptions import HealthCheckError
from katran.core.types import (
    HcMac,
    HcRealDefinition,
    HealthCheckProgStats,
    RealDefinition,
    VipKey,
)

if TYPE_CHECKING:
    from katran.bpf.maps.hc_ctrl_map import HcCtrlMap
    from katran.bpf.maps.hc_key_map import HcKeyMap
    from katran.bpf.maps.hc_pckt_macs_map import HcPcktMacsMap
    from katran.bpf.maps.hc_pckt_srcs_map import HcPcktSrcsMap
    from katran.bpf.maps.hc_reals_map import HcRealsMap
    from katran.bpf.maps.hc_stats_map import HcStatsMap
    from katran.bpf.maps.per_hckey_stats_map import PerHcKeyStatsMap

logger = logging.getLogger(__name__)


class HealthCheckManager:
    """Coordinates all health-check BPF maps.

    Manages HC destinations (somark -> real IP), HC keys (VipKey -> index),
    source/dest MAC and IP configuration, interface binding, and stats.
    """

    def __init__(
        self,
        hc_reals_map: HcRealsMap,
        hc_key_map: HcKeyMap,
        hc_ctrl_map: HcCtrlMap,
        hc_pckt_srcs_map: HcPcktSrcsMap,
        hc_pckt_macs: HcPcktMacsMap,
        hc_stats_map: HcStatsMap,
        per_hckey_stats: PerHcKeyStatsMap,
        max_vips: int = MAX_VIPS,
        tunnel_based_hc: bool = True,
    ) -> None:
        self._hc_reals_map = hc_reals_map
        self._hc_key_map = hc_key_map
        self._hc_ctrl_map = hc_ctrl_map
        self._hc_pckt_srcs_map = hc_pckt_srcs_map
        self._hc_pckt_macs = hc_pckt_macs
        self._hc_stats_map = hc_stats_map
        self._per_hckey_stats = per_hckey_stats
        self._tunnel_based_hc = tunnel_based_hc
        self._hc_key_to_index: dict[VipKey, int] = {}
        self._index_allocator = IndexAllocator(max_vips)
        self._somark_to_dst: dict[int, str] = {}
        self._lock = RLock()

    # ------------------------------------------------------------------
    # HC destination management (somark -> backend IP)
    # ------------------------------------------------------------------

    def add_hc_dst(self, somark: int, dst: str) -> None:
        """Register a health-check destination keyed by SO_MARK."""
        with self._lock:
            from ipaddress import ip_address as parse_addr

            addr = parse_addr(dst)
            flags = 1 if addr.version == 6 else 0
            hrd = HcRealDefinition(address=dst, flags=flags)
            self._hc_reals_map.set(somark, hrd)
            self._somark_to_dst[somark] = dst

    def del_hc_dst(self, somark: int) -> None:
        """Remove a health-check destination by SO_MARK."""
        with self._lock:
            if somark not in self._somark_to_dst:
                raise HealthCheckError(f"HC destination not found for somark {somark}")
            self._hc_reals_map.delete(somark)
            del self._somark_to_dst[somark]

    def get_hc_dsts(self) -> dict[int, str]:
        """Return a snapshot of all HC destinations."""
        with self._lock:
            return dict(self._somark_to_dst)

    # ------------------------------------------------------------------
    # HC key management (VipKey -> index)
    # ------------------------------------------------------------------

    def add_hc_key(self, key: VipKey) -> int:
        """Allocate an HC-key index and store the mapping."""
        with self._lock:
            if key in self._hc_key_to_index:
                raise HealthCheckError(f"HC key already exists: {key}")
            idx = self._index_allocator.allocate()
            self._hc_key_map.set(key, idx)
            self._hc_key_to_index[key] = idx
            return idx

    def del_hc_key(self, key: VipKey) -> None:
        """Remove an HC key and free its index."""
        with self._lock:
            if key not in self._hc_key_to_index:
                raise HealthCheckError(f"HC key not found: {key}")
            idx = self._hc_key_to_index[key]
            self._hc_key_map.delete(key)
            self._index_allocator.free(idx)
            del self._hc_key_to_index[key]

    def get_hc_keys(self) -> dict[VipKey, int]:
        """Return a snapshot of all HC keys and their indices."""
        with self._lock:
            return dict(self._hc_key_to_index)

    # ------------------------------------------------------------------
    # Packet source / MAC / interface configuration
    # ------------------------------------------------------------------

    def set_hc_src_ip(self, address: str) -> None:
        """Set the source IP for health-check probe packets."""
        from ipaddress import ip_address as parse_addr

        addr = parse_addr(address)
        index = V4_SRC_INDEX if addr.version == 4 else V6_SRC_INDEX
        real_def = RealDefinition(address=addr)
        self._hc_pckt_srcs_map.set(index, real_def)

    def set_hc_dst_mac(self, mac: str) -> None:
        """Set the destination MAC for health-check packets."""
        self._hc_pckt_macs.set(HC_DST_MAC_POS, HcMac.from_string(mac))

    def set_hc_src_mac(self, mac: str) -> None:
        """Set the source MAC for health-check packets."""
        self._hc_pckt_macs.set(HC_SRC_MAC_POS, HcMac.from_string(mac))

    def set_hc_interface(self, ifindex: int) -> None:
        """Set the egress interface index for health-check packets."""
        self._hc_ctrl_map.set(HC_MAIN_INTF_POSITION, ifindex)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self) -> HealthCheckProgStats:
        """Retrieve aggregated HC program statistics."""
        result = self._hc_stats_map.get(0)
        return result if result is not None else HealthCheckProgStats()

    def get_packets_for_hc_key(self, key: VipKey) -> int:
        """Get the per-CPU-aggregated packet count for a specific HC key."""
        with self._lock:
            if key not in self._hc_key_to_index:
                raise HealthCheckError(f"HC key not found: {key}")
            idx = self._hc_key_to_index[key]
            result = self._per_hckey_stats.get(idx)
            return result if result is not None else 0
