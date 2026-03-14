"""
Katran service coordinator.

Wires together BPF maps, managers, and provides lifecycle management.
"""

from __future__ import annotations

from typing import Any, Optional

from katran.bpf import (
    BpfMap,
    ChRingsMap,
    CtlArray,
    HcRealsMap,
    LruMap,
    PcktSrcsMap,
    RealsMap,
    StatsMap,
    VipMap,
)
from katran.core.config import KatranConfig
from katran.core.constants import (
    V4_SRC_INDEX,
    V6_SRC_INDEX,
    KatranFeature,
    ModifyAction,
)
from katran.core.exceptions import FeatureNotEnabledError
from katran.core.logging import get_logger
from katran.core.types import (
    LbStats,
    LruAnalysis,
    LruEntries,
    PurgeResponse,
    QuicPacketStats,
    QuicReal,
    RealDefinition,
    VipKey,
)
from katran.lb import MaglevHashRing, RealManager, VipManager
from katran.lb.decap_manager import DecapManager
from katran.lb.down_real_manager import DownRealManager
from katran.lb.hc_manager import HealthCheckManager
from katran.lb.lru_manager import LruManager
from katran.lb.quic_manager import QuicManager
from katran.lb.src_routing_manager import SrcRoutingManager
from katran.lb.stats_manager import StatsManager

logger = get_logger(__name__)


class KatranService:
    """
    Main service coordinator that owns maps, managers, and lifecycle.

    Attributes:
        config: Service configuration.
        vip_map, reals_map, ch_rings_map, stats_map, ctl_array,
        hc_reals_map, lru_map: BPF map wrappers (set after start).
        vip_manager, real_manager: High-level managers (set after start).
    """

    def __init__(self, config: KatranConfig) -> None:
        self.config = config

        # Maps (populated on start)
        self.vip_map: Optional[VipMap] = None
        self.reals_map: Optional[RealsMap] = None
        self.ch_rings_map: Optional[ChRingsMap] = None
        self.stats_map: Optional[StatsMap] = None
        self.ctl_array: Optional[CtlArray] = None
        self.hc_reals_map: Optional[HcRealsMap] = None
        self.lru_map: Optional[LruMap] = None
        self._pckt_srcs_map: Optional[PcktSrcsMap] = None

        # Core managers (populated on start)
        self.vip_manager: Optional[VipManager] = None
        self.real_manager: Optional[RealManager] = None

        # Feature managers (populated when features are enabled and maps available)
        self._src_routing_manager: Optional[SrcRoutingManager] = None
        self._decap_manager: Optional[DecapManager] = None
        self._quic_manager: Optional[QuicManager] = None
        self._hc_manager: Optional[HealthCheckManager] = None
        self._lru_manager: Optional[LruManager] = None
        self._down_real_manager: Optional[DownRealManager] = None
        self._stats_manager: Optional[StatsManager] = None

        self._running = False
        self._opened_maps: list = []

    # -------------------------------------------------------------------------
    # Properties
    # -------------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def is_healthy(self) -> bool:
        return self._running and self.vip_manager is not None and self.real_manager is not None

    # -------------------------------------------------------------------------
    # Feature checking
    # -------------------------------------------------------------------------

    def has_feature(self, feature: KatranFeature) -> bool:
        """Check whether a feature is enabled in the configuration."""
        return bool(KatranFeature(self.config.features) & feature)

    def _require_feature(self, feature: KatranFeature) -> None:
        """Raise FeatureNotEnabledError if the feature is not enabled."""
        if not self.has_feature(feature):
            raise FeatureNotEnabledError(feature.name)

    # -------------------------------------------------------------------------
    # Optional map helper
    # -------------------------------------------------------------------------

    def _try_open(self, map_cls: type, *args: Any, **kwargs: Any) -> Any:
        """Try to open an optional map, returning None on failure."""
        try:
            m = map_cls(*args, **kwargs)
            m.open()
            self._opened_maps.append(m)
            return m
        except Exception:
            logger.info("Optional map %s unavailable", map_cls.__name__)
            return None

    # -------------------------------------------------------------------------
    # Lifecycle
    # -------------------------------------------------------------------------

    def _open_maps(self) -> None:
        """Instantiate and open all BPF maps.

        Required maps (vip_map, reals_map, ch_rings_map, stats_map, ctl_array)
        must succeed.  Optional maps (hc_reals_map, lru_map) are opened on a
        best-effort basis -- failure is logged but does not prevent startup.
        """
        pin_path = self.config.bpf.pin_path
        maps_cfg = self.config.maps

        self.vip_map = VipMap(pin_path, max_vips=maps_cfg.max_vips)
        self.reals_map = RealsMap(pin_path, max_reals=maps_cfg.max_reals)
        self.ch_rings_map = ChRingsMap(
            pin_path,
            ring_size=maps_cfg.ring_size,
            max_vips=maps_cfg.max_vips,
        )
        self.stats_map = StatsMap(pin_path, max_vips=maps_cfg.max_vips)
        self.ctl_array = CtlArray(pin_path)

        required_maps: list[BpfMap[Any, Any]] = [
            self.vip_map,
            self.reals_map,
            self.ch_rings_map,
            self.stats_map,
            self.ctl_array,
        ]

        for m in required_maps:
            m.open()
            self._opened_maps.append(m)
            logger.debug("Opened map: %s", type(m).__name__)

        # Optional maps -- tolerate missing pins (e.g. hc_reals comes from a
        # separate TC healthcheck program that may not be loaded).
        optional_specs: list[tuple[str, Any]] = [
            ("hc_reals_map", lambda: HcRealsMap(pin_path)),
            ("lru_map", lambda: LruMap(pin_path, max_entries=maps_cfg.lru_size)),
        ]

        for attr, factory in optional_specs:
            try:
                opt_map: BpfMap[Any, Any] = factory()
                opt_map.open()
                setattr(self, attr, opt_map)
                self._opened_maps.append(opt_map)
                logger.debug("Opened optional map: %s", type(opt_map).__name__)
            except Exception:
                logger.info("Optional map %s unavailable, skipping", attr)

    def _initialize_managers(self) -> None:
        """Create VipManager and RealManager with correct signatures."""
        assert self.vip_map is not None
        assert self.ch_rings_map is not None
        assert self.reals_map is not None

        self.vip_manager = VipManager(
            self.vip_map,
            self.ch_rings_map,
            max_vips=self.config.maps.max_vips,
        )

        ring_builder = MaglevHashRing(ring_size=self.config.maps.ring_size)

        self.real_manager = RealManager(
            self.reals_map,
            self.ch_rings_map,
            ring_builder=ring_builder,
            max_reals=self.config.maps.max_reals,
        )

        logger.info("Managers initialized")

    def _close_maps(self) -> None:
        """Close all opened maps."""
        for m in reversed(self._opened_maps):
            try:
                m.close()
            except Exception:
                logger.warning("Error closing map %s", type(m).__name__, exc_info=True)
        self._opened_maps.clear()

    def start(self) -> None:
        """Start the service: open maps, initialize managers."""
        if self._running:
            raise RuntimeError("Service is already running")

        logger.info("Starting Katran service...")
        try:
            self._open_maps()
            self._initialize_managers()
            self._running = True
            logger.info("Katran service started")
        except Exception:
            logger.error("Failed to start service, cleaning up", exc_info=True)
            self._close_maps()
            self.vip_manager = None
            self.real_manager = None
            raise

    def stop(self) -> None:
        """Stop the service and close all maps."""
        if not self._running:
            return

        logger.info("Stopping Katran service...")
        self._close_maps()
        self.vip_manager = None
        self.real_manager = None
        self._src_routing_manager = None
        self._decap_manager = None
        self._quic_manager = None
        self._hc_manager = None
        self._lru_manager = None
        self._down_real_manager = None
        self._stats_manager = None
        self._running = False
        logger.info("Katran service stopped")

    # =========================================================================
    # Source routing delegation
    # =========================================================================

    def add_src_routing_rules(self, srcs: list[str], dst: str) -> int:
        """Add source routing rules. Returns count of failures."""
        self._require_feature(KatranFeature.SRC_ROUTING)
        assert self._src_routing_manager is not None
        return self._src_routing_manager.add_rules(srcs, dst)

    def del_src_routing_rules(self, srcs: list[str]) -> bool:
        """Delete source routing rules."""
        self._require_feature(KatranFeature.SRC_ROUTING)
        assert self._src_routing_manager is not None
        return self._src_routing_manager.del_rules(srcs)

    def get_src_routing_rules(self) -> dict[str, str]:
        """Get all source routing rules."""
        self._require_feature(KatranFeature.SRC_ROUTING)
        assert self._src_routing_manager is not None
        return self._src_routing_manager.get_rules()

    def clear_src_routing_rules(self) -> None:
        """Remove all source routing rules."""
        self._require_feature(KatranFeature.SRC_ROUTING)
        assert self._src_routing_manager is not None
        self._src_routing_manager.clear_all()

    # =========================================================================
    # Inline decap delegation
    # =========================================================================

    def add_decap_dst(self, dst: str) -> None:
        """Add a decap destination."""
        self._require_feature(KatranFeature.INLINE_DECAP)
        assert self._decap_manager is not None
        self._decap_manager.add_dst(dst)

    def del_decap_dst(self, dst: str) -> None:
        """Remove a decap destination."""
        self._require_feature(KatranFeature.INLINE_DECAP)
        assert self._decap_manager is not None
        self._decap_manager.del_dst(dst)

    def get_decap_dsts(self) -> list[str]:
        """List all decap destinations."""
        self._require_feature(KatranFeature.INLINE_DECAP)
        assert self._decap_manager is not None
        return self._decap_manager.get_dsts()

    # =========================================================================
    # QUIC delegation
    # =========================================================================

    def modify_quic_mapping(
        self, action: ModifyAction, quic_reals: list[QuicReal]
    ) -> int:
        """Modify QUIC server ID mappings. Returns failure count."""
        assert self._quic_manager is not None
        return self._quic_manager.modify_mapping(action, quic_reals)

    def get_quic_mapping(self) -> list[QuicReal]:
        """Get all QUIC server ID mappings."""
        assert self._quic_manager is not None
        return self._quic_manager.get_mapping()

    def invalidate_quic_server_ids(self, server_ids: list[int]) -> None:
        """Invalidate QUIC server IDs (write 0 to BPF map)."""
        assert self._quic_manager is not None
        self._quic_manager.invalidate_server_ids(server_ids)

    def revalidate_quic_server_ids(self, quic_reals: list[QuicReal]) -> None:
        """Revalidate QUIC server IDs (write current index back to BPF map)."""
        assert self._quic_manager is not None
        self._quic_manager.revalidate_server_ids(quic_reals)

    # =========================================================================
    # Health check delegation
    # =========================================================================

    def add_hc_dst(self, somark: int, dst: str) -> None:
        """Register a health-check destination keyed by SO_MARK."""
        self._require_feature(KatranFeature.DIRECT_HEALTHCHECKING)
        assert self._hc_manager is not None
        self._hc_manager.add_hc_dst(somark, dst)

    def del_hc_dst(self, somark: int) -> None:
        """Remove a health-check destination."""
        self._require_feature(KatranFeature.DIRECT_HEALTHCHECKING)
        assert self._hc_manager is not None
        self._hc_manager.del_hc_dst(somark)

    def get_hc_dsts(self) -> dict[int, str]:
        """Return all HC destinations."""
        self._require_feature(KatranFeature.DIRECT_HEALTHCHECKING)
        assert self._hc_manager is not None
        return self._hc_manager.get_hc_dsts()

    def add_hc_key(self, key: VipKey) -> int:
        """Allocate an HC key index."""
        self._require_feature(KatranFeature.DIRECT_HEALTHCHECKING)
        assert self._hc_manager is not None
        return self._hc_manager.add_hc_key(key)

    def del_hc_key(self, key: VipKey) -> None:
        """Remove an HC key."""
        self._require_feature(KatranFeature.DIRECT_HEALTHCHECKING)
        assert self._hc_manager is not None
        self._hc_manager.del_hc_key(key)

    def get_hc_keys(self) -> dict[VipKey, int]:
        """Return all HC keys and their indices."""
        self._require_feature(KatranFeature.DIRECT_HEALTHCHECKING)
        assert self._hc_manager is not None
        return self._hc_manager.get_hc_keys()

    def set_hc_src_ip(self, address: str) -> None:
        """Set the source IP for HC probe packets."""
        self._require_feature(KatranFeature.DIRECT_HEALTHCHECKING)
        assert self._hc_manager is not None
        self._hc_manager.set_hc_src_ip(address)

    def set_hc_src_mac(self, mac: str) -> None:
        """Set the source MAC for HC packets."""
        self._require_feature(KatranFeature.DIRECT_HEALTHCHECKING)
        assert self._hc_manager is not None
        self._hc_manager.set_hc_src_mac(mac)

    def set_hc_dst_mac(self, mac: str) -> None:
        """Set the destination MAC for HC packets."""
        self._require_feature(KatranFeature.DIRECT_HEALTHCHECKING)
        assert self._hc_manager is not None
        self._hc_manager.set_hc_dst_mac(mac)

    def set_hc_interface(self, ifindex: int) -> None:
        """Set the egress interface for HC packets."""
        self._require_feature(KatranFeature.DIRECT_HEALTHCHECKING)
        assert self._hc_manager is not None
        self._hc_manager.set_hc_interface(ifindex)

    def get_hc_stats(self) -> Any:
        """Get HC program statistics."""
        self._require_feature(KatranFeature.DIRECT_HEALTHCHECKING)
        assert self._hc_manager is not None
        return self._hc_manager.get_stats()

    def get_packets_for_hc_key(self, key: VipKey) -> int:
        """Get packet count for a specific HC key."""
        self._require_feature(KatranFeature.DIRECT_HEALTHCHECKING)
        assert self._hc_manager is not None
        return self._hc_manager.get_packets_for_hc_key(key)

    # =========================================================================
    # Encap source IP
    # =========================================================================

    def set_src_ip_for_encap(self, address: str) -> None:
        """Set the source IP used for encapsulation (pckt_srcs_map)."""
        from ipaddress import ip_address as parse_addr

        addr = parse_addr(address)
        index = V4_SRC_INDEX if addr.version == 4 else V6_SRC_INDEX
        if self._pckt_srcs_map is not None:
            self._pckt_srcs_map.set(index, RealDefinition(address=addr))

    # =========================================================================
    # LRU delegation
    # =========================================================================

    def lru_search(self, vip_key: VipKey, src_ip: str, src_port: int) -> LruEntries:
        """Search for LRU entries matching a specific flow."""
        assert self._lru_manager is not None
        return self._lru_manager.search(vip_key, src_ip, src_port)

    def lru_list(self, vip_key: VipKey, limit: int = 100) -> LruEntries:
        """List LRU entries for a VIP."""
        assert self._lru_manager is not None
        return self._lru_manager.list(vip_key, limit)

    def lru_delete(
        self, vip_key: VipKey, src_ip: str, src_port: int
    ) -> list[str]:
        """Delete LRU entries matching a flow from all maps."""
        assert self._lru_manager is not None
        return self._lru_manager.delete(vip_key, src_ip, src_port)

    def lru_purge_vip(self, vip_key: VipKey) -> PurgeResponse:
        """Remove all LRU entries for a VIP."""
        assert self._lru_manager is not None
        return self._lru_manager.purge_vip(vip_key)

    def lru_purge_vip_for_real(
        self, vip_key: VipKey, real_index: int
    ) -> PurgeResponse:
        """Remove LRU entries for a VIP pointing to a specific backend."""
        assert self._lru_manager is not None
        return self._lru_manager.purge_vip_for_real(vip_key, real_index)

    def lru_analyze(self) -> LruAnalysis:
        """Analyze all LRU entries across all maps."""
        assert self._lru_manager is not None
        return self._lru_manager.analyze()

    # =========================================================================
    # Down real delegation
    # =========================================================================

    def add_down_real(self, vip_key: VipKey, real_index: int) -> None:
        """Mark a backend as down for a VIP."""
        assert self._down_real_manager is not None
        self._down_real_manager.add_down_real(vip_key, real_index)

    def remove_down_real(self, vip_key: VipKey, real_index: int) -> None:
        """Un-mark a backend as down for a VIP."""
        assert self._down_real_manager is not None
        self._down_real_manager.remove_real(vip_key, real_index)

    def remove_down_reals_vip(self, vip_key: VipKey) -> None:
        """Remove all down-real tracking for a VIP."""
        assert self._down_real_manager is not None
        self._down_real_manager.remove_vip(vip_key)

    def check_down_real(self, vip_key: VipKey, real_index: int) -> bool:
        """Check whether a backend is marked down for a VIP."""
        assert self._down_real_manager is not None
        return self._down_real_manager.check_real(vip_key, real_index)

    # =========================================================================
    # Stats delegation
    # =========================================================================

    def get_vip_stats(self, vip_num: int) -> LbStats:
        """Get aggregated stats for a single VIP."""
        assert self._stats_manager is not None
        return self._stats_manager.get_vip_stats(vip_num)

    def get_real_stats(self, real_index: int) -> LbStats:
        """Get aggregated stats for a single backend."""
        assert self._stats_manager is not None
        return self._stats_manager.get_real_stats(real_index)

    def get_quic_packet_stats(self) -> QuicPacketStats:
        """Get QUIC packet statistics."""
        assert self._stats_manager is not None
        return self._stats_manager.get_quic_packet_stats()

    def get_hc_program_stats(self) -> Any:
        """Get HC BPF program statistics."""
        assert self._stats_manager is not None
        return self._stats_manager.get_hc_program_stats()

    def get_per_core_packets_stats(self) -> list[int]:
        """Get XDP total packets broken down by CPU core."""
        assert self._stats_manager is not None
        return self._stats_manager.get_per_core_packets_stats()

    def get_all_global_stats(self) -> dict[str, dict[str, int]]:
        """Get a summary of key global counters."""
        assert self._stats_manager is not None
        sm = self._stats_manager
        lru = sm.get_lru_stats()
        lru_miss = sm.get_lru_miss_stats()
        xdp_total = sm.get_xdp_total_stats()
        ch_drops = sm.get_ch_drop_stats()
        encap_fail = sm.get_encap_fail_stats()
        return {
            "lru": {"v1": lru.v1, "v2": lru.v2},
            "lru_miss": {"v1": lru_miss.v1, "v2": lru_miss.v2},
            "xdp_total": {"v1": xdp_total.v1, "v2": xdp_total.v2},
            "ch_drops": {"v1": ch_drops.v1, "v2": ch_drops.v2},
            "encap_fail": {"v1": encap_fail.v1, "v2": encap_fail.v2},
        }
