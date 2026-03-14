"""Centralized statistics access for all BPF stats maps."""

from __future__ import annotations

from typing import TYPE_CHECKING

from katran.core.constants import MAX_VIPS, StatsCounterIndex
from katran.core.types import HealthCheckProgStats, LbStats, QuicPacketStats

if TYPE_CHECKING:
    from katran.bpf.maps.decap_vip_stats_map import DecapVipStatsMap
    from katran.bpf.maps.hc_stats_map import HcStatsMap
    from katran.bpf.maps.lru_miss_stats_map import LruMissStatsMap
    from katran.bpf.maps.per_hckey_stats_map import PerHcKeyStatsMap
    from katran.bpf.maps.quic_stats_map import QuicStatsMap
    from katran.bpf.maps.reals_stats_map import RealsStatsMap
    from katran.bpf.maps.server_id_stats_map import ServerIdStatsMap
    from katran.bpf.maps.stats_map import StatsMap


class StatsManager:
    """Centralized statistics access for all BPF stats maps.

    Provides a unified interface to query per-VIP, per-real, global,
    QUIC, health-check, and LRU miss statistics from BPF maps.
    """

    def __init__(
        self,
        stats_map: StatsMap,
        max_vips: int = MAX_VIPS,
        reals_stats_map: RealsStatsMap | None = None,
        lru_miss_stats_map: LruMissStatsMap | None = None,
        quic_stats_map: QuicStatsMap | None = None,
        decap_vip_stats_map: DecapVipStatsMap | None = None,
        server_id_stats_map: ServerIdStatsMap | None = None,
        hc_stats_map: HcStatsMap | None = None,
        per_hckey_stats: PerHcKeyStatsMap | None = None,
    ) -> None:
        self._stats_map = stats_map
        self._max_vips = max_vips
        self._reals_stats_map = reals_stats_map
        self._lru_miss_stats_map = lru_miss_stats_map
        self._quic_stats_map = quic_stats_map
        self._decap_vip_stats_map = decap_vip_stats_map
        self._server_id_stats_map = server_id_stats_map
        self._hc_stats_map = hc_stats_map
        self._per_hckey_stats = per_hckey_stats

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _global_index(self, counter: StatsCounterIndex) -> int:
        """Compute the stats map index for a global counter."""
        return self._max_vips + counter

    def _get_global(self, counter: StatsCounterIndex) -> LbStats:
        """Look up a global counter, returning zeroed stats on miss."""
        result = self._stats_map.get(self._global_index(counter))
        return result if result is not None else LbStats()

    # -------------------------------------------------------------------------
    # Per-VIP stats
    # -------------------------------------------------------------------------

    def get_vip_stats(self, vip_num: int) -> LbStats:
        """Get aggregated stats (packets/bytes) for a single VIP."""
        result = self._stats_map.get(vip_num)
        return result if result is not None else LbStats()

    def get_decap_stats_for_vip(self, vip_num: int) -> LbStats:
        """Get decap stats for a VIP (requires decap_vip_stats_map)."""
        if self._decap_vip_stats_map is None:
            return LbStats()
        result = self._decap_vip_stats_map.get(vip_num)
        return result if result is not None else LbStats()

    def get_sid_routing_stats_for_vip(self, vip_num: int) -> LbStats:
        """Get server-ID routing stats for a VIP (requires server_id_stats_map)."""
        if self._server_id_stats_map is None:
            return LbStats()
        result = self._server_id_stats_map.get(vip_num)
        return result if result is not None else LbStats()

    # -------------------------------------------------------------------------
    # Per-real stats
    # -------------------------------------------------------------------------

    def get_real_stats(self, real_index: int) -> LbStats:
        """Get aggregated stats for a single backend."""
        if self._reals_stats_map is None:
            return LbStats()
        result = self._reals_stats_map.get(real_index)
        return result if result is not None else LbStats()

    def get_reals_stats(self, indices: list[int]) -> dict[int, LbStats]:
        """Get stats for a batch of backend indices."""
        return {idx: self.get_real_stats(idx) for idx in indices}

    # -------------------------------------------------------------------------
    # Global counters
    # -------------------------------------------------------------------------

    def get_lru_stats(self) -> LbStats:
        """LRU cache hit counters."""
        return self._get_global(StatsCounterIndex.LRU_CNTRS)

    def get_lru_miss_stats(self) -> LbStats:
        """TCP SYN/non-SYN miss counters."""
        return self._get_global(StatsCounterIndex.LRU_MISS_CNTR)

    def get_new_conn_rate_stats(self) -> LbStats:
        """New connection rate counter."""
        return self._get_global(StatsCounterIndex.NEW_CONN_RATE_CNTR)

    def get_lru_fallback_stats(self) -> LbStats:
        """Fallback LRU hit counter."""
        return self._get_global(StatsCounterIndex.FALLBACK_LRU_CNTR)

    def get_global_lru_stats(self) -> LbStats:
        """Global LRU counter."""
        return self._get_global(StatsCounterIndex.GLOBAL_LRU_CNTR)

    def get_icmp_toobig_stats(self) -> LbStats:
        """ICMP Packet-Too-Big counter."""
        return self._get_global(StatsCounterIndex.ICMP_TOOBIG_CNTRS)

    def get_icmp_ptb_v4_stats(self) -> LbStats:
        """IPv4 PTB counter."""
        return self._get_global(StatsCounterIndex.ICMP_PTB_V4_STATS)

    def get_icmp_ptb_v6_stats(self) -> LbStats:
        """IPv6 PTB counter."""
        return self._get_global(StatsCounterIndex.ICMP_PTB_V6_STATS)

    def get_ch_drop_stats(self) -> LbStats:
        """Consistent-hash drop counter."""
        return self._get_global(StatsCounterIndex.CH_DROP_STATS)

    def get_encap_fail_stats(self) -> LbStats:
        """Encapsulation failure counter."""
        return self._get_global(StatsCounterIndex.ENCAP_FAIL_CNTR)

    def get_src_routing_stats(self) -> LbStats:
        """Source-based routing counter."""
        return self._get_global(StatsCounterIndex.LPM_SRC_CNTRS)

    def get_inline_decap_stats(self) -> LbStats:
        """Remote encapsulation / inline decap counter."""
        return self._get_global(StatsCounterIndex.REMOTE_ENCAP_CNTRS)

    def get_decap_stats(self) -> LbStats:
        """Decapsulation counter."""
        return self._get_global(StatsCounterIndex.DECAP_CNTR)

    def get_xpop_decap_stats(self) -> LbStats:
        """Cross-PoP decap success counter."""
        return self._get_global(StatsCounterIndex.XPOP_DECAP_SUCCESSFUL)

    def get_udp_flow_migration_stats(self) -> LbStats:
        """UDP flow migration counter."""
        return self._get_global(StatsCounterIndex.UDP_FLOW_MIGRATION_STATS)

    def get_quic_icmp_stats(self) -> LbStats:
        """QUIC ICMP message counter."""
        return self._get_global(StatsCounterIndex.QUIC_ICMP_STATS)

    def get_xdp_total_stats(self) -> LbStats:
        """Total XDP packets counter."""
        return self._get_global(StatsCounterIndex.XDP_TOTAL_CNTR)

    def get_xdp_tx_stats(self) -> LbStats:
        """XDP_TX action counter."""
        return self._get_global(StatsCounterIndex.XDP_TX_CNTR)

    def get_xdp_drop_stats(self) -> LbStats:
        """XDP_DROP action counter."""
        return self._get_global(StatsCounterIndex.XDP_DROP_CNTR)

    def get_xdp_pass_stats(self) -> LbStats:
        """XDP_PASS action counter."""
        return self._get_global(StatsCounterIndex.XDP_PASS_CNTR)

    # -------------------------------------------------------------------------
    # Per-core stats
    # -------------------------------------------------------------------------

    def get_per_core_packets_stats(self) -> list[int]:
        """Get XDP total packets broken down by CPU core."""
        per_cpu = self._stats_map.get_all_cpus(
            self._global_index(StatsCounterIndex.XDP_TOTAL_CNTR)
        )
        return [s.v1 for s in per_cpu] if per_cpu else []

    # -------------------------------------------------------------------------
    # QUIC stats
    # -------------------------------------------------------------------------

    def get_quic_packet_stats(self) -> QuicPacketStats:
        """Get QUIC packet stats (requires quic_stats_map)."""
        if self._quic_stats_map is None:
            return QuicPacketStats()
        result = self._quic_stats_map.get(0)
        return result if result is not None else QuicPacketStats()

    # -------------------------------------------------------------------------
    # Health-check stats
    # -------------------------------------------------------------------------

    def get_hc_program_stats(self) -> HealthCheckProgStats:
        """Get HC BPF program stats (requires hc_stats_map)."""
        if self._hc_stats_map is None:
            return HealthCheckProgStats()
        result = self._hc_stats_map.get(0)
        return result if result is not None else HealthCheckProgStats()

    def get_packets_for_hc_key(self, hc_key_index: int) -> int:
        """Get packet count for a specific HC key (requires per_hckey_stats)."""
        if self._per_hckey_stats is None:
            return 0
        result = self._per_hckey_stats.get(hc_key_index)
        return result if result is not None else 0

    # -------------------------------------------------------------------------
    # LRU miss per-real
    # -------------------------------------------------------------------------

    def get_lru_miss_stats_for_real(self, real_index: int) -> int:
        """Get LRU miss count for a specific backend (requires lru_miss_stats_map)."""
        if self._lru_miss_stats_map is None:
            return 0
        result = self._lru_miss_stats_map.get(real_index)
        return result if result is not None else 0
