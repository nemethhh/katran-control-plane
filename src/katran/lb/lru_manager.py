"""Advanced LRU operations matching the reference implementation."""

from __future__ import annotations

import logging
import time
from threading import RLock
from typing import TYPE_CHECKING

from katran.core.types import (
    FlowKey,
    LruAnalysis,
    LruEntries,
    LruEntry,
    PurgeResponse,
    RealPosLru,
    VipKey,
    VipLruStats,
)

if TYPE_CHECKING:
    from katran.bpf.maps.lru_map import LruMap
    from katran.bpf.maps.lru_miss_stats_map import LruMissStatsMap
    from katran.lb.real_manager import RealManager
    from katran.lb.vip_manager import VipManager

logger = logging.getLogger(__name__)

ONE_SEC_NS = 1_000_000_000
THIRTY_SEC_NS = 30 * ONE_SEC_NS
SIXTY_SEC_NS = 60 * ONE_SEC_NS


class LruManager:
    """Manages LRU flow caches (per-CPU + fallback) with search, purge, and analysis."""

    def __init__(
        self,
        fallback_lru: LruMap,
        per_cpu_lru_fds: list[int] | None = None,
        lru_miss_stats_map: LruMissStatsMap | None = None,
        vip_manager: VipManager | None = None,
        real_manager: RealManager | None = None,
    ) -> None:
        self._fallback_lru = fallback_lru
        self._per_cpu_lru_fds = per_cpu_lru_fds
        self._lru_miss_stats_map = lru_miss_stats_map
        self._vip_manager = vip_manager
        self._real_manager = real_manager
        self._lock = RLock()

    def _iter_all_lru_entries(self) -> list[tuple[FlowKey, RealPosLru, int]]:
        """Iterate all LRU maps (per-CPU + fallback).

        Returns list of (flow, value, cpu) tuples where cpu=-1 means fallback.
        """
        entries: list[tuple[FlowKey, RealPosLru, int]] = []
        if self._per_cpu_lru_fds:
            for cpu, fd in enumerate(self._per_cpu_lru_fds):
                try:
                    for flow, value in self._iter_lru_fd(fd):
                        entries.append((flow, value, cpu))
                except Exception:
                    logger.warning("Failed to iterate per-CPU LRU map for CPU %d", cpu)
        for flow, value in self._fallback_lru.items():
            entries.append((flow, value, -1))
        return entries

    def _iter_lru_fd(self, fd: int) -> list[tuple[FlowKey, RealPosLru]]:
        """Iterate an LRU map by raw FD using BPF get_next_key + lookup."""
        import ctypes

        from katran.bpf.map_manager import BpfAttrMapElem, BpfCmd, _bpf_syscall
        from katran.core.types import FLOW_KEY_SIZE, REAL_POS_LRU_SIZE

        results: list[tuple[FlowKey, RealPosLru]] = []
        key_buf = ctypes.create_string_buffer(FLOW_KEY_SIZE)
        next_key_buf = ctypes.create_string_buffer(FLOW_KEY_SIZE)
        value_buf = ctypes.create_string_buffer(REAL_POS_LRU_SIZE)

        attr = BpfAttrMapElem()
        attr.map_fd = fd
        attr.key = 0
        attr.value_or_next_key = ctypes.cast(next_key_buf, ctypes.c_void_p).value or 0
        result = _bpf_syscall(BpfCmd.MAP_GET_NEXT_KEY, attr, ctypes.sizeof(attr))

        while result >= 0:
            ctypes.memmove(key_buf, next_key_buf, FLOW_KEY_SIZE)
            attr2 = BpfAttrMapElem()
            attr2.map_fd = fd
            attr2.key = ctypes.cast(key_buf, ctypes.c_void_p).value or 0
            attr2.value_or_next_key = ctypes.cast(value_buf, ctypes.c_void_p).value or 0
            if _bpf_syscall(BpfCmd.MAP_LOOKUP_ELEM, attr2, ctypes.sizeof(attr2)) >= 0:
                flow = FlowKey.from_bytes(bytes(key_buf.raw))
                value = RealPosLru.from_bytes(bytes(value_buf.raw))
                results.append((flow, value))
            attr.key = ctypes.cast(key_buf, ctypes.c_void_p).value or 0
            result = _bpf_syscall(BpfCmd.MAP_GET_NEXT_KEY, attr, ctypes.sizeof(attr))
        return results

    def _delete_from_fd(self, fd: int, flow: FlowKey) -> bool:
        """Delete a single flow entry from an LRU map by raw FD."""
        import ctypes

        from katran.bpf.map_manager import BpfAttrMapElem, BpfCmd, _bpf_syscall

        key_buf = ctypes.create_string_buffer(flow.to_bytes())
        attr = BpfAttrMapElem()
        attr.map_fd = fd
        attr.key = ctypes.cast(key_buf, ctypes.c_void_p).value or 0
        attr.value_or_next_key = 0
        return _bpf_syscall(BpfCmd.MAP_DELETE_ELEM, attr, ctypes.sizeof(attr)) >= 0

    def _matches_vip(self, flow: FlowKey, vip: VipKey) -> bool:
        """Check if a flow's destination matches a VIP."""
        return (
            flow.dst_addr == vip.address
            and flow.dst_port == vip.port
            and flow.protocol == vip.protocol
        )

    def search(self, dst_vip: VipKey, src_ip: str, src_port: int) -> LruEntries:
        """Search for LRU entries matching a specific flow."""
        from ipaddress import ip_address

        src_addr = ip_address(src_ip)
        entries: list[LruEntry] = []
        now_ns = time.time_ns()
        with self._lock:
            for flow, value, cpu in self._iter_all_lru_entries():
                if (
                    self._matches_vip(flow, dst_vip)
                    and flow.src_addr == src_addr
                    and flow.src_port == src_port
                ):
                    delta = (now_ns - value.atime) / ONE_SEC_NS if value.atime else 0
                    entries.append(
                        LruEntry(
                            flow=flow,
                            real_index=value.pos,
                            atime=value.atime,
                            atime_delta_sec=delta,
                            cpu=cpu,
                        )
                    )
        return LruEntries(entries=entries)

    def list(self, dst_vip: VipKey, limit: int = 100) -> LruEntries:
        """List LRU entries for a VIP, up to the given limit."""
        entries: list[LruEntry] = []
        now_ns = time.time_ns()
        with self._lock:
            for flow, value, cpu in self._iter_all_lru_entries():
                if self._matches_vip(flow, dst_vip):
                    delta = (now_ns - value.atime) / ONE_SEC_NS if value.atime else 0
                    entries.append(
                        LruEntry(
                            flow=flow,
                            real_index=value.pos,
                            atime=value.atime,
                            atime_delta_sec=delta,
                            cpu=cpu,
                        )
                    )
                    if len(entries) >= limit:
                        break
        return LruEntries(entries=entries)

    def _delete_from_all(self, flow: FlowKey) -> bool:
        """Delete a flow from all LRU maps (per-CPU + fallback)."""
        deleted = False
        if self._per_cpu_lru_fds:
            for fd in self._per_cpu_lru_fds:
                if self._delete_from_fd(fd, flow):
                    deleted = True
        if self._fallback_lru.delete(flow):
            deleted = True
        return deleted

    def delete(self, dst_vip: VipKey, src_ip: str, src_port: int) -> list[str]:
        """Delete LRU entries matching a specific flow from all maps."""
        from ipaddress import ip_address

        src_addr = ip_address(src_ip)
        deleted: list[str] = []
        with self._lock:
            for flow, value, cpu in self._iter_all_lru_entries():
                if (
                    self._matches_vip(flow, dst_vip)
                    and flow.src_addr == src_addr
                    and flow.src_port == src_port
                ):
                    if self._delete_from_all(flow):
                        deleted.append(f"cpu={cpu}")
        return deleted

    def purge_vip(self, dst_vip: VipKey) -> PurgeResponse:
        """Remove all LRU entries for a VIP."""
        count = 0
        with self._lock:
            to_delete: list[FlowKey] = []
            for flow, value, cpu in self._iter_all_lru_entries():
                if self._matches_vip(flow, dst_vip):
                    to_delete.append(flow)
            for flow in to_delete:
                if self._delete_from_all(flow):
                    count += 1
        return PurgeResponse(deleted_count=count)

    def purge_vip_for_real(self, dst_vip: VipKey, real_index: int) -> PurgeResponse:
        """Remove LRU entries for a VIP that point to a specific backend index."""
        count = 0
        with self._lock:
            to_delete: list[FlowKey] = []
            for flow, value, cpu in self._iter_all_lru_entries():
                if self._matches_vip(flow, dst_vip) and value.pos == real_index:
                    to_delete.append(flow)
            for flow in to_delete:
                if self._delete_from_all(flow):
                    count += 1
        return PurgeResponse(deleted_count=count)

    def analyze(self) -> LruAnalysis:
        """Analyze all LRU entries across all maps, bucketing by atime."""
        now_ns = time.time_ns()
        analysis = LruAnalysis()
        with self._lock:
            for flow, value, cpu in self._iter_all_lru_entries():
                analysis.total_entries += 1
                vip_str = f"{flow.dst_addr}:{flow.dst_port}/{flow.protocol}"
                if vip_str not in analysis.per_vip:
                    analysis.per_vip[vip_str] = VipLruStats()
                stats = analysis.per_vip[vip_str]
                stats.entry_count += 1
                if value.atime == 0:
                    stats.atime_zero_count += 1
                else:
                    delta_ns = now_ns - value.atime
                    if delta_ns < THIRTY_SEC_NS:
                        stats.atime_under_30s_count += 1
                    elif delta_ns < SIXTY_SEC_NS:
                        stats.atime_30_to_60s_count += 1
                    else:
                        stats.atime_over_60s_count += 1
        return analysis

    def get_vip_lru_miss_stats(self, vip: VipKey) -> dict[str, int]:
        """Get per-real LRU miss counts for a VIP's backends."""
        if self._lru_miss_stats_map is None or self._vip_manager is None:
            return {}
        vip_obj = self._vip_manager.get_vip(
            address=str(vip.address),
            port=vip.port,
            protocol=vip.protocol,
        )
        if vip_obj is None:
            return {}
        result: dict[str, int] = {}
        for real in vip_obj.reals:
            miss_count = self._lru_miss_stats_map.get(real.index)
            if miss_count is not None:
                result[str(real.address)] = miss_count
        return result
