"""
Prometheus metrics collector for Katran load balancer.

Exposes BPF statistics as Prometheus metrics by implementing a custom collector
that reads data fresh from BPF maps on each scrape.
"""

from __future__ import annotations

from collections.abc import Generator
from typing import TYPE_CHECKING, Any

from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily
from prometheus_client.registry import Collector

from katran.core.logging import get_logger

if TYPE_CHECKING:
    from katran.service import KatranService

log = get_logger(__name__)


class KatranMetricsCollector(Collector):
    """
    Custom Prometheus collector for Katran metrics.

    Reads statistics directly from BPF maps on each scrape, providing
    fresh data without caching.

    Implements unchecked collector pattern (describe() returns empty list)
    because VIP label sets are dynamic and change at runtime.
    """

    def __init__(self, service: KatranService) -> None:
        """
        Initialize collector with service reference.

        Args:
            service: KatranService instance with stats_map and vip_manager
        """
        self.service = service

    def describe(self) -> list[Any]:
        """
        Return empty list for unchecked collector.

        Dynamic VIP label sets make it impractical to describe metrics
        ahead of time.
        """
        return []

    def collect(self) -> Generator[Any, None, None]:
        """
        Collect all metrics and yield metric families.

        Each subsystem (_collect_*) catches exceptions internally to ensure
        one failure doesn't block other metrics.
        """
        metrics: list[Any] = []

        # Early validation - check service reference exists
        if self.service is None:
            log.warning("Service reference is None during metrics collection")
            up_metric = GaugeMetricFamily("katran_up", "Service running status")
            up_metric.add_metric([], 0)
            yield up_metric
            return

        try:
            # Collect all metrics into a list first to avoid generator issues
            metrics.extend(self._collect_service_info())
            metrics.extend(self._collect_vip_stats())
            metrics.extend(self._collect_global_stats())
            metrics.extend(self._collect_xdp_stats())
            metrics.extend(self._collect_per_cpu_stats())
        except Exception:
            # Last resort: catch any unexpected errors to prevent server crash
            log.error("Unexpected error in metrics collection", exc_info=True)
            # Clear any partial metrics and return minimal safe metric
            metrics = []
            up_metric = GaugeMetricFamily("katran_up", "Service running status")
            up_metric.add_metric([], 0)
            metrics.append(up_metric)

        # Yield collected metrics
        for metric in metrics:
            yield metric

    def _collect_service_info(self) -> Generator[Any, None, None]:
        """Collect service state metrics (gauges)."""
        try:
            # Service up/down
            up_metric = GaugeMetricFamily(
                "katran_up",
                "1 if service running, 0 otherwise",
            )
            up_metric.add_metric([], 1 if self.service.is_running else 0)
            yield up_metric

            # Number of configured VIPs
            if self.service.is_running and self.service.vip_manager is not None:
                vip_count = self.service.vip_manager.get_vip_count()
                vips_metric = GaugeMetricFamily(
                    "katran_vips_configured",
                    "Number of configured VIPs",
                )
                vips_metric.add_metric([], vip_count)
                yield vips_metric
        except Exception:
            log.warning("Failed to collect service info metrics", exc_info=True)

    def _collect_vip_stats(self) -> Generator[Any, None, None]:
        """Collect per-VIP statistics."""
        if (
            not self.service.is_running
            or self.service.vip_manager is None
            or self.service.stats_map is None
        ):
            # Yield empty metric families to indicate no data available
            packets = CounterMetricFamily(
                "katran_vip_packets_total",
                "Packets forwarded per VIP",
                labels=["address", "port", "protocol"],
            )
            yield packets

            bytes_metric = CounterMetricFamily(
                "katran_vip_bytes_total",
                "Bytes forwarded per VIP",
                labels=["address", "port", "protocol"],
            )
            yield bytes_metric

            lru_hits = CounterMetricFamily(
                "katran_vip_lru_hits_total",
                "LRU cache hits per VIP",
                labels=["address", "port", "protocol"],
            )
            yield lru_hits

            lru_misses = CounterMetricFamily(
                "katran_vip_lru_misses_total",
                "LRU cache misses per VIP",
                labels=["address", "port", "protocol"],
            )
            yield lru_misses

            backends = GaugeMetricFamily(
                "katran_vip_backends",
                "Number of active backends per VIP",
                labels=["address", "port", "protocol"],
            )
            yield backends
            return

        try:
            # Initialize metric families
            packets = CounterMetricFamily(
                "katran_vip_packets_total",
                "Packets forwarded per VIP",
                labels=["address", "port", "protocol"],
            )

            bytes_metric = CounterMetricFamily(
                "katran_vip_bytes_total",
                "Bytes forwarded per VIP",
                labels=["address", "port", "protocol"],
            )

            lru_hits = CounterMetricFamily(
                "katran_vip_lru_hits_total",
                "LRU cache hits per VIP",
                labels=["address", "port", "protocol"],
            )

            lru_misses = CounterMetricFamily(
                "katran_vip_lru_misses_total",
                "LRU cache misses per VIP",
                labels=["address", "port", "protocol"],
            )

            backends = GaugeMetricFamily(
                "katran_vip_backends",
                "Number of active backends per VIP",
                labels=["address", "port", "protocol"],
            )

            # Collect stats for each VIP
            vips = self.service.vip_manager.list_vips()
            for vip in vips:
                try:
                    # Get stats from BPF map
                    stats = self.service.stats_map.get_vip_stats(vip.vip_num)

                    # Create label values
                    labels = [
                        str(vip.key.address),
                        str(vip.key.port),
                        vip.key.protocol.name.lower(),
                    ]

                    # Add samples
                    packets.add_metric(labels, stats.packets)
                    bytes_metric.add_metric(labels, stats.bytes)
                    lru_hits.add_metric(labels, stats.lru_hits)
                    lru_misses.add_metric(labels, stats.lru_misses)
                    backends.add_metric(labels, len(vip.active_reals))
                except Exception:
                    log.warning(
                        "Failed to collect stats for VIP %s:%d/%s",
                        vip.key.address,
                        vip.key.port,
                        vip.key.protocol.name,
                        exc_info=True,
                    )
                    # Continue with other VIPs

            yield packets
            yield bytes_metric
            yield lru_hits
            yield lru_misses
            yield backends
        except Exception:
            log.warning("Failed to collect VIP stats", exc_info=True)

    def _collect_global_stats(self) -> Generator[Any, None, None]:
        """Collect global statistics counters."""
        if not self.service.is_running or self.service.stats_map is None:
            return

        try:
            stats = self.service.stats_map.get_global_stats()

            # Total packets
            packets = CounterMetricFamily(
                "katran_packets_total",
                "Total packets processed",
            )
            packets.add_metric([], stats.total_packets)
            yield packets

            # Total bytes
            bytes_metric = CounterMetricFamily(
                "katran_bytes_total",
                "Total bytes processed",
            )
            bytes_metric.add_metric([], stats.total_bytes)
            yield bytes_metric

            # LRU hits
            lru_hits = CounterMetricFamily(
                "katran_lru_hits_total",
                "Global LRU cache hits",
            )
            lru_hits.add_metric([], stats.total_lru_hits)
            yield lru_hits

            # LRU misses
            lru_misses = CounterMetricFamily(
                "katran_lru_misses_total",
                "Global LRU cache misses",
            )
            lru_misses.add_metric([], stats.total_lru_misses)
            yield lru_misses

            # VIP misses
            vip_misses = CounterMetricFamily(
                "katran_vip_misses_total",
                "Packets matching no VIP",
            )
            vip_misses.add_metric([], stats.vip_misses)
            yield vip_misses

            # ICMP too-big
            icmp_toobig = CounterMetricFamily(
                "katran_icmp_toobig_total",
                "ICMP too-big messages sent",
            )
            icmp_toobig.add_metric([], stats.icmp_toobig)
            yield icmp_toobig

            # New connections
            new_conns = CounterMetricFamily(
                "katran_new_connections_total",
                "New connections established",
            )
            new_conns.add_metric([], stats.new_connections)
            yield new_conns
        except Exception:
            log.warning("Failed to collect global stats", exc_info=True)

    def _collect_xdp_stats(self) -> Generator[Any, None, None]:
        """Collect XDP action statistics."""
        if not self.service.is_running or self.service.stats_map is None:
            return

        try:
            xdp_stats = self.service.stats_map.get_xdp_action_stats()

            xdp_packets = CounterMetricFamily(
                "katran_xdp_packets_total",
                "Packets per XDP action",
                labels=["action"],
            )

            for action, count in xdp_stats.items():
                xdp_packets.add_metric([action], count)

            yield xdp_packets
        except Exception:
            log.warning("Failed to collect XDP stats", exc_info=True)

    def _collect_per_cpu_stats(self) -> Generator[Any, None, None]:
        """Collect per-CPU packet counters."""
        if not self.service.is_running or self.service.stats_map is None:
            return

        try:
            # Use XDP total counter to get per-CPU breakdown
            # Global counters live at MAX_VIPS + offset in the stats map
            from katran.core.constants import StatsCounterIndex

            stats_map = self.service.stats_map
            per_cpu_values = stats_map.get_counter_per_cpu(
                stats_map._global_index(StatsCounterIndex.XDP_TOTAL_CNTR)
            )

            cpu_packets = CounterMetricFamily(
                "katran_cpu_packets_total",
                "Packets processed per CPU core",
                labels=["cpu"],
            )

            for cpu_id, stats in enumerate(per_cpu_values):
                cpu_packets.add_metric([str(cpu_id)], stats.v1)

            yield cpu_packets
        except Exception:
            log.warning("Failed to collect per-CPU stats", exc_info=True)
