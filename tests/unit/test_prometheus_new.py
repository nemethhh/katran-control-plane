"""Tests for extended Prometheus metrics collector methods."""

from unittest.mock import Mock

import pytest

from katran.core.types import HealthCheckProgStats, LbStats, QuicPacketStats
from katran.stats.collector import KatranMetricsCollector


def _collect_metrics_as_dict(collector):
    """Helper to collect metrics and convert to dict for easier testing."""
    result = {}
    for metric_family in collector.collect():
        for sample in metric_family.samples:
            key = (sample.name, tuple(sorted(sample.labels.items())))
            result[key] = sample.value
    return result


def _metric_names(collector):
    """Return set of all metric family names from collect()."""
    return {m.name for m in collector.collect()}


@pytest.fixture
def mock_service():
    """Create a mock KatranService with _stats_manager properly configured."""
    service = Mock()
    service.is_running = True
    service.stats_map = None
    service.vip_manager = None
    service.real_manager = None

    # Set up _stats_manager with real return values
    stats_mgr = Mock()
    stats_mgr.get_ch_drop_stats.return_value = LbStats(v1=10, v2=0)
    stats_mgr.get_encap_fail_stats.return_value = LbStats(v1=5, v2=0)
    stats_mgr.get_lru_fallback_stats.return_value = LbStats(v1=20, v2=0)
    stats_mgr.get_global_lru_stats.return_value = LbStats(v1=30, v2=0)
    stats_mgr.get_decap_stats.return_value = LbStats(v1=15, v2=0)
    stats_mgr.get_src_routing_stats.return_value = LbStats(v1=25, v2=0)
    stats_mgr.get_quic_icmp_stats.return_value = LbStats(v1=3, v2=0)
    stats_mgr.get_icmp_ptb_v4_stats.return_value = LbStats(v1=7, v2=0)
    stats_mgr.get_icmp_ptb_v6_stats.return_value = LbStats(v1=4, v2=0)
    stats_mgr.get_xpop_decap_stats.return_value = LbStats(v1=8, v2=0)
    stats_mgr.get_udp_flow_migration_stats.return_value = LbStats(v1=2, v2=0)
    stats_mgr.get_real_stats.return_value = LbStats(v1=100, v2=2000)
    stats_mgr.get_quic_packet_stats.return_value = QuicPacketStats(
        ch_routed=50, cid_routed=30, cid_invalid_server_id=2, cid_unknown_real_dropped=1
    )
    stats_mgr.get_hc_program_stats.return_value = HealthCheckProgStats(
        packets_processed=42, packets_dropped=3, packets_skipped=5
    )
    service._stats_manager = stats_mgr

    return service


# ---------------------------------------------------------------------------
# Extended global stats
# ---------------------------------------------------------------------------


class TestExtendedGlobalMetrics:
    def test_ch_drops_metric(self, mock_service):
        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_ch_drops_total", ())) == 10

    def test_encap_failures_metric(self, mock_service):
        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_encap_failures_total", ())) == 5

    def test_lru_fallback_metric(self, mock_service):
        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_lru_fallback_hits_total", ())) == 20

    def test_global_lru_hits_metric(self, mock_service):
        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_global_lru_hits_total", ())) == 30

    def test_decap_packets_metric(self, mock_service):
        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_decap_packets_total", ())) == 15

    def test_src_routing_packets_metric(self, mock_service):
        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_src_routing_packets_total", ())) == 25

    def test_quic_icmp_metric(self, mock_service):
        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_quic_icmp_total", ())) == 3

    def test_icmp_ptb_v4_metric(self, mock_service):
        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_icmp_ptb_v4_total", ())) == 7

    def test_icmp_ptb_v6_metric(self, mock_service):
        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_icmp_ptb_v6_total", ())) == 4

    def test_xpop_decap_metric(self, mock_service):
        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_xpop_decap_total", ())) == 8

    def test_udp_flow_migration_metric(self, mock_service):
        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_udp_flow_migration_total", ())) == 2

    def test_skipped_when_service_not_running(self, mock_service):
        mock_service.is_running = False
        collector = KatranMetricsCollector(mock_service)
        names = _metric_names(collector)
        assert "katran_ch_drops" not in names

    def test_skipped_when_no_stats_manager(self, mock_service):
        mock_service._stats_manager = None
        collector = KatranMetricsCollector(mock_service)
        names = _metric_names(collector)
        assert "katran_ch_drops" not in names


# ---------------------------------------------------------------------------
# Per-real stats
# ---------------------------------------------------------------------------


class TestPerRealMetrics:
    def test_per_real_packets_and_bytes(self, mock_service):
        # Set up real_manager with _reals dict
        real_mgr = Mock()
        real_meta = Mock()
        real_meta.num = 1
        real_mgr._reals = {"10.0.0.100": real_meta}
        mock_service.real_manager = real_mgr

        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)

        assert (
            metrics.get(
                ("katran_real_packets_total", (("address", "10.0.0.100"),))
            )
            == 100
        )
        assert (
            metrics.get(
                ("katran_real_bytes_total", (("address", "10.0.0.100"),))
            )
            == 2000
        )

    def test_skipped_when_no_real_manager(self, mock_service):
        mock_service.real_manager = None
        collector = KatranMetricsCollector(mock_service)
        names = _metric_names(collector)
        assert "katran_real_packets" not in names

    def test_skipped_when_no_stats_manager(self, mock_service):
        mock_service._stats_manager = None
        real_mgr = Mock()
        real_mgr._reals = {"10.0.0.100": Mock(num=1)}
        mock_service.real_manager = real_mgr
        collector = KatranMetricsCollector(mock_service)
        names = _metric_names(collector)
        assert "katran_real_packets" not in names


# ---------------------------------------------------------------------------
# QUIC detail stats
# ---------------------------------------------------------------------------


class TestQuicDetailMetrics:
    def test_quic_ch_routed(self, mock_service):
        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_quic_ch_routed_total", ())) == 50

    def test_quic_cid_routed(self, mock_service):
        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_quic_cid_routed_total", ())) == 30

    def test_quic_cid_invalid_server_id(self, mock_service):
        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_quic_cid_invalid_server_id_total", ())) == 2

    def test_quic_cid_unknown_real_dropped(self, mock_service):
        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_quic_cid_unknown_real_dropped_total", ())) == 1

    def test_skipped_when_no_stats_manager(self, mock_service):
        mock_service._stats_manager = None
        collector = KatranMetricsCollector(mock_service)
        names = _metric_names(collector)
        assert "katran_quic_ch_routed" not in names


# ---------------------------------------------------------------------------
# HC program stats
# ---------------------------------------------------------------------------


class TestHcProgramMetrics:
    def test_hc_packets_processed(self, mock_service):
        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_hc_packets_processed_total", ())) == 42

    def test_hc_packets_dropped(self, mock_service):
        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_hc_packets_dropped_total", ())) == 3

    def test_hc_packets_skipped(self, mock_service):
        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_hc_packets_skipped_total", ())) == 5

    def test_skipped_when_no_stats_manager(self, mock_service):
        mock_service._stats_manager = None
        collector = KatranMetricsCollector(mock_service)
        names = _metric_names(collector)
        assert "katran_hc_packets_processed" not in names


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestExtendedErrorHandling:
    def test_extended_global_error_doesnt_crash(self, mock_service):
        """Stats manager exception shouldn't crash collection."""
        mock_service._stats_manager.get_ch_drop_stats.side_effect = Exception("BPF error")
        collector = KatranMetricsCollector(mock_service)
        # Should not crash, just skip extended global stats
        metrics = list(collector.collect())
        assert any(m.name == "katran_up" for m in metrics)

    def test_quic_stats_error_doesnt_crash(self, mock_service):
        """QUIC stats exception shouldn't crash collection."""
        mock_service._stats_manager.get_quic_packet_stats.side_effect = Exception("err")
        collector = KatranMetricsCollector(mock_service)
        metrics = list(collector.collect())
        assert any(m.name == "katran_up" for m in metrics)

    def test_hc_stats_error_doesnt_crash(self, mock_service):
        """HC stats exception shouldn't crash collection."""
        mock_service._stats_manager.get_hc_program_stats.side_effect = Exception("err")
        collector = KatranMetricsCollector(mock_service)
        metrics = list(collector.collect())
        assert any(m.name == "katran_up" for m in metrics)
