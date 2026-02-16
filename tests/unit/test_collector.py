"""Unit tests for Prometheus metrics collector."""

from unittest.mock import Mock, PropertyMock, patch

import pytest
from prometheus_client import CollectorRegistry

from katran.bpf.maps.stats_map import GlobalStatistics, VipStatistics
from katran.core.constants import Protocol, StatsCounterIndex
from katran.core.types import LbStats
from katran.stats.collector import KatranMetricsCollector


@pytest.fixture
def mock_service():
    """Create a mock KatranService."""
    service = Mock()
    service.is_running = True
    service.stats_map = Mock()
    service.vip_manager = Mock()
    return service


@pytest.fixture
def mock_vip():
    """Create a mock VIP object."""
    vip = Mock()
    vip.vip_num = 0
    vip.key.address = "10.0.0.1"
    vip.key.port = 80
    vip.key.protocol = Protocol.TCP
    vip.active_reals = []
    return vip


def _collect_metrics_as_dict(collector):
    """Helper to collect metrics and convert to dict for easier testing."""
    result = {}
    for metric_family in collector.collect():
        for sample in metric_family.samples:
            key = (sample.name, tuple(sorted(sample.labels.items())))
            result[key] = sample.value
    return result


class TestServiceMetrics:
    """Test service state metrics."""

    def test_service_down_emits_up_zero(self):
        """katran_up should be 0 when service is not running."""
        service = Mock()
        service.is_running = False
        collector = KatranMetricsCollector(service)

        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_up", ())) == 0

    def test_service_up_emits_up_one(self, mock_service):
        """katran_up should be 1 when service is running."""
        mock_service.vip_manager.get_vip_count.return_value = 0
        collector = KatranMetricsCollector(mock_service)

        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_up", ())) == 1

    def test_vips_configured_count(self, mock_service):
        """katran_vips_configured should reflect VIP count."""
        mock_service.vip_manager.get_vip_count.return_value = 5
        collector = KatranMetricsCollector(mock_service)

        metrics = _collect_metrics_as_dict(collector)
        assert metrics.get(("katran_vips_configured", ())) == 5


class TestVipMetrics:
    """Test per-VIP statistics."""

    def test_vip_stats_basic(self, mock_service, mock_vip):
        """Verify all per-VIP counter and gauge metrics."""
        # Setup two VIPs
        vip1 = Mock()
        vip1.vip_num = 0
        vip1.key.address = "10.0.0.1"
        vip1.key.port = 80
        vip1.key.protocol = Protocol.TCP
        vip1.active_reals = [Mock(), Mock()]

        vip2 = Mock()
        vip2.vip_num = 1
        vip2.key.address = "10.0.0.2"
        vip2.key.port = 443
        vip2.key.protocol = Protocol.UDP
        vip2.active_reals = [Mock()]

        mock_service.vip_manager.list_vips.return_value = [vip1, vip2]
        mock_service.vip_manager.get_vip_count.return_value = 2

        # Mock stats
        mock_service.stats_map.get_vip_stats.side_effect = [
            VipStatistics(packets=100, bytes=5000, lru_hits=90, lru_misses=10),
            VipStatistics(packets=200, bytes=10000, lru_hits=180, lru_misses=20),
        ]

        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)

        # Check VIP 1 metrics
        assert (
            metrics.get(
                (
                    "katran_vip_packets_total",
                    (("address", "10.0.0.1"), ("port", "80"), ("protocol", "tcp")),
                )
            )
            == 100
        )
        assert (
            metrics.get(
                (
                    "katran_vip_bytes_total",
                    (("address", "10.0.0.1"), ("port", "80"), ("protocol", "tcp")),
                )
            )
            == 5000
        )
        assert (
            metrics.get(
                (
                    "katran_vip_lru_hits_total",
                    (("address", "10.0.0.1"), ("port", "80"), ("protocol", "tcp")),
                )
            )
            == 90
        )
        assert (
            metrics.get(
                (
                    "katran_vip_lru_misses_total",
                    (("address", "10.0.0.1"), ("port", "80"), ("protocol", "tcp")),
                )
            )
            == 10
        )
        assert (
            metrics.get(
                (
                    "katran_vip_backends",
                    (("address", "10.0.0.1"), ("port", "80"), ("protocol", "tcp")),
                )
            )
            == 2
        )

        # Check VIP 2 metrics
        assert (
            metrics.get(
                (
                    "katran_vip_packets_total",
                    (("address", "10.0.0.2"), ("port", "443"), ("protocol", "udp")),
                )
            )
            == 200
        )
        assert (
            metrics.get(
                (
                    "katran_vip_backends",
                    (("address", "10.0.0.2"), ("port", "443"), ("protocol", "udp")),
                )
            )
            == 1
        )

    def test_vip_backends_gauge(self, mock_service, mock_vip):
        """katran_vip_backends should reflect active_reals count."""
        mock_vip.active_reals = [Mock(), Mock(), Mock()]
        mock_service.vip_manager.list_vips.return_value = [mock_vip]
        mock_service.vip_manager.get_vip_count.return_value = 1
        mock_service.stats_map.get_vip_stats.return_value = VipStatistics()

        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)

        assert (
            metrics.get(
                (
                    "katran_vip_backends",
                    (("address", "10.0.0.1"), ("port", "80"), ("protocol", "tcp")),
                )
            )
            == 3
        )

    def test_no_vips_configured(self, mock_service):
        """VIP metrics should be yielded with zero samples when no VIPs exist."""
        mock_service.vip_manager.list_vips.return_value = []
        mock_service.vip_manager.get_vip_count.return_value = 0
        # Mock other methods that collect() calls
        mock_service.stats_map.get_global_stats.return_value = GlobalStatistics()
        mock_service.stats_map.get_xdp_action_stats.return_value = {
            "total": 0,
            "tx": 0,
            "drop": 0,
            "pass": 0,
        }
        mock_service.stats_map.get_counter_per_cpu.return_value = []

        collector = KatranMetricsCollector(mock_service)
        # Just verify collection doesn't crash
        metrics = list(collector.collect())
        metric_names = [m.name for m in metrics]
        # Prometheus adds _total suffix at render time for counter families
        assert "katran_vip_packets" in metric_names

    def test_ipv6_vip_labels(self, mock_service):
        """IPv6 addresses should format correctly in labels."""
        vip = Mock()
        vip.vip_num = 0
        vip.key.address = "2001:db8::1"
        vip.key.port = 80
        vip.key.protocol = Protocol.TCP
        vip.active_reals = []

        mock_service.vip_manager.list_vips.return_value = [vip]
        mock_service.vip_manager.get_vip_count.return_value = 1
        mock_service.stats_map.get_vip_stats.return_value = VipStatistics(
            packets=42, bytes=1000, lru_hits=40, lru_misses=2
        )

        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)

        assert (
            metrics.get(
                (
                    "katran_vip_packets_total",
                    (("address", "2001:db8::1"), ("port", "80"), ("protocol", "tcp")),
                )
            )
            == 42
        )


class TestGlobalMetrics:
    """Test global statistics."""

    def test_global_stats(self, mock_service):
        """Verify all global counter metrics."""
        mock_service.vip_manager.get_vip_count.return_value = 0
        mock_service.stats_map.get_global_stats.return_value = GlobalStatistics(
            total_packets=1000,
            total_bytes=50000,
            total_lru_hits=900,
            total_lru_misses=100,
            vip_misses=10,
            icmp_toobig=5,
            new_connections=50,
        )

        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)

        assert metrics.get(("katran_packets_total", ())) == 1000
        assert metrics.get(("katran_bytes_total", ())) == 50000
        assert metrics.get(("katran_lru_hits_total", ())) == 900
        assert metrics.get(("katran_lru_misses_total", ())) == 100
        assert metrics.get(("katran_vip_misses_total", ())) == 10
        assert metrics.get(("katran_icmp_toobig_total", ())) == 5
        assert metrics.get(("katran_new_connections_total", ())) == 50


class TestXdpMetrics:
    """Test XDP action statistics."""

    def test_xdp_stats(self, mock_service):
        """Verify XDP action counters with all 4 actions."""
        mock_service.vip_manager.get_vip_count.return_value = 0
        mock_service.stats_map.get_xdp_action_stats.return_value = {
            "total": 1000,
            "tx": 900,
            "drop": 50,
            "pass": 50,
        }

        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)

        assert metrics.get(("katran_xdp_packets_total", (("action", "total"),))) == 1000
        assert metrics.get(("katran_xdp_packets_total", (("action", "tx"),))) == 900
        assert metrics.get(("katran_xdp_packets_total", (("action", "drop"),))) == 50
        assert metrics.get(("katran_xdp_packets_total", (("action", "pass"),))) == 50


class TestPerCpuMetrics:
    """Test per-CPU statistics."""

    def test_per_cpu_stats(self, mock_service):
        """Verify per-CPU packet counters."""
        mock_service.vip_manager.get_vip_count.return_value = 0
        # Simulate 4 CPUs
        mock_service.stats_map.get_counter_per_cpu.return_value = [
            LbStats(v1=100, v2=5000),
            LbStats(v1=200, v2=10000),
            LbStats(v1=150, v2=7500),
            LbStats(v1=300, v2=15000),
        ]

        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)

        assert metrics.get(("katran_cpu_packets_total", (("cpu", "0"),))) == 100
        assert metrics.get(("katran_cpu_packets_total", (("cpu", "1"),))) == 200
        assert metrics.get(("katran_cpu_packets_total", (("cpu", "2"),))) == 150
        assert metrics.get(("katran_cpu_packets_total", (("cpu", "3"),))) == 300


class TestErrorHandling:
    """Test graceful error handling."""

    def test_vip_stats_error_graceful(self, mock_service):
        """One VIP failing shouldn't block others."""
        vip1 = Mock()
        vip1.vip_num = 0
        vip1.key.address = "10.0.0.1"
        vip1.key.port = 80
        vip1.key.protocol = Protocol.TCP
        vip1.active_reals = []

        vip2 = Mock()
        vip2.vip_num = 1
        vip2.key.address = "10.0.0.2"
        vip2.key.port = 443
        vip2.key.protocol = Protocol.TCP
        vip2.active_reals = []

        mock_service.vip_manager.list_vips.return_value = [vip1, vip2]
        mock_service.vip_manager.get_vip_count.return_value = 2

        # First VIP fails, second succeeds
        mock_service.stats_map.get_vip_stats.side_effect = [
            Exception("BPF error"),
            VipStatistics(packets=100, bytes=5000, lru_hits=90, lru_misses=10),
        ]

        collector = KatranMetricsCollector(mock_service)
        metrics = _collect_metrics_as_dict(collector)

        # VIP 2 should still have metrics
        assert (
            metrics.get(
                (
                    "katran_vip_packets_total",
                    (("address", "10.0.0.2"), ("port", "443"), ("protocol", "tcp")),
                )
            )
            == 100
        )

    def test_global_stats_error_graceful(self, mock_service):
        """Global stats failure shouldn't block other subsystems."""
        mock_service.vip_manager.list_vips.return_value = []
        mock_service.vip_manager.get_vip_count.return_value = 0
        mock_service.stats_map.get_global_stats.side_effect = Exception("BPF error")

        collector = KatranMetricsCollector(mock_service)
        # Should not crash, just skip global stats
        metrics = list(collector.collect())
        assert any(m.name == "katran_up" for m in metrics)

    def test_missing_stats_map_graceful(self, mock_service):
        """Missing stats_map shouldn't crash VIP metrics collection."""
        vip = Mock()
        vip.vip_num = 0
        vip.key.address = "10.0.0.1"
        vip.key.port = 80
        vip.key.protocol = Protocol.TCP
        vip.active_reals = []

        mock_service.vip_manager.list_vips.return_value = [vip]
        mock_service.vip_manager.get_vip_count.return_value = 1
        mock_service.stats_map = None  # Simulate missing stats_map

        collector = KatranMetricsCollector(mock_service)
        # Should not crash, just return empty metrics
        metrics = list(collector.collect())
        assert any(m.name == "katran_up" for m in metrics)
        assert any(m.name == "katran_vip_packets" for m in metrics)

    def test_none_service_graceful(self):
        """None service reference shouldn't crash collection."""
        collector = KatranMetricsCollector(None)
        # Should not crash, just return katran_up=0
        metrics = list(collector.collect())
        assert len(metrics) == 1
        assert metrics[0].name == "katran_up"


class TestCollectorInterface:
    """Test collector interface methods."""

    def test_describe_returns_empty(self, mock_service):
        """describe() should return empty list for unchecked collector."""
        collector = KatranMetricsCollector(mock_service)
        assert collector.describe() == []


class TestMetricsEndpoint:
    """Test metrics HTTP endpoint integration."""

    def test_metrics_endpoint_returns_200(self, mock_service):
        """GET /metrics should return 200 with Prometheus content-type."""
        from httpx import AsyncClient

        from katran.api.rest.app import create_app

        mock_service.vip_manager.list_vips.return_value = []
        mock_service.vip_manager.get_vip_count.return_value = 0
        mock_service.stats_map.get_global_stats.return_value = GlobalStatistics()
        mock_service.stats_map.get_xdp_action_stats.return_value = {
            "total": 0,
            "tx": 0,
            "drop": 0,
            "pass": 0,
        }
        mock_service.stats_map.get_counter_per_cpu.return_value = []

        app = create_app(service=mock_service)

        # Use sync test client since we're in pytest without async markers
        from fastapi.testclient import TestClient

        client = TestClient(app)
        response = client.get("/metrics")

        assert response.status_code == 200
        assert "text/plain" in response.headers["content-type"]
        assert b"katran_up" in response.content

    def test_metrics_no_service_returns_404(self):
        """GET /metrics should return 404 when no service is configured."""
        from katran.api.rest.app import create_app

        app = create_app(service=None)

        from fastapi.testclient import TestClient

        client = TestClient(app)
        response = client.get("/metrics")

        assert response.status_code == 404
