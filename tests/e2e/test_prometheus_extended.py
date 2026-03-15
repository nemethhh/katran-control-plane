"""E2E tests for extended Prometheus metrics — per-real, QUIC, HC, LRU, global."""

import time

import pytest
from helpers import (
    add_backend,
    parse_metric_value,
    remove_backend,
    send_requests,
    setup_vip,
    teardown_vip,
)

VIP = "10.200.0.48"


@pytest.fixture(scope="module")
def metrics_setup(api_client, backend_1_addr):
    """Module fixture: create VIP, add backend, send traffic for metrics population."""
    setup_vip(api_client, VIP)
    add_backend(api_client, VIP, backend_1_addr)
    time.sleep(2)
    send_requests(VIP, count=20)
    time.sleep(2)
    yield
    remove_backend(api_client, VIP, backend_1_addr)
    teardown_vip(api_client, VIP)


def _get_metrics(api_client):
    resp = api_client.get("/metrics/")
    assert resp.status_code == 200
    return resp.text


class TestPrometheusExtended:
    """Verify all extended Prometheus metrics exist after traffic."""

    def test_per_real_packets_metric(self, api_client, metrics_setup, backend_1_addr):
        content = _get_metrics(api_client)
        value = parse_metric_value(
            content, "katran_real_packets_total", {"address": backend_1_addr}
        )
        assert value is not None, "katran_real_packets_total metric not found"

    def test_per_real_bytes_metric(self, api_client, metrics_setup, backend_1_addr):
        content = _get_metrics(api_client)
        value = parse_metric_value(
            content, "katran_real_bytes_total", {"address": backend_1_addr}
        )
        assert value is not None, "katran_real_bytes_total metric not found"

    def test_lru_hit_miss_metrics(self, api_client, metrics_setup):
        content = _get_metrics(api_client)
        hits = parse_metric_value(content, "katran_lru_hits_total")
        misses = parse_metric_value(content, "katran_lru_misses_total")
        assert hits is not None or misses is not None

    def test_ch_drops_metric(self, api_client, metrics_setup):
        content = _get_metrics(api_client)
        value = parse_metric_value(content, "katran_ch_drops_total")
        assert value is not None

    def test_encap_failures_metric(self, api_client, metrics_setup):
        content = _get_metrics(api_client)
        value = parse_metric_value(content, "katran_encap_failures_total")
        assert value is not None

    def test_lru_fallback_metric(self, api_client, metrics_setup):
        content = _get_metrics(api_client)
        value = parse_metric_value(content, "katran_lru_fallback_hits_total")
        assert value is not None

    def test_global_lru_metric(self, api_client, metrics_setup):
        content = _get_metrics(api_client)
        value = parse_metric_value(content, "katran_global_lru_hits_total")
        assert value is not None

    def test_decap_metric(self, api_client, metrics_setup):
        content = _get_metrics(api_client)
        value = parse_metric_value(content, "katran_decap_packets_total")
        assert value is not None

    def test_src_routing_metric(self, api_client, metrics_setup):
        content = _get_metrics(api_client)
        value = parse_metric_value(content, "katran_src_routing_packets_total")
        assert value is not None

    def test_quic_ch_routed_metric(self, api_client, metrics_setup):
        content = _get_metrics(api_client)
        value = parse_metric_value(content, "katran_quic_ch_routed_total")
        assert value is not None

    def test_quic_cid_routed_metric(self, api_client, metrics_setup):
        content = _get_metrics(api_client)
        value = parse_metric_value(content, "katran_quic_cid_routed_total")
        assert value is not None

    def test_quic_invalid_server_id_metric(self, api_client, metrics_setup):
        content = _get_metrics(api_client)
        value = parse_metric_value(content, "katran_quic_cid_invalid_server_id_total")
        assert value is not None

    def test_quic_unknown_real_metric(self, api_client, metrics_setup):
        content = _get_metrics(api_client)
        value = parse_metric_value(content, "katran_quic_cid_unknown_real_dropped_total")
        assert value is not None

    def test_hc_processed_metric(self, api_client, metrics_setup):
        content = _get_metrics(api_client)
        value = parse_metric_value(content, "katran_hc_packets_processed_total")
        assert value is not None

    def test_hc_dropped_metric(self, api_client, metrics_setup):
        content = _get_metrics(api_client)
        value = parse_metric_value(content, "katran_hc_packets_dropped_total")
        assert value is not None

    def test_hc_skipped_metric(self, api_client, metrics_setup):
        content = _get_metrics(api_client)
        value = parse_metric_value(content, "katran_hc_packets_skipped_total")
        assert value is not None

    def test_xdp_action_metrics(self, api_client, metrics_setup):
        content = _get_metrics(api_client)
        value = parse_metric_value(
            content, "katran_xdp_packets_total", {"action": "tx"}
        )
        assert value is not None

    def test_cpu_packets_metric(self, api_client, metrics_setup):
        content = _get_metrics(api_client)
        value = parse_metric_value(
            content, "katran_cpu_packets_total", {"cpu": "0"}
        )
        assert value is not None

    def test_icmp_ptb_v4_metric(self, api_client, metrics_setup):
        content = _get_metrics(api_client)
        value = parse_metric_value(content, "katran_icmp_ptb_v4_total")
        assert value is not None

    def test_icmp_ptb_v6_metric(self, api_client, metrics_setup):
        content = _get_metrics(api_client)
        value = parse_metric_value(content, "katran_icmp_ptb_v6_total")
        assert value is not None
