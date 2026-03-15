"""E2E tests for extended stats endpoints."""

import time

import pytest

from conftest import add_backend, remove_backend, send_requests, setup_vip, teardown_vip

VIP = "10.200.0.47"


@pytest.fixture(scope="module")
def stats_vip(api_client, backend_1_addr, backend_2_addr):
    """Module fixture: create VIP, add backends, send traffic."""
    setup_vip(api_client, VIP)
    resp1 = add_backend(api_client, VIP, backend_1_addr)
    resp2 = add_backend(api_client, VIP, backend_2_addr)
    time.sleep(2)
    send_requests(VIP, count=20)
    time.sleep(2)
    yield {
        "vip": VIP,
        "real_index_1": resp1["index"] if resp1 else 0,
        "real_index_2": resp2["index"] if resp2 else 1,
    }
    remove_backend(api_client, VIP, backend_2_addr)
    remove_backend(api_client, VIP, backend_1_addr)
    teardown_vip(api_client, VIP)


class TestStats:
    """Stats endpoint tests — traffic must be sent first."""

    def test_vip_stats(self, api_client, stats_vip):
        resp = api_client.get(
            "/api/v1/stats/vip",
            params={"address": VIP, "port": 80, "protocol": "tcp"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("packets", data.get("v1", 0)) > 0

    def test_real_stats(self, api_client, stats_vip):
        resp = api_client.get(
            "/api/v1/stats/real", params={"index": stats_vip["real_index_1"]}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)

    def test_global_stats(self, api_client, stats_vip):
        resp = api_client.get("/api/v1/stats/global")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)

    def test_quic_stats(self, api_client, stats_vip):
        resp = api_client.get("/api/v1/stats/quic")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)

    def test_hc_stats(self, api_client, stats_vip):
        resp = api_client.get("/api/v1/stats/hc")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)

    def test_per_cpu_stats(self, api_client, stats_vip):
        resp = api_client.get("/api/v1/stats/per-cpu")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0

    def test_vip_stats_unknown_vip(self, api_client, stats_vip):
        resp = api_client.get(
            "/api/v1/stats/vip",
            params={"address": "192.168.99.99", "port": 80, "protocol": "tcp"},
        )
        assert resp.status_code == 404
