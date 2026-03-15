"""E2E tests for inline decap feature — API CRUD and stats verification."""

import time

from helpers import (
    add_backend,
    parse_metric_value,
    remove_backend,
    send_requests,
    setup_vip,
    teardown_vip,
)

VIP = "10.200.0.41"


class TestDecapAPI:
    """API-level decap destination CRUD tests."""

    def test_add_decap_dst_v4(self, api_client):
        resp = api_client.post("/api/v1/decap/dst/add", json={"address": "10.200.0.10"})
        assert resp.status_code == 200
        api_client.post("/api/v1/decap/dst/remove", json={"address": "10.200.0.10"})

    def test_add_decap_dst_v6(self, api_client):
        resp = api_client.post("/api/v1/decap/dst/add", json={"address": "fd00:200::10"})
        assert resp.status_code == 200
        api_client.post("/api/v1/decap/dst/remove", json={"address": "fd00:200::10"})

    def test_list_decap_dsts(self, api_client):
        api_client.post("/api/v1/decap/dst/add", json={"address": "10.200.0.10"})
        try:
            resp = api_client.get("/api/v1/decap/dst")
            assert resp.status_code == 200
            dsts = resp.json()
            assert isinstance(dsts, list)
            assert "10.200.0.10" in dsts
        finally:
            api_client.post("/api/v1/decap/dst/remove", json={"address": "10.200.0.10"})

    def test_remove_decap_dst(self, api_client):
        api_client.post("/api/v1/decap/dst/add", json={"address": "10.200.0.10"})
        resp = api_client.post("/api/v1/decap/dst/remove", json={"address": "10.200.0.10"})
        assert resp.status_code == 200
        dsts = api_client.get("/api/v1/decap/dst").json()
        assert "10.200.0.10" not in dsts

    def test_add_duplicate_decap_dst(self, api_client):
        api_client.post("/api/v1/decap/dst/add", json={"address": "10.200.0.10"})
        try:
            resp = api_client.post("/api/v1/decap/dst/add", json={"address": "10.200.0.10"})
            assert resp.status_code in (200, 400, 409)
        finally:
            api_client.post("/api/v1/decap/dst/remove", json={"address": "10.200.0.10"})

    def test_remove_nonexistent_decap_dst(self, api_client):
        resp = api_client.post(
            "/api/v1/decap/dst/remove", json={"address": "192.168.99.99"}
        )
        assert resp.status_code in (400, 404)


class TestDecapTraffic:
    """Traffic tests verifying decap stats integration."""

    def test_decap_stats_after_traffic(self, api_client, backend_1_addr):
        api_client.post("/api/v1/decap/dst/add", json={"address": "10.200.0.10"})

        setup_vip(api_client, VIP)
        add_backend(api_client, VIP, backend_1_addr)
        time.sleep(2)

        try:
            send_requests(VIP, count=10)
            time.sleep(1)

            resp = api_client.get("/metrics/")
            assert resp.status_code == 200
            value = parse_metric_value(resp.text, "katran_decap_packets_total")
            assert value is not None or "katran_decap" in resp.text
        finally:
            remove_backend(api_client, VIP, backend_1_addr)
            teardown_vip(api_client, VIP)
            api_client.post("/api/v1/decap/dst/remove", json={"address": "10.200.0.10"})
