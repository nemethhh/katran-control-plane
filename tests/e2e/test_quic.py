"""E2E tests for QUIC server ID feature — API CRUD and UDP traffic."""

import time

from conftest import (
    add_backend,
    parse_metric_value,
    remove_backend,
    send_udp_packets,
    setup_vip,
    teardown_vip,
)

VIP = "10.200.0.42"


class TestQuicAPI:
    """API-level QUIC mapping CRUD tests."""

    def test_add_quic_mapping(self, api_client, backend_1_addr):
        resp = api_client.post(
            "/api/v1/quic/mapping",
            json={"action": "add", "mappings": [{"address": backend_1_addr, "id": 1000}]},
        )
        assert resp.status_code == 200
        assert resp.json()["failures"] == 0
        api_client.post(
            "/api/v1/quic/mapping",
            json={"action": "del", "mappings": [{"address": backend_1_addr, "id": 1000}]},
        )

    def test_list_quic_mappings(self, api_client, backend_1_addr):
        api_client.post(
            "/api/v1/quic/mapping",
            json={"action": "add", "mappings": [{"address": backend_1_addr, "id": 1000}]},
        )
        try:
            resp = api_client.get("/api/v1/quic/mapping")
            assert resp.status_code == 200
            mappings = resp.json()
            assert isinstance(mappings, list)
            assert len(mappings) > 0
        finally:
            api_client.post(
                "/api/v1/quic/mapping",
                json={"action": "del", "mappings": [{"address": backend_1_addr, "id": 1000}]},
            )

    def test_remove_quic_mapping(self, api_client, backend_1_addr):
        api_client.post(
            "/api/v1/quic/mapping",
            json={"action": "add", "mappings": [{"address": backend_1_addr, "id": 1000}]},
        )
        resp = api_client.post(
            "/api/v1/quic/mapping",
            json={"action": "del", "mappings": [{"address": backend_1_addr, "id": 1000}]},
        )
        assert resp.status_code == 200
        mappings = api_client.get("/api/v1/quic/mapping").json()
        assert len(mappings) == 0

    def test_add_multiple_mappings(self, api_client, backend_1_addr, backend_2_addr):
        resp = api_client.post(
            "/api/v1/quic/mapping",
            json={
                "action": "add",
                "mappings": [
                    {"address": backend_1_addr, "id": 2000},
                    {"address": backend_2_addr, "id": 2001},
                    {"address": backend_1_addr, "id": 2002},
                ],
            },
        )
        assert resp.status_code == 200
        assert resp.json()["failures"] == 0
        try:
            mappings = api_client.get("/api/v1/quic/mapping").json()
            assert len(mappings) >= 3
        finally:
            api_client.post(
                "/api/v1/quic/mapping",
                json={
                    "action": "del",
                    "mappings": [
                        {"address": backend_1_addr, "id": 2000},
                        {"address": backend_2_addr, "id": 2001},
                        {"address": backend_1_addr, "id": 2002},
                    ],
                },
            )

    def test_invalidate_server_ids(self, api_client, backend_1_addr):
        api_client.post(
            "/api/v1/quic/mapping",
            json={
                "action": "add",
                "mappings": [
                    {"address": backend_1_addr, "id": 3000},
                    {"address": backend_1_addr, "id": 3001},
                ],
            },
        )
        try:
            resp = api_client.post(
                "/api/v1/quic/invalidate", json={"server_ids": [3000, 3001]}
            )
            assert resp.status_code == 200
        finally:
            api_client.post(
                "/api/v1/quic/mapping",
                json={
                    "action": "del",
                    "mappings": [
                        {"address": backend_1_addr, "id": 3000},
                        {"address": backend_1_addr, "id": 3001},
                    ],
                },
            )

    def test_revalidate_server_ids(self, api_client, backend_1_addr):
        api_client.post(
            "/api/v1/quic/mapping",
            json={"action": "add", "mappings": [{"address": backend_1_addr, "id": 4000}]},
        )
        api_client.post("/api/v1/quic/invalidate", json={"server_ids": [4000]})
        try:
            resp = api_client.post(
                "/api/v1/quic/revalidate",
                json={"mappings": [{"address": backend_1_addr, "id": 4000}]},
            )
            assert resp.status_code == 200
        finally:
            api_client.post(
                "/api/v1/quic/mapping",
                json={"action": "del", "mappings": [{"address": backend_1_addr, "id": 4000}]},
            )

    def test_add_mapping_invalid_action(self, api_client, backend_1_addr):
        resp = api_client.post(
            "/api/v1/quic/mapping",
            json={
                "action": "invalid",
                "mappings": [{"address": backend_1_addr, "id": 5000}],
            },
        )
        assert resp.status_code in (400, 422)


class TestQuicTraffic:
    """Traffic tests with UDP datagrams to QUIC VIP."""

    def test_quic_stats_after_udp_traffic(self, api_client, backend_1_addr):
        setup_vip(api_client, VIP, port=443, protocol="udp")
        add_backend(api_client, VIP, backend_1_addr, port=443, protocol="udp")
        time.sleep(2)

        try:
            send_udp_packets(VIP, port=443, count=20)
            time.sleep(2)

            resp = api_client.get("/api/v1/stats/quic")
            assert resp.status_code == 200
            stats = resp.json()
            assert isinstance(stats, dict)
            assert "ch_routed" in stats, f"Expected ch_routed in QUIC stats, got: {stats.keys()}"
        finally:
            remove_backend(api_client, VIP, backend_1_addr, port=443, protocol="udp")
            teardown_vip(api_client, VIP, port=443, protocol="udp")

    def test_quic_prometheus_metrics(self, api_client, backend_1_addr):
        setup_vip(api_client, VIP, port=443, protocol="udp")
        add_backend(api_client, VIP, backend_1_addr, port=443, protocol="udp")
        time.sleep(2)

        try:
            send_udp_packets(VIP, port=443, count=20)
            time.sleep(2)

            resp = api_client.get("/metrics/")
            assert resp.status_code == 200
            value = parse_metric_value(resp.text, "katran_quic_ch_routed_total")
            assert value is not None or "katran_quic" in resp.text
        finally:
            remove_backend(api_client, VIP, backend_1_addr, port=443, protocol="udp")
            teardown_vip(api_client, VIP, port=443, protocol="udp")
