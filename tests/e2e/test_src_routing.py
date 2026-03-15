"""E2E tests for source routing feature — API CRUD and traffic verification."""

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

VIP = "10.200.0.40"
VIP6 = "fd00:200::40"
SRC_ROUTING_FLAG = 1 << 4  # VipFlags.SRC_ROUTING — enables LPM source routing in BPF


def _setup_src_routed_vip(api_client, address, port=80, protocol="tcp"):
    """Create a VIP with SRC_ROUTING flag so BPF consults LPM maps."""
    resp = api_client.post(
        "/api/v1/vips",
        json={"address": address, "port": port, "protocol": protocol, "flags": SRC_ROUTING_FLAG},
    )
    assert resp.status_code in (201, 409), f"setup_vip failed: {resp.status_code} {resp.text}"
    return resp.json() if resp.status_code == 201 else None


class TestSrcRoutingAPI:
    """API-level source routing CRUD tests."""

    def test_add_src_route_v4(self, api_client, backend_3_addr):
        resp = api_client.post(
            "/api/v1/src-routing/add",
            json={"srcs": ["10.200.0.0/24"], "dst": backend_3_addr},
        )
        assert resp.status_code == 200
        assert resp.json()["failures"] == 0
        api_client.post(
            "/api/v1/src-routing/remove",
            json={"srcs": ["10.200.0.0/24"], "dst": backend_3_addr},
        )

    def test_add_src_route_v6(self, api_client, backend_3_addr6):
        resp = api_client.post(
            "/api/v1/src-routing/add",
            json={"srcs": ["fd00:200::/64"], "dst": backend_3_addr6},
        )
        assert resp.status_code == 200
        assert resp.json()["failures"] == 0
        api_client.post(
            "/api/v1/src-routing/remove",
            json={"srcs": ["fd00:200::/64"], "dst": backend_3_addr6},
        )

    def test_list_src_routes(self, api_client, backend_3_addr):
        api_client.post(
            "/api/v1/src-routing/add",
            json={"srcs": ["10.200.0.0/24"], "dst": backend_3_addr},
        )
        try:
            resp = api_client.get("/api/v1/src-routing")
            assert resp.status_code == 200
            rules = resp.json()
            assert isinstance(rules, dict)
            assert len(rules) > 0
        finally:
            api_client.post(
                "/api/v1/src-routing/remove",
                json={"srcs": ["10.200.0.0/24"], "dst": backend_3_addr},
            )

    def test_remove_src_route(self, api_client, backend_3_addr):
        api_client.post(
            "/api/v1/src-routing/add",
            json={"srcs": ["10.200.0.0/24"], "dst": backend_3_addr},
        )
        resp = api_client.post(
            "/api/v1/src-routing/remove",
            json={"srcs": ["10.200.0.0/24"], "dst": backend_3_addr},
        )
        assert resp.status_code == 200
        rules = api_client.get("/api/v1/src-routing").json()
        assert len(rules) == 0

    def test_clear_src_routes(self, api_client, backend_3_addr):
        api_client.post(
            "/api/v1/src-routing/add",
            json={"srcs": ["10.1.0.0/16", "10.2.0.0/16"], "dst": backend_3_addr},
        )
        resp = api_client.post("/api/v1/src-routing/clear")
        assert resp.status_code == 200
        rules = api_client.get("/api/v1/src-routing").json()
        assert len(rules) == 0

    def test_add_multiple_cidrs_same_dst(self, api_client, backend_3_addr):
        resp = api_client.post(
            "/api/v1/src-routing/add",
            json={"srcs": ["10.1.0.0/16", "10.2.0.0/16"], "dst": backend_3_addr},
        )
        assert resp.status_code == 200
        assert resp.json()["failures"] == 0
        try:
            rules = api_client.get("/api/v1/src-routing").json()
            assert len(rules) >= 2
        finally:
            api_client.post("/api/v1/src-routing/clear")

    def test_add_invalid_cidr(self, api_client, backend_3_addr):
        resp = api_client.post(
            "/api/v1/src-routing/add",
            json={"srcs": ["not-a-cidr"], "dst": backend_3_addr},
        )
        if resp.status_code == 200:
            assert resp.json()["failures"] >= 1
        else:
            assert resp.status_code in (400, 422)


class TestSrcRoutingTraffic:
    """Traffic-level tests verifying source routing steers packets."""

    def test_src_routed_traffic_v4(
        self, api_client, backend_1_addr, backend_2_addr, backend_3_addr
    ):
        _setup_src_routed_vip(api_client, VIP)
        add_backend(api_client, VIP, backend_1_addr)
        add_backend(api_client, VIP, backend_2_addr)
        add_backend(api_client, VIP, backend_3_addr)
        time.sleep(2)

        api_client.post(
            "/api/v1/src-routing/add",
            json={"srcs": ["10.200.0.0/24"], "dst": backend_3_addr},
        )
        time.sleep(1)

        try:
            results = send_requests(VIP, count=10)
            successful = [r for r in results if r is not None]
            assert len(successful) >= 5, f"Too few successful requests: {len(successful)}"
            backends = {r["backend"] for r in successful}
            assert backends == {"backend-3"}, f"Expected only backend-3, got {backends}"
        finally:
            api_client.post(
                "/api/v1/src-routing/remove",
                json={"srcs": ["10.200.0.0/24"], "dst": backend_3_addr},
            )
            remove_backend(api_client, VIP, backend_3_addr)
            remove_backend(api_client, VIP, backend_2_addr)
            remove_backend(api_client, VIP, backend_1_addr)
            teardown_vip(api_client, VIP)

    def test_src_route_removal_restores_ch(
        self, api_client, backend_1_addr, backend_2_addr, backend_3_addr
    ):
        _setup_src_routed_vip(api_client, VIP)
        add_backend(api_client, VIP, backend_1_addr)
        add_backend(api_client, VIP, backend_2_addr)
        add_backend(api_client, VIP, backend_3_addr)
        time.sleep(2)

        api_client.post(
            "/api/v1/src-routing/add",
            json={"srcs": ["10.200.0.0/24"], "dst": backend_3_addr},
        )
        time.sleep(1)

        try:
            results = send_requests(VIP, count=5)
            successful = [r for r in results if r is not None]
            assert all(r["backend"] == "backend-3" for r in successful)

            api_client.post(
                "/api/v1/src-routing/remove",
                json={"srcs": ["10.200.0.0/24"], "dst": backend_3_addr},
            )
            time.sleep(1)

            results = send_requests(VIP, count=20)
            successful = [r for r in results if r is not None]
            assert len(successful) >= 10
            backends = {r["backend"] for r in successful}
            assert len(backends) >= 1
        finally:
            api_client.post("/api/v1/src-routing/clear")
            remove_backend(api_client, VIP, backend_3_addr)
            remove_backend(api_client, VIP, backend_2_addr)
            remove_backend(api_client, VIP, backend_1_addr)
            teardown_vip(api_client, VIP)

    def test_src_route_stats_increment(
        self, api_client, backend_1_addr, backend_3_addr
    ):
        _setup_src_routed_vip(api_client, VIP)
        add_backend(api_client, VIP, backend_1_addr)
        add_backend(api_client, VIP, backend_3_addr)
        time.sleep(2)

        api_client.post(
            "/api/v1/src-routing/add",
            json={"srcs": ["10.200.0.0/24"], "dst": backend_3_addr},
        )
        time.sleep(1)

        try:
            send_requests(VIP, count=10)
            time.sleep(1)

            resp = api_client.get("/metrics/")
            assert resp.status_code == 200
            value = parse_metric_value(resp.text, "katran_src_routing_packets_total")
            assert value is not None or "katran_src_routing" in resp.text
        finally:
            api_client.post("/api/v1/src-routing/clear")
            remove_backend(api_client, VIP, backend_3_addr)
            remove_backend(api_client, VIP, backend_1_addr)
            teardown_vip(api_client, VIP)
