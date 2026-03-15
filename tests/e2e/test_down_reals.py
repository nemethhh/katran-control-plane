"""E2E tests for down reals feature — API CRUD and traffic avoidance."""

import time

import pytest
from helpers import (
    add_backend,
    parse_metric_value,
    remove_backend,
    send_udp_packets,
    setup_vip,
    teardown_vip,
)

VIP = "10.200.0.44"
UDP_FLOW_MIGRATION_FLAG = 1 << 9  # VipFlags.UDP_FLOW_MIGRATION


def _setup_udp_vip(api_client, address, port=80):
    """Create a UDP VIP with F_UDP_FLOW_MIGRATION so BPF checks down-reals."""
    resp = api_client.post(
        "/api/v1/vips",
        json={
            "address": address,
            "port": port,
            "protocol": "udp",
            "flags": UDP_FLOW_MIGRATION_FLAG,
        },
    )
    assert resp.status_code in (201, 409), f"setup_vip failed: {resp.status_code} {resp.text}"


def _teardown_udp_vip(api_client, address, port=80):
    api_client.post(
        "/api/v1/vips/remove",
        json={"address": address, "port": port, "protocol": "udp"},
    )


def _make_vip_id(address=VIP, port=80, protocol="tcp"):
    return {"address": address, "port": port, "protocol": protocol}


@pytest.mark.usefixtures("requires_down_reals")
class TestDownRealsAPI:
    """API-level down real CRUD tests."""

    def test_mark_real_down(self, api_client, backend_1_addr):
        setup_vip(api_client, VIP)
        resp_add = add_backend(api_client, VIP, backend_1_addr)
        real_index = resp_add["index"] if resp_add else 0

        try:
            resp = api_client.post(
                "/api/v1/down-reals/add",
                json={"vip": _make_vip_id(), "real_index": real_index},
            )
            assert resp.status_code == 200
        finally:
            api_client.post(
                "/api/v1/down-reals/remove",
                json={"vip": _make_vip_id(), "real_index": real_index},
            )
            remove_backend(api_client, VIP, backend_1_addr)
            teardown_vip(api_client, VIP)

    def test_check_real_is_down(self, api_client, backend_1_addr):
        setup_vip(api_client, VIP)
        resp_add = add_backend(api_client, VIP, backend_1_addr)
        real_index = resp_add["index"] if resp_add else 0

        api_client.post(
            "/api/v1/down-reals/add",
            json={"vip": _make_vip_id(), "real_index": real_index},
        )

        try:
            resp = api_client.post(
                "/api/v1/down-reals/check",
                json={"vip": _make_vip_id(), "real_index": real_index},
            )
            assert resp.status_code == 200
            assert resp.json()["is_down"] is True
        finally:
            api_client.post(
                "/api/v1/down-reals/remove",
                json={"vip": _make_vip_id(), "real_index": real_index},
            )
            remove_backend(api_client, VIP, backend_1_addr)
            teardown_vip(api_client, VIP)

    def test_check_real_not_down(self, api_client, backend_1_addr):
        setup_vip(api_client, VIP)
        resp_add = add_backend(api_client, VIP, backend_1_addr)
        real_index = resp_add["index"] if resp_add else 0

        try:
            resp = api_client.post(
                "/api/v1/down-reals/check",
                json={"vip": _make_vip_id(), "real_index": real_index},
            )
            assert resp.status_code == 200
            assert resp.json()["is_down"] is False
        finally:
            remove_backend(api_client, VIP, backend_1_addr)
            teardown_vip(api_client, VIP)

    def test_unmark_real(self, api_client, backend_1_addr):
        setup_vip(api_client, VIP)
        resp_add = add_backend(api_client, VIP, backend_1_addr)
        real_index = resp_add["index"] if resp_add else 0

        api_client.post(
            "/api/v1/down-reals/add",
            json={"vip": _make_vip_id(), "real_index": real_index},
        )

        try:
            api_client.post(
                "/api/v1/down-reals/remove",
                json={"vip": _make_vip_id(), "real_index": real_index},
            )
            resp = api_client.post(
                "/api/v1/down-reals/check",
                json={"vip": _make_vip_id(), "real_index": real_index},
            )
            assert resp.json()["is_down"] is False
        finally:
            remove_backend(api_client, VIP, backend_1_addr)
            teardown_vip(api_client, VIP)

    def test_remove_all_down_for_vip(self, api_client, backend_1_addr, backend_2_addr):
        setup_vip(api_client, VIP)
        resp1 = add_backend(api_client, VIP, backend_1_addr)
        resp2 = add_backend(api_client, VIP, backend_2_addr)
        idx1 = resp1["index"] if resp1 else 0
        idx2 = resp2["index"] if resp2 else 1

        vip_id = _make_vip_id()

        api_client.post("/api/v1/down-reals/add", json={"vip": vip_id, "real_index": idx1})
        api_client.post("/api/v1/down-reals/add", json={"vip": vip_id, "real_index": idx2})

        try:
            # remove-vip takes flat VipId (not nested {vip: ...})
            resp = api_client.post("/api/v1/down-reals/remove-vip", json=vip_id)
            assert resp.status_code == 200

            check1 = api_client.post(
                "/api/v1/down-reals/check", json={"vip": vip_id, "real_index": idx1}
            )
            check2 = api_client.post(
                "/api/v1/down-reals/check", json={"vip": vip_id, "real_index": idx2}
            )
            assert check1.json()["is_down"] is False
            assert check2.json()["is_down"] is False
        finally:
            remove_backend(api_client, VIP, backend_2_addr)
            remove_backend(api_client, VIP, backend_1_addr)
            teardown_vip(api_client, VIP)


@pytest.mark.usefixtures("requires_down_reals")
class TestDownRealsTraffic:
    """Traffic tests verifying down real detection fires in XDP program.

    BPF down-real enforcement requires UDP + F_UDP_FLOW_MIGRATION flag.
    When a cached LRU entry points to a down real, BPF invalidates the
    entry and increments the UDP_FLOW_MIGRATION_STATS counter.
    """

    def test_down_real_traffic_avoidance(
        self, api_client, backend_1_addr, backend_2_addr
    ):
        udp_vip_id = {"address": VIP, "port": 80, "protocol": "udp"}
        _setup_udp_vip(api_client, VIP)
        resp1 = add_backend(api_client, VIP, backend_1_addr, protocol="udp")
        add_backend(api_client, VIP, backend_2_addr, protocol="udp")
        idx1 = resp1["index"] if resp1 else 0
        time.sleep(2)

        try:
            # Send UDP traffic to populate LRU entries
            send_udp_packets(VIP, port=80, count=50)
            time.sleep(1)

            # Mark backend-1 as down
            api_client.post(
                "/api/v1/down-reals/add",
                json={"vip": udp_vip_id, "real_index": idx1},
            )
            time.sleep(1)

            # Send more UDP traffic — BPF should detect down real and
            # invalidate LRU entries, incrementing the migration counter
            send_udp_packets(VIP, port=80, count=50)
            time.sleep(1)

            resp = api_client.get("/metrics/")
            assert resp.status_code == 200
            value = parse_metric_value(
                resp.text, "katran_udp_flow_migration_total"
            )
            assert value is not None and value > 0, (
                "Expected UDP flow migration counter to increment when down real is hit"
            )
        finally:
            api_client.post(
                "/api/v1/down-reals/remove",
                json={"vip": udp_vip_id, "real_index": idx1},
            )
            remove_backend(api_client, VIP, backend_2_addr, protocol="udp")
            remove_backend(api_client, VIP, backend_1_addr, protocol="udp")
            _teardown_udp_vip(api_client, VIP)
