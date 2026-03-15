"""E2E tests for down reals feature — API CRUD and traffic avoidance."""

import time

import pytest
from helpers import (
    add_backend,
    remove_backend,
    send_requests,
    setup_vip,
    teardown_vip,
)

VIP = "10.200.0.44"


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
                json={
                    "vip": {"address": VIP, "port": 80, "protocol": "tcp"},
                    "real_index": real_index,
                },
            )
            assert resp.status_code == 200
        finally:
            api_client.post(
                "/api/v1/down-reals/remove",
                json={
                    "vip": {"address": VIP, "port": 80, "protocol": "tcp"},
                    "real_index": real_index,
                },
            )
            remove_backend(api_client, VIP, backend_1_addr)
            teardown_vip(api_client, VIP)

    def test_check_real_is_down(self, api_client, backend_1_addr):
        setup_vip(api_client, VIP)
        resp_add = add_backend(api_client, VIP, backend_1_addr)
        real_index = resp_add["index"] if resp_add else 0

        api_client.post(
            "/api/v1/down-reals/add",
            json={
                "vip": {"address": VIP, "port": 80, "protocol": "tcp"},
                "real_index": real_index,
            },
        )

        try:
            resp = api_client.post(
                "/api/v1/down-reals/check",
                json={
                    "vip": {"address": VIP, "port": 80, "protocol": "tcp"},
                    "real_index": real_index,
                },
            )
            assert resp.status_code == 200
            assert resp.json()["is_down"] is True
        finally:
            api_client.post(
                "/api/v1/down-reals/remove",
                json={
                    "vip": {"address": VIP, "port": 80, "protocol": "tcp"},
                    "real_index": real_index,
                },
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
                json={
                    "vip": {"address": VIP, "port": 80, "protocol": "tcp"},
                    "real_index": real_index,
                },
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
            json={
                "vip": {"address": VIP, "port": 80, "protocol": "tcp"},
                "real_index": real_index,
            },
        )

        try:
            api_client.post(
                "/api/v1/down-reals/remove",
                json={
                    "vip": {"address": VIP, "port": 80, "protocol": "tcp"},
                    "real_index": real_index,
                },
            )
            resp = api_client.post(
                "/api/v1/down-reals/check",
                json={
                    "vip": {"address": VIP, "port": 80, "protocol": "tcp"},
                    "real_index": real_index,
                },
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

        vip_id = {"address": VIP, "port": 80, "protocol": "tcp"}

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
    """Traffic tests verifying down real avoidance by XDP program."""

    @pytest.mark.skip(
        reason="BPF down-real enforcement requires UDP + F_UDP_FLOW_MIGRATION flag"
    )
    def test_down_real_traffic_avoidance(
        self, api_client, backend_1_addr, backend_2_addr
    ):
        setup_vip(api_client, VIP)
        resp1 = add_backend(api_client, VIP, backend_1_addr)
        add_backend(api_client, VIP, backend_2_addr)
        idx1 = resp1["index"] if resp1 else 0
        time.sleep(2)

        try:
            api_client.post(
                "/api/v1/down-reals/add",
                json={
                    "vip": {"address": VIP, "port": 80, "protocol": "tcp"},
                    "real_index": idx1,
                },
            )
            time.sleep(1)

            results = send_requests(VIP, count=20)
            successful = [r for r in results if r is not None]
            assert len(successful) >= 10
            backends = {r["backend"] for r in successful}
            assert backends == {"backend-2"}, f"Expected only backend-2, got {backends}"
        finally:
            api_client.post(
                "/api/v1/down-reals/remove",
                json={
                    "vip": {"address": VIP, "port": 80, "protocol": "tcp"},
                    "real_index": idx1,
                },
            )
            remove_backend(api_client, VIP, backend_2_addr)
            remove_backend(api_client, VIP, backend_1_addr)
            teardown_vip(api_client, VIP)
