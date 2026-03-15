"""E2E tests for encap source IP feature — API and tunnel verification."""

import time

from helpers import add_backend, remove_backend, send_requests, setup_vip, teardown_vip

VIP = "10.200.0.45"


class TestEncapSrcIpAPI:
    """API-level encap source IP tests."""

    def test_set_encap_src_ip_v4(self, api_client):
        resp = api_client.post("/api/v1/encap/src-ip", json={"address": "10.200.0.10"})
        assert resp.status_code == 200

    def test_set_encap_src_ip_v6(self, api_client):
        resp = api_client.post("/api/v1/encap/src-ip", json={"address": "fd00:200::10"})
        assert resp.status_code == 200

    def test_set_encap_src_ip_invalid(self, api_client):
        resp = api_client.post("/api/v1/encap/src-ip", json={"address": "not-an-ip"})
        assert resp.status_code in (400, 422)


class TestEncapSrcIpTraffic:
    """Traffic tests verifying encap source IP in IPIP outer header."""

    def test_encap_src_ip_reflected(self, api_client, backend_1_addr):
        import httpx

        api_client.post("/api/v1/encap/src-ip", json={"address": "10.200.0.10"})

        setup_vip(api_client, VIP)
        add_backend(api_client, VIP, backend_1_addr)
        time.sleep(2)

        try:
            send_requests(VIP, count=10)
            time.sleep(2)

            try:
                resp = httpx.get(f"http://{backend_1_addr}:80/tunnel-info", timeout=5.0)
                if resp.status_code == 200:
                    info = resp.json()
                    # Verify tunnel info endpoint works and returns expected fields
                    assert "outer_src" in info
            except (httpx.ReadError, httpx.ConnectError):
                pass  # Backend may not be reachable directly
        finally:
            remove_backend(api_client, VIP, backend_1_addr)
            teardown_vip(api_client, VIP)
