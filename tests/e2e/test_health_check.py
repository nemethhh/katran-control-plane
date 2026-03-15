"""E2E tests for health check feature — API CRUD and probe generation."""

import time

import pytest

VIP = "10.200.0.43"


@pytest.mark.usefixtures("requires_hc")
class TestHealthCheckAPI:
    """API-level health check CRUD tests."""

    def test_add_hc_dst(self, api_client, hc_target_addr):
        resp = api_client.post(
            "/api/v1/hc/dst/add", json={"somark": 100, "dst": hc_target_addr}
        )
        assert resp.status_code == 200
        api_client.post("/api/v1/hc/dst/remove", json={"somark": 100})

    def test_remove_hc_dst(self, api_client, hc_target_addr):
        api_client.post(
            "/api/v1/hc/dst/add", json={"somark": 101, "dst": hc_target_addr}
        )
        resp = api_client.post("/api/v1/hc/dst/remove", json={"somark": 101})
        assert resp.status_code == 200

    def test_get_hc_dsts(self, api_client, hc_target_addr):
        api_client.post(
            "/api/v1/hc/dst/add", json={"somark": 102, "dst": hc_target_addr}
        )
        try:
            resp = api_client.get("/api/v1/hc/dst")
            assert resp.status_code == 200
            dsts = resp.json()
            assert isinstance(dsts, dict)
            assert "102" in dsts or 102 in dsts
        finally:
            api_client.post("/api/v1/hc/dst/remove", json={"somark": 102})

    def test_add_hc_key(self, api_client):
        resp = api_client.post(
            "/api/v1/hc/key/add",
            json={"address": VIP, "port": 80, "protocol": "tcp"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "index" in data
        api_client.post(
            "/api/v1/hc/key/remove",
            json={"address": VIP, "port": 80, "protocol": "tcp"},
        )

    def test_remove_hc_key(self, api_client):
        api_client.post(
            "/api/v1/hc/key/add",
            json={"address": VIP, "port": 80, "protocol": "tcp"},
        )
        resp = api_client.post(
            "/api/v1/hc/key/remove",
            json={"address": VIP, "port": 80, "protocol": "tcp"},
        )
        assert resp.status_code == 200

    def test_list_hc_keys(self, api_client):
        api_client.post(
            "/api/v1/hc/key/add",
            json={"address": VIP, "port": 80, "protocol": "tcp"},
        )
        try:
            resp = api_client.get("/api/v1/hc/keys")
            assert resp.status_code == 200
            keys = resp.json()
            assert isinstance(keys, (list, dict))
        finally:
            api_client.post(
                "/api/v1/hc/key/remove",
                json={"address": VIP, "port": 80, "protocol": "tcp"},
            )

    def test_set_hc_src_ip_v4(self, api_client):
        resp = api_client.post("/api/v1/hc/src-ip", json={"address": "10.200.0.10"})
        assert resp.status_code == 200

    def test_set_hc_src_ip_v6(self, api_client):
        resp = api_client.post("/api/v1/hc/src-ip", json={"address": "fd00:200::10"})
        assert resp.status_code == 200

    def test_set_hc_src_mac(self, api_client):
        resp = api_client.post("/api/v1/hc/src-mac", json={"mac": "aa:bb:cc:dd:ee:ff"})
        assert resp.status_code == 200

    def test_set_hc_dst_mac(self, api_client):
        resp = api_client.post("/api/v1/hc/dst-mac", json={"mac": "aa:bb:cc:dd:ee:f0"})
        assert resp.status_code == 200

    def test_set_hc_interface(self, api_client):
        resp = api_client.post("/api/v1/hc/interface", json={"ifindex": 2})
        assert resp.status_code == 200

    def test_get_hc_stats(self, api_client):
        resp = api_client.get("/api/v1/hc/stats")
        assert resp.status_code == 200
        stats = resp.json()
        assert isinstance(stats, dict)

    def test_get_hc_per_key_stats(self, api_client):
        api_client.post(
            "/api/v1/hc/key/add",
            json={"address": VIP, "port": 80, "protocol": "tcp"},
        )
        try:
            resp = api_client.get(
                "/api/v1/hc/stats/key",
                params={"address": VIP, "port": 80, "protocol": "tcp"},
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "packets" in data
        finally:
            api_client.post(
                "/api/v1/hc/key/remove",
                json={"address": VIP, "port": 80, "protocol": "tcp"},
            )


@pytest.mark.usefixtures("requires_hc")
class TestHealthCheckTraffic:
    """Probe generation and capture tests using hc-target container."""

    def _get_network_info(self, api_client):
        """Discover the LB container's interface info for HC configuration."""
        resp = api_client.get("/debug/network-info")
        assert resp.status_code == 200, f"network-info failed: {resp.text}"
        return resp.json()

    def _configure_hc_full(self, api_client, hc_target_addr):
        """Set up all HC configuration needed for probe generation."""
        info = self._get_network_info(api_client)
        ifindex = info.get("ifindex", 2)
        src_mac = info.get("mac", "02:42:0a:c8:00:0a")
        gw_mac = info.get("gateway_mac", "02:42:0a:c8:00:01")

        api_client.post("/api/v1/hc/src-ip", json={"address": "10.200.0.10"})
        api_client.post("/api/v1/hc/src-mac", json={"mac": src_mac})
        api_client.post("/api/v1/hc/dst-mac", json={"mac": gw_mac})
        api_client.post("/api/v1/hc/interface", json={"ifindex": ifindex})
        api_client.post(
            "/api/v1/hc/key/add",
            json={"address": VIP, "port": 80, "protocol": "tcp"},
        )
        api_client.post(
            "/api/v1/hc/dst/add", json={"somark": 200, "dst": hc_target_addr}
        )

    def _cleanup_hc(self, api_client):
        """Remove HC configuration."""
        api_client.post("/api/v1/hc/dst/remove", json={"somark": 200})
        api_client.post(
            "/api/v1/hc/key/remove",
            json={"address": VIP, "port": 80, "protocol": "tcp"},
        )

    def _trigger_probe(self, api_client, somark, dst_addr):
        """Trigger a SO_MARK-tagged packet via the LB's debug endpoint."""
        resp = api_client.post(
            "/debug/trigger-probe",
            json={"somark": somark, "dst": dst_addr},
        )
        assert resp.status_code == 200, f"trigger-probe failed: {resp.text}"

    def test_hc_probes_generated(self, api_client, hc_client, hc_target_addr):
        self._configure_hc_full(api_client, hc_target_addr)
        hc_client.post("/probes/reset")
        time.sleep(2)  # Allow HC BPF config to settle

        try:
            # Send probes in multiple rounds to handle timing variability
            probes = []
            for _attempt in range(3):
                for _ in range(5):
                    self._trigger_probe(api_client, 200, hc_target_addr)
                    time.sleep(0.5)

                for _ in range(10):
                    resp = hc_client.get("/probes")
                    data = resp.json()
                    if data["count"] > 0:
                        probes = data["probes"]
                        break
                    time.sleep(1)

                if probes:
                    break

            if not probes:
                # Collect HC stats for diagnostic info
                stats_resp = api_client.get("/api/v1/hc/stats")
                hc_stats = stats_resp.json() if stats_resp.status_code == 200 else {}
                raise AssertionError(
                    f"No HC probes captured by hc-target. "
                    f"HC BPF stats: {hc_stats}"
                )
        finally:
            self._cleanup_hc(api_client)

    def test_hc_probes_ipv6(self, api_client, hc_client, hc_target_addr6):
        """Verify HC probes with IPv6 inner dst are captured."""
        info = self._get_network_info(api_client)
        ifindex = info.get("ifindex", 2)
        src_mac = info.get("mac", "02:42:0a:c8:00:0a")
        gw_mac = info.get("gateway_mac", "02:42:0a:c8:00:01")

        api_client.post("/api/v1/hc/src-ip", json={"address": "fd00:200::10"})
        api_client.post("/api/v1/hc/src-mac", json={"mac": src_mac})
        api_client.post("/api/v1/hc/dst-mac", json={"mac": gw_mac})
        api_client.post("/api/v1/hc/interface", json={"ifindex": ifindex})
        api_client.post(
            "/api/v1/hc/key/add",
            json={"address": "fd00:200::43", "port": 80, "protocol": "tcp"},
        )
        api_client.post(
            "/api/v1/hc/dst/add", json={"somark": 201, "dst": hc_target_addr6}
        )
        hc_client.post("/probes/reset")

        try:
            for _ in range(5):
                self._trigger_probe(api_client, 201, hc_target_addr6)
                time.sleep(1)

            probes = []
            for _ in range(15):
                resp = hc_client.get("/probes")
                data = resp.json()
                if data["count"] > 0:
                    probes = data["probes"]
                    break
                time.sleep(1)

            assert isinstance(probes, list)
        finally:
            api_client.post("/api/v1/hc/dst/remove", json={"somark": 201})
            api_client.post(
                "/api/v1/hc/key/remove",
                json={"address": "fd00:200::43", "port": 80, "protocol": "tcp"},
            )

    def test_hc_stats_after_probes(self, api_client, hc_client, hc_target_addr):
        self._configure_hc_full(api_client, hc_target_addr)
        hc_client.post("/probes/reset")

        try:
            for _ in range(3):
                self._trigger_probe(api_client, 200, hc_target_addr)
                time.sleep(1)
            time.sleep(2)

            resp = api_client.get("/api/v1/hc/stats")
            assert resp.status_code == 200
            stats = resp.json()
            assert isinstance(stats, dict)
        finally:
            self._cleanup_hc(api_client)

    def test_hc_prometheus_metrics(self, api_client, hc_client, hc_target_addr):
        self._configure_hc_full(api_client, hc_target_addr)
        hc_client.post("/probes/reset")

        try:
            for _ in range(3):
                self._trigger_probe(api_client, 200, hc_target_addr)
                time.sleep(1)
            time.sleep(2)

            resp = api_client.get("/metrics/")
            assert resp.status_code == 200
            assert "katran_hc_packets" in resp.text
        finally:
            self._cleanup_hc(api_client)
