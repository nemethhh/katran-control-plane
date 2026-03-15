"""E2E tests for LRU management — search, list, purge, analyze."""

import time

from helpers import add_backend, remove_backend, send_requests, setup_vip, teardown_vip

VIP = "10.200.0.46"


class TestLru:
    """LRU cache management tests. Each test creates its own VIP and traffic."""

    def _setup_and_send_traffic(self, api_client, backend_1_addr):
        setup_vip(api_client, VIP)
        add_backend(api_client, VIP, backend_1_addr)
        time.sleep(2)
        send_requests(VIP, count=10)
        time.sleep(1)

    def _cleanup(self, api_client, backend_1_addr):
        remove_backend(api_client, VIP, backend_1_addr)
        teardown_vip(api_client, VIP)

    def test_lru_list_after_traffic(self, api_client, backend_1_addr):
        self._setup_and_send_traffic(api_client, backend_1_addr)
        try:
            resp = api_client.post(
                "/api/v1/lru/list",
                json={
                    "vip": {"address": VIP, "port": 80, "protocol": "tcp"},
                    "limit": 100,
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "entries" in data
        finally:
            self._cleanup(api_client, backend_1_addr)

    def test_lru_search_after_traffic(self, api_client, backend_1_addr, test_client_addr):
        self._setup_and_send_traffic(api_client, backend_1_addr)
        try:
            resp = api_client.post(
                "/api/v1/lru/search",
                json={
                    "vip": {"address": VIP, "port": 80, "protocol": "tcp"},
                    "src_ip": test_client_addr,
                    "src_port": 0,
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "entries" in data
            assert "error" in data
        finally:
            self._cleanup(api_client, backend_1_addr)

    def test_lru_search_no_match(self, api_client, backend_1_addr):
        self._setup_and_send_traffic(api_client, backend_1_addr)
        try:
            resp = api_client.post(
                "/api/v1/lru/search",
                json={
                    "vip": {"address": VIP, "port": 80, "protocol": "tcp"},
                    "src_ip": "192.168.99.99",
                    "src_port": 0,
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["entries"] == 0
        finally:
            self._cleanup(api_client, backend_1_addr)

    def test_lru_delete_entry(self, api_client, backend_1_addr, test_client_addr):
        self._setup_and_send_traffic(api_client, backend_1_addr)
        try:
            resp = api_client.post(
                "/api/v1/lru/delete",
                json={
                    "vip": {"address": VIP, "port": 80, "protocol": "tcp"},
                    "src_ip": test_client_addr,
                    "src_port": 0,
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "deleted" in data
        finally:
            self._cleanup(api_client, backend_1_addr)

    def test_lru_purge_vip(self, api_client, backend_1_addr):
        self._setup_and_send_traffic(api_client, backend_1_addr)
        try:
            resp = api_client.post(
                "/api/v1/lru/purge-vip",
                json={
                    "vip": {"address": VIP, "port": 80, "protocol": "tcp"},
                    "limit": 100,
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "deleted_count" in data
        finally:
            self._cleanup(api_client, backend_1_addr)

    def test_lru_purge_real(self, api_client, backend_1_addr):
        setup_vip(api_client, VIP)
        resp_add = add_backend(api_client, VIP, backend_1_addr)
        real_index = resp_add["index"] if resp_add else 0
        time.sleep(2)
        send_requests(VIP, count=10)
        time.sleep(1)

        try:
            resp = api_client.post(
                "/api/v1/lru/purge-real",
                json={
                    "vip": {"address": VIP, "port": 80, "protocol": "tcp"},
                    "real_index": real_index,
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert "deleted_count" in data
        finally:
            self._cleanup(api_client, backend_1_addr)

    def test_lru_analyze(self, api_client, backend_1_addr):
        self._setup_and_send_traffic(api_client, backend_1_addr)
        try:
            resp = api_client.get("/api/v1/lru/analyze")
            assert resp.status_code == 200
            data = resp.json()
            assert "total_entries" in data
            assert "per_vip" in data
        finally:
            self._cleanup(api_client, backend_1_addr)
