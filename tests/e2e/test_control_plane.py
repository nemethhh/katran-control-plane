"""
End-to-end tests for Katran control plane API.

These tests exercise the full stack over real HTTP:
  test-client -> HTTP -> katran-lb:8080 -> managers -> BPF maps
"""

import pytest


pytestmark = pytest.mark.e2e


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_endpoint(self, api_client):
        resp = api_client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"


# ---------------------------------------------------------------------------
# VIP lifecycle
# ---------------------------------------------------------------------------

class TestVipLifecycle:
    def test_vip_crud(self, api_client):
        """Full create -> list -> get -> delete cycle."""
        # Create
        resp = api_client.post("/api/v1/vips", json={
            "address": "10.100.0.1", "port": 80, "protocol": "tcp",
        })
        assert resp.status_code == 201
        body = resp.json()
        assert body["address"] == "10.100.0.1"
        assert body["port"] == 80

        try:
            # List
            resp = api_client.get("/api/v1/vips")
            assert resp.status_code == 200
            vips = resp.json()
            assert any(v["address"] == "10.100.0.1" and v["port"] == 80 for v in vips)

            # Get
            resp = api_client.get("/api/v1/vips/10.100.0.1/80/tcp")
            assert resp.status_code == 200
            assert resp.json()["address"] == "10.100.0.1"
        finally:
            # Delete
            resp = api_client.delete("/api/v1/vips/10.100.0.1/80/tcp")
            assert resp.status_code == 200

    def test_duplicate_vip_409(self, api_client):
        payload = {"address": "10.100.0.10", "port": 443, "protocol": "tcp"}
        resp = api_client.post("/api/v1/vips", json=payload)
        assert resp.status_code == 201
        try:
            resp = api_client.post("/api/v1/vips", json=payload)
            assert resp.status_code == 409
        finally:
            api_client.delete("/api/v1/vips/10.100.0.10/443/tcp")

    def test_get_missing_vip_404(self, api_client):
        resp = api_client.get("/api/v1/vips/10.255.255.255/9999/tcp")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Backend lifecycle
# ---------------------------------------------------------------------------

class TestBackendLifecycle:
    def test_backend_crud(self, api_client):
        # Setup VIP
        resp = api_client.post("/api/v1/vips", json={
            "address": "10.100.0.20", "port": 80, "protocol": "tcp",
        })
        assert resp.status_code == 201

        try:
            # Add backend
            resp = api_client.post(
                "/api/v1/vips/10.100.0.20/80/tcp/backends",
                json={"address": "10.0.1.1", "weight": 100},
            )
            assert resp.status_code == 201
            assert resp.json()["address"] == "10.0.1.1"

            # Verify backend appears in VIP detail
            resp = api_client.get("/api/v1/vips/10.100.0.20/80/tcp")
            assert resp.status_code == 200
            assert len(resp.json()["backends"]) == 1

            # Drain
            resp = api_client.put(
                "/api/v1/vips/10.100.0.20/80/tcp/backends/10.0.1.1/drain"
            )
            assert resp.status_code == 200

            # Verify drained (weight=0)
            resp = api_client.get("/api/v1/vips/10.100.0.20/80/tcp")
            backend = resp.json()["backends"][0]
            assert backend["weight"] == 0

            # Remove backend
            resp = api_client.delete(
                "/api/v1/vips/10.100.0.20/80/tcp/backends/10.0.1.1"
            )
            assert resp.status_code == 200
        finally:
            api_client.delete("/api/v1/vips/10.100.0.20/80/tcp")

    def test_backend_on_missing_vip_404(self, api_client):
        resp = api_client.post(
            "/api/v1/vips/10.255.255.255/9999/tcp/backends",
            json={"address": "10.0.0.1", "weight": 100},
        )
        assert resp.status_code == 404
