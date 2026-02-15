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


# ---------------------------------------------------------------------------
# VIP error paths
# ---------------------------------------------------------------------------

class TestVipErrors:
    def test_delete_nonexistent_vip_404(self, api_client):
        """DELETE on a VIP that doesn't exist should return 404."""
        resp = api_client.delete("/api/v1/vips/10.100.1.1/9999/tcp")
        assert resp.status_code == 404

    def test_invalid_protocol_400(self, api_client):
        """POST VIP with an unsupported protocol should return 400."""
        resp = api_client.post("/api/v1/vips", json={
            "address": "10.100.1.2", "port": 80, "protocol": "sctp",
        })
        assert resp.status_code == 400

    def test_get_vip_invalid_protocol_400(self, api_client):
        """GET VIP with bad protocol in URL should return 400."""
        resp = api_client.get("/api/v1/vips/10.100.1.3/80/sctp")
        assert resp.status_code == 400


# ---------------------------------------------------------------------------
# VIP creation variants
# ---------------------------------------------------------------------------

class TestVipCreation:
    def test_vip_with_flags(self, api_client):
        """Create VIP with flags=1, verify in POST and GET responses."""
        resp = api_client.post("/api/v1/vips", json={
            "address": "10.100.2.1", "port": 80, "protocol": "tcp", "flags": 1,
        })
        assert resp.status_code == 201
        try:
            assert resp.json()["flags"] == 1

            resp = api_client.get("/api/v1/vips/10.100.2.1/80/tcp")
            assert resp.status_code == 200
            assert resp.json()["flags"] == 1
        finally:
            api_client.delete("/api/v1/vips/10.100.2.1/80/tcp")

    def test_udp_vip_creation(self, api_client):
        """Create UDP VIP, verify protocol in response and GET."""
        resp = api_client.post("/api/v1/vips", json={
            "address": "10.100.2.2", "port": 53, "protocol": "udp",
        })
        assert resp.status_code == 201
        try:
            assert resp.json()["protocol"] == "udp"

            resp = api_client.get("/api/v1/vips/10.100.2.2/53/udp")
            assert resp.status_code == 200
            assert resp.json()["protocol"] == "udp"
        finally:
            api_client.delete("/api/v1/vips/10.100.2.2/53/udp")


# ---------------------------------------------------------------------------
# VIP lifecycle extended
# ---------------------------------------------------------------------------

class TestVipLifecycleExtended:
    def test_vip_recreate_after_delete(self, api_client):
        """Delete VIP, recreate same address -> 201 (index recycling)."""
        resp = api_client.post("/api/v1/vips", json={
            "address": "10.100.3.1", "port": 80, "protocol": "tcp",
        })
        assert resp.status_code == 201

        try:
            # Delete
            resp = api_client.delete("/api/v1/vips/10.100.3.1/80/tcp")
            assert resp.status_code == 200

            # Recreate same
            resp = api_client.post("/api/v1/vips", json={
                "address": "10.100.3.1", "port": 80, "protocol": "tcp",
            })
            assert resp.status_code == 201
        finally:
            api_client.delete("/api/v1/vips/10.100.3.1/80/tcp")

    def test_multiple_vips_coexistence(self, api_client):
        """Create 3 VIPs, verify list count, delete one, verify count drops."""
        vips = [
            {"address": "10.100.3.10", "port": 80, "protocol": "tcp"},
            {"address": "10.100.3.11", "port": 80, "protocol": "tcp"},
            {"address": "10.100.3.12", "port": 80, "protocol": "tcp"},
        ]
        for v in vips:
            resp = api_client.post("/api/v1/vips", json=v)
            assert resp.status_code == 201

        try:
            resp = api_client.get("/api/v1/vips")
            assert resp.status_code == 200
            initial_count = len(resp.json())
            assert initial_count >= 3

            # Delete one
            resp = api_client.delete("/api/v1/vips/10.100.3.11/80/tcp")
            assert resp.status_code == 200

            resp = api_client.get("/api/v1/vips")
            assert resp.status_code == 200
            assert len(resp.json()) == initial_count - 1
        finally:
            api_client.delete("/api/v1/vips/10.100.3.10/80/tcp")
            api_client.delete("/api/v1/vips/10.100.3.11/80/tcp")
            api_client.delete("/api/v1/vips/10.100.3.12/80/tcp")


# ---------------------------------------------------------------------------
# Backend error paths
# ---------------------------------------------------------------------------

class TestBackendErrors:
    def test_duplicate_backend_409(self, api_client):
        """Add same backend twice -> 409."""
        resp = api_client.post("/api/v1/vips", json={
            "address": "10.100.4.1", "port": 80, "protocol": "tcp",
        })
        assert resp.status_code == 201

        try:
            resp = api_client.post(
                "/api/v1/vips/10.100.4.1/80/tcp/backends",
                json={"address": "10.0.2.1", "weight": 100},
            )
            assert resp.status_code == 201

            resp = api_client.post(
                "/api/v1/vips/10.100.4.1/80/tcp/backends",
                json={"address": "10.0.2.1", "weight": 100},
            )
            assert resp.status_code == 409
        finally:
            api_client.delete("/api/v1/vips/10.100.4.1/80/tcp")

    def test_remove_backend_missing_vip_404(self, api_client):
        """Remove backend on non-existent VIP -> 404."""
        resp = api_client.delete(
            "/api/v1/vips/10.255.255.254/9999/tcp/backends/10.0.2.1"
        )
        assert resp.status_code == 404

    def test_drain_backend_missing_vip_404(self, api_client):
        """Drain on non-existent VIP -> 404."""
        resp = api_client.put(
            "/api/v1/vips/10.255.255.254/9999/tcp/backends/10.0.2.1/drain"
        )
        assert resp.status_code == 404

    def test_remove_missing_backend_from_existing_vip(self, api_client):
        """Remove non-existent backend from existing VIP -> 404."""
        resp = api_client.post("/api/v1/vips", json={
            "address": "10.100.4.2", "port": 80, "protocol": "tcp",
        })
        assert resp.status_code == 201

        try:
            resp = api_client.delete(
                "/api/v1/vips/10.100.4.2/80/tcp/backends/10.0.2.99"
            )
            assert resp.status_code == 404
        finally:
            api_client.delete("/api/v1/vips/10.100.4.2/80/tcp")

    def test_drain_missing_backend_from_existing_vip(self, api_client):
        """Drain non-existent backend from existing VIP -> 404."""
        resp = api_client.post("/api/v1/vips", json={
            "address": "10.100.4.3", "port": 80, "protocol": "tcp",
        })
        assert resp.status_code == 201

        try:
            resp = api_client.put(
                "/api/v1/vips/10.100.4.3/80/tcp/backends/10.0.2.99/drain"
            )
            assert resp.status_code == 404
        finally:
            api_client.delete("/api/v1/vips/10.100.4.3/80/tcp")


# ---------------------------------------------------------------------------
# Backend details
# ---------------------------------------------------------------------------

class TestBackendDetails:
    def test_backend_weight_in_response(self, api_client):
        """Add with weight=75, verify in POST and GET."""
        resp = api_client.post("/api/v1/vips", json={
            "address": "10.100.5.1", "port": 80, "protocol": "tcp",
        })
        assert resp.status_code == 201

        try:
            resp = api_client.post(
                "/api/v1/vips/10.100.5.1/80/tcp/backends",
                json={"address": "10.0.3.1", "weight": 75},
            )
            assert resp.status_code == 201
            assert resp.json()["weight"] == 75

            resp = api_client.get("/api/v1/vips/10.100.5.1/80/tcp")
            assert resp.status_code == 200
            backends = resp.json()["backends"]
            assert len(backends) == 1
            assert backends[0]["weight"] == 75
        finally:
            api_client.delete("/api/v1/vips/10.100.5.1/80/tcp")

    def test_multiple_backends_on_same_vip(self, api_client):
        """Add 2 backends, verify count and unique indices."""
        resp = api_client.post("/api/v1/vips", json={
            "address": "10.100.5.2", "port": 80, "protocol": "tcp",
        })
        assert resp.status_code == 201

        try:
            resp1 = api_client.post(
                "/api/v1/vips/10.100.5.2/80/tcp/backends",
                json={"address": "10.0.3.10", "weight": 100},
            )
            assert resp1.status_code == 201
            idx1 = resp1.json()["index"]

            resp2 = api_client.post(
                "/api/v1/vips/10.100.5.2/80/tcp/backends",
                json={"address": "10.0.3.11", "weight": 100},
            )
            assert resp2.status_code == 201
            idx2 = resp2.json()["index"]

            # Unique indices
            assert idx1 != idx2

            # Verify count
            resp = api_client.get("/api/v1/vips/10.100.5.2/80/tcp")
            assert resp.status_code == 200
            assert len(resp.json()["backends"]) == 2
        finally:
            api_client.delete("/api/v1/vips/10.100.5.2/80/tcp")

    def test_shared_backend_across_vips(self, api_client):
        """Same backend on 2 VIPs shares index; deleting VIP-A preserves backend on VIP-B."""
        resp = api_client.post("/api/v1/vips", json={
            "address": "10.100.5.3", "port": 80, "protocol": "tcp",
        })
        assert resp.status_code == 201

        resp = api_client.post("/api/v1/vips", json={
            "address": "10.100.5.4", "port": 80, "protocol": "tcp",
        })
        assert resp.status_code == 201

        try:
            # Add same backend to both VIPs
            resp_a = api_client.post(
                "/api/v1/vips/10.100.5.3/80/tcp/backends",
                json={"address": "10.0.3.20", "weight": 100},
            )
            assert resp_a.status_code == 201
            idx_a = resp_a.json()["index"]

            resp_b = api_client.post(
                "/api/v1/vips/10.100.5.4/80/tcp/backends",
                json={"address": "10.0.3.20", "weight": 100},
            )
            assert resp_b.status_code == 201
            idx_b = resp_b.json()["index"]

            # Shared index
            assert idx_a == idx_b

            # Delete VIP-A
            resp = api_client.delete("/api/v1/vips/10.100.5.3/80/tcp")
            assert resp.status_code == 200

            # Backend still exists on VIP-B
            resp = api_client.get("/api/v1/vips/10.100.5.4/80/tcp")
            assert resp.status_code == 200
            backends = resp.json()["backends"]
            assert len(backends) == 1
            assert backends[0]["address"] == "10.0.3.20"
        finally:
            api_client.delete("/api/v1/vips/10.100.5.3/80/tcp")
            api_client.delete("/api/v1/vips/10.100.5.4/80/tcp")


# ===========================================================================
# IPv6 tests
# ===========================================================================

# ---------------------------------------------------------------------------
# VIP lifecycle (IPv6)
# ---------------------------------------------------------------------------

class TestVipLifecycleV6:
    def test_vip_crud_v6(self, api_client):
        """Full create -> list -> get -> delete cycle with IPv6 VIP."""
        resp = api_client.post("/api/v1/vips", json={
            "address": "fc00::1", "port": 80, "protocol": "tcp",
        })
        assert resp.status_code == 201
        body = resp.json()
        assert body["address"] == "fc00::1"
        assert body["port"] == 80

        try:
            # List
            resp = api_client.get("/api/v1/vips")
            assert resp.status_code == 200
            vips = resp.json()
            assert any(v["address"] == "fc00::1" and v["port"] == 80 for v in vips)

            # Get
            resp = api_client.get("/api/v1/vips/fc00::1/80/tcp")
            assert resp.status_code == 200
            assert resp.json()["address"] == "fc00::1"
        finally:
            resp = api_client.delete("/api/v1/vips/fc00::1/80/tcp")
            assert resp.status_code == 200

    def test_duplicate_v6_vip_409(self, api_client):
        payload = {"address": "fc00::10", "port": 443, "protocol": "tcp"}
        resp = api_client.post("/api/v1/vips", json=payload)
        assert resp.status_code == 201
        try:
            resp = api_client.post("/api/v1/vips", json=payload)
            assert resp.status_code == 409
        finally:
            api_client.delete("/api/v1/vips/fc00::10/443/tcp")

    def test_get_missing_v6_vip_404(self, api_client):
        resp = api_client.get("/api/v1/vips/fc00::ffff/9999/tcp")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Backend lifecycle (IPv6)
# ---------------------------------------------------------------------------

class TestBackendLifecycleV6:
    def test_backend_crud_v6(self, api_client):
        """IPv6 backend add/drain/remove on IPv6 VIP."""
        resp = api_client.post("/api/v1/vips", json={
            "address": "fc00::20", "port": 80, "protocol": "tcp",
        })
        assert resp.status_code == 201

        try:
            # Add IPv6 backend
            resp = api_client.post(
                "/api/v1/vips/fc00::20/80/tcp/backends",
                json={"address": "fc00:1::1", "weight": 100},
            )
            assert resp.status_code == 201
            assert resp.json()["address"] == "fc00:1::1"

            # Verify backend appears in VIP detail
            resp = api_client.get("/api/v1/vips/fc00::20/80/tcp")
            assert resp.status_code == 200
            assert len(resp.json()["backends"]) == 1

            # Drain
            resp = api_client.put(
                "/api/v1/vips/fc00::20/80/tcp/backends/fc00:1::1/drain"
            )
            assert resp.status_code == 200

            # Verify drained (weight=0)
            resp = api_client.get("/api/v1/vips/fc00::20/80/tcp")
            backend = resp.json()["backends"][0]
            assert backend["weight"] == 0

            # Remove backend
            resp = api_client.delete(
                "/api/v1/vips/fc00::20/80/tcp/backends/fc00:1::1"
            )
            assert resp.status_code == 200
        finally:
            api_client.delete("/api/v1/vips/fc00::20/80/tcp")

    def test_backend_on_missing_v6_vip_404(self, api_client):
        resp = api_client.post(
            "/api/v1/vips/fc00::ffff/9999/tcp/backends",
            json={"address": "fc00:1::1", "weight": 100},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# VIP creation variants (IPv6)
# ---------------------------------------------------------------------------

class TestVipCreationV6:
    def test_udp_v6_vip(self, api_client):
        """Create UDP IPv6 VIP, verify protocol in response and GET."""
        resp = api_client.post("/api/v1/vips", json={
            "address": "fc00::30", "port": 53, "protocol": "udp",
        })
        assert resp.status_code == 201
        try:
            assert resp.json()["protocol"] == "udp"

            resp = api_client.get("/api/v1/vips/fc00::30/53/udp")
            assert resp.status_code == 200
            assert resp.json()["protocol"] == "udp"
        finally:
            api_client.delete("/api/v1/vips/fc00::30/53/udp")

    def test_v6_vip_with_flags(self, api_client):
        """Create IPv6 VIP with flags=1, verify in POST and GET."""
        resp = api_client.post("/api/v1/vips", json={
            "address": "fc00::31", "port": 80, "protocol": "tcp", "flags": 1,
        })
        assert resp.status_code == 201
        try:
            assert resp.json()["flags"] == 1

            resp = api_client.get("/api/v1/vips/fc00::31/80/tcp")
            assert resp.status_code == 200
            assert resp.json()["flags"] == 1
        finally:
            api_client.delete("/api/v1/vips/fc00::31/80/tcp")


# ---------------------------------------------------------------------------
# Mixed addressing (IPv4 VIP + IPv6 backend and vice versa)
# ---------------------------------------------------------------------------

class TestMixedAddressing:
    def test_v6_vip_v4_backend(self, api_client):
        """IPv6 VIP with IPv4 backend."""
        resp = api_client.post("/api/v1/vips", json={
            "address": "fc00::40", "port": 80, "protocol": "tcp",
        })
        assert resp.status_code == 201
        try:
            resp = api_client.post(
                "/api/v1/vips/fc00::40/80/tcp/backends",
                json={"address": "10.0.10.1", "weight": 100},
            )
            assert resp.status_code == 201
            assert resp.json()["address"] == "10.0.10.1"
        finally:
            api_client.delete("/api/v1/vips/fc00::40/80/tcp")

    def test_v4_vip_v6_backend(self, api_client):
        """IPv4 VIP with IPv6 backend."""
        resp = api_client.post("/api/v1/vips", json={
            "address": "10.100.6.1", "port": 80, "protocol": "tcp",
        })
        assert resp.status_code == 201
        try:
            resp = api_client.post(
                "/api/v1/vips/10.100.6.1/80/tcp/backends",
                json={"address": "fc00:2::1", "weight": 100},
            )
            assert resp.status_code == 201
            assert resp.json()["address"] == "fc00:2::1"
        finally:
            api_client.delete("/api/v1/vips/10.100.6.1/80/tcp")

    def test_mixed_backends_on_same_vip(self, api_client):
        """IPv4 and IPv6 backends on the same VIP."""
        resp = api_client.post("/api/v1/vips", json={
            "address": "fc00::41", "port": 80, "protocol": "tcp",
        })
        assert resp.status_code == 201
        try:
            resp = api_client.post(
                "/api/v1/vips/fc00::41/80/tcp/backends",
                json={"address": "10.0.10.2", "weight": 100},
            )
            assert resp.status_code == 201

            resp = api_client.post(
                "/api/v1/vips/fc00::41/80/tcp/backends",
                json={"address": "fc00:2::2", "weight": 100},
            )
            assert resp.status_code == 201

            # Verify both backends present
            resp = api_client.get("/api/v1/vips/fc00::41/80/tcp")
            assert resp.status_code == 200
            backends = resp.json()["backends"]
            assert len(backends) == 2
            addrs = {b["address"] for b in backends}
            assert addrs == {"10.0.10.2", "fc00:2::2"}
        finally:
            api_client.delete("/api/v1/vips/fc00::41/80/tcp")
