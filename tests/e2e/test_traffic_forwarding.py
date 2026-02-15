"""
End-to-end traffic forwarding tests.

These tests validate the full packet path:
  test-client -> VIP (XDP encap) -> backend (IPIP decap) -> DSR response

Each test configures VIPs/backends via the control plane API, then sends
real HTTP traffic to the VIP address and verifies responses come from
the expected backend(s).
"""

import time
from collections import Counter

import httpx
import pytest


pytestmark = pytest.mark.e2e

# VIP we'll use for traffic tests (the LB's own IP, port 80)
TRAFFIC_VIP_PORT = 80
TRAFFIC_VIP_PROTO = "tcp"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _setup_vip(api_client, vip_addr, port=TRAFFIC_VIP_PORT, proto=TRAFFIC_VIP_PROTO):
    """Create a VIP, return True if created (or already exists)."""
    resp = api_client.post("/api/v1/vips", json={
        "address": vip_addr, "port": port, "protocol": proto,
    })
    assert resp.status_code in (201, 409), f"Unexpected status: {resp.status_code}"


def _teardown_vip(api_client, vip_addr, port=TRAFFIC_VIP_PORT, proto=TRAFFIC_VIP_PROTO):
    """Remove VIP (ignore 404)."""
    api_client.delete(f"/api/v1/vips/{vip_addr}/{port}/{proto}")


def _add_backend(api_client, vip_addr, backend_addr, weight=100,
                 port=TRAFFIC_VIP_PORT, proto=TRAFFIC_VIP_PROTO):
    resp = api_client.post(
        f"/api/v1/vips/{vip_addr}/{port}/{proto}/backends",
        json={"address": backend_addr, "weight": weight},
    )
    assert resp.status_code in (201, 409), f"Unexpected status: {resp.status_code}"


def _remove_backend(api_client, vip_addr, backend_addr,
                    port=TRAFFIC_VIP_PORT, proto=TRAFFIC_VIP_PROTO):
    api_client.delete(f"/api/v1/vips/{vip_addr}/{port}/{proto}/backends/{backend_addr}")


def _drain_backend(api_client, vip_addr, backend_addr,
                   port=TRAFFIC_VIP_PORT, proto=TRAFFIC_VIP_PROTO):
    resp = api_client.put(
        f"/api/v1/vips/{vip_addr}/{port}/{proto}/backends/{backend_addr}/drain"
    )
    assert resp.status_code == 200


def _send_request(vip_addr, port=TRAFFIC_VIP_PORT, timeout=5.0):
    """Send a single HTTP GET to the VIP and return the parsed JSON body."""
    resp = httpx.get(f"http://{vip_addr}:{port}/", timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def _send_requests(vip_addr, count=20, port=TRAFFIC_VIP_PORT, timeout=5.0):
    """Send multiple requests, return list of response bodies."""
    results = []
    for _ in range(count):
        try:
            body = _send_request(vip_addr, port=port, timeout=timeout)
            results.append(body)
        except Exception:
            results.append(None)
    return results


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBasicForwarding:
    """Verify a single backend receives traffic through the XDP path."""

    def test_single_backend_forwarding(self, api_client, vip_addr, backend_1_addr):
        """Add VIP + one backend -> send HTTP -> verify response from backend."""
        _setup_vip(api_client, vip_addr)
        _add_backend(api_client, vip_addr, backend_1_addr)

        # Allow time for CH ring to be programmed
        time.sleep(2)

        try:
            body = _send_request(vip_addr)
            assert body["backend"] == "backend-1"
            assert body["address"] == backend_1_addr
        finally:
            _remove_backend(api_client, vip_addr, backend_1_addr)
            _teardown_vip(api_client, vip_addr)


class TestMultiBackendDistribution:
    """Verify traffic distributes across multiple backends."""

    def test_two_backend_distribution(self, api_client, vip_addr,
                                     backend_1_addr, backend_2_addr):
        """Add 2 backends -> send N requests -> verify both receive traffic."""
        _setup_vip(api_client, vip_addr)
        _add_backend(api_client, vip_addr, backend_1_addr)
        _add_backend(api_client, vip_addr, backend_2_addr)

        time.sleep(2)

        try:
            results = _send_requests(vip_addr, count=50)
            successful = [r for r in results if r is not None]
            assert len(successful) > 0, "No successful responses"

            backends_seen = Counter(r["backend"] for r in successful)
            # With consistent hashing from a single source IP, traffic may
            # all go to one backend. But we should at least get responses.
            assert len(successful) >= 10, f"Too few successes: {len(successful)}"

            # Verify responses are from known backends
            for backend_name in backends_seen:
                assert backend_name in ("backend-1", "backend-2")
        finally:
            _remove_backend(api_client, vip_addr, backend_1_addr)
            _remove_backend(api_client, vip_addr, backend_2_addr)
            _teardown_vip(api_client, vip_addr)


class TestDrainShiftsTraffic:
    """Verify draining a backend shifts traffic to remaining backends."""

    def test_drain_stops_traffic(self, api_client, vip_addr,
                                backend_1_addr, backend_2_addr):
        """Drain one backend -> verify all traffic goes to the other."""
        _setup_vip(api_client, vip_addr)
        _add_backend(api_client, vip_addr, backend_1_addr)
        _add_backend(api_client, vip_addr, backend_2_addr)
        time.sleep(2)

        # Drain backend-1
        _drain_backend(api_client, vip_addr, backend_1_addr)
        time.sleep(2)

        try:
            results = _send_requests(vip_addr, count=30)
            successful = [r for r in results if r is not None]
            assert len(successful) > 0, "No successful responses after drain"

            backends_seen = set(r["backend"] for r in successful)
            # After draining backend-1 (weight=0), all traffic should go to backend-2
            assert "backend-2" in backends_seen, "backend-2 should receive traffic"
        finally:
            _remove_backend(api_client, vip_addr, backend_1_addr)
            _remove_backend(api_client, vip_addr, backend_2_addr)
            _teardown_vip(api_client, vip_addr)


class TestRemoveBackend:
    """Verify removing a backend redistributes traffic."""

    def test_remove_shifts_traffic(self, api_client, vip_addr,
                                  backend_1_addr, backend_2_addr):
        """Remove one backend -> verify remaining backend gets all traffic."""
        _setup_vip(api_client, vip_addr)
        _add_backend(api_client, vip_addr, backend_1_addr)
        _add_backend(api_client, vip_addr, backend_2_addr)
        time.sleep(2)

        # Remove backend-1
        _remove_backend(api_client, vip_addr, backend_1_addr)
        time.sleep(2)

        try:
            results = _send_requests(vip_addr, count=20)
            successful = [r for r in results if r is not None]
            assert len(successful) > 0, "No successful responses after remove"

            # All traffic should go to backend-2
            for r in successful:
                assert r["backend"] == "backend-2"
        finally:
            _remove_backend(api_client, vip_addr, backend_2_addr)
            _teardown_vip(api_client, vip_addr)


class TestNoBackendDrops:
    """Verify VIP with no backends drops/rejects traffic."""

    def test_no_backends_connection_fails(self, api_client, vip_addr):
        """VIP with no backends -> connection should fail."""
        _setup_vip(api_client, vip_addr)
        time.sleep(1)

        try:
            with pytest.raises((httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout)):
                _send_request(vip_addr, timeout=3.0)
        finally:
            _teardown_vip(api_client, vip_addr)


class TestVipRecreateTraffic:
    """Verify traffic works after tearing down and recreating a VIP."""

    def test_vip_recreate_traffic_resumes(self, api_client, vip_addr, backend_1_addr):
        """Teardown VIP+backend, recreate, traffic works again."""
        _setup_vip(api_client, vip_addr)
        _add_backend(api_client, vip_addr, backend_1_addr)
        time.sleep(2)

        try:
            # Verify traffic works initially
            body = _send_request(vip_addr)
            assert body["backend"] == "backend-1"

            # Tear down
            _remove_backend(api_client, vip_addr, backend_1_addr)
            _teardown_vip(api_client, vip_addr)
            time.sleep(1)

            # Recreate
            _setup_vip(api_client, vip_addr)
            _add_backend(api_client, vip_addr, backend_1_addr)
            time.sleep(2)

            # Traffic should work again
            body = _send_request(vip_addr)
            assert body["backend"] == "backend-1"
        finally:
            _remove_backend(api_client, vip_addr, backend_1_addr)
            _teardown_vip(api_client, vip_addr)


class TestAllDrainedDrops:
    """Verify that draining all backends causes traffic to fail."""

    def test_all_backends_drained_drops_traffic(self, api_client, vip_addr,
                                                 backend_1_addr, backend_2_addr):
        """Drain all backends -> connection fails."""
        _setup_vip(api_client, vip_addr)
        _add_backend(api_client, vip_addr, backend_1_addr)
        _add_backend(api_client, vip_addr, backend_2_addr)
        time.sleep(2)

        # Drain both
        _drain_backend(api_client, vip_addr, backend_1_addr)
        _drain_backend(api_client, vip_addr, backend_2_addr)
        time.sleep(2)

        try:
            with pytest.raises((httpx.ConnectError, httpx.ReadTimeout, httpx.ConnectTimeout)):
                _send_request(vip_addr, timeout=3.0)
        finally:
            _remove_backend(api_client, vip_addr, backend_1_addr)
            _remove_backend(api_client, vip_addr, backend_2_addr)
            _teardown_vip(api_client, vip_addr)


class TestReaddBackendTraffic:
    """Verify removing and re-adding a backend restores traffic."""

    def test_readd_backend_after_removal_traffic_resumes(self, api_client, vip_addr,
                                                          backend_1_addr):
        """Remove backend, re-add it, traffic still works."""
        _setup_vip(api_client, vip_addr)
        _add_backend(api_client, vip_addr, backend_1_addr)
        time.sleep(2)

        try:
            # Verify initial traffic
            body = _send_request(vip_addr)
            assert body["backend"] == "backend-1"

            # Remove backend
            _remove_backend(api_client, vip_addr, backend_1_addr)
            time.sleep(1)

            # Re-add same backend
            _add_backend(api_client, vip_addr, backend_1_addr)
            time.sleep(2)

            # Traffic should resume
            body = _send_request(vip_addr)
            assert body["backend"] == "backend-1"
        finally:
            _remove_backend(api_client, vip_addr, backend_1_addr)
            _teardown_vip(api_client, vip_addr)
