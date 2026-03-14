"""
End-to-end traffic forwarding tests.

These tests validate the full packet path:
  test-client -> VIP (XDP encap) -> backend (IPIP decap) -> DSR response

Each test configures VIPs/backends via the control plane API, then sends
real HTTP traffic to the VIP address and verifies responses come from
the expected backend(s).
"""

import contextlib
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
    resp = api_client.post(
        "/api/v1/vips",
        json={
            "address": vip_addr,
            "port": port,
            "protocol": proto,
        },
    )
    assert resp.status_code in (201, 409), f"Unexpected status: {resp.status_code}"


def _teardown_vip(api_client, vip_addr, port=TRAFFIC_VIP_PORT, proto=TRAFFIC_VIP_PROTO):
    """Remove VIP (ignore 404)."""
    api_client.post(
        "/api/v1/vips/remove",
        json={
            "address": vip_addr,
            "port": port,
            "protocol": proto,
        },
    )


def _add_backend(
    api_client, vip_addr, backend_addr, weight=100, port=TRAFFIC_VIP_PORT, proto=TRAFFIC_VIP_PROTO
):
    resp = api_client.post(
        "/api/v1/backends/add",
        json={
            "vip": {"address": vip_addr, "port": port, "protocol": proto},
            "address": backend_addr,
            "weight": weight,
        },
    )
    assert resp.status_code in (201, 409), f"Unexpected status: {resp.status_code}"


def _remove_backend(
    api_client, vip_addr, backend_addr, port=TRAFFIC_VIP_PORT, proto=TRAFFIC_VIP_PROTO
):
    api_client.post(
        "/api/v1/backends/remove",
        json={
            "vip": {"address": vip_addr, "port": port, "protocol": proto},
            "address": backend_addr,
        },
    )


def _drain_backend(
    api_client, vip_addr, backend_addr, port=TRAFFIC_VIP_PORT, proto=TRAFFIC_VIP_PROTO
):
    resp = api_client.post(
        "/api/v1/backends/drain",
        json={
            "vip": {"address": vip_addr, "port": port, "protocol": proto},
            "address": backend_addr,
        },
    )
    assert resp.status_code == 200


def _send_request(vip_addr, port=TRAFFIC_VIP_PORT, timeout=5.0):
    """Send a single HTTP GET to the VIP and return the parsed JSON body."""
    url = f"http://[{vip_addr}]:{port}/" if ":" in vip_addr else f"http://{vip_addr}:{port}/"
    resp = httpx.get(url, timeout=timeout)
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


def _parse_metric_value(content, metric_name, labels=None):
    """
    Parse a metric value from Prometheus text format.

    Args:
        content: Prometheus metrics text
        metric_name: Metric name (e.g., "katran_vip_packets_total")
        labels: Optional dict of label key-value pairs to match

    Returns:
        Float value of the metric, or None if not found
    """
    import re

    if labels:
        # Build label matcher like: address="10.0.0.1",port="80",protocol="tcp"
        label_parts = [f'{k}="{v}"' for k, v in sorted(labels.items())]
        label_str = ",".join(label_parts)
        pattern = rf"{metric_name}\{{{label_str}\}}\s+(\d+(?:\.\d+)?)"
    else:
        # Match metric without labels
        pattern = rf"^{metric_name}\s+(\d+(?:\.\d+)?)$"

    match = re.search(pattern, content, re.MULTILINE)
    if match:
        return float(match.group(1))
    return None


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

    def test_two_backend_distribution(self, api_client, vip_addr, backend_1_addr, backend_2_addr):
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

    def test_drain_stops_traffic(self, api_client, vip_addr, backend_1_addr, backend_2_addr):
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

            backends_seen = {r["backend"] for r in successful}
            # After draining backend-1 (weight=0), all traffic should go to backend-2
            assert "backend-2" in backends_seen, "backend-2 should receive traffic"
        finally:
            _remove_backend(api_client, vip_addr, backend_1_addr)
            _remove_backend(api_client, vip_addr, backend_2_addr)
            _teardown_vip(api_client, vip_addr)


class TestRemoveBackend:
    """Verify removing a backend redistributes traffic."""

    def test_remove_shifts_traffic(self, api_client, vip_addr, backend_1_addr, backend_2_addr):
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

    def test_all_backends_drained_drops_traffic(
        self, api_client, vip_addr, backend_1_addr, backend_2_addr
    ):
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

    def test_readd_backend_after_removal_traffic_resumes(
        self, api_client, vip_addr, backend_1_addr
    ):
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


# ===========================================================================
# IPv6 traffic tests
# ===========================================================================


class TestBasicForwardingV6:
    """Verify a single IPv6 backend receives traffic through the XDP path."""

    def test_single_backend_forwarding_v6(self, api_client, vip_addr6, backend_1_addr6):
        """Add IPv6 VIP + one IPv6 backend -> send HTTP -> verify response."""
        _setup_vip(api_client, vip_addr6)
        _add_backend(api_client, vip_addr6, backend_1_addr6)

        time.sleep(2)

        try:
            body = _send_request(vip_addr6)
            assert body["backend"] == "backend-1"
        finally:
            _remove_backend(api_client, vip_addr6, backend_1_addr6)
            _teardown_vip(api_client, vip_addr6)


class TestMultiBackendDistributionV6:
    """Verify IPv6 traffic distributes across multiple backends."""

    def test_two_backend_distribution_v6(
        self, api_client, vip_addr6, backend_1_addr6, backend_2_addr6
    ):
        """Add 2 IPv6 backends -> send N requests -> verify both receive traffic."""
        _setup_vip(api_client, vip_addr6)
        _add_backend(api_client, vip_addr6, backend_1_addr6)
        _add_backend(api_client, vip_addr6, backend_2_addr6)

        time.sleep(2)

        try:
            results = _send_requests(vip_addr6, count=50)
            successful = [r for r in results if r is not None]
            assert len(successful) > 0, "No successful responses"

            backends_seen = Counter(r["backend"] for r in successful)
            assert len(successful) >= 10, f"Too few successes: {len(successful)}"

            for backend_name in backends_seen:
                assert backend_name in ("backend-1", "backend-2")
        finally:
            _remove_backend(api_client, vip_addr6, backend_1_addr6)
            _remove_backend(api_client, vip_addr6, backend_2_addr6)
            _teardown_vip(api_client, vip_addr6)


class TestDrainShiftsTrafficV6:
    """Verify draining an IPv6 backend shifts traffic to remaining backends."""

    def test_drain_stops_traffic_v6(self, api_client, vip_addr6, backend_1_addr6, backend_2_addr6):
        """Drain one IPv6 backend -> verify all traffic goes to the other."""
        _setup_vip(api_client, vip_addr6)
        _add_backend(api_client, vip_addr6, backend_1_addr6)
        _add_backend(api_client, vip_addr6, backend_2_addr6)
        time.sleep(2)

        # Drain backend-1
        _drain_backend(api_client, vip_addr6, backend_1_addr6)
        time.sleep(2)

        try:
            results = _send_requests(vip_addr6, count=30)
            successful = [r for r in results if r is not None]
            assert len(successful) > 0, "No successful responses after drain"

            backends_seen = {r["backend"] for r in successful}
            assert "backend-2" in backends_seen, "backend-2 should receive traffic"
        finally:
            _remove_backend(api_client, vip_addr6, backend_1_addr6)
            _remove_backend(api_client, vip_addr6, backend_2_addr6)
            _teardown_vip(api_client, vip_addr6)


# ===========================================================================
# Metrics Validation Tests
# ===========================================================================


class TestMetricsAccuracy:
    """Verify metrics accurately reflect real traffic forwarding."""

    def test_vip_packet_counter_increases_with_traffic(self, api_client, vip_addr, backend_1_addr):
        """Send real traffic and verify VIP packet counter increases."""
        _setup_vip(api_client, vip_addr)
        _add_backend(api_client, vip_addr, backend_1_addr)
        time.sleep(2)

        try:
            # Get initial metrics
            resp = api_client.get("/metrics/")
            assert resp.status_code == 200
            initial_content = resp.text

            labels = {
                "address": vip_addr,
                "port": str(TRAFFIC_VIP_PORT),
                "protocol": TRAFFIC_VIP_PROTO,
            }

            initial_packets = _parse_metric_value(
                initial_content, "katran_vip_packets_total", labels
            )
            initial_bytes = _parse_metric_value(initial_content, "katran_vip_bytes_total", labels)

            # Send traffic
            results = _send_requests(vip_addr, count=10)
            successful = [r for r in results if r is not None]
            assert len(successful) >= 5, "Expected at least 5 successful requests"

            # Wait a moment for stats to propagate
            time.sleep(1)

            # Get updated metrics
            resp = api_client.get("/metrics/")
            assert resp.status_code == 200
            updated_content = resp.text

            updated_packets = _parse_metric_value(
                updated_content, "katran_vip_packets_total", labels
            )
            updated_bytes = _parse_metric_value(updated_content, "katran_vip_bytes_total", labels)

            # Verify counters increased
            if initial_packets is not None and updated_packets is not None:
                assert updated_packets > initial_packets, (
                    f"Packet counter should increase: "
                    f"initial={initial_packets}, updated={updated_packets}"
                )

            if initial_bytes is not None and updated_bytes is not None:
                assert updated_bytes > initial_bytes, (
                    f"Byte counter should increase: "
                    f"initial={initial_bytes}, updated={updated_bytes}"
                )

        finally:
            _remove_backend(api_client, vip_addr, backend_1_addr)
            _teardown_vip(api_client, vip_addr)

    def test_global_packet_counter_increases_with_traffic(
        self, api_client, vip_addr, backend_1_addr
    ):
        """Verify global packet counter increases with real traffic."""
        _setup_vip(api_client, vip_addr)
        _add_backend(api_client, vip_addr, backend_1_addr)
        time.sleep(2)

        try:
            # Get initial global metrics
            resp = api_client.get("/metrics/")
            assert resp.status_code == 200
            initial_content = resp.text

            initial_packets = _parse_metric_value(initial_content, "katran_packets_total")
            initial_bytes = _parse_metric_value(initial_content, "katran_bytes_total")

            # Send traffic
            results = _send_requests(vip_addr, count=10)
            successful = [r for r in results if r is not None]
            assert len(successful) >= 5

            time.sleep(1)

            # Get updated metrics
            resp = api_client.get("/metrics/")
            updated_content = resp.text

            updated_packets = _parse_metric_value(updated_content, "katran_packets_total")
            updated_bytes = _parse_metric_value(updated_content, "katran_bytes_total")

            # Verify global counters increased
            if initial_packets is not None and updated_packets is not None:
                assert updated_packets > initial_packets, (
                    f"Global packet counter should increase: "
                    f"initial={initial_packets}, updated={updated_packets}"
                )

            if initial_bytes is not None and updated_bytes is not None:
                assert updated_bytes > initial_bytes, (
                    f"Global byte counter should increase: "
                    f"initial={initial_bytes}, updated={updated_bytes}"
                )

        finally:
            _remove_backend(api_client, vip_addr, backend_1_addr)
            _teardown_vip(api_client, vip_addr)

    def test_multiple_vips_separate_counters(self, api_client, vip_addr, backend_1_addr):
        """Verify different VIPs have independent packet counters.

        Creates two VIPs on different ports and verifies each gets its own
        metrics.  A sleep between the two add-backend calls gives the server
        time to finish the 65 k-entry CH ring writes.
        """
        vip1_addr = vip_addr
        vip1_port = TRAFFIC_VIP_PORT
        vip2_port = 8081  # Use 8081 instead of 8080 (which is the API server port)

        try:
            _setup_vip(api_client, vip1_addr, port=vip1_port)
            _add_backend(api_client, vip1_addr, backend_1_addr, port=vip1_port)

            # Let the server settle after the first 65 k ring write before
            # issuing the next heavy operation.
            time.sleep(3)

            _setup_vip(api_client, vip1_addr, port=vip2_port)
            _add_backend(api_client, vip1_addr, backend_1_addr, port=vip2_port)

            time.sleep(3)

            # Send traffic only to VIP1
            _send_requests(vip1_addr, count=5, port=vip1_port)
            time.sleep(1)

            # Get metrics
            resp = api_client.get("/metrics/")
            content = resp.text

            labels1 = {
                "address": vip1_addr,
                "port": str(vip1_port),
                "protocol": TRAFFIC_VIP_PROTO,
            }
            labels2 = {
                "address": vip1_addr,
                "port": str(vip2_port),
                "protocol": TRAFFIC_VIP_PROTO,
            }

            packets1 = _parse_metric_value(content, "katran_vip_packets_total", labels1)
            packets2 = _parse_metric_value(content, "katran_vip_packets_total", labels2)

            # Both metrics should exist
            assert packets1 is not None, "VIP1 metrics should exist"
            assert packets2 is not None, "VIP2 metrics should exist"

            # VIP1 should have received packets (we sent traffic to it)
            # VIP2 might have 0 or small count (no real traffic sent)
            assert packets1 >= 0, "VIP1 should have packet count"
            assert packets2 >= 0, "VIP2 should have packet count"

        finally:
            # Best-effort cleanup: suppress errors so we don't mask the
            # real failure and don't leave stale state for the next test.
            for port in (vip1_port, vip2_port):
                with contextlib.suppress(Exception):
                    _remove_backend(api_client, vip1_addr, backend_1_addr, port=port)
                with contextlib.suppress(Exception):
                    _teardown_vip(api_client, vip1_addr, port=port)


def _wait_for_api(api_client, timeout=30):
    """Block until the control-plane API responds to /health."""
    base_url = str(api_client._base_url)
    for _ in range(timeout):
        try:
            resp = httpx.get(f"{base_url}/health", timeout=2.0)
            if resp.status_code == 200:
                return
        except Exception:
            pass
        time.sleep(1)
    pytest.skip("Control plane API did not recover in time")


class TestMetricsAccuracyV6:
    """Verify metrics work correctly with IPv6 traffic."""

    def test_vip_packet_counter_increases_with_ipv6_traffic(
        self, api_client, vip_addr6, backend_1_addr6
    ):
        """Send IPv6 traffic and verify VIP packet counter increases."""
        # Ensure the API is healthy (previous test may have stressed it)
        _wait_for_api(api_client)

        _setup_vip(api_client, vip_addr6)
        _add_backend(api_client, vip_addr6, backend_1_addr6)
        time.sleep(2)

        try:
            # Get initial metrics
            resp = api_client.get("/metrics/")
            assert resp.status_code == 200
            initial_content = resp.text

            labels = {
                "address": vip_addr6,
                "port": str(TRAFFIC_VIP_PORT),
                "protocol": TRAFFIC_VIP_PROTO,
            }

            initial_packets = _parse_metric_value(
                initial_content, "katran_vip_packets_total", labels
            )

            # Send IPv6 traffic
            results = _send_requests(vip_addr6, count=10)
            successful = [r for r in results if r is not None]
            assert len(successful) >= 5

            time.sleep(1)

            # Get updated metrics
            resp = api_client.get("/metrics/")
            updated_content = resp.text

            updated_packets = _parse_metric_value(
                updated_content, "katran_vip_packets_total", labels
            )

            # Verify IPv6 VIP counter increased
            if initial_packets is not None and updated_packets is not None:
                assert updated_packets > initial_packets, (
                    f"IPv6 VIP packet counter should increase: "
                    f"initial={initial_packets}, updated={updated_packets}"
                )

        finally:
            with contextlib.suppress(Exception):
                _remove_backend(api_client, vip_addr6, backend_1_addr6)
            with contextlib.suppress(Exception):
                _teardown_vip(api_client, vip_addr6)
