#!/usr/bin/env python3
"""
Debug script to reproduce test_global_packet_counter_increases_with_traffic
followed by test_multiple_vips_separate_counters.

Run from test-client container with e2e environment running.
"""

import contextlib
import sys
import time

import httpx

# Configuration
API_URL = "http://katran-lb:8080"
VIP_ADDR = "10.200.0.10"
BACKEND_1_ADDR = "10.200.0.20"
TRAFFIC_VIP_PORT = 80
TRAFFIC_VIP_PROTO = "tcp"


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _setup_vip(api_client, vip_addr, port=TRAFFIC_VIP_PORT, proto=TRAFFIC_VIP_PROTO):
    """Create a VIP, return True if created (or already exists)."""
    log(f"Creating VIP {vip_addr}:{port}/{proto}")
    resp = api_client.post(
        "/api/v1/vips",
        json={
            "address": vip_addr,
            "port": port,
            "protocol": proto,
        },
    )
    assert resp.status_code in (201, 409), f"Unexpected status: {resp.status_code}"
    log(f"  → Status: {resp.status_code}")


def _add_backend(
    api_client, vip_addr, backend_addr, weight=100, port=TRAFFIC_VIP_PORT, proto=TRAFFIC_VIP_PROTO
):
    log(f"Adding backend {backend_addr} to VIP {vip_addr}:{port}/{proto}")
    start = time.time()
    resp = api_client.post(
        "/api/v1/backends/add",
        json={
            "vip": {"address": vip_addr, "port": port, "protocol": proto},
            "address": backend_addr,
            "weight": weight,
        },
    )
    elapsed = time.time() - start
    assert resp.status_code in (201, 409), f"Unexpected status: {resp.status_code}"
    log(f"  → Status: {resp.status_code}, took {elapsed:.2f}s")


def _send_requests(vip_addr, count=10, port=TRAFFIC_VIP_PORT):
    """Send multiple requests, return list of response bodies."""
    results = []
    for i in range(count):
        try:
            url = f"http://{vip_addr}:{port}/"
            resp = httpx.get(url, timeout=5.0)
            resp.raise_for_status()
            results.append(resp.json())
        except Exception as e:
            log(f"  Request {i + 1}/{count} failed: {e}")
            results.append(None)
    return results


def test_1_global_counter(api_client):
    """Reproduce test_global_packet_counter_increases_with_traffic"""
    log("\n=== TEST 1: Global packet counter ===")

    vip_addr = VIP_ADDR
    backend_addr = BACKEND_1_ADDR

    _setup_vip(api_client, vip_addr)
    _add_backend(api_client, vip_addr, backend_addr)

    log("Waiting 2s for CH ring programming...")
    time.sleep(2)

    log("Sending 10 requests to VIP...")
    results = _send_requests(vip_addr, count=10)
    successful = [r for r in results if r is not None]
    log(f"  → {len(successful)}/10 successful")

    log("Checking metrics...")
    resp = api_client.get("/metrics/")
    log(f"  → Metrics status: {resp.status_code}")

    log("Cleaning up...")
    api_client.post(
        "/api/v1/backends/remove",
        json={
            "vip": {"address": vip_addr, "port": TRAFFIC_VIP_PORT, "protocol": TRAFFIC_VIP_PROTO},
            "address": backend_addr,
        },
    )
    api_client.post(
        "/api/v1/vips/remove",
        json={
            "address": vip_addr,
            "port": TRAFFIC_VIP_PORT,
            "protocol": TRAFFIC_VIP_PROTO,
        },
    )

    log("✓ TEST 1 COMPLETED\n")


def test_2_multiple_vips(api_client):
    """Reproduce test_multiple_vips_separate_counters"""
    log("\n=== TEST 2: Multiple VIPs separate counters ===")

    vip1_addr = VIP_ADDR
    vip1_port = 80
    vip2_port = 8080
    backend_addr = BACKEND_1_ADDR

    try:
        log("Step 1: Create VIP1 (port 80)")
        _setup_vip(api_client, vip1_addr, port=vip1_port)

        log("Step 2: Add backend to VIP1 (port 80)")
        _add_backend(api_client, vip1_addr, backend_addr, port=vip1_port)

        log("Step 3: Sleep 3s (let server settle after 65k ring write)")
        time.sleep(3)

        log("Step 4: Create VIP2 (port 8080)")
        _setup_vip(api_client, vip1_addr, port=vip2_port)

        log("Step 5: Add backend to VIP2 (port 8080) - THIS IS WHERE IT HANGS")
        _add_backend(api_client, vip1_addr, backend_addr, port=vip2_port)

        log("Step 6: Sleep 3s")
        time.sleep(3)

        log("Step 7: Send traffic to VIP1")
        _send_requests(vip1_addr, count=5, port=vip1_port)

        log("Step 8: Check metrics")
        resp = api_client.get("/metrics/")
        log(f"  → Metrics status: {resp.status_code}")

        log("✓ TEST 2 COMPLETED\n")

    finally:
        log("Cleanup...")
        for port in (vip1_port, vip2_port):
            with contextlib.suppress(Exception):
                api_client.post(
                    "/api/v1/backends/remove",
                    json={
                        "vip": {"address": vip1_addr, "port": port, "protocol": TRAFFIC_VIP_PROTO},
                        "address": backend_addr,
                    },
                )
            with contextlib.suppress(Exception):
                api_client.post(
                    "/api/v1/vips/remove",
                    json={
                        "address": vip1_addr,
                        "port": port,
                        "protocol": TRAFFIC_VIP_PROTO,
                    },
                )


def main():
    log("Starting debug script...")
    log(f"API URL: {API_URL}")
    log(f"VIP: {VIP_ADDR}")
    log(f"Backend: {BACKEND_1_ADDR}")

    # Create HTTP client with 60s timeout
    client = httpx.Client(base_url=API_URL, timeout=60.0)

    # Wait for API
    log("\nWaiting for API to be healthy...")
    for i in range(30):
        try:
            resp = client.get("/health")
            if resp.status_code == 200:
                log("  → API is healthy")
                break
        except Exception as e:
            if i == 0:
                log(f"  Waiting... ({e})")
        time.sleep(1)
    else:
        log("ERROR: API not healthy after 30s")
        sys.exit(1)

    try:
        # Run test 1
        test_1_global_counter(client)

        # Run test 2
        test_2_multiple_vips(client)

        log("\n✓ ALL TESTS COMPLETED SUCCESSFULLY")

    except Exception as e:
        log(f"\n✗ TEST FAILED: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
    finally:
        client.close()


if __name__ == "__main__":
    main()
