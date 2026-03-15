"""
Shared helper functions for E2E tests.

These are plain functions (not pytest fixtures) used by feature test modules
to set up VIPs, manage backends, and send traffic.
"""

import re
import socket
import time

import httpx


def make_vip_id(address: str, port: int = 80, protocol: str = "tcp") -> dict:
    return {"address": address, "port": port, "protocol": protocol}


def setup_vip(
    api_client: httpx.Client, address: str, port: int = 80, protocol: str = "tcp"
) -> dict | None:
    resp = api_client.post(
        "/api/v1/vips", json={"address": address, "port": port, "protocol": protocol}
    )
    assert resp.status_code in (201, 409), f"setup_vip failed: {resp.status_code} {resp.text}"
    return resp.json() if resp.status_code == 201 else None


def teardown_vip(
    api_client: httpx.Client, address: str, port: int = 80, protocol: str = "tcp"
) -> None:
    api_client.post(
        "/api/v1/vips/remove",
        json={"address": address, "port": port, "protocol": protocol},
    )


def add_backend(
    api_client: httpx.Client,
    vip_addr: str,
    backend_addr: str,
    port: int = 80,
    protocol: str = "tcp",
    weight: int = 100,
) -> dict | None:
    resp = api_client.post(
        "/api/v1/backends/add",
        json={
            "vip": {"address": vip_addr, "port": port, "protocol": protocol},
            "address": backend_addr,
            "weight": weight,
        },
    )
    assert resp.status_code in (201, 409), f"add_backend failed: {resp.status_code} {resp.text}"
    return resp.json() if resp.status_code == 201 else None


def remove_backend(
    api_client: httpx.Client,
    vip_addr: str,
    backend_addr: str,
    port: int = 80,
    protocol: str = "tcp",
) -> None:
    api_client.post(
        "/api/v1/backends/remove",
        json={
            "vip": {"address": vip_addr, "port": port, "protocol": protocol},
            "address": backend_addr,
        },
    )


def send_request(vip_addr: str, port: int = 80, timeout: float = 5.0) -> dict:
    url = f"http://[{vip_addr}]:{port}/" if ":" in vip_addr else f"http://{vip_addr}:{port}/"
    resp = httpx.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def send_requests(
    vip_addr: str, count: int = 20, port: int = 80, timeout: float = 5.0
) -> list[dict | None]:
    results: list[dict | None] = []
    for _ in range(count):
        try:
            results.append(send_request(vip_addr, port=port, timeout=timeout))
        except Exception:
            results.append(None)
    return results


def wait_for_condition(fn, timeout: int = 10, interval: int = 1):
    """Poll fn() until it returns truthy, or raise after timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = fn()
        if result:
            return result
        time.sleep(interval)
    raise TimeoutError(f"Condition not met within {timeout}s")


def parse_metric_value(
    content: str, metric_name: str, labels: dict[str, str] | None = None
) -> float | None:
    """Parse a Prometheus metric value from text format."""
    if labels:
        label_parts = [f'{k}="{v}"' for k, v in sorted(labels.items())]
        label_str = ",".join(label_parts)
        pattern = rf"{metric_name}\{{{label_str}\}}\s+(\d+(?:\.\d+)?)"
    else:
        pattern = rf"^{metric_name}\s+(\d+(?:\.\d+)?)$"
    match = re.search(pattern, content, re.MULTILINE)
    return float(match.group(1)) if match else None


def send_udp_packets(
    addr: str, port: int, count: int = 20, payload: bytes = b"test"
) -> None:
    """Send UDP datagrams to an address (for QUIC VIP tests)."""
    family = socket.AF_INET6 if ":" in addr else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        for _ in range(count):
            sock.sendto(payload, (addr, port))
    finally:
        sock.close()
