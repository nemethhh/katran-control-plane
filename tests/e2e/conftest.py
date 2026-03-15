"""
E2E test fixtures for multi-container Katran tests.

Expects the following env vars (set by docker-compose.e2e.yml):
  KATRAN_E2E=1            - guard: skip if not in E2E env
  KATRAN_API_URL           - control plane URL (http://katran-lb:8080)
  KATRAN_VIP_ADDR          - VIP address assigned to the LB (10.200.0.10)
  BACKEND_1_ADDR           - first backend IP  (10.200.0.20)
  BACKEND_2_ADDR           - second backend IP (10.200.0.21)
"""

import os
import sys
import time

import httpx
import pytest

# Ensure tests/e2e/ is on sys.path so test modules can `from helpers import ...`
sys.path.insert(0, os.path.dirname(__file__))


def pytest_collection_modifyitems(config, items):
    """Skip E2E tests when not running inside the E2E environment."""
    if os.environ.get("KATRAN_E2E") != "1":
        skip = pytest.mark.skip(reason="KATRAN_E2E not set (run via run-e2e.sh)")
        for item in items:
            if "e2e" in item.nodeid.split("::")[0]:
                item.add_marker(skip)


# ---------------------------------------------------------------------------
# Configuration fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def api_url() -> str:
    return os.environ.get("KATRAN_API_URL", "http://katran-lb:8080")


@pytest.fixture(scope="session")
def vip_addr() -> str:
    return os.environ.get("KATRAN_VIP_ADDR", "10.200.0.10")


@pytest.fixture(scope="session")
def backend_1_addr() -> str:
    return os.environ.get("BACKEND_1_ADDR", "10.200.0.20")


@pytest.fixture(scope="session")
def backend_2_addr() -> str:
    return os.environ.get("BACKEND_2_ADDR", "10.200.0.21")


@pytest.fixture(scope="session")
def vip_addr6() -> str:
    return os.environ.get("KATRAN_VIP6_ADDR", "fd00:200::10")


@pytest.fixture(scope="session")
def backend_1_addr6() -> str:
    return os.environ.get("BACKEND_1_ADDR6", "fd00:200::20")


@pytest.fixture(scope="session")
def backend_2_addr6() -> str:
    return os.environ.get("BACKEND_2_ADDR6", "fd00:200::21")


@pytest.fixture(scope="session")
def backend_3_addr() -> str:
    return os.environ.get("BACKEND_3_ADDR", "10.200.0.22")


@pytest.fixture(scope="session")
def backend_3_addr6() -> str:
    return os.environ.get("BACKEND_3_ADDR6", "fd00:200::22")


@pytest.fixture(scope="session")
def hc_target_addr() -> str:
    return os.environ.get("HC_TARGET_ADDR", "10.200.0.30")


@pytest.fixture(scope="session")
def hc_target_addr6() -> str:
    return os.environ.get("HC_TARGET_ADDR6", "fd00:200::30")


@pytest.fixture(scope="session")
def hc_target_url() -> str:
    return os.environ.get("HC_TARGET_URL", "http://hc-target:8080")


@pytest.fixture(scope="session")
def test_client_addr() -> str:
    return os.environ.get("TEST_CLIENT_ADDR", "10.200.0.100")


@pytest.fixture(scope="session")
def test_client_addr6() -> str:
    return os.environ.get("TEST_CLIENT_ADDR6", "fd00:200::100")


# ---------------------------------------------------------------------------
# HTTP client fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def api_client(api_url) -> httpx.Client:
    """Session-scoped HTTP client pointing to the control plane API.

    Waits for the API to become healthy before yielding.
    """
    client = httpx.Client(base_url=api_url, timeout=30.0)

    # Wait for API readiness
    for _attempt in range(30):
        try:
            resp = client.get("/health")
            if resp.status_code == 200:
                break
        except httpx.ConnectError:
            pass
        time.sleep(2)
    else:
        raise RuntimeError(f"Control plane at {api_url} not ready after 60s")

    yield client
    client.close()


@pytest.fixture(scope="session")
def vip_client() -> httpx.Client:
    """Session-scoped HTTP client for sending traffic to the VIP.

    Uses a shorter timeout since traffic tests may hit connection failures
    when no backends are configured.
    """
    client = httpx.Client(timeout=5.0)
    yield client
    client.close()


@pytest.fixture(scope="session")
def hc_client(hc_target_url) -> httpx.Client:
    """Session-scoped client for querying hc-target probe capture."""
    client = httpx.Client(base_url=hc_target_url, timeout=10.0)
    for _ in range(20):
        try:
            if client.get("/health").status_code == 200:
                break
        except httpx.ConnectError:
            pass
        time.sleep(1)
    yield client
    client.close()


# ---------------------------------------------------------------------------
# Feature availability fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def hc_available(api_client) -> bool:
    """Check if HealthCheckManager is available (HC BPF program loaded)."""
    resp = api_client.get("/api/v1/hc/dst")
    return resp.status_code == 200


@pytest.fixture(scope="session")
def down_reals_available(api_client) -> bool:
    """Check if DownRealManager is available (vip_to_down_reals map loaded)."""
    resp = api_client.post(
        "/api/v1/down-reals/check",
        json={
            "vip": {"address": "10.200.0.10", "port": 80, "protocol": "tcp"},
            "real_index": 0,
        },
    )
    return resp.status_code != 500


@pytest.fixture(autouse=False)
def requires_hc(hc_available):
    """Skip test if HC is not available."""
    if not hc_available:
        pytest.skip("HealthCheckManager not available (HC BPF program not loaded)")


@pytest.fixture(autouse=False)
def requires_down_reals(down_reals_available):
    """Skip test if down reals feature is not available."""
    if not down_reals_available:
        pytest.skip("DownRealManager not available (vip_to_down_reals map not loaded)")


# ---------------------------------------------------------------------------
# Shared helpers for feature tests
# ---------------------------------------------------------------------------


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
    import time as _time

    deadline = _time.time() + timeout
    while _time.time() < deadline:
        result = fn()
        if result:
            return result
        _time.sleep(interval)
    raise TimeoutError(f"Condition not met within {timeout}s")


def parse_metric_value(
    content: str, metric_name: str, labels: dict[str, str] | None = None
) -> float | None:
    """Parse a Prometheus metric value from text format."""
    import re

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
    import socket

    family = socket.AF_INET6 if ":" in addr else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        for _ in range(count):
            sock.sendto(payload, (addr, port))
    finally:
        sock.close()
