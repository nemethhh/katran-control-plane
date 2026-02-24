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
import time

import httpx
import pytest


def pytest_collection_modifyitems(config, items):
    """Skip all E2E tests when not running inside the E2E environment."""
    if os.environ.get("KATRAN_E2E") != "1":
        skip = pytest.mark.skip(reason="KATRAN_E2E not set (run via run-e2e.sh)")
        for item in items:
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
    for attempt in range(30):
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
