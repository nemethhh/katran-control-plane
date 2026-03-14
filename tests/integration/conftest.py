"""
Pytest configuration and fixtures for integration tests.

These tests require:
- Root/CAP_BPF privileges
- BPF filesystem mounted at /sys/fs/bpf
- Katran BPF programs loaded via xdp-loader
- Maps pinned at /sys/fs/bpf/katran

Run with: ./tests/integration/run-tests.sh
Or: docker compose -f docker-compose.test.yml run katran-target pytest tests/integration/
"""

import os
from ipaddress import IPv4Address
from pathlib import Path
from typing import Generator

import pytest

from katran.core.constants import Protocol, RealFlags, VipFlags
from katran.core.types import Real, RealDefinition, Vip, VipKey, VipMeta

# Environment configuration
BPF_PATH = Path(os.environ.get("KATRAN_BPF_PATH", "/app/katran-bpfs"))
PIN_PATH = Path(os.environ.get("KATRAN_PIN_PATH", "/sys/fs/bpf/katran"))
INTERFACE = os.environ.get("KATRAN_INTERFACE", "eth0")

# BPF program files
BALANCER_BPF = BPF_PATH / "balancer.bpf.o"


def is_root() -> bool:
    """Check if running as root."""
    return os.geteuid() == 0


def has_bpf_fs() -> bool:
    """Check if BPF filesystem is mounted."""
    return Path("/sys/fs/bpf").exists()


def has_pinned_maps() -> bool:
    """Check if Katran maps are pinned."""
    return PIN_PATH.exists() and any(PIN_PATH.iterdir())


def get_pinned_map_names() -> list[str]:
    """Get list of pinned map names."""
    if not PIN_PATH.exists():
        return []
    return [p.name for p in PIN_PATH.iterdir() if p.is_file()]


def skip_if_no_bpf_env() -> None:
    """Skip test if BPF environment is not available."""
    if not is_root():
        pytest.skip("Integration tests require root privileges")
    if not has_bpf_fs():
        pytest.skip("BPF filesystem not mounted at /sys/fs/bpf")
    if not has_pinned_maps():
        pytest.skip(f"No BPF maps pinned at {PIN_PATH} - load XDP program first")


@pytest.fixture(scope="session")
def bpf_environment() -> Generator[dict, None, None]:
    """
    Session-scoped fixture that validates BPF environment.

    Returns dict with environment info.
    """
    skip_if_no_bpf_env()

    pinned_maps = get_pinned_map_names()

    yield {
        "bpf_path": BPF_PATH,
        "pin_path": PIN_PATH,
        "interface": INTERFACE,
        "balancer_bpf": BALANCER_BPF,
        "pinned_maps": pinned_maps,
    }


@pytest.fixture(scope="session")
def pin_path(bpf_environment: dict) -> Path:
    """Fixture providing the BPF pin path."""
    return bpf_environment["pin_path"]


@pytest.fixture(scope="session")
def pinned_map_names(bpf_environment: dict) -> list[str]:
    """List of pinned map names."""
    return bpf_environment["pinned_maps"]


# =============================================================================
# Test Data Fixtures
# =============================================================================


@pytest.fixture
def test_vip_ipv4() -> Vip:
    """Test VIP for integration tests."""
    return Vip.create(
        address="10.200.1.1",
        port=80,
        protocol=Protocol.TCP,
        flags=VipFlags(0),
    )


@pytest.fixture
def test_vip_ipv6() -> Vip:
    """Test IPv6 VIP for integration tests."""
    return Vip.create(
        address="2001:db8::1",
        port=443,
        protocol=Protocol.TCP,
        flags=VipFlags(0),
    )


@pytest.fixture
def test_backends() -> list[Real]:
    """Test backend servers."""
    return [
        Real(address=IPv4Address("10.0.0.100"), weight=100),
        Real(address=IPv4Address("10.0.0.101"), weight=100),
        Real(address=IPv4Address("10.0.0.102"), weight=50),
    ]


@pytest.fixture
def test_vip_key() -> VipKey:
    """Test VIP key."""
    return VipKey(
        address=IPv4Address("10.200.1.1"),
        port=80,
        protocol=Protocol.TCP,
    )


@pytest.fixture
def test_vip_meta() -> VipMeta:
    """Test VIP metadata."""
    return VipMeta(flags=VipFlags(0), vip_num=0)


@pytest.fixture
def test_real_definition() -> RealDefinition:
    """Test backend definition."""
    return RealDefinition(
        address=IPv4Address("10.0.0.100"),
        flags=RealFlags(0),
    )


# =============================================================================
# Test Reporting Hooks
# =============================================================================


def pytest_runtest_setup(item):
    """Hook called before each test."""
    print(f"\n{'=' * 70}")
    print(f"SETUP: {item.nodeid}")
    print(f"{'=' * 70}")


def pytest_runtest_teardown(item, nextitem):
    """Hook called after each test."""
    print(f"\n{'=' * 70}")
    print(f"TEARDOWN: {item.nodeid}")
    print(f"{'=' * 70}")


def pytest_runtest_makereport(item, call):
    """Hook to customize test report."""
    if call.when == "call":
        import sys

        sys.stdout.flush()
        sys.stderr.flush()
