"""
Pytest configuration and fixtures for Katran control plane tests.
"""

import pytest
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
import tempfile
import os

from katran.core.constants import Protocol, VipFlags, RealFlags
from katran.core.types import (
    VipKey,
    VipMeta,
    RealDefinition,
    FlowKey,
    RealPosLru,
    CtlValue,
    LbStats,
    Vip,
    Real,
)


# =============================================================================
# Sample Data Fixtures
# =============================================================================


@pytest.fixture
def sample_ipv4_vip_key() -> VipKey:
    """Sample IPv4 VIP key."""
    return VipKey(
        address=IPv4Address("10.200.1.1"),
        port=80,
        protocol=Protocol.TCP,
    )


@pytest.fixture
def sample_ipv6_vip_key() -> VipKey:
    """Sample IPv6 VIP key."""
    return VipKey(
        address=IPv6Address("2001:db8::1"),
        port=443,
        protocol=Protocol.TCP,
    )


@pytest.fixture
def sample_vip_meta() -> VipMeta:
    """Sample VIP metadata."""
    return VipMeta(
        flags=VipFlags.NO_SRC_PORT | VipFlags.QUIC_VIP,
        vip_num=42,
    )


@pytest.fixture
def sample_ipv4_real_definition() -> RealDefinition:
    """Sample IPv4 backend definition."""
    return RealDefinition(
        address=IPv4Address("10.0.0.100"),
        flags=RealFlags.NONE,
    )


@pytest.fixture
def sample_ipv6_real_definition() -> RealDefinition:
    """Sample IPv6 backend definition."""
    return RealDefinition(
        address=IPv6Address("2001:db8:1::100"),
        flags=RealFlags.IPV6,
    )


@pytest.fixture
def sample_ipv4_flow_key() -> FlowKey:
    """Sample IPv4 5-tuple flow key."""
    return FlowKey(
        src_addr=IPv4Address("192.168.1.100"),
        dst_addr=IPv4Address("10.200.1.1"),
        src_port=54321,
        dst_port=80,
        protocol=Protocol.TCP,
    )


@pytest.fixture
def sample_ipv6_flow_key() -> FlowKey:
    """Sample IPv6 5-tuple flow key."""
    return FlowKey(
        src_addr=IPv6Address("2001:db8:1::100"),
        dst_addr=IPv6Address("2001:db8:2::1"),
        src_port=54321,
        dst_port=443,
        protocol=Protocol.TCP,
    )


@pytest.fixture
def sample_real_pos_lru() -> RealPosLru:
    """Sample LRU cache entry."""
    return RealPosLru(
        pos=5,
        atime=1234567890000000000,  # Nanoseconds
    )


@pytest.fixture
def sample_lb_stats() -> LbStats:
    """Sample statistics."""
    return LbStats(
        v1=1000000,  # packets
        v2=1500000000,  # bytes
    )


@pytest.fixture
def sample_vip(sample_ipv4_vip_key: VipKey) -> Vip:
    """Sample VIP."""
    return Vip(
        key=sample_ipv4_vip_key,
        flags=VipFlags.NONE,
        vip_num=0,
    )


@pytest.fixture
def sample_real() -> Real:
    """Sample backend server."""
    return Real(
        address=IPv4Address("10.0.0.100"),
        weight=100,
        index=1,
        flags=RealFlags.NONE,
    )


# =============================================================================
# Directory Fixtures
# =============================================================================


@pytest.fixture
def temp_pin_path() -> Path:
    """Temporary directory for mock BPF map pins."""
    with tempfile.TemporaryDirectory(prefix="katran_test_") as tmpdir:
        yield Path(tmpdir)


# =============================================================================
# Mock BPF Map Fixtures
# =============================================================================


class MockBpfMap:
    """Mock BPF map for testing without actual BPF syscalls."""

    def __init__(self, key_size: int, value_size: int) -> None:
        self.key_size = key_size
        self.value_size = value_size
        self._data: dict[bytes, bytes] = {}
        self._fd = 1000  # Fake fd

    def lookup(self, key: bytes) -> bytes | None:
        return self._data.get(key)

    def update(self, key: bytes, value: bytes) -> None:
        self._data[key] = value

    def delete(self, key: bytes) -> bool:
        if key in self._data:
            del self._data[key]
            return True
        return False

    def items(self):
        return list(self._data.items())


@pytest.fixture
def mock_vip_map() -> MockBpfMap:
    """Mock VIP map."""
    return MockBpfMap(key_size=20, value_size=8)


@pytest.fixture
def mock_reals_map() -> MockBpfMap:
    """Mock reals map."""
    return MockBpfMap(key_size=4, value_size=20)


@pytest.fixture
def mock_ch_rings_map() -> MockBpfMap:
    """Mock consistent hash rings map."""
    return MockBpfMap(key_size=4, value_size=4)


@pytest.fixture
def mock_stats_map() -> MockBpfMap:
    """Mock statistics map."""
    return MockBpfMap(key_size=4, value_size=16)


# =============================================================================
# Manager Fixtures (for Phase 2 unit tests)
# =============================================================================

from unittest.mock import Mock, MagicMock
from katran.lb.maglev import MaglevHashRing
from katran.lb.vip_manager import VipManager
from katran.lb.real_manager import RealManager


@pytest.fixture
def mock_vip_map():
    """Mock VipMap for unit testing."""
    mock = MagicMock()
    mock.add_vip = MagicMock()
    mock.remove_vip = MagicMock(return_value=True)
    mock.set = MagicMock()
    mock.get = MagicMock(return_value=None)
    mock.items = MagicMock(return_value=[])
    return mock


@pytest.fixture
def mock_reals_map():
    """Mock RealsMap for unit testing."""
    mock = MagicMock()
    mock.allocate_index = MagicMock(side_effect=lambda: mock.allocate_index.call_count)
    mock.free_index = MagicMock()
    mock.set = MagicMock()
    mock.get = MagicMock(return_value=None)
    return mock


@pytest.fixture
def mock_ch_rings_map():
    """Mock ChRingsMap for unit testing."""
    mock = MagicMock()
    mock.ring_size = 65537
    mock.write_ring = MagicMock()
    mock.read_ring = MagicMock(return_value=[])
    return mock


@pytest.fixture
def mock_ring_builder():
    """Mock MaglevHashRing for unit testing."""
    mock = MagicMock(spec=MaglevHashRing)
    mock.ring_size = 65537
    mock.build = MagicMock(return_value=[1] * 65537)
    mock.rebuild = MagicMock(return_value=([1] * 65537, {}))
    return mock


@pytest.fixture
def vip_manager(mock_vip_map, mock_ch_rings_map):
    """VipManager instance with mocked maps."""
    return VipManager(mock_vip_map, mock_ch_rings_map, max_vips=512)


@pytest.fixture
def real_manager(mock_reals_map, mock_ch_rings_map):
    """RealManager instance with mocked maps."""
    return RealManager(mock_reals_map, mock_ch_rings_map, max_reals=4096)
