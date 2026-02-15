"""
Unit tests for core data structure serialization.

Tests verify that data structures serialize/deserialize correctly
to match the BPF struct layouts defined in balancer_structs.h.
"""

import pytest
from ipaddress import IPv4Address, IPv6Address

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
    VIP_KEY_SIZE,
    VIP_META_SIZE,
    REAL_DEFINITION_SIZE,
    FLOW_KEY_SIZE,
    REAL_POS_LRU_SIZE,
    CTL_VALUE_SIZE,
    LB_STATS_SIZE,
)
from katran.core.exceptions import SerializationError


class TestVipKey:
    """Tests for VipKey serialization."""

    def test_ipv4_serialization_size(self, sample_ipv4_vip_key: VipKey) -> None:
        """IPv4 VIP key serializes to correct size."""
        data = sample_ipv4_vip_key.to_bytes()
        assert len(data) == VIP_KEY_SIZE

    def test_ipv6_serialization_size(self, sample_ipv6_vip_key: VipKey) -> None:
        """IPv6 VIP key serializes to correct size."""
        data = sample_ipv6_vip_key.to_bytes()
        assert len(data) == VIP_KEY_SIZE

    def test_ipv4_roundtrip(self, sample_ipv4_vip_key: VipKey) -> None:
        """IPv4 VIP key survives roundtrip serialization."""
        data = sample_ipv4_vip_key.to_bytes()
        restored = VipKey.from_bytes(data)
        assert restored == sample_ipv4_vip_key

    def test_ipv6_roundtrip(self, sample_ipv6_vip_key: VipKey) -> None:
        """IPv6 VIP key survives roundtrip serialization."""
        data = sample_ipv6_vip_key.to_bytes()
        restored = VipKey.from_bytes(data)
        assert restored == sample_ipv6_vip_key

    def test_ipv4_address_layout(self) -> None:
        """IPv4 address stored in first 4 bytes."""
        key = VipKey(
            address=IPv4Address("192.168.1.1"),
            port=8080,
            protocol=Protocol.UDP,
        )
        data = key.to_bytes()

        # IPv4 address should be in network byte order (big-endian)
        # 192.168.1.1 = 0xC0A80101
        assert data[0:4] == bytes([192, 168, 1, 1])

        # Bytes 4-15 should be zero (padding for IPv4)
        assert data[4:16] == b"\x00" * 12

        # Port at bytes 16-17 (network byte order / big-endian)
        assert int.from_bytes(data[16:18], "big") == 8080

        # Protocol at byte 18
        assert data[18] == Protocol.UDP.value

    def test_ipv6_address_layout(self) -> None:
        """IPv6 address stored in full 16 bytes."""
        key = VipKey(
            address=IPv6Address("2001:db8::1"),
            port=443,
            protocol=Protocol.TCP,
        )
        data = key.to_bytes()

        # IPv6 address in network byte order
        expected_addr = IPv6Address("2001:db8::1").packed
        assert data[0:16] == expected_addr

        # Port at bytes 16-17 (network byte order / big-endian)
        assert int.from_bytes(data[16:18], "big") == 443

        # Protocol at byte 18
        assert data[18] == Protocol.TCP.value

    def test_invalid_port_raises(self) -> None:
        """Invalid port raises ValueError."""
        with pytest.raises(ValueError):
            VipKey(
                address=IPv4Address("10.0.0.1"),
                port=70000,  # > 65535
                protocol=Protocol.TCP,
            )

    def test_invalid_protocol_raises(self) -> None:
        """Invalid protocol raises ValueError."""
        with pytest.raises(ValueError):
            VipKey(
                address=IPv4Address("10.0.0.1"),
                port=80,
                protocol=1,  # ICMP, not TCP/UDP
            )

    def test_from_bytes_wrong_size_raises(self) -> None:
        """Deserializing wrong size data raises error."""
        with pytest.raises(SerializationError):
            VipKey.from_bytes(b"\x00" * 10)

    def test_is_ipv6_property(self) -> None:
        """is_ipv6 property correctly identifies address type."""
        ipv4_key = VipKey(IPv4Address("10.0.0.1"), 80, Protocol.TCP)
        ipv6_key = VipKey(IPv6Address("::1"), 80, Protocol.TCP)

        assert not ipv4_key.is_ipv6
        assert ipv6_key.is_ipv6

    def test_str_representation(self) -> None:
        """String representation is human-readable."""
        key = VipKey(IPv4Address("10.200.1.1"), 80, Protocol.TCP)
        assert str(key) == "10.200.1.1:80/tcp"


class TestVipMeta:
    """Tests for VipMeta serialization."""

    def test_serialization_size(self, sample_vip_meta: VipMeta) -> None:
        """VIP meta serializes to correct size."""
        data = sample_vip_meta.to_bytes()
        assert len(data) == VIP_META_SIZE

    def test_roundtrip(self, sample_vip_meta: VipMeta) -> None:
        """VIP meta survives roundtrip serialization."""
        data = sample_vip_meta.to_bytes()
        restored = VipMeta.from_bytes(data)
        assert restored.flags == sample_vip_meta.flags
        assert restored.vip_num == sample_vip_meta.vip_num

    def test_flags_preserved(self) -> None:
        """Multiple flags are preserved."""
        flags = VipFlags.NO_SRC_PORT | VipFlags.NO_LRU | VipFlags.QUIC_VIP
        meta = VipMeta(flags=flags, vip_num=123)

        data = meta.to_bytes()
        restored = VipMeta.from_bytes(data)

        assert restored.flags == flags
        assert VipFlags.NO_SRC_PORT in restored.flags
        assert VipFlags.NO_LRU in restored.flags
        assert VipFlags.QUIC_VIP in restored.flags

    def test_layout(self) -> None:
        """Verify memory layout matches BPF struct."""
        meta = VipMeta(flags=VipFlags(0x0F), vip_num=256)
        data = meta.to_bytes()

        # flags at bytes 0-3 (little-endian)
        assert int.from_bytes(data[0:4], "little") == 0x0F

        # vip_num at bytes 4-7 (little-endian)
        assert int.from_bytes(data[4:8], "little") == 256


class TestRealDefinition:
    """Tests for RealDefinition serialization."""

    def test_ipv4_serialization_size(self, sample_ipv4_real_definition: RealDefinition) -> None:
        """IPv4 real definition serializes to correct size."""
        data = sample_ipv4_real_definition.to_bytes()
        assert len(data) == REAL_DEFINITION_SIZE

    def test_ipv6_serialization_size(self, sample_ipv6_real_definition: RealDefinition) -> None:
        """IPv6 real definition serializes to correct size."""
        data = sample_ipv6_real_definition.to_bytes()
        assert len(data) == REAL_DEFINITION_SIZE

    def test_ipv4_roundtrip(self, sample_ipv4_real_definition: RealDefinition) -> None:
        """IPv4 real definition survives roundtrip."""
        data = sample_ipv4_real_definition.to_bytes()
        restored = RealDefinition.from_bytes(data)
        assert restored.address == sample_ipv4_real_definition.address

    def test_ipv6_roundtrip(self, sample_ipv6_real_definition: RealDefinition) -> None:
        """IPv6 real definition survives roundtrip."""
        data = sample_ipv6_real_definition.to_bytes()
        restored = RealDefinition.from_bytes(data)
        assert restored.address == sample_ipv6_real_definition.address
        assert restored.flags == sample_ipv6_real_definition.flags

    def test_ipv6_flag_auto_set(self) -> None:
        """IPv6 flag is automatically set for IPv6 addresses."""
        real = RealDefinition(address=IPv6Address("::1"))
        assert RealFlags.IPV6 in real.flags

    def test_layout(self) -> None:
        """Verify memory layout matches BPF struct."""
        real = RealDefinition(
            address=IPv4Address("10.0.0.100"),
            flags=RealFlags.LOCAL_REAL,
        )
        data = real.to_bytes()

        # Address in first 4 bytes (IPv4)
        assert data[0:4] == bytes([10, 0, 0, 100])

        # Padding (bytes 4-15)
        assert data[4:16] == b"\x00" * 12

        # Flags at byte 16
        assert data[16] == RealFlags.LOCAL_REAL.value


class TestFlowKey:
    """Tests for FlowKey serialization."""

    def test_ipv4_serialization_size(self, sample_ipv4_flow_key: FlowKey) -> None:
        """IPv4 flow key serializes to correct size."""
        data = sample_ipv4_flow_key.to_bytes()
        assert len(data) == FLOW_KEY_SIZE

    def test_ipv6_serialization_size(self, sample_ipv6_flow_key: FlowKey) -> None:
        """IPv6 flow key serializes to correct size."""
        data = sample_ipv6_flow_key.to_bytes()
        assert len(data) == FLOW_KEY_SIZE

    def test_ipv4_roundtrip(self, sample_ipv4_flow_key: FlowKey) -> None:
        """IPv4 flow key survives roundtrip."""
        data = sample_ipv4_flow_key.to_bytes()
        restored = FlowKey.from_bytes(data)
        assert restored == sample_ipv4_flow_key

    def test_ipv6_roundtrip(self, sample_ipv6_flow_key: FlowKey) -> None:
        """IPv6 flow key survives roundtrip."""
        data = sample_ipv6_flow_key.to_bytes()
        restored = FlowKey.from_bytes(data)
        assert restored == sample_ipv6_flow_key

    def test_layout(self) -> None:
        """Verify memory layout matches BPF struct."""
        flow = FlowKey(
            src_addr=IPv4Address("192.168.1.1"),
            dst_addr=IPv4Address("10.0.0.1"),
            src_port=12345,
            dst_port=80,
            protocol=Protocol.TCP,
        )
        data = flow.to_bytes()

        # Source address (bytes 0-3 for IPv4)
        assert data[0:4] == bytes([192, 168, 1, 1])

        # Dest address (bytes 16-19 for IPv4)
        assert data[16:20] == bytes([10, 0, 0, 1])

        # Ports (bytes 32-35, network byte order / big-endian)
        src_port = int.from_bytes(data[32:34], "big")
        dst_port = int.from_bytes(data[34:36], "big")
        assert src_port == 12345
        assert dst_port == 80

        # Protocol (byte 36)
        assert data[36] == Protocol.TCP.value


class TestRealPosLru:
    """Tests for RealPosLru serialization."""

    def test_serialization_size(self, sample_real_pos_lru: RealPosLru) -> None:
        """RealPosLru serializes to correct size."""
        data = sample_real_pos_lru.to_bytes()
        assert len(data) == REAL_POS_LRU_SIZE

    def test_roundtrip(self, sample_real_pos_lru: RealPosLru) -> None:
        """RealPosLru survives roundtrip."""
        data = sample_real_pos_lru.to_bytes()
        restored = RealPosLru.from_bytes(data)
        assert restored.pos == sample_real_pos_lru.pos
        assert restored.atime == sample_real_pos_lru.atime

    def test_layout(self) -> None:
        """Verify memory layout matches BPF struct."""
        lru = RealPosLru(pos=42, atime=1000000000)
        data = lru.to_bytes()

        # pos at bytes 0-3
        assert int.from_bytes(data[0:4], "little") == 42

        # padding at bytes 4-7
        assert data[4:8] == b"\x00" * 4

        # atime at bytes 8-15
        assert int.from_bytes(data[8:16], "little") == 1000000000


class TestCtlValue:
    """Tests for CtlValue serialization."""

    def test_serialization_size(self) -> None:
        """CtlValue serializes to correct size."""
        value = CtlValue(value=b"\x00" * 8)
        data = value.to_bytes()
        assert len(data) == CTL_VALUE_SIZE

    def test_from_mac(self) -> None:
        """MAC address creation and retrieval."""
        mac_str = "aa:bb:cc:dd:ee:ff"
        value = CtlValue.from_mac(mac_str)

        assert value.as_mac() == mac_str

        # Verify bytes
        expected = bytes.fromhex("aabbccddeeff")
        assert value.value[:6] == expected

    def test_from_ifindex(self) -> None:
        """Interface index creation and retrieval."""
        value = CtlValue.from_ifindex(42)
        assert value.as_ifindex() == 42

    def test_from_u64(self) -> None:
        """64-bit value creation and retrieval."""
        big_value = 0x123456789ABCDEF0
        value = CtlValue.from_u64(big_value)
        assert value.as_u64() == big_value

    def test_padding(self) -> None:
        """Short values are padded to 8 bytes."""
        value = CtlValue(value=b"\x01\x02")
        assert len(value.value) == 8
        assert value.value[:2] == b"\x01\x02"
        assert value.value[2:] == b"\x00" * 6


class TestLbStats:
    """Tests for LbStats serialization."""

    def test_serialization_size(self, sample_lb_stats: LbStats) -> None:
        """LbStats serializes to correct size."""
        data = sample_lb_stats.to_bytes()
        assert len(data) == LB_STATS_SIZE

    def test_roundtrip(self, sample_lb_stats: LbStats) -> None:
        """LbStats survives roundtrip."""
        data = sample_lb_stats.to_bytes()
        restored = LbStats.from_bytes(data)
        assert restored.v1 == sample_lb_stats.v1
        assert restored.v2 == sample_lb_stats.v2

    def test_addition(self) -> None:
        """Stats can be added together."""
        stats1 = LbStats(v1=100, v2=200)
        stats2 = LbStats(v1=50, v2=150)

        combined = stats1 + stats2
        assert combined.v1 == 150
        assert combined.v2 == 350

    def test_aggregate(self) -> None:
        """Stats list can be aggregated."""
        stats_list = [
            LbStats(v1=100, v2=1000),
            LbStats(v1=200, v2=2000),
            LbStats(v1=300, v2=3000),
        ]

        aggregated = LbStats.aggregate(stats_list)
        assert aggregated.v1 == 600
        assert aggregated.v2 == 6000

    def test_properties(self) -> None:
        """packets and bytes properties work."""
        stats = LbStats(v1=1000, v2=15000)
        assert stats.packets == 1000
        assert stats.bytes == 15000


class TestVip:
    """Tests for Vip high-level type."""

    def test_create_ipv4(self) -> None:
        """Create VIP with IPv4 address string."""
        vip = Vip.create("10.200.1.1", 80, "tcp")
        assert vip.address == IPv4Address("10.200.1.1")
        assert vip.port == 80
        assert vip.protocol == Protocol.TCP

    def test_create_ipv6(self) -> None:
        """Create VIP with IPv6 address string."""
        vip = Vip.create("2001:db8::1", 443, Protocol.TCP)
        assert vip.address == IPv6Address("2001:db8::1")
        assert vip.port == 443

    def test_is_allocated(self) -> None:
        """is_allocated reflects vip_num state."""
        vip = Vip.create("10.0.0.1", 80, "tcp")
        assert not vip.is_allocated

        vip.vip_num = 0
        assert vip.is_allocated

    def test_active_reals(self) -> None:
        """active_reals filters out drained backends."""
        vip = Vip.create("10.0.0.1", 80, "tcp")
        vip.reals = [
            Real(address=IPv4Address("10.0.0.100"), weight=100, index=1),
            Real(address=IPv4Address("10.0.0.101"), weight=0, index=2),  # Drained
            Real(address=IPv4Address("10.0.0.102"), weight=50, index=3),
        ]

        active = vip.active_reals
        assert len(active) == 2
        assert all(r.weight > 0 for r in active)

    def test_to_vip_meta(self) -> None:
        """Converts to VipMeta for BPF storage."""
        vip = Vip.create("10.0.0.1", 80, "tcp", flags=VipFlags.NO_LRU)
        vip.vip_num = 42

        meta = vip.to_vip_meta()
        assert meta.flags == VipFlags.NO_LRU
        assert meta.vip_num == 42


class TestReal:
    """Tests for Real high-level type."""

    def test_is_allocated(self) -> None:
        """is_allocated reflects index state."""
        real = Real(address=IPv4Address("10.0.0.100"), index=-1)
        assert not real.is_allocated

        real.index = 1
        assert real.is_allocated

    def test_is_drained(self) -> None:
        """is_drained reflects weight state."""
        real = Real(address=IPv4Address("10.0.0.100"), weight=100)
        assert not real.is_drained

        real.weight = 0
        assert real.is_drained

    def test_to_real_definition(self) -> None:
        """Converts to RealDefinition for BPF storage."""
        real = Real(
            address=IPv4Address("10.0.0.100"),
            weight=100,
            index=5,
            flags=RealFlags.LOCAL_REAL,
        )

        real_def = real.to_real_definition()
        assert real_def.address == real.address
        assert real_def.flags == real.flags
