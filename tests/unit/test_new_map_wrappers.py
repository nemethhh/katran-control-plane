"""Unit tests for new BPF map wrapper serialization."""

import struct
from ipaddress import IPv4Address, IPv6Address

from katran.core.types import HcMac, HcRealDefinition, RealDefinition, V4LpmKey, V6LpmKey


class TestLpmSrcV4MapSerialization:
    def test_serialize_key(self) -> None:
        from katran.bpf.maps.lpm_src_map import LpmSrcV4Map

        m = LpmSrcV4Map.__new__(LpmSrcV4Map)
        key = V4LpmKey(prefixlen=24, addr="10.0.0.0")
        data = m._serialize_key(key)
        assert len(data) == 8
        assert struct.unpack("<I", data[:4])[0] == 24

    def test_deserialize_key(self) -> None:
        from katran.bpf.maps.lpm_src_map import LpmSrcV4Map

        m = LpmSrcV4Map.__new__(LpmSrcV4Map)
        key = V4LpmKey(prefixlen=24, addr="10.0.0.0")
        data = m._serialize_key(key)
        restored = m._deserialize_key(data)
        assert restored == key

    def test_serialize_value(self) -> None:
        from katran.bpf.maps.lpm_src_map import LpmSrcV4Map

        m = LpmSrcV4Map.__new__(LpmSrcV4Map)
        data = m._serialize_value(42)
        assert struct.unpack("<I", data)[0] == 42


class TestLpmSrcV6MapSerialization:
    def test_serialize_key(self) -> None:
        from katran.bpf.maps.lpm_src_map import LpmSrcV6Map

        m = LpmSrcV6Map.__new__(LpmSrcV6Map)
        key = V6LpmKey(prefixlen=64, addr="2001:db8::")
        data = m._serialize_key(key)
        assert len(data) == 20

    def test_roundtrip(self) -> None:
        from katran.bpf.maps.lpm_src_map import LpmSrcV6Map

        m = LpmSrcV6Map.__new__(LpmSrcV6Map)
        key = V6LpmKey(prefixlen=48, addr="2001:db8:1::")
        assert m._deserialize_key(m._serialize_key(key)) == key


class TestDecapDstMapSerialization:
    def test_key_ipv4(self) -> None:
        from katran.bpf.maps.decap_dst_map import DecapDstMap

        m = DecapDstMap.__new__(DecapDstMap)
        data = m._serialize_key("10.0.0.1")
        assert len(data) == 16
        assert data[:4] == IPv4Address("10.0.0.1").packed
        assert data[4:] == b"\x00" * 12

    def test_key_ipv6(self) -> None:
        from katran.bpf.maps.decap_dst_map import DecapDstMap

        m = DecapDstMap.__new__(DecapDstMap)
        data = m._serialize_key("2001:db8::1")
        assert len(data) == 16
        assert data == IPv6Address("2001:db8::1").packed

    def test_value_roundtrip(self) -> None:
        from katran.bpf.maps.decap_dst_map import DecapDstMap

        m = DecapDstMap.__new__(DecapDstMap)
        data = m._serialize_value(1)
        assert m._deserialize_value(data) == 1


class TestServerIdMapSerialization:
    def test_key_roundtrip(self) -> None:
        from katran.bpf.maps.server_id_map import ServerIdMap

        m = ServerIdMap.__new__(ServerIdMap)
        data = m._serialize_key(12345)
        assert m._deserialize_key(data) == 12345

    def test_value_roundtrip(self) -> None:
        from katran.bpf.maps.server_id_map import ServerIdMap

        m = ServerIdMap.__new__(ServerIdMap)
        data = m._serialize_value(7)
        assert m._deserialize_value(data) == 7


class TestPcktSrcsMapSerialization:
    def test_key_roundtrip(self) -> None:
        from katran.bpf.maps.pckt_srcs_map import PcktSrcsMap

        m = PcktSrcsMap.__new__(PcktSrcsMap)
        data = m._serialize_key(0)
        assert m._deserialize_key(data) == 0

    def test_value_roundtrip(self) -> None:
        from katran.bpf.maps.pckt_srcs_map import PcktSrcsMap

        m = PcktSrcsMap.__new__(PcktSrcsMap)
        rd = RealDefinition(address=IPv4Address("10.0.0.1"))
        data = m._serialize_value(rd)
        restored = m._deserialize_value(data)
        assert restored.address == IPv4Address("10.0.0.1")


# =========================================================================
# Task 8: Per-CPU Stats Map Wrappers
# =========================================================================


class TestRealsStatsMapSerialization:
    def test_value_size(self) -> None:
        from katran.bpf.maps.reals_stats_map import RealsStatsMap

        m = RealsStatsMap.__new__(RealsStatsMap)
        assert m._value_size == 16

    def test_value_roundtrip(self) -> None:
        from katran.bpf.maps.reals_stats_map import RealsStatsMap
        from katran.core.types import LbStats

        m = RealsStatsMap.__new__(RealsStatsMap)
        val = LbStats(v1=42, v2=99)
        assert m._deserialize_value(m._serialize_value(val)) == val

    def test_aggregate(self) -> None:
        from katran.bpf.maps.reals_stats_map import RealsStatsMap
        from katran.core.types import LbStats

        m = RealsStatsMap.__new__(RealsStatsMap)
        values = [LbStats(v1=10, v2=20), LbStats(v1=30, v2=40)]
        agg = m._aggregate_values(values)
        assert agg.v1 == 40
        assert agg.v2 == 60


class TestLruMissStatsMapSerialization:
    def test_value_size(self) -> None:
        from katran.bpf.maps.lru_miss_stats_map import LruMissStatsMap

        m = LruMissStatsMap.__new__(LruMissStatsMap)
        assert m._value_size == 4

    def test_value_roundtrip(self) -> None:
        from katran.bpf.maps.lru_miss_stats_map import LruMissStatsMap

        m = LruMissStatsMap.__new__(LruMissStatsMap)
        assert m._deserialize_value(m._serialize_value(123)) == 123

    def test_aggregate(self) -> None:
        from katran.bpf.maps.lru_miss_stats_map import LruMissStatsMap

        m = LruMissStatsMap.__new__(LruMissStatsMap)
        assert m._aggregate_values([10, 20, 30]) == 60


class TestQuicStatsMapSerialization:
    def test_value_size(self) -> None:
        from katran.bpf.maps.quic_stats_map import QuicStatsMap

        m = QuicStatsMap.__new__(QuicStatsMap)
        assert m._value_size == 104

    def test_value_roundtrip(self) -> None:
        from katran.bpf.maps.quic_stats_map import QuicStatsMap
        from katran.core.types import QuicPacketStats

        m = QuicStatsMap.__new__(QuicStatsMap)
        val = QuicPacketStats(
            ch_routed=1, cid_initial=2, cid_routed=5, cid_v0=10, dst_match_in_lru=20
        )
        restored = m._deserialize_value(m._serialize_value(val))
        assert restored.ch_routed == 1
        assert restored.cid_routed == 5
        assert restored.dst_match_in_lru == 20

    def test_aggregate(self) -> None:
        from katran.bpf.maps.quic_stats_map import QuicStatsMap
        from katran.core.types import QuicPacketStats

        m = QuicStatsMap.__new__(QuicStatsMap)
        v1 = QuicPacketStats(ch_routed=10, cid_routed=5)
        v2 = QuicPacketStats(ch_routed=20, cid_routed=15)
        agg = m._aggregate_values([v1, v2])
        assert agg.ch_routed == 30
        assert agg.cid_routed == 20


class TestDecapVipStatsMapSerialization:
    def test_value_size(self) -> None:
        from katran.bpf.maps.decap_vip_stats_map import DecapVipStatsMap

        m = DecapVipStatsMap.__new__(DecapVipStatsMap)
        assert m._value_size == 16

    def test_value_roundtrip(self) -> None:
        from katran.bpf.maps.decap_vip_stats_map import DecapVipStatsMap
        from katran.core.types import LbStats

        m = DecapVipStatsMap.__new__(DecapVipStatsMap)
        val = LbStats(v1=100, v2=200)
        assert m._deserialize_value(m._serialize_value(val)) == val


class TestServerIdStatsMapSerialization:
    def test_value_size(self) -> None:
        from katran.bpf.maps.server_id_stats_map import ServerIdStatsMap

        m = ServerIdStatsMap.__new__(ServerIdStatsMap)
        assert m._value_size == 16

    def test_value_roundtrip(self) -> None:
        from katran.bpf.maps.server_id_stats_map import ServerIdStatsMap
        from katran.core.types import LbStats

        m = ServerIdStatsMap.__new__(ServerIdStatsMap)
        val = LbStats(v1=50, v2=75)
        assert m._deserialize_value(m._serialize_value(val)) == val


# =========================================================================
# Task 9: HC Key + Ctrl + Sources + MACs Maps
# =========================================================================


class TestHcKeyMapSerialization:
    def test_key_is_vipkey(self) -> None:
        from katran.bpf.maps.hc_key_map import HcKeyMap

        m = HcKeyMap.__new__(HcKeyMap)
        assert m._key_size == 20

    def test_value_is_u32(self) -> None:
        from katran.bpf.maps.hc_key_map import HcKeyMap

        m = HcKeyMap.__new__(HcKeyMap)
        assert m._value_size == 4


class TestHcPcktSrcsMapSerialization:
    def test_value_size(self) -> None:
        from katran.bpf.maps.hc_pckt_srcs_map import HcPcktSrcsMap

        m = HcPcktSrcsMap.__new__(HcPcktSrcsMap)
        assert m._value_size == 20


class TestHcCtrlMapSerialization:
    def test_value_roundtrip(self) -> None:
        from katran.bpf.maps.hc_ctrl_map import HcCtrlMap

        m = HcCtrlMap.__new__(HcCtrlMap)
        assert m._deserialize_value(m._serialize_value(42)) == 42


class TestHcPcktMacsSerialization:
    def test_value_roundtrip(self) -> None:
        from katran.bpf.maps.hc_pckt_macs_map import HcPcktMacsMap

        m = HcPcktMacsMap.__new__(HcPcktMacsMap)
        mac = HcMac(mac=b"\xaa\xbb\xcc\xdd\xee\xff")
        data = m._serialize_value(mac)
        restored = m._deserialize_value(data)
        assert restored.mac == mac.mac


# =========================================================================
# Task 10: HC Stats + Per-HC-Key Stats Maps
# =========================================================================


class TestHcStatsMapSerialization:
    def test_value_size(self) -> None:
        from katran.bpf.maps.hc_stats_map import HC_STATS_VALUE_SIZE, HcStatsMap

        m = HcStatsMap.__new__(HcStatsMap)
        assert m._value_size == HC_STATS_VALUE_SIZE

    def test_value_roundtrip(self) -> None:
        from katran.bpf.maps.hc_stats_map import HcStatsMap
        from katran.core.types import HealthCheckProgStats

        m = HcStatsMap.__new__(HcStatsMap)
        val = HealthCheckProgStats(
            packets_processed=10,
            packets_dropped=2,
            packets_skipped=3,
            packets_too_big=1,
            packets_dst_matched=4,
        )
        restored = m._deserialize_value(m._serialize_value(val))
        assert restored.packets_processed == 10
        assert restored.packets_dst_matched == 4


class TestPerHcKeyStatsMapSerialization:
    def test_value_is_u64(self) -> None:
        from katran.bpf.maps.per_hckey_stats_map import PerHcKeyStatsMap

        m = PerHcKeyStatsMap.__new__(PerHcKeyStatsMap)
        assert m._value_size == 8

    def test_aggregate(self) -> None:
        from katran.bpf.maps.per_hckey_stats_map import PerHcKeyStatsMap

        m = PerHcKeyStatsMap.__new__(PerHcKeyStatsMap)
        assert m._aggregate_values([10, 20, 30]) == 60


# =========================================================================
# Task 11: HcRealsMap Rewrite (u32 -> HcRealDefinition)
# =========================================================================


class TestHcRealsMapRewrite:
    def test_value_size_is_20(self) -> None:
        from katran.bpf.maps.hc_reals_map import HcRealsMap

        m = HcRealsMap.__new__(HcRealsMap)
        assert m._value_size == 20

    def test_serialize_value_ipv4(self) -> None:
        from katran.bpf.maps.hc_reals_map import HcRealsMap

        m = HcRealsMap.__new__(HcRealsMap)
        m._tunnel_based_hc = True
        hrd = HcRealDefinition(address="10.0.0.1", flags=0)
        data = m._serialize_value(hrd)
        assert len(data) == 20

    def test_roundtrip_tunnel_mode(self) -> None:
        from katran.bpf.maps.hc_reals_map import HcRealsMap

        m = HcRealsMap.__new__(HcRealsMap)
        m._tunnel_based_hc = True
        hrd = HcRealDefinition(address="10.0.0.1", flags=0)
        restored = m._deserialize_value(m._serialize_value(hrd))
        assert restored.address == "10.0.0.1"
        assert restored.flags == 0

    def test_roundtrip_direct_mode(self) -> None:
        from katran.bpf.maps.hc_reals_map import HcRealsMap

        m = HcRealsMap.__new__(HcRealsMap)
        m._tunnel_based_hc = False
        hrd = HcRealDefinition(address="10.0.0.1", flags=0)
        restored = m._deserialize_value(m._serialize_value(hrd))
        assert restored.address == "10.0.0.1"


# =========================================================================
# Task 12: Down Reals Map (HASH_OF_MAPS)
# =========================================================================


class TestDownRealsMapSerialization:
    def test_key_is_vipkey(self) -> None:
        from katran.bpf.maps.down_reals_map import VipToDownRealsMap

        m = VipToDownRealsMap.__new__(VipToDownRealsMap)
        assert m._key_size == 20

    def test_value_is_u32(self) -> None:
        from katran.bpf.maps.down_reals_map import VipToDownRealsMap

        m = VipToDownRealsMap.__new__(VipToDownRealsMap)
        assert m._value_size == 4
