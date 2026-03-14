"""Unit tests for new BPF map wrapper serialization."""

import struct
from ipaddress import IPv4Address, IPv6Address

import pytest

from katran.core.types import V4LpmKey, V6LpmKey, RealDefinition, HcRealDefinition, HcMac


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
