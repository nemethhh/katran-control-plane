"""Unit tests for HealthCheckManager."""

from ipaddress import IPv4Address
from unittest.mock import MagicMock

import pytest

from katran.core.constants import Protocol
from katran.core.exceptions import HealthCheckError
from katran.core.types import VipKey


class TestHealthCheckManager:
    @pytest.fixture
    def mocks(self):
        return {
            "hc_reals_map": MagicMock(),
            "hc_key_map": MagicMock(),
            "hc_ctrl_map": MagicMock(),
            "hc_pckt_srcs_map": MagicMock(),
            "hc_pckt_macs": MagicMock(),
            "hc_stats_map": MagicMock(),
            "per_hckey_stats": MagicMock(),
        }

    @pytest.fixture
    def manager(self, mocks):
        from katran.lb.hc_manager import HealthCheckManager

        return HealthCheckManager(**mocks, max_vips=512, tunnel_based_hc=True)

    def test_add_hc_dst(self, manager, mocks):
        manager.add_hc_dst(1000, "10.0.0.1")
        mocks["hc_reals_map"].set.assert_called_once()
        assert manager.get_hc_dsts() == {1000: "10.0.0.1"}

    def test_del_hc_dst(self, manager, mocks):
        manager.add_hc_dst(1000, "10.0.0.1")
        manager.del_hc_dst(1000)
        mocks["hc_reals_map"].delete.assert_called_once()

    def test_del_hc_dst_not_found(self, manager):
        with pytest.raises(HealthCheckError):
            manager.del_hc_dst(9999)

    def test_add_hc_key(self, manager, mocks):
        key = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        idx = manager.add_hc_key(key)
        assert idx >= 0
        mocks["hc_key_map"].set.assert_called_once()

    def test_del_hc_key(self, manager, mocks):
        key = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        manager.add_hc_key(key)
        manager.del_hc_key(key)
        mocks["hc_key_map"].delete.assert_called_once()

    def test_set_hc_interface(self, manager, mocks):
        manager.set_hc_interface(42)
        mocks["hc_ctrl_map"].set.assert_called_once()

    def test_set_hc_src_mac(self, manager, mocks):
        manager.set_hc_src_mac("aa:bb:cc:dd:ee:ff")
        mocks["hc_pckt_macs"].set.assert_called_once()

    def test_add_hc_key_duplicate(self, manager):
        key = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        manager.add_hc_key(key)
        with pytest.raises(HealthCheckError, match="already exists"):
            manager.add_hc_key(key)

    def test_get_stats(self, manager, mocks):
        from katran.core.types import HealthCheckProgStats

        mocks["hc_stats_map"].get = MagicMock(
            return_value=HealthCheckProgStats(packets_processed=42)
        )
        stats = manager.get_stats()
        assert stats.packets_processed == 42

    def test_get_stats_returns_default_when_none(self, manager, mocks):
        mocks["hc_stats_map"].get = MagicMock(return_value=None)
        stats = manager.get_stats()
        assert stats.packets_processed == 0

    def test_get_packets_for_hc_key(self, manager, mocks):
        key = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        manager.add_hc_key(key)
        mocks["per_hckey_stats"].get = MagicMock(return_value=100)
        assert manager.get_packets_for_hc_key(key) == 100

    def test_get_packets_for_hc_key_not_found(self, manager):
        key = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        with pytest.raises(HealthCheckError, match="HC key not found"):
            manager.get_packets_for_hc_key(key)

    def test_get_packets_for_hc_key_returns_zero_when_none(self, manager, mocks):
        key = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        manager.add_hc_key(key)
        mocks["per_hckey_stats"].get = MagicMock(return_value=None)
        assert manager.get_packets_for_hc_key(key) == 0

    def test_set_hc_src_ip_v4(self, manager, mocks):
        manager.set_hc_src_ip("10.0.0.1")
        mocks["hc_pckt_srcs_map"].set.assert_called_once()

    def test_set_hc_src_ip_v6(self, manager, mocks):
        manager.set_hc_src_ip("::1")
        mocks["hc_pckt_srcs_map"].set.assert_called_once()

    def test_set_hc_dst_mac(self, manager, mocks):
        manager.set_hc_dst_mac("aa:bb:cc:dd:ee:ff")
        mocks["hc_pckt_macs"].set.assert_called_once()

    def test_get_hc_keys_empty(self, manager):
        assert manager.get_hc_keys() == {}

    def test_get_hc_keys_populated(self, manager):
        k1 = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        k2 = VipKey(address=IPv4Address("10.0.0.2"), port=443, protocol=Protocol.TCP)
        idx1 = manager.add_hc_key(k1)
        idx2 = manager.add_hc_key(k2)
        keys = manager.get_hc_keys()
        assert keys == {k1: idx1, k2: idx2}

    def test_del_hc_key_not_found(self, manager):
        key = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        with pytest.raises(HealthCheckError, match="HC key not found"):
            manager.del_hc_key(key)

    def test_add_hc_dst_ipv6(self, manager, mocks):
        manager.add_hc_dst(2000, "::1")
        mocks["hc_reals_map"].set.assert_called_once()
        assert manager.get_hc_dsts() == {2000: "::1"}

    def test_hc_dst_byte_order_tunnel(self):
        from katran.lb.hc_manager import HealthCheckManager

        mocks = {
            k: MagicMock()
            for k in [
                "hc_reals_map",
                "hc_key_map",
                "hc_ctrl_map",
                "hc_pckt_srcs_map",
                "hc_pckt_macs",
                "hc_stats_map",
                "per_hckey_stats",
            ]
        }
        mgr = HealthCheckManager(**mocks, tunnel_based_hc=True)
        mgr.add_hc_dst(1000, "10.0.0.1")
        mocks["hc_reals_map"].set.assert_called_once()
