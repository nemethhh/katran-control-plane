"""Unit tests for LruManager."""

import time
from ipaddress import IPv4Address
from unittest.mock import MagicMock, patch

import pytest

from katran.core.constants import Protocol
from katran.core.types import FlowKey, RealPosLru, VipKey


class TestLruManager:
    @pytest.fixture
    def mock_lru(self):
        mock = MagicMock()
        mock.items = MagicMock(return_value=[])
        return mock

    @pytest.fixture
    def manager(self, mock_lru):
        from katran.lb.lru_manager import LruManager

        return LruManager(fallback_lru=mock_lru)

    def test_search_no_match(self, manager):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        result = manager.search(vip, "192.168.1.1", 12345)
        assert len(result.entries) == 0

    def test_search_with_match(self, manager, mock_lru):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        flow = FlowKey(
            src_addr=IPv4Address("192.168.1.1"),
            dst_addr=IPv4Address("10.0.0.1"),
            src_port=12345,
            dst_port=80,
            protocol=Protocol.TCP,
        )
        mock_lru.items.return_value = [(flow, RealPosLru(pos=5, atime=100))]
        result = manager.search(vip, "192.168.1.1", 12345)
        assert len(result.entries) == 1
        assert result.entries[0].real_index == 5

    def test_search_no_match_wrong_src(self, manager, mock_lru):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        flow = FlowKey(
            src_addr=IPv4Address("192.168.1.99"),
            dst_addr=IPv4Address("10.0.0.1"),
            src_port=12345,
            dst_port=80,
            protocol=Protocol.TCP,
        )
        mock_lru.items.return_value = [(flow, RealPosLru(pos=5, atime=100))]
        result = manager.search(vip, "192.168.1.1", 12345)
        assert len(result.entries) == 0

    def test_list_with_limit(self, manager, mock_lru):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        flows = [
            (
                FlowKey(
                    src_addr=IPv4Address(f"192.168.1.{i}"),
                    dst_addr=IPv4Address("10.0.0.1"),
                    src_port=i,
                    dst_port=80,
                    protocol=Protocol.TCP,
                ),
                RealPosLru(pos=1, atime=0),
            )
            for i in range(10)
        ]
        mock_lru.items.return_value = flows
        result = manager.list(vip, limit=3)
        assert len(result.entries) == 3

    def test_list_returns_all_when_under_limit(self, manager, mock_lru):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        flows = [
            (
                FlowKey(
                    src_addr=IPv4Address(f"192.168.1.{i}"),
                    dst_addr=IPv4Address("10.0.0.1"),
                    src_port=i,
                    dst_port=80,
                    protocol=Protocol.TCP,
                ),
                RealPosLru(pos=1, atime=0),
            )
            for i in range(2)
        ]
        mock_lru.items.return_value = flows
        result = manager.list(vip, limit=100)
        assert len(result.entries) == 2

    def test_delete(self, manager, mock_lru):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        flow = FlowKey(
            src_addr=IPv4Address("192.168.1.1"),
            dst_addr=IPv4Address("10.0.0.1"),
            src_port=12345,
            dst_port=80,
            protocol=Protocol.TCP,
        )
        mock_lru.items.return_value = [(flow, RealPosLru(pos=5, atime=0))]
        mock_lru.delete.return_value = True
        result = manager.delete(vip, "192.168.1.1", 12345)
        assert len(result) == 1

    def test_purge_vip(self, manager, mock_lru):
        vip_key = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        flow = FlowKey(
            src_addr=IPv4Address("192.168.1.1"),
            dst_addr=IPv4Address("10.0.0.1"),
            src_port=12345,
            dst_port=80,
            protocol=Protocol.TCP,
        )
        mock_lru.items.return_value = [(flow, RealPosLru(pos=5, atime=0))]
        mock_lru.delete.return_value = True
        result = manager.purge_vip(vip_key)
        assert result.deleted_count == 1

    def test_purge_vip_no_match(self, manager, mock_lru):
        vip_key = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        flow = FlowKey(
            src_addr=IPv4Address("192.168.1.1"),
            dst_addr=IPv4Address("10.0.0.99"),
            src_port=12345,
            dst_port=80,
            protocol=Protocol.TCP,
        )
        mock_lru.items.return_value = [(flow, RealPosLru(pos=5, atime=0))]
        result = manager.purge_vip(vip_key)
        assert result.deleted_count == 0

    def test_purge_vip_for_real(self, manager, mock_lru):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        flow1 = FlowKey(
            src_addr=IPv4Address("192.168.1.1"),
            dst_addr=IPv4Address("10.0.0.1"),
            src_port=100,
            dst_port=80,
            protocol=Protocol.TCP,
        )
        flow2 = FlowKey(
            src_addr=IPv4Address("192.168.1.2"),
            dst_addr=IPv4Address("10.0.0.1"),
            src_port=200,
            dst_port=80,
            protocol=Protocol.TCP,
        )
        mock_lru.items.return_value = [
            (flow1, RealPosLru(pos=5, atime=0)),
            (flow2, RealPosLru(pos=7, atime=0)),
        ]
        mock_lru.delete.return_value = True
        result = manager.purge_vip_for_real(vip, 5)
        assert result.deleted_count == 1

    def test_analyze_empty(self, manager):
        result = manager.analyze()
        assert result.total_entries == 0
        assert len(result.per_vip) == 0

    def test_analyze_with_entries(self, manager, mock_lru):
        flow = FlowKey(
            src_addr=IPv4Address("192.168.1.1"),
            dst_addr=IPv4Address("10.0.0.1"),
            src_port=100,
            dst_port=80,
            protocol=Protocol.TCP,
        )
        mock_lru.items.return_value = [(flow, RealPosLru(pos=5, atime=0))]
        result = manager.analyze()
        assert result.total_entries == 1
        assert len(result.per_vip) == 1

    def test_analyze_atime_buckets(self, manager, mock_lru):
        now_ns = time.time_ns()
        flow1 = FlowKey(
            src_addr=IPv4Address("192.168.1.1"),
            dst_addr=IPv4Address("10.0.0.1"),
            src_port=100,
            dst_port=80,
            protocol=Protocol.TCP,
        )
        flow2 = FlowKey(
            src_addr=IPv4Address("192.168.1.2"),
            dst_addr=IPv4Address("10.0.0.1"),
            src_port=200,
            dst_port=80,
            protocol=Protocol.TCP,
        )
        flow3 = FlowKey(
            src_addr=IPv4Address("192.168.1.3"),
            dst_addr=IPv4Address("10.0.0.1"),
            src_port=300,
            dst_port=80,
            protocol=Protocol.TCP,
        )
        mock_lru.items.return_value = [
            (flow1, RealPosLru(pos=1, atime=0)),  # atime_zero_count
            (flow2, RealPosLru(pos=2, atime=now_ns - 5_000_000_000)),  # <30s
            (flow3, RealPosLru(pos=3, atime=now_ns - 45_000_000_000)),  # 30-60s
        ]
        result = manager.analyze()
        assert result.total_entries == 3
        vip_key = f"10.0.0.1:80/{Protocol.TCP}"
        stats = result.per_vip[vip_key]
        assert stats.atime_zero_count == 1
        assert stats.atime_under_30s_count == 1
        assert stats.atime_30_to_60s_count == 1

    def test_per_cpu_iteration_concatenates(self, mock_lru):
        from katran.lb.lru_manager import LruManager

        fallback_flow = FlowKey(
            src_addr=IPv4Address("192.168.1.1"),
            dst_addr=IPv4Address("10.0.0.1"),
            src_port=100,
            dst_port=80,
            protocol=Protocol.TCP,
        )
        mock_lru.items.return_value = [(fallback_flow, RealPosLru(pos=1, atime=0))]

        cpu_flow = FlowKey(
            src_addr=IPv4Address("192.168.1.2"),
            dst_addr=IPv4Address("10.0.0.1"),
            src_port=200,
            dst_port=80,
            protocol=Protocol.TCP,
        )

        mgr = LruManager(fallback_lru=mock_lru, per_cpu_lru_fds=[42])
        with patch.object(
            mgr, "_iter_lru_fd", return_value=[(cpu_flow, RealPosLru(pos=2, atime=0))]
        ):
            entries = mgr._iter_all_lru_entries()
            assert len(entries) == 2
            cpus = [e[2] for e in entries]
            assert 0 in cpus
            assert -1 in cpus

    def test_per_cpu_iteration_handles_failure(self, mock_lru):
        from katran.lb.lru_manager import LruManager

        mock_lru.items.return_value = []

        mgr = LruManager(fallback_lru=mock_lru, per_cpu_lru_fds=[42])
        with patch.object(mgr, "_iter_lru_fd", side_effect=OSError("bad fd")):
            entries = mgr._iter_all_lru_entries()
            # Should still return fallback entries (empty here) without raising
            assert len(entries) == 0

    def test_get_vip_lru_miss_stats_no_deps(self, manager):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        result = manager.get_vip_lru_miss_stats(vip)
        assert result == {}

    def test_get_vip_lru_miss_stats_vip_not_found(self, mock_lru):
        from katran.lb.lru_manager import LruManager

        mock_miss_map = MagicMock()
        mock_vip_mgr = MagicMock()
        mock_vip_mgr.get_vip.return_value = None
        mgr = LruManager(
            fallback_lru=mock_lru,
            lru_miss_stats_map=mock_miss_map,
            vip_manager=mock_vip_mgr,
        )
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        result = mgr.get_vip_lru_miss_stats(vip)
        assert result == {}

    def test_get_vip_lru_miss_stats_with_reals(self, mock_lru):
        from katran.lb.lru_manager import LruManager

        mock_miss_map = MagicMock()
        mock_miss_map.get.return_value = 42
        mock_vip_mgr = MagicMock()
        real = MagicMock()
        real.index = 5
        real.address = IPv4Address("10.0.1.1")
        vip_obj = MagicMock()
        vip_obj.reals = [real]
        mock_vip_mgr.get_vip.return_value = vip_obj
        mgr = LruManager(
            fallback_lru=mock_lru,
            lru_miss_stats_map=mock_miss_map,
            vip_manager=mock_vip_mgr,
        )
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        result = mgr.get_vip_lru_miss_stats(vip)
        assert result == {"10.0.1.1": 42}

    def test_matches_vip_protocol_mismatch(self, manager, mock_lru):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        flow = FlowKey(
            src_addr=IPv4Address("192.168.1.1"),
            dst_addr=IPv4Address("10.0.0.1"),
            src_port=12345,
            dst_port=80,
            protocol=Protocol.UDP,
        )
        mock_lru.items.return_value = [(flow, RealPosLru(pos=5, atime=0))]
        result = manager.search(vip, "192.168.1.1", 12345)
        assert len(result.entries) == 0
