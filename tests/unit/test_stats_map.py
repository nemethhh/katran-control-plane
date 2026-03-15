# tests/unit/test_stats_map.py
"""Unit tests for StatsMap — no BPF kernel required."""
from unittest.mock import MagicMock

import pytest

from katran.bpf.maps.stats_map import GlobalStatistics, StatsMap, VipStatistics
from katran.core.constants import MAX_VIPS, StatsCounterIndex
from katran.core.types import LbStats


def _make_stats_map(max_vips: int = 16) -> StatsMap:
    """Create a StatsMap with mocked BPF methods."""
    sm = StatsMap.__new__(StatsMap)
    StatsMap.__init__(sm, "/fake/path", max_vips=max_vips, num_cpus=2)
    sm.get = MagicMock(return_value=None)
    sm.set = MagicMock()
    sm.get_all_cpus = MagicMock(return_value=[LbStats(), LbStats()])
    return sm


class TestVipStatisticsHitRatio:
    def test_hit_ratio_zero_when_no_traffic(self):
        stats = VipStatistics(packets=0, bytes=0, lru_hits=0, lru_misses=0)
        assert stats.hit_ratio == 0.0

    def test_hit_ratio_perfect(self):
        stats = VipStatistics(lru_hits=100, lru_misses=0)
        assert stats.hit_ratio == 1.0

    def test_hit_ratio_partial(self):
        stats = VipStatistics(lru_hits=50, lru_misses=50)
        assert stats.hit_ratio == 0.5


class TestStatsMapAggregateValues:
    def test_aggregate_single_cpu(self):
        sm = _make_stats_map()
        values = [LbStats(v1=100, v2=200)]

        result = sm._aggregate_values(values)

        assert result.v1 == 100
        assert result.v2 == 200

    def test_aggregate_multi_cpu_sums(self):
        sm = _make_stats_map()
        values = [LbStats(v1=100, v2=200), LbStats(v1=50, v2=100)]

        result = sm._aggregate_values(values)

        assert result.v1 == 150
        assert result.v2 == 300

    def test_aggregate_empty_list_returns_zero_stats(self):
        sm = _make_stats_map()

        result = sm._aggregate_values([])

        assert result.v1 == 0
        assert result.v2 == 0


class TestStatsMapGetCounter:
    def test_get_counter_returns_aggregated_stats(self):
        sm = _make_stats_map()
        sm.get = MagicMock(return_value=LbStats(v1=999, v2=888))

        result = sm.get_counter(5)

        assert result.v1 == 999
        sm.get.assert_called_once_with(5)

    def test_get_counter_not_found_returns_empty_stats(self):
        sm = _make_stats_map()
        sm.get = MagicMock(return_value=None)

        result = sm.get_counter(5)

        assert result.v1 == 0
        assert result.v2 == 0

    def test_get_counter_per_cpu_delegates_to_get_all_cpus(self):
        sm = _make_stats_map()
        per_cpu = [LbStats(v1=10), LbStats(v1=20)]
        sm.get_all_cpus = MagicMock(return_value=per_cpu)

        result = sm.get_counter_per_cpu(3)

        assert result == per_cpu
        sm.get_all_cpus.assert_called_once_with(3)


class TestStatsMapGetVipStats:
    def test_get_vip_stats_returns_vip_statistics(self):
        sm = _make_stats_map()
        sm.get = MagicMock(return_value=LbStats(v1=1000, v2=50000))

        result = sm.get_vip_stats(vip_num=0)

        assert isinstance(result, VipStatistics)
        assert result.packets == 1000
        assert result.bytes == 50000
        assert result.lru_hits == 0   # Per-VIP LRU not tracked
        assert result.lru_misses == 0
        sm.get.assert_called_once_with(0)

    def test_get_vip_stats_boundary_last_vip(self):
        sm = _make_stats_map(max_vips=16)
        sm.get = MagicMock(return_value=LbStats(v1=5, v2=10))

        result = sm.get_vip_stats(vip_num=15)

        sm.get.assert_called_once_with(15)
        assert result.packets == 5


class TestStatsMapGetGlobalStats:
    def test_get_global_stats_aggregates_all_counters(self):
        sm = _make_stats_map(max_vips=16)

        call_map: dict[int, LbStats] = {
            16 + StatsCounterIndex.LRU_CNTRS: LbStats(v1=100, v2=5),
            16 + StatsCounterIndex.LRU_MISS_CNTR: LbStats(v1=10, v2=0),
            16 + StatsCounterIndex.NEW_CONN_RATE_CNTR: LbStats(v1=200, v2=0),
            16 + StatsCounterIndex.ICMP_TOOBIG_CNTRS: LbStats(v1=3, v2=0),
            16 + StatsCounterIndex.XDP_TOTAL_CNTR: LbStats(v1=500, v2=1000000),
        }

        def fake_get(idx):
            return call_map.get(idx, LbStats())

        sm.get = MagicMock(side_effect=fake_get)

        result = sm.get_global_stats()

        assert isinstance(result, GlobalStatistics)
        assert result.total_packets == 500
        assert result.total_bytes == 1000000
        assert result.total_lru_hits == 100
        assert result.total_lru_misses == 10
        assert result.new_connections == 200
        assert result.icmp_toobig == 3


class TestStatsMapGetXdpActionStats:
    def test_get_xdp_action_stats_returns_dict(self):
        sm = _make_stats_map(max_vips=16)

        call_map: dict[int, LbStats] = {
            16 + StatsCounterIndex.XDP_TOTAL_CNTR: LbStats(v1=500),
            16 + StatsCounterIndex.XDP_TX_CNTR: LbStats(v1=480),
            16 + StatsCounterIndex.XDP_DROP_CNTR: LbStats(v1=10),
            16 + StatsCounterIndex.XDP_PASS_CNTR: LbStats(v1=10),
        }

        def fake_get(idx):
            return call_map.get(idx, LbStats())

        sm.get = MagicMock(side_effect=fake_get)

        result = sm.get_xdp_action_stats()

        assert result["total"] == 500
        assert result["tx"] == 480
        assert result["drop"] == 10
        assert result["pass"] == 10

    def test_get_all_vip_stats_batch(self):
        sm = _make_stats_map(max_vips=16)
        sm.get = MagicMock(return_value=LbStats(v1=100, v2=200))

        result = sm.get_all_vip_stats([0, 1, 2])

        assert len(result) == 3
        for vip_num in [0, 1, 2]:
            assert vip_num in result
            assert result[vip_num].packets == 100


class TestStatsMapReset:
    def test_reset_counter_writes_zero_lbstats(self):
        sm = _make_stats_map()

        sm.reset_counter(5)

        sm.set.assert_called_once_with(5, LbStats(v1=0, v2=0))

    def test_reset_vip_stats_delegates_to_reset_counter(self):
        sm = _make_stats_map()

        sm.reset_vip_stats(vip_num=3)

        sm.set.assert_called_once_with(3, LbStats(v1=0, v2=0))

    def test_global_index_adds_max_vips_offset(self):
        sm = _make_stats_map(max_vips=16)

        result = sm._global_index(StatsCounterIndex.LRU_CNTRS)

        assert result == 16 + StatsCounterIndex.LRU_CNTRS
