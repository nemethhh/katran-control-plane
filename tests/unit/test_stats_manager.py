"""Tests for StatsManager centralized statistics access."""

from unittest.mock import MagicMock

import pytest

from katran.core.constants import MAX_VIPS, StatsCounterIndex
from katran.core.types import HealthCheckProgStats, LbStats, QuicPacketStats
from katran.lb.stats_manager import StatsManager


class TestStatsManager:
    @pytest.fixture
    def mock_stats_map(self):
        mock = MagicMock()
        mock.get = MagicMock(return_value=LbStats(v1=100, v2=200))
        mock.get_all_cpus = MagicMock(
            return_value=[LbStats(v1=50, v2=100), LbStats(v1=50, v2=100)]
        )
        return mock

    @pytest.fixture
    def manager(self, mock_stats_map):
        return StatsManager(stats_map=mock_stats_map, max_vips=512)

    def test_get_vip_stats(self, manager, mock_stats_map):
        result = manager.get_vip_stats(0)
        assert result.v1 == 100
        assert result.v2 == 200
        mock_stats_map.get.assert_called_with(0)

    def test_get_vip_stats_returns_default_on_none(self, manager, mock_stats_map):
        mock_stats_map.get.return_value = None
        result = manager.get_vip_stats(5)
        assert result.v1 == 0
        assert result.v2 == 0

    def test_get_lru_stats(self, manager, mock_stats_map):
        result = manager.get_lru_stats()
        assert isinstance(result, LbStats)
        mock_stats_map.get.assert_called_with(512 + StatsCounterIndex.LRU_CNTRS)

    def test_get_xdp_total_stats(self, manager, mock_stats_map):
        result = manager.get_xdp_total_stats()
        assert isinstance(result, LbStats)
        mock_stats_map.get.assert_called_with(512 + StatsCounterIndex.XDP_TOTAL_CNTR)

    def test_get_xdp_tx_stats(self, manager, mock_stats_map):
        result = manager.get_xdp_tx_stats()
        mock_stats_map.get.assert_called_with(512 + StatsCounterIndex.XDP_TX_CNTR)

    def test_get_xdp_drop_stats(self, manager, mock_stats_map):
        result = manager.get_xdp_drop_stats()
        mock_stats_map.get.assert_called_with(512 + StatsCounterIndex.XDP_DROP_CNTR)

    def test_get_xdp_pass_stats(self, manager, mock_stats_map):
        result = manager.get_xdp_pass_stats()
        mock_stats_map.get.assert_called_with(512 + StatsCounterIndex.XDP_PASS_CNTR)

    def test_get_ch_drop_stats(self, manager, mock_stats_map):
        result = manager.get_ch_drop_stats()
        mock_stats_map.get.assert_called_with(512 + StatsCounterIndex.CH_DROP_STATS)

    def test_get_encap_fail_stats(self, manager, mock_stats_map):
        result = manager.get_encap_fail_stats()
        mock_stats_map.get.assert_called_with(512 + StatsCounterIndex.ENCAP_FAIL_CNTR)

    def test_get_decap_stats(self, manager, mock_stats_map):
        result = manager.get_decap_stats()
        mock_stats_map.get.assert_called_with(512 + StatsCounterIndex.DECAP_CNTR)

    def test_get_real_stats_with_map(self, manager):
        manager._reals_stats_map = MagicMock()
        manager._reals_stats_map.get = MagicMock(return_value=LbStats(v1=10, v2=20))
        result = manager.get_real_stats(1)
        assert result.v1 == 10
        assert result.v2 == 20
        manager._reals_stats_map.get.assert_called_with(1)

    def test_get_real_stats_without_map(self, manager):
        result = manager.get_real_stats(1)
        assert result.v1 == 0
        assert result.v2 == 0

    def test_get_reals_stats_batch(self, manager):
        manager._reals_stats_map = MagicMock()
        manager._reals_stats_map.get = MagicMock(return_value=LbStats(v1=5, v2=10))
        result = manager.get_reals_stats([1, 2, 3])
        assert len(result) == 3
        assert all(s.v1 == 5 for s in result.values())

    def test_get_quic_packet_stats_with_map(self, manager):
        manager._quic_stats_map = MagicMock()
        manager._quic_stats_map.get = MagicMock(return_value=QuicPacketStats(ch_routed=5))
        result = manager.get_quic_packet_stats()
        assert result.ch_routed == 5

    def test_get_quic_packet_stats_without_map(self, manager):
        result = manager.get_quic_packet_stats()
        assert result.ch_routed == 0

    def test_get_hc_program_stats_with_map(self, manager):
        manager._hc_stats_map = MagicMock()
        manager._hc_stats_map.get = MagicMock(
            return_value=HealthCheckProgStats(packets_processed=42)
        )
        result = manager.get_hc_program_stats()
        assert result.packets_processed == 42

    def test_get_hc_program_stats_without_map(self, manager):
        result = manager.get_hc_program_stats()
        assert result.packets_processed == 0

    def test_get_per_core_packets_stats(self, manager, mock_stats_map):
        result = manager.get_per_core_packets_stats()
        assert isinstance(result, list)
        assert result == [50, 50]

    def test_get_per_core_packets_stats_empty(self, manager, mock_stats_map):
        mock_stats_map.get_all_cpus.return_value = []
        result = manager.get_per_core_packets_stats()
        assert result == []

    def test_get_decap_stats_for_vip_with_map(self, manager):
        manager._decap_vip_stats_map = MagicMock()
        manager._decap_vip_stats_map.get = MagicMock(return_value=LbStats(v1=7, v2=14))
        result = manager.get_decap_stats_for_vip(3)
        assert result.v1 == 7

    def test_get_decap_stats_for_vip_without_map(self, manager):
        result = manager.get_decap_stats_for_vip(3)
        assert result.v1 == 0

    def test_get_sid_routing_stats_for_vip_with_map(self, manager):
        manager._server_id_stats_map = MagicMock()
        manager._server_id_stats_map.get = MagicMock(return_value=LbStats(v1=9, v2=18))
        result = manager.get_sid_routing_stats_for_vip(2)
        assert result.v1 == 9

    def test_get_sid_routing_stats_for_vip_without_map(self, manager):
        result = manager.get_sid_routing_stats_for_vip(2)
        assert result.v1 == 0

    def test_get_packets_for_hc_key_with_map(self, manager):
        manager._per_hckey_stats = MagicMock()
        manager._per_hckey_stats.get = MagicMock(return_value=99)
        result = manager.get_packets_for_hc_key(5)
        assert result == 99

    def test_get_packets_for_hc_key_without_map(self, manager):
        result = manager.get_packets_for_hc_key(5)
        assert result == 0

    def test_get_lru_miss_stats_for_real_with_map(self, manager):
        manager._lru_miss_stats_map = MagicMock()
        manager._lru_miss_stats_map.get = MagicMock(return_value=42)
        result = manager.get_lru_miss_stats_for_real(7)
        assert result == 42

    def test_get_lru_miss_stats_for_real_without_map(self, manager):
        result = manager.get_lru_miss_stats_for_real(7)
        assert result == 0

    def test_global_index_calculation(self, manager):
        assert manager._global_index(StatsCounterIndex.LRU_CNTRS) == 512
        assert manager._global_index(StatsCounterIndex.XDP_TOTAL_CNTR) == 512 + 16

    def test_get_src_routing_stats(self, manager, mock_stats_map):
        result = manager.get_src_routing_stats()
        mock_stats_map.get.assert_called_with(512 + StatsCounterIndex.LPM_SRC_CNTRS)

    def test_get_inline_decap_stats(self, manager, mock_stats_map):
        result = manager.get_inline_decap_stats()
        mock_stats_map.get.assert_called_with(512 + StatsCounterIndex.REMOTE_ENCAP_CNTRS)

    def test_get_lru_miss_stats(self, manager, mock_stats_map):
        result = manager.get_lru_miss_stats()
        mock_stats_map.get.assert_called_with(512 + StatsCounterIndex.LRU_MISS_CNTR)

    def test_get_new_conn_rate_stats(self, manager, mock_stats_map):
        result = manager.get_new_conn_rate_stats()
        mock_stats_map.get.assert_called_with(512 + StatsCounterIndex.NEW_CONN_RATE_CNTR)

    def test_get_lru_fallback_stats(self, manager, mock_stats_map):
        result = manager.get_lru_fallback_stats()
        mock_stats_map.get.assert_called_with(512 + StatsCounterIndex.FALLBACK_LRU_CNTR)

    def test_get_global_lru_stats(self, manager, mock_stats_map):
        result = manager.get_global_lru_stats()
        mock_stats_map.get.assert_called_with(512 + StatsCounterIndex.GLOBAL_LRU_CNTR)

    def test_get_icmp_toobig_stats(self, manager, mock_stats_map):
        result = manager.get_icmp_toobig_stats()
        mock_stats_map.get.assert_called_with(512 + StatsCounterIndex.ICMP_TOOBIG_CNTRS)

    def test_get_icmp_ptb_v4_stats(self, manager, mock_stats_map):
        result = manager.get_icmp_ptb_v4_stats()
        mock_stats_map.get.assert_called_with(512 + StatsCounterIndex.ICMP_PTB_V4_STATS)

    def test_get_icmp_ptb_v6_stats(self, manager, mock_stats_map):
        result = manager.get_icmp_ptb_v6_stats()
        mock_stats_map.get.assert_called_with(512 + StatsCounterIndex.ICMP_PTB_V6_STATS)

    def test_get_xpop_decap_stats(self, manager, mock_stats_map):
        result = manager.get_xpop_decap_stats()
        mock_stats_map.get.assert_called_with(512 + StatsCounterIndex.XPOP_DECAP_SUCCESSFUL)

    def test_get_udp_flow_migration_stats(self, manager, mock_stats_map):
        result = manager.get_udp_flow_migration_stats()
        mock_stats_map.get.assert_called_with(
            512 + StatsCounterIndex.UDP_FLOW_MIGRATION_STATS
        )

    def test_get_quic_icmp_stats(self, manager, mock_stats_map):
        result = manager.get_quic_icmp_stats()
        mock_stats_map.get.assert_called_with(512 + StatsCounterIndex.QUIC_ICMP_STATS)
