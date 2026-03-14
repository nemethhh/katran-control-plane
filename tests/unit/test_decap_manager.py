from unittest.mock import MagicMock

import pytest

from katran.core.exceptions import DecapError


class TestDecapManager:
    @pytest.fixture
    def mock_map(self):
        return MagicMock()

    @pytest.fixture
    def manager(self, mock_map):
        from katran.lb.decap_manager import DecapManager

        return DecapManager(mock_map, max_decap_dst=6)

    def test_add_dst(self, manager, mock_map):
        manager.add_dst("10.0.0.1")
        mock_map.set.assert_called_once()
        assert manager.get_dst_count() == 1

    def test_add_dst_ipv6(self, manager, mock_map):
        manager.add_dst("2001:db8::1")
        assert manager.get_dst_count() == 1

    def test_add_dst_duplicate(self, manager):
        manager.add_dst("10.0.0.1")
        with pytest.raises(DecapError, match="already exists"):
            manager.add_dst("10.0.0.1")

    def test_add_dst_capacity(self, manager):
        for i in range(6):
            manager.add_dst(f"10.0.0.{i + 1}")
        with pytest.raises(DecapError, match="capacity"):
            manager.add_dst("10.0.0.7")

    def test_del_dst(self, manager, mock_map):
        manager.add_dst("10.0.0.1")
        manager.del_dst("10.0.0.1")
        mock_map.delete.assert_called_once()
        assert manager.get_dst_count() == 0

    def test_del_dst_not_found(self, manager):
        with pytest.raises(DecapError, match="not found"):
            manager.del_dst("10.0.0.99")

    def test_get_dsts(self, manager):
        manager.add_dst("10.0.0.1")
        manager.add_dst("10.0.0.2")
        dsts = manager.get_dsts()
        assert len(dsts) == 2
        assert "10.0.0.1" in dsts
