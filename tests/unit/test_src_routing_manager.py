from unittest.mock import MagicMock

import pytest

from katran.core.exceptions import SrcRoutingError


class TestSrcRoutingManager:
    @pytest.fixture
    def mock_v4_map(self):
        return MagicMock()

    @pytest.fixture
    def mock_v6_map(self):
        return MagicMock()

    @pytest.fixture
    def mock_real_manager(self):
        mock = MagicMock()
        mock.increase_ref_count = MagicMock(return_value=5)
        mock.decrease_ref_count = MagicMock()
        return mock

    @pytest.fixture
    def manager(self, mock_v4_map, mock_v6_map, mock_real_manager):
        from katran.lb.src_routing_manager import SrcRoutingManager

        return SrcRoutingManager(mock_v4_map, mock_v6_map, mock_real_manager)

    def test_add_rules_v4(self, manager, mock_v4_map, mock_real_manager):
        failures = manager.add_rules(["10.0.0.0/24"], "192.168.1.1")
        assert failures == 0
        mock_real_manager.increase_ref_count.assert_called_once_with("192.168.1.1")
        mock_v4_map.set.assert_called_once()

    def test_add_rules_v6(self, manager, mock_v6_map, mock_real_manager):
        failures = manager.add_rules(["2001:db8::/32"], "2001:db8::1")
        assert failures == 0
        mock_v6_map.set.assert_called_once()

    def test_add_rules_invalid_cidr(self, manager):
        failures = manager.add_rules(["not-a-cidr"], "10.0.0.1")
        assert failures == 1

    def test_add_rules_duplicate(self, manager):
        manager.add_rules(["10.0.0.0/24"], "192.168.1.1")
        failures = manager.add_rules(["10.0.0.0/24"], "192.168.1.2")
        assert failures == 1

    def test_del_rules(self, manager, mock_v4_map, mock_real_manager):
        manager.add_rules(["10.0.0.0/24"], "192.168.1.1")
        result = manager.del_rules(["10.0.0.0/24"])
        assert result is True
        mock_real_manager.decrease_ref_count.assert_called_once()

    def test_del_rules_not_found(self, manager, mock_real_manager):
        result = manager.del_rules(["10.0.0.0/24"])
        assert result is True
        mock_real_manager.decrease_ref_count.assert_not_called()

    def test_get_rules(self, manager):
        manager.add_rules(["10.0.0.0/24"], "192.168.1.1")
        rules = manager.get_rules()
        assert "10.0.0.0/24" in rules

    def test_clear_all(self, manager, mock_real_manager):
        manager.add_rules(["10.0.0.0/24", "10.1.0.0/16"], "192.168.1.1")
        manager.clear_all()
        assert manager.get_rule_count() == 0

    def test_get_rule_count(self, manager):
        assert manager.get_rule_count() == 0
        manager.add_rules(["10.0.0.0/24"], "192.168.1.1")
        assert manager.get_rule_count() == 1

    def test_add_rules_capacity(self, manager):
        """Test that SrcRoutingError is raised when LPM capacity is reached."""
        from katran.lb.src_routing_manager import SrcRoutingManager

        small_mgr = SrcRoutingManager(
            MagicMock(), MagicMock(), MagicMock(increase_ref_count=MagicMock(return_value=1)),
            max_lpm_src=2,
        )
        small_mgr.add_rules(["10.0.0.0/24", "10.1.0.0/24"], "192.168.1.1")
        with pytest.raises(SrcRoutingError, match="capacity"):
            small_mgr.add_rules(["10.2.0.0/24"], "192.168.1.1")
