from unittest.mock import MagicMock

import pytest

from katran.core.constants import ModifyAction
from katran.core.exceptions import QuicMappingError
from katran.core.types import QuicReal


class TestQuicManager:
    @pytest.fixture
    def mock_map(self):
        return MagicMock()

    @pytest.fixture
    def mock_real_manager(self):
        mock = MagicMock()
        mock.increase_ref_count = MagicMock(return_value=5)
        mock.decrease_ref_count = MagicMock()
        mock.get_index_for_real = MagicMock(return_value=5)
        return mock

    @pytest.fixture
    def manager(self, mock_map, mock_real_manager):
        from katran.lb.quic_manager import QuicManager

        return QuicManager(mock_map, mock_real_manager, max_server_ids=100)

    def test_add_mapping(self, manager, mock_map, mock_real_manager):
        reals = [QuicReal(address="10.0.0.1", id=1)]
        failures = manager.modify_mapping(ModifyAction.ADD, reals)
        assert failures == 0
        mock_real_manager.increase_ref_count.assert_called_once_with("10.0.0.1")
        mock_map.set.assert_called_once()

    def test_add_mapping_id_zero(self, manager):
        reals = [QuicReal(address="10.0.0.1", id=0)]
        failures = manager.modify_mapping(ModifyAction.ADD, reals)
        assert failures == 1

    def test_add_mapping_id_too_large(self, manager):
        reals = [QuicReal(address="10.0.0.1", id=200)]
        failures = manager.modify_mapping(ModifyAction.ADD, reals)
        assert failures == 1

    def test_del_mapping(self, manager, mock_map, mock_real_manager):
        manager.modify_mapping(ModifyAction.ADD, [QuicReal(address="10.0.0.1", id=1)])
        failures = manager.modify_mapping(ModifyAction.DEL, [QuicReal(address="10.0.0.1", id=1)])
        assert failures == 0
        mock_real_manager.decrease_ref_count.assert_called_once()

    def test_del_mapping_not_found(self, manager):
        failures = manager.modify_mapping(ModifyAction.DEL, [QuicReal(address="10.0.0.1", id=99)])
        assert failures == 1

    def test_get_mapping(self, manager):
        manager.modify_mapping(ModifyAction.ADD, [QuicReal(address="10.0.0.1", id=1)])
        mappings = manager.get_mapping()
        assert len(mappings) == 1
        assert mappings[0].id == 1
        assert mappings[0].address == "10.0.0.1"

    def test_invalidate_server_ids(self, manager, mock_map):
        manager.modify_mapping(ModifyAction.ADD, [QuicReal(address="10.0.0.1", id=1)])
        manager.invalidate_server_ids([1])
        # First call: add (set id->real_index), second call: invalidate (set id->0)
        assert mock_map.set.call_count == 2
        mock_map.set.assert_called_with(1, 0)

    def test_invalidate_unknown_id(self, manager, mock_map):
        """Invalidating an unknown server ID is a no-op."""
        manager.invalidate_server_ids([999])
        mock_map.set.assert_not_called()

    def test_revalidate_server_ids(self, manager, mock_map, mock_real_manager):
        manager.modify_mapping(ModifyAction.ADD, [QuicReal(address="10.0.0.1", id=1)])
        mock_real_manager.get_index_for_real.return_value = 7
        manager.revalidate_server_ids([QuicReal(address="10.0.0.1", id=1)])
        # Last set call should be the revalidation with index 7
        mock_map.set.assert_called_with(1, 7)

    def test_revalidate_unknown_id(self, manager, mock_map, mock_real_manager):
        """Revalidating an unknown server ID is a no-op."""
        manager.revalidate_server_ids([QuicReal(address="10.0.0.1", id=999)])
        mock_real_manager.get_index_for_real.assert_not_called()

    def test_batch_add(self, manager, mock_real_manager):
        reals = [
            QuicReal(address="10.0.0.1", id=1),
            QuicReal(address="10.0.0.2", id=2),
            QuicReal(address="10.0.0.3", id=3),
        ]
        failures = manager.modify_mapping(ModifyAction.ADD, reals)
        assert failures == 0
        assert len(manager.get_mapping()) == 3
