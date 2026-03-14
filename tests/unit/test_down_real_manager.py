"""Unit tests for DownRealManager."""

from ipaddress import IPv4Address
from unittest.mock import MagicMock, patch

import pytest

from katran.core.constants import Protocol
from katran.core.exceptions import VipNotFoundError
from katran.core.types import VipKey


class TestDownRealManager:
    @pytest.fixture
    def mock_down_reals_map(self):
        mock = MagicMock()
        mock.get = MagicMock(return_value=None)
        mock.set = MagicMock()
        mock.delete = MagicMock(return_value=True)
        mock.fd = 100
        return mock

    @pytest.fixture
    def mock_vip_manager(self):
        mock = MagicMock()
        mock.get_vip = MagicMock(return_value=MagicMock())
        return mock

    @pytest.fixture
    def manager(self, mock_down_reals_map, mock_vip_manager):
        from katran.lb.down_real_manager import DownRealManager

        return DownRealManager(mock_down_reals_map, mock_vip_manager)

    def test_add_down_real_creates_inner_map(self, manager, mock_down_reals_map):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        mock_down_reals_map.get.return_value = None
        with patch("katran.lb.down_real_manager.bpf_map_create", return_value=200):
            with patch("katran.lb.down_real_manager._bpf_syscall", return_value=0):
                with patch("katran.lb.down_real_manager.os.close"):
                    manager.add_down_real(vip, 5)

    def test_add_down_real_reuses_existing_inner_map(
        self, manager, mock_down_reals_map
    ):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        mock_down_reals_map.get.return_value = 42  # existing map ID
        with patch(
            "katran.lb.down_real_manager.bpf_map_get_fd_by_id", return_value=200
        ):
            with patch("katran.lb.down_real_manager._bpf_syscall", return_value=0):
                with patch("katran.lb.down_real_manager.os.close"):
                    manager.add_down_real(vip, 5)

    def test_check_real_not_found(self, manager, mock_down_reals_map):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        mock_down_reals_map.get.return_value = None
        assert manager.check_real(vip, 5) is False

    def test_check_real_found(self, manager, mock_down_reals_map):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        mock_down_reals_map.get.return_value = 42
        with patch(
            "katran.lb.down_real_manager.bpf_map_get_fd_by_id", return_value=200
        ):
            with patch(
                "katran.lb.down_real_manager._bpf_syscall", return_value=0
            ):  # lookup succeeds
                with patch("katran.lb.down_real_manager.os.close"):
                    assert manager.check_real(vip, 5) is True

    def test_check_real_inner_fd_fails(self, manager, mock_down_reals_map):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        mock_down_reals_map.get.return_value = 42
        with patch(
            "katran.lb.down_real_manager.bpf_map_get_fd_by_id",
            side_effect=Exception("bad id"),
        ):
            assert manager.check_real(vip, 5) is False

    def test_remove_vip(self, manager, mock_down_reals_map):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        manager.remove_vip(vip)
        mock_down_reals_map.delete.assert_called_once()

    def test_remove_real(self, manager, mock_down_reals_map):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        mock_down_reals_map.get.return_value = None
        # No inner map exists, should be a no-op
        manager.remove_real(vip, 5)

    def test_remove_real_with_inner_map(self, manager, mock_down_reals_map):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        mock_down_reals_map.get.return_value = 42
        with patch(
            "katran.lb.down_real_manager.bpf_map_get_fd_by_id", return_value=200
        ):
            with patch("katran.lb.down_real_manager._bpf_syscall", return_value=0):
                with patch("katran.lb.down_real_manager.os.close"):
                    manager.remove_real(vip, 5)

    def test_remove_real_inner_fd_fails(self, manager, mock_down_reals_map):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        mock_down_reals_map.get.return_value = 42
        with patch(
            "katran.lb.down_real_manager.bpf_map_get_fd_by_id",
            side_effect=Exception("bad id"),
        ):
            # Should silently return, not raise
            manager.remove_real(vip, 5)

    def test_validate_vip_not_found(self, manager, mock_vip_manager):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        mock_vip_manager.get_vip.return_value = None
        with pytest.raises(VipNotFoundError):
            manager.add_down_real(vip, 5)

    def test_check_real_validates_vip(self, manager, mock_vip_manager):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        manager.check_real(vip, 5)
        mock_vip_manager.get_vip.assert_called()

    def test_remove_vip_idempotent(self, manager, mock_down_reals_map):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        mock_down_reals_map.delete.return_value = False
        manager.remove_vip(vip)

    def test_add_down_real_closes_fd_on_write_error(
        self, manager, mock_down_reals_map
    ):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        mock_down_reals_map.get.return_value = None
        with patch("katran.lb.down_real_manager.bpf_map_create", return_value=200):
            with patch(
                "katran.lb.down_real_manager._bpf_syscall", return_value=-1
            ):
                with patch("katran.lb.down_real_manager.os.close") as mock_close:
                    # _write_inner calls _bpf_syscall which returns -1 but doesn't
                    # raise; the fd should still be closed in the finally block
                    manager.add_down_real(vip, 5)
                    mock_close.assert_called_once_with(200)
