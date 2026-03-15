# tests/unit/test_ctl_array.py
"""Unit tests for CtlArray — no BPF kernel required."""
from unittest.mock import MagicMock, call

import pytest

from katran.bpf.maps.ctl_array import CtlArray
from katran.core.constants import CtlArrayIndex
from katran.core.types import CtlValue


def _make_ctl_array() -> CtlArray:
    """Create a CtlArray with mocked BPF methods."""
    ca = CtlArray.__new__(CtlArray)
    CtlArray.__init__(ca, "/fake/path")
    ca.get = MagicMock(return_value=None)
    ca.set = MagicMock()
    return ca


class TestCtlArrayMac:
    def test_set_mac_string_calls_set(self):
        ca = _make_ctl_array()
        ca.set_mac("aa:bb:cc:dd:ee:ff")
        ca.set.assert_called_once()
        idx, val = ca.set.call_args[0]
        assert idx == CtlArrayIndex.MAC_ADDRESS_POS
        assert isinstance(val, CtlValue)

    def test_set_mac_custom_index(self):
        ca = _make_ctl_array()
        ca.set_mac("aa:bb:cc:dd:ee:ff", index=2)
        idx = ca.set.call_args[0][0]
        assert idx == 2

    def test_get_mac_returns_string(self):
        ca = _make_ctl_array()
        mock_val = MagicMock()
        mock_val.as_mac.return_value = "aa:bb:cc:dd:ee:ff"
        ca.get = MagicMock(return_value=mock_val)

        result = ca.get_mac()

        assert result == "aa:bb:cc:dd:ee:ff"
        ca.get.assert_called_once_with(CtlArrayIndex.MAC_ADDRESS_POS)

    def test_get_mac_not_set_returns_none(self):
        ca = _make_ctl_array()
        ca.get = MagicMock(return_value=None)

        result = ca.get_mac()

        assert result is None

    def test_get_mac_bytes_returns_6_bytes(self):
        ca = _make_ctl_array()
        mock_val = MagicMock()
        mock_val.value = b"\xaa\xbb\xcc\xdd\xee\xff\x00\x00"
        ca.get = MagicMock(return_value=mock_val)

        result = ca.get_mac_bytes()

        assert result == b"\xaa\xbb\xcc\xdd\xee\xff"

    def test_get_mac_bytes_not_set_returns_none(self):
        ca = _make_ctl_array()
        ca.get = MagicMock(return_value=None)

        result = ca.get_mac_bytes()

        assert result is None


class TestCtlArrayIfindex:
    def test_set_ifindex_calls_set_at_ifindex_pos(self):
        ca = _make_ctl_array()
        ca.set_ifindex(42)
        ca.set.assert_called_once()
        idx, val = ca.set.call_args[0]
        assert idx == CtlArrayIndex.IFINDEX_POS
        assert isinstance(val, CtlValue)

    def test_set_ifindex_custom_index(self):
        ca = _make_ctl_array()
        ca.set_ifindex(42, index=3)
        idx = ca.set.call_args[0][0]
        assert idx == 3

    def test_get_ifindex_returns_int(self):
        ca = _make_ctl_array()
        mock_val = MagicMock()
        mock_val.as_ifindex.return_value = 42
        ca.get = MagicMock(return_value=mock_val)

        result = ca.get_ifindex()

        assert result == 42

    def test_get_ifindex_not_set_returns_none(self):
        ca = _make_ctl_array()
        ca.get = MagicMock(return_value=None)

        result = ca.get_ifindex()

        assert result is None


class TestCtlArrayU64:
    def test_set_u64_boundary_zero(self):
        ca = _make_ctl_array()
        ca.set_u64(0, index=5)
        ca.set.assert_called_once()
        idx, val = ca.set.call_args[0]
        assert idx == 5
        assert isinstance(val, CtlValue)

    def test_set_u64_boundary_max(self):
        ca = _make_ctl_array()
        ca.set_u64(2**64 - 1, index=5)
        ca.set.assert_called_once()

    def test_get_u64_returns_int(self):
        ca = _make_ctl_array()
        mock_val = MagicMock()
        mock_val.as_u64.return_value = 12345
        ca.get = MagicMock(return_value=mock_val)

        result = ca.get_u64(5)

        assert result == 12345

    def test_get_u64_not_set_returns_none(self):
        ca = _make_ctl_array()
        ca.get = MagicMock(return_value=None)

        result = ca.get_u64(5)

        assert result is None


class TestCtlArrayConvenienceMethods:
    def test_configure_gateway_calls_set_mac_and_set_ifindex(self):
        ca = _make_ctl_array()

        ca.configure_gateway("aa:bb:cc:dd:ee:ff", 42)

        # set() should be called twice: once for MAC, once for ifindex
        assert ca.set.call_count == 2

    def test_get_configuration_both_present(self):
        ca = _make_ctl_array()
        mac_val = MagicMock()
        mac_val.as_mac.return_value = "aa:bb:cc:dd:ee:ff"
        ifindex_val = MagicMock()
        ifindex_val.as_ifindex.return_value = 42

        def fake_get(index):
            if index == CtlArrayIndex.MAC_ADDRESS_POS:
                return mac_val
            if index == CtlArrayIndex.IFINDEX_POS:
                return ifindex_val
            return None

        ca.get = MagicMock(side_effect=fake_get)

        result = ca.get_configuration()

        assert result["mac_address"] == "aa:bb:cc:dd:ee:ff"
        assert result["ifindex"] == 42

    def test_get_configuration_both_none(self):
        ca = _make_ctl_array()
        ca.get = MagicMock(return_value=None)

        result = ca.get_configuration()

        assert result["mac_address"] is None
        assert result["ifindex"] is None

    def test_get_configuration_mac_only(self):
        ca = _make_ctl_array()
        mac_val = MagicMock()
        mac_val.as_mac.return_value = "aa:bb:cc:dd:ee:ff"

        def fake_get(index):
            if index == CtlArrayIndex.MAC_ADDRESS_POS:
                return mac_val
            return None

        ca.get = MagicMock(side_effect=fake_get)

        result = ca.get_configuration()

        assert result["mac_address"] == "aa:bb:cc:dd:ee:ff"
        assert result["ifindex"] is None
