"""Tests for KatranService lifecycle."""

from unittest.mock import MagicMock, patch

import pytest

from katran.core.config import KatranConfig
from katran.service import KatranService


@pytest.fixture
def config():
    return KatranConfig.from_dict(
        {
            "bpf": {"pin_path": "/tmp/fake"},
            "maps": {"max_vips": 64, "max_reals": 256, "ring_size": 13, "lru_size": 100},
        }
    )


def _make_mock_map():
    m = MagicMock()
    m.open = MagicMock()
    m.close = MagicMock()
    return m


@pytest.fixture
def mock_maps():
    """Patch all BPF map constructors to return mocks."""
    map_classes = [
        "katran.service.VipMap",
        "katran.service.RealsMap",
        "katran.service.ChRingsMap",
        "katran.service.StatsMap",
        "katran.service.CtlArray",
        "katran.service.HcRealsMap",
        "katran.service.LruMap",
    ]
    mocks = {}
    patchers = []
    for cls_path in map_classes:
        name = cls_path.rsplit(".", 1)[-1]
        mock_instance = _make_mock_map()
        # Add ring_size for ChRingsMap
        if name == "ChRingsMap":
            mock_instance.ring_size = 13
        p = patch(cls_path, return_value=mock_instance)
        mocks[name] = mock_instance
        patchers.append(p)

    for p in patchers:
        p.start()

    yield mocks

    for p in patchers:
        p.stop()


class TestServiceLifecycle:
    def test_start_opens_maps_and_creates_managers(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()

        assert svc.is_running
        assert svc.is_healthy
        assert svc.vip_manager is not None
        assert svc.real_manager is not None

        # All maps were opened
        for m in mock_maps.values():
            m.open.assert_called_once()

    def test_stop_closes_maps(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()
        svc.stop()

        assert not svc.is_running
        assert svc.vip_manager is None
        assert svc.real_manager is None

        for m in mock_maps.values():
            m.close.assert_called_once()

    def test_start_when_already_running(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()
        with pytest.raises(RuntimeError, match="already running"):
            svc.start()

    def test_stop_when_not_running(self, config, mock_maps):
        svc = KatranService(config)
        svc.stop()  # Should be a no-op, no error

    def test_is_running_transitions(self, config, mock_maps):
        svc = KatranService(config)
        assert not svc.is_running
        svc.start()
        assert svc.is_running
        svc.stop()
        assert not svc.is_running

    def test_failed_start_cleans_up(self, config):
        """If a map open() fails, already-opened maps should be closed."""
        good_map = _make_mock_map()
        bad_map = _make_mock_map()
        bad_map.open.side_effect = OSError("Permission denied")


        def make_map_factory(instances):
            """Return different mock instances on successive calls."""
            idx = [0]

            def factory(*args, **kwargs):
                if idx[0] < len(instances):
                    m = instances[idx[0]]
                    idx[0] += 1
                    return m
                return _make_mock_map()

            return factory

        # VipMap succeeds, RealsMap fails
        with (
            patch("katran.service.VipMap", side_effect=lambda *a, **kw: good_map),
            patch("katran.service.RealsMap", side_effect=lambda *a, **kw: bad_map),
            patch("katran.service.ChRingsMap", side_effect=lambda *a, **kw: _make_mock_map()),
            patch("katran.service.StatsMap", side_effect=lambda *a, **kw: _make_mock_map()),
            patch("katran.service.CtlArray", side_effect=lambda *a, **kw: _make_mock_map()),
            patch("katran.service.HcRealsMap", side_effect=lambda *a, **kw: _make_mock_map()),
            patch("katran.service.LruMap", side_effect=lambda *a, **kw: _make_mock_map()),
        ):
            svc = KatranService(config)
            with pytest.raises(OSError):
                svc.start()

            # Service should not be running
            assert not svc.is_running
            # The good map that was opened before failure should have been closed
            good_map.close.assert_called_once()

from katran.core.constants import KatranFeature
from katran.core.exceptions import FeatureNotEnabledError, KatranError
from katran.core.types import Protocol, VipKey
from ipaddress import IPv4Address


class TestServiceFeatureChecks:
    def test_has_feature_returns_true_when_enabled(self, mock_maps):
        config_with_src = KatranConfig.from_dict({
            "bpf": {"pin_path": "/tmp/fake"},
            "maps": {"max_vips": 64, "max_reals": 256, "ring_size": 13, "lru_size": 100},
            "features": int(KatranFeature.SRC_ROUTING),
        })
        svc = KatranService(config_with_src)
        svc.start()

        assert svc.has_feature(KatranFeature.SRC_ROUTING) is True

    def test_has_feature_returns_false_when_not_enabled(self, config, mock_maps):
        svc = KatranService(config)  # No features enabled
        svc.start()

        assert svc.has_feature(KatranFeature.SRC_ROUTING) is False

    def test_require_feature_raises_when_not_enabled(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()

        with pytest.raises(FeatureNotEnabledError):
            svc._require_feature(KatranFeature.SRC_ROUTING)

    def test_require_manager_raises_when_none(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()

        with pytest.raises(KatranError, match="not available"):
            svc._require_manager(None, "TestManager")

    def test_require_manager_returns_manager_when_present(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()

        mock_mgr = MagicMock()
        result = svc._require_manager(mock_mgr, "TestManager")

        assert result is mock_mgr


class TestServiceTryOpen:
    def test_try_open_success_returns_map(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()

        mock_map = MagicMock()
        mock_cls = MagicMock(return_value=mock_map)

        result = svc._try_open(mock_cls, "/fake/path")

        assert result is mock_map
        mock_map.open.assert_called_once()
        assert mock_map in svc._opened_maps

    def test_try_open_failure_returns_none(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()

        mock_cls = MagicMock(side_effect=OSError("map not found"))
        mock_cls.__name__ = "FakeMap"

        result = svc._try_open(mock_cls, "/fake/path")

        assert result is None


class TestServiceIsHealthy:
    def test_is_healthy_true_when_running_with_managers(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()

        assert svc.is_healthy is True

    def test_is_healthy_false_when_not_running(self, config):
        svc = KatranService(config)

        assert svc.is_healthy is False

    def test_is_healthy_false_when_vip_manager_is_none(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()
        svc.vip_manager = None

        assert svc.is_healthy is False


class TestServiceDelegation:
    """Test that service delegation methods call through to the right manager."""

    def test_get_vip_stats_delegates_to_stats_manager(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()
        svc._stats_manager = MagicMock()

        svc.get_vip_stats(vip_num=0)

        svc._stats_manager.get_vip_stats.assert_called_once_with(0)

    def test_get_real_stats_delegates_to_stats_manager(self, config, mock_maps):
        svc = KatranService(config)
        svc.start()
        svc._stats_manager = MagicMock()

        svc.get_real_stats(real_index=1)

        svc._stats_manager.get_real_stats.assert_called_once_with(1)

    def test_add_decap_dst_raises_feature_not_enabled(self, config, mock_maps):
        """add_decap_dst raises FeatureNotEnabledError when INLINE_DECAP not configured."""
        svc = KatranService(config)
        svc.start()

        with pytest.raises(FeatureNotEnabledError):
            svc.add_decap_dst("10.0.0.1")

    def test_add_src_routing_rules_raises_feature_not_enabled(self, config, mock_maps):
        """add_src_routing_rules raises FeatureNotEnabledError when SRC_ROUTING not configured."""
        svc = KatranService(config)
        svc.start()

        with pytest.raises(FeatureNotEnabledError):
            svc.add_src_routing_rules(["192.168.0.0/24"], "10.0.0.1")

    def test_add_hc_dst_raises_feature_not_enabled(self, config, mock_maps):
        """add_hc_dst raises FeatureNotEnabledError when DIRECT_HEALTHCHECKING not configured."""
        svc = KatranService(config)
        svc.start()

        with pytest.raises(FeatureNotEnabledError):
            svc.add_hc_dst(somark=1, dst="10.0.0.1")

    def test_add_down_real_raises_when_manager_not_initialized(self, config, mock_maps):
        """add_down_real raises KatranError when down_real_manager not available."""
        svc = KatranService(config)
        svc.start()
        svc._down_real_manager = None

        with pytest.raises(KatranError, match="not available"):
            key = VipKey(IPv4Address("10.0.0.1"), 80, Protocol.TCP)
            svc.add_down_real(key, real_index=1)
