"""Tests for KatranService lifecycle."""

from unittest.mock import MagicMock, patch

import pytest

from katran.core.config import KatranConfig
from katran.service import KatranService


@pytest.fixture
def config():
    return KatranConfig.from_dict({
        "bpf": {"pin_path": "/tmp/fake"},
        "maps": {"max_vips": 64, "max_reals": 256, "ring_size": 13, "lru_size": 100},
    })


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

        call_count = 0

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
