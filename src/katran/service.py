"""
Katran service coordinator.

Wires together BPF maps, managers, and provides lifecycle management.
"""

from __future__ import annotations

import logging
from typing import Optional

from katran.bpf import (
    ChRingsMap,
    CtlArray,
    HcRealsMap,
    LruMap,
    RealsMap,
    StatsMap,
    VipMap,
)
from katran.core.config import KatranConfig
from katran.core.logging import get_logger
from katran.lb import MaglevHashRing, RealManager, VipManager

logger = get_logger(__name__)


class KatranService:
    """
    Main service coordinator that owns maps, managers, and lifecycle.

    Attributes:
        config: Service configuration.
        vip_map, reals_map, ch_rings_map, stats_map, ctl_array,
        hc_reals_map, lru_map: BPF map wrappers (set after start).
        vip_manager, real_manager: High-level managers (set after start).
    """

    def __init__(self, config: KatranConfig) -> None:
        self.config = config

        # Maps (populated on start)
        self.vip_map: Optional[VipMap] = None
        self.reals_map: Optional[RealsMap] = None
        self.ch_rings_map: Optional[ChRingsMap] = None
        self.stats_map: Optional[StatsMap] = None
        self.ctl_array: Optional[CtlArray] = None
        self.hc_reals_map: Optional[HcRealsMap] = None
        self.lru_map: Optional[LruMap] = None

        # Managers (populated on start)
        self.vip_manager: Optional[VipManager] = None
        self.real_manager: Optional[RealManager] = None

        self._running = False
        self._opened_maps: list = []

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def is_healthy(self) -> bool:
        return (
            self._running
            and self.vip_manager is not None
            and self.real_manager is not None
        )

    def _open_maps(self) -> None:
        """Instantiate and open all BPF maps.

        Required maps (vip_map, reals_map, ch_rings_map, stats_map, ctl_array)
        must succeed.  Optional maps (hc_reals_map, lru_map) are opened on a
        best-effort basis – failure is logged but does not prevent startup.
        """
        pin_path = self.config.bpf.pin_path
        maps_cfg = self.config.maps

        self.vip_map = VipMap(pin_path, max_vips=maps_cfg.max_vips)
        self.reals_map = RealsMap(pin_path, max_reals=maps_cfg.max_reals)
        self.ch_rings_map = ChRingsMap(
            pin_path,
            ring_size=maps_cfg.ring_size,
            max_vips=maps_cfg.max_vips,
        )
        self.stats_map = StatsMap(pin_path, max_vips=maps_cfg.max_vips)
        self.ctl_array = CtlArray(pin_path)

        required_maps = [
            self.vip_map,
            self.reals_map,
            self.ch_rings_map,
            self.stats_map,
            self.ctl_array,
        ]

        for m in required_maps:
            m.open()
            self._opened_maps.append(m)
            logger.debug("Opened map: %s", type(m).__name__)

        # Optional maps – tolerate missing pins (e.g. hc_reals comes from a
        # separate TC healthcheck program that may not be loaded).
        optional_specs = [
            ("hc_reals_map", lambda: HcRealsMap(pin_path)),
            ("lru_map", lambda: LruMap(pin_path, max_entries=maps_cfg.lru_size)),
        ]

        for attr, factory in optional_specs:
            try:
                m = factory()
                m.open()
                setattr(self, attr, m)
                self._opened_maps.append(m)
                logger.debug("Opened optional map: %s", type(m).__name__)
            except Exception:
                logger.info("Optional map %s unavailable, skipping", attr)

    def _initialize_managers(self) -> None:
        """Create VipManager and RealManager with correct signatures."""
        self.vip_manager = VipManager(
            self.vip_map,
            self.ch_rings_map,
            max_vips=self.config.maps.max_vips,
        )

        ring_builder = MaglevHashRing(ring_size=self.config.maps.ring_size)

        self.real_manager = RealManager(
            self.reals_map,
            self.ch_rings_map,
            ring_builder=ring_builder,
            max_reals=self.config.maps.max_reals,
        )

        logger.info("Managers initialized")

    def _close_maps(self) -> None:
        """Close all opened maps."""
        for m in reversed(self._opened_maps):
            try:
                m.close()
            except Exception:
                logger.warning("Error closing map %s", type(m).__name__, exc_info=True)
        self._opened_maps.clear()

    def start(self) -> None:
        """Start the service: open maps, initialize managers."""
        if self._running:
            raise RuntimeError("Service is already running")

        logger.info("Starting Katran service...")
        try:
            self._open_maps()
            self._initialize_managers()
            self._running = True
            logger.info("Katran service started")
        except Exception:
            logger.error("Failed to start service, cleaning up", exc_info=True)
            self._close_maps()
            self.vip_manager = None
            self.real_manager = None
            raise

    def stop(self) -> None:
        """Stop the service and close all maps."""
        if not self._running:
            return

        logger.info("Stopping Katran service...")
        self._close_maps()
        self.vip_manager = None
        self.real_manager = None
        self._running = False
        logger.info("Katran service stopped")
