"""Per-VIP down real tracking via HASH_OF_MAPS."""

from __future__ import annotations

import ctypes
import logging
import os
import struct
from threading import RLock
from typing import TYPE_CHECKING

from katran.bpf.map_manager import (
    BPF_F_NO_PREALLOC,
    BpfAttrMapElem,
    BpfCmd,
    BpfMapType,
    _bpf_syscall,
    bpf_map_create,
    bpf_map_get_fd_by_id,
)
from katran.core.constants import MAX_REALS
from katran.core.types import VipKey

if TYPE_CHECKING:
    from katran.bpf.maps.down_reals_map import VipToDownRealsMap
    from katran.lb.vip_manager import VipManager

logger = logging.getLogger(__name__)


class DownRealManager:
    """Tracks per-VIP down backends using BPF HASH_OF_MAPS.

    The outer map (VipKey -> inner_map_id) is a HASH_OF_MAPS.  Each inner
    map is a plain HASH map (real_index u32 -> dummy u8) created on demand
    when the first backend for a VIP is marked down.
    """

    def __init__(self, down_reals_map: VipToDownRealsMap, vip_manager: VipManager) -> None:
        self._map = down_reals_map
        self._vip_manager = vip_manager
        self._lock = RLock()

    # ------------------------------------------------------------------
    # Inner-map helpers (raw BPF syscall wrappers)
    # ------------------------------------------------------------------

    def _get_or_create_inner_map(self, vip: VipKey) -> int:
        """Return an FD for the VIP's inner map, creating one if needed."""
        inner_map_id = self._map.get(vip)
        if inner_map_id is not None:
            return bpf_map_get_fd_by_id(inner_map_id)
        inner_fd = bpf_map_create(
            map_type=BpfMapType.HASH,
            key_size=4,
            value_size=1,
            max_entries=MAX_REALS,
            flags=BPF_F_NO_PREALLOC,
        )
        try:
            self._map.set(vip, inner_fd)
        except Exception:
            os.close(inner_fd)
            raise
        return inner_fd

    def _write_inner(self, fd: int, real_index: int, value: int) -> None:
        key_buf = ctypes.create_string_buffer(struct.pack("<I", real_index))
        val_buf = ctypes.create_string_buffer(struct.pack("B", value))
        attr = BpfAttrMapElem()
        attr.map_fd = fd
        attr.key = ctypes.cast(key_buf, ctypes.c_void_p).value or 0
        attr.value_or_next_key = ctypes.cast(val_buf, ctypes.c_void_p).value or 0
        attr.flags = 0
        _bpf_syscall(BpfCmd.MAP_UPDATE_ELEM, attr, ctypes.sizeof(attr))

    def _lookup_inner(self, fd: int, real_index: int) -> bool:
        key_buf = ctypes.create_string_buffer(struct.pack("<I", real_index))
        val_buf = ctypes.create_string_buffer(1)
        attr = BpfAttrMapElem()
        attr.map_fd = fd
        attr.key = ctypes.cast(key_buf, ctypes.c_void_p).value or 0
        attr.value_or_next_key = ctypes.cast(val_buf, ctypes.c_void_p).value or 0
        attr.flags = 0
        result = _bpf_syscall(BpfCmd.MAP_LOOKUP_ELEM, attr, ctypes.sizeof(attr))
        return result >= 0

    def _delete_inner(self, fd: int, real_index: int) -> None:
        key_buf = ctypes.create_string_buffer(struct.pack("<I", real_index))
        attr = BpfAttrMapElem()
        attr.map_fd = fd
        attr.key = ctypes.cast(key_buf, ctypes.c_void_p).value or 0
        attr.value_or_next_key = 0
        attr.flags = 0
        _bpf_syscall(BpfCmd.MAP_DELETE_ELEM, attr, ctypes.sizeof(attr))

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate_vip(self, vip: VipKey) -> None:
        if (
            self._vip_manager.get_vip(
                address=str(vip.address),
                port=vip.port,
                protocol=vip.protocol,
            )
            is None
        ):
            from katran.core.exceptions import VipNotFoundError

            raise VipNotFoundError(str(vip.address), vip.port, vip.protocol.name)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_down_real(self, vip: VipKey, real_index: int) -> None:
        """Mark a backend as down for a VIP."""
        with self._lock:
            self._validate_vip(vip)
            inner_fd = self._get_or_create_inner_map(vip)
            try:
                self._write_inner(inner_fd, real_index, 1)
            finally:
                os.close(inner_fd)

    def check_real(self, vip: VipKey, real_index: int) -> bool:
        """Return True if the backend is marked down for the VIP."""
        with self._lock:
            self._validate_vip(vip)
            inner_map_id = self._map.get(vip)
            if inner_map_id is None:
                return False
            try:
                inner_fd = bpf_map_get_fd_by_id(inner_map_id)
            except Exception:
                return False
            try:
                return self._lookup_inner(inner_fd, real_index)
            finally:
                os.close(inner_fd)

    def remove_vip(self, vip: VipKey) -> None:
        """Remove all down-real tracking for a VIP."""
        with self._lock:
            self._validate_vip(vip)
            self._map.delete(vip)

    def remove_real(self, vip: VipKey, real_index: int) -> None:
        """Un-mark a backend as down for a VIP."""
        with self._lock:
            self._validate_vip(vip)
            inner_map_id = self._map.get(vip)
            if inner_map_id is None:
                return
            try:
                inner_fd = bpf_map_get_fd_by_id(inner_map_id)
            except Exception:
                return
            try:
                self._delete_inner(inner_fd, real_index)
            finally:
                os.close(inner_fd)
