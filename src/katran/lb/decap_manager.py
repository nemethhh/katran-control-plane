"""Inline decapsulation destination manager."""

from __future__ import annotations

from threading import RLock
from typing import TYPE_CHECKING

from katran.core.exceptions import DecapError

if TYPE_CHECKING:
    from katran.bpf.maps.decap_dst_map import DecapDstMap


class DecapManager:
    def __init__(self, decap_dst_map: DecapDstMap, max_decap_dst: int = 6) -> None:
        self._map = decap_dst_map
        self._max = max_decap_dst
        self._decap_dsts: set[str] = set()
        self._lock = RLock()

    def add_dst(self, dst: str) -> None:
        with self._lock:
            if dst in self._decap_dsts:
                raise DecapError(f"Decap destination already exists: {dst}")
            if len(self._decap_dsts) >= self._max:
                raise DecapError(f"Decap destination capacity reached ({self._max})")
            self._map.set(dst, 1)
            self._decap_dsts.add(dst)

    def del_dst(self, dst: str) -> None:
        with self._lock:
            if dst not in self._decap_dsts:
                raise DecapError(f"Decap destination not found: {dst}")
            self._map.delete(dst)
            self._decap_dsts.discard(dst)

    def get_dsts(self) -> list[str]:
        with self._lock:
            return list(self._decap_dsts)

    def get_dst_count(self) -> int:
        with self._lock:
            return len(self._decap_dsts)
