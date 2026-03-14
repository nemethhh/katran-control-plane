"""QUIC server ID to backend real mapping manager."""

from __future__ import annotations

import logging
from threading import RLock
from typing import TYPE_CHECKING

from katran.core.constants import MAX_QUIC_REALS, ModifyAction
from katran.core.exceptions import QuicMappingError
from katran.core.types import QuicReal

if TYPE_CHECKING:
    from katran.bpf.maps.server_id_map import ServerIdMap
    from katran.lb.real_manager import RealManager

logger = logging.getLogger(__name__)


class QuicManager:
    def __init__(
        self,
        server_id_map: ServerIdMap,
        real_manager: RealManager,
        max_server_ids: int = MAX_QUIC_REALS,
    ) -> None:
        self._map = server_id_map
        self._real_manager = real_manager
        self._max = max_server_ids
        self._quic_mapping: dict[int, str] = {}
        self._lock = RLock()

    def modify_mapping(self, action: ModifyAction, quic_reals: list[QuicReal]) -> int:
        failures = 0
        with self._lock:
            for qr in quic_reals:
                try:
                    if action == ModifyAction.ADD:
                        self._add_one(qr)
                    else:
                        self._del_one(qr)
                except (QuicMappingError, ValueError):
                    failures += 1
        return failures

    def _add_one(self, qr: QuicReal) -> None:
        if qr.id <= 0 or qr.id > self._max:
            raise QuicMappingError(f"Server ID {qr.id} out of range (1..{self._max})")
        real_index = self._real_manager.increase_ref_count(qr.address)
        self._map.set(qr.id, real_index)
        self._quic_mapping[qr.id] = qr.address

    def _del_one(self, qr: QuicReal) -> None:
        if qr.id not in self._quic_mapping:
            raise QuicMappingError(f"Server ID {qr.id} not found")
        self._real_manager.decrease_ref_count(self._quic_mapping[qr.id])
        self._map.set(qr.id, 0)
        del self._quic_mapping[qr.id]

    def get_mapping(self) -> list[QuicReal]:
        with self._lock:
            return [
                QuicReal(address=addr, id=sid) for sid, addr in self._quic_mapping.items()
            ]

    def invalidate_server_ids(self, server_ids: list[int]) -> None:
        """Write 0 to BPF map without touching ref counts or in-memory state."""
        with self._lock:
            for sid in server_ids:
                if sid in self._quic_mapping:
                    self._map.set(sid, 0)

    def revalidate_server_ids(self, quic_reals: list[QuicReal]) -> None:
        """Look up real's current index and write back to BPF map."""
        with self._lock:
            for qr in quic_reals:
                if qr.id in self._quic_mapping:
                    real_index = self._real_manager.get_index_for_real(qr.address)
                    if real_index is not None:
                        self._map.set(qr.id, real_index)
