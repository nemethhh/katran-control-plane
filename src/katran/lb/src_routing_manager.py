"""Source-based routing manager using LPM trie BPF maps."""

from __future__ import annotations

import logging
from ipaddress import IPv4Network, IPv6Network, ip_network
from threading import RLock
from typing import TYPE_CHECKING

from katran.core.constants import MAX_LPM_SRC
from katran.core.exceptions import SrcRoutingError
from katran.core.types import V4LpmKey, V6LpmKey

if TYPE_CHECKING:
    from katran.bpf.maps.lpm_src_map import LpmSrcV4Map, LpmSrcV6Map
    from katran.lb.real_manager import RealManager

logger = logging.getLogger(__name__)


class SrcRoutingManager:
    def __init__(
        self,
        lpm_src_v4_map: LpmSrcV4Map,
        lpm_src_v6_map: LpmSrcV6Map,
        real_manager: RealManager,
        max_lpm_src: int = MAX_LPM_SRC,
    ) -> None:
        self._v4_map = lpm_src_v4_map
        self._v6_map = lpm_src_v6_map
        self._real_manager = real_manager
        self._max = max_lpm_src
        self._lpm_mapping: dict[tuple[str, int], int] = {}
        self._lpm_dst: dict[tuple[str, int], str] = {}
        self._lock = RLock()

    def add_rules(self, srcs: list[str], dst: str) -> int:
        """Add source routing rules. Returns count of failed validations."""
        failures = 0
        with self._lock:
            for src in srcs:
                try:
                    network = ip_network(src, strict=False)
                except ValueError:
                    failures += 1
                    continue

                key_tuple = (str(network.network_address), network.prefixlen)
                if key_tuple in self._lpm_mapping:
                    failures += 1
                    continue

                if len(self._lpm_mapping) >= self._max:
                    raise SrcRoutingError(f"LPM capacity reached ({self._max})")

                real_index = self._real_manager.increase_ref_count(dst)

                if isinstance(network, IPv4Network):
                    lpm_key = V4LpmKey(
                        prefixlen=network.prefixlen, addr=str(network.network_address)
                    )
                    self._v4_map.set(lpm_key, real_index)
                else:
                    lpm_key = V6LpmKey(
                        prefixlen=network.prefixlen, addr=str(network.network_address)
                    )
                    self._v6_map.set(lpm_key, real_index)

                self._lpm_mapping[key_tuple] = real_index
                self._lpm_dst[key_tuple] = dst

        return failures

    def del_rules(self, srcs: list[str]) -> bool:
        with self._lock:
            for src in srcs:
                try:
                    network = ip_network(src, strict=False)
                except ValueError:
                    continue

                key_tuple = (str(network.network_address), network.prefixlen)
                if key_tuple not in self._lpm_mapping:
                    continue

                dst = self._lpm_dst[key_tuple]
                self._real_manager.decrease_ref_count(dst)

                if isinstance(network, IPv4Network):
                    lpm_key = V4LpmKey(
                        prefixlen=network.prefixlen, addr=str(network.network_address)
                    )
                    self._v4_map.delete(lpm_key)
                else:
                    lpm_key = V6LpmKey(
                        prefixlen=network.prefixlen, addr=str(network.network_address)
                    )
                    self._v6_map.delete(lpm_key)

                del self._lpm_mapping[key_tuple]
                del self._lpm_dst[key_tuple]
        return True

    def clear_all(self) -> None:
        with self._lock:
            for key_tuple, dst in list(self._lpm_dst.items()):
                self._real_manager.decrease_ref_count(dst)
                network_addr, prefixlen = key_tuple
                try:
                    network = ip_network(f"{network_addr}/{prefixlen}", strict=False)
                    if isinstance(network, IPv4Network):
                        self._v4_map.delete(
                            V4LpmKey(prefixlen=prefixlen, addr=network_addr)
                        )
                    else:
                        self._v6_map.delete(
                            V6LpmKey(prefixlen=prefixlen, addr=network_addr)
                        )
                except Exception:
                    pass
            self._lpm_mapping.clear()
            self._lpm_dst.clear()

    def get_rules(self) -> dict[str, str]:
        """Returns 'src/prefix' -> 'dst_ip' from in-memory state."""
        with self._lock:
            result = {}
            for (network_addr, prefixlen), dst in self._lpm_dst.items():
                result[f"{network_addr}/{prefixlen}"] = dst
            return result

    def get_rule_count(self) -> int:
        with self._lock:
            return len(self._lpm_mapping)
