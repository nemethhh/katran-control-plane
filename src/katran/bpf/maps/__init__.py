"""Individual BPF map wrappers."""

from katran.bpf.maps.vip_map import VipMap
from katran.bpf.maps.reals_map import RealsMap
from katran.bpf.maps.ch_rings_map import ChRingsMap
from katran.bpf.maps.stats_map import StatsMap
from katran.bpf.maps.ctl_array import CtlArray
from katran.bpf.maps.hc_reals_map import HcRealsMap
from katran.bpf.maps.lru_map import LruMap

__all__ = [
    "VipMap",
    "RealsMap",
    "ChRingsMap",
    "StatsMap",
    "CtlArray",
    "HcRealsMap",
    "LruMap",
]
