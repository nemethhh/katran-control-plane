"""Individual BPF map wrappers."""

from katran.bpf.maps.ch_rings_map import ChRingsMap
from katran.bpf.maps.ctl_array import CtlArray
from katran.bpf.maps.decap_dst_map import DecapDstMap
from katran.bpf.maps.decap_vip_stats_map import DecapVipStatsMap
from katran.bpf.maps.down_reals_map import VipToDownRealsMap
from katran.bpf.maps.hc_ctrl_map import HcCtrlMap
from katran.bpf.maps.hc_key_map import HcKeyMap
from katran.bpf.maps.hc_pckt_macs_map import HcPcktMacsMap
from katran.bpf.maps.hc_pckt_srcs_map import HcPcktSrcsMap
from katran.bpf.maps.hc_reals_map import HcRealsMap
from katran.bpf.maps.hc_stats_map import HcStatsMap
from katran.bpf.maps.lpm_src_map import LpmSrcV4Map, LpmSrcV6Map
from katran.bpf.maps.lru_map import LruMap
from katran.bpf.maps.lru_miss_stats_map import LruMissStatsMap
from katran.bpf.maps.pckt_srcs_map import PcktSrcsMap
from katran.bpf.maps.per_hckey_stats_map import PerHcKeyStatsMap
from katran.bpf.maps.quic_stats_map import QuicStatsMap
from katran.bpf.maps.reals_map import RealsMap
from katran.bpf.maps.reals_stats_map import RealsStatsMap
from katran.bpf.maps.server_id_map import ServerIdMap
from katran.bpf.maps.server_id_stats_map import ServerIdStatsMap
from katran.bpf.maps.stats_map import StatsMap
from katran.bpf.maps.vip_map import VipMap

__all__ = [
    "ChRingsMap",
    "CtlArray",
    "DecapDstMap",
    "DecapVipStatsMap",
    "VipToDownRealsMap",
    "HcCtrlMap",
    "HcKeyMap",
    "HcPcktMacsMap",
    "HcPcktSrcsMap",
    "HcRealsMap",
    "HcStatsMap",
    "LpmSrcV4Map",
    "LpmSrcV6Map",
    "LruMap",
    "LruMissStatsMap",
    "PcktSrcsMap",
    "PerHcKeyStatsMap",
    "QuicStatsMap",
    "RealsMap",
    "RealsStatsMap",
    "ServerIdMap",
    "ServerIdStatsMap",
    "StatsMap",
    "VipMap",
]
