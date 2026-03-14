"""
Constants and enumerations matching Katran BPF definitions.

These values must stay synchronized with:
- katran/lib/bpf/balancer_consts.h
- katran/lib/bpf/balancer_structs.h
"""

from enum import Enum, IntEnum, IntFlag

# =============================================================================
# Map Size Constants
# =============================================================================

RING_SIZE: int = 65537  # Maglev consistent hash ring size (prime number)
MAX_VIPS: int = 512  # Maximum number of VIPs
MAX_REALS: int = 4096  # Maximum number of backend servers
MAX_SUPPORTED_CPUS: int = 128  # Maximum CPUs for per-CPU structures
CH_RINGS_SIZE: int = MAX_VIPS * RING_SIZE  # Total consistent hash ring entries
STATS_MAP_SIZE: int = MAX_VIPS * 2  # Stats map size
CTL_MAP_SIZE: int = 16  # Control array size
DEFAULT_LRU_SIZE: int = 1000  # Default LRU map entries
DEFAULT_GLOBAL_LRU_SIZE: int = 10000  # Default global LRU entries

# =============================================================================
# Hash Seeds
# =============================================================================

INIT_JHASH_SEED: int = CH_RINGS_SIZE  # Hash seed for Maglev
INIT_JHASH_SEED_V6: int = MAX_VIPS  # IPv6 hash seed

# =============================================================================
# Network Protocol Constants
# =============================================================================

# Ethernet protocol types (big-endian values as seen in BPF)
BE_ETH_P_IP: int = 8  # 0x0800 in network order -> 0x0008 as u16
BE_ETH_P_IPV6: int = 56710  # 0x86DD in network order -> 0xDD86 as u16

# IP protocols
IPPROTO_TCP: int = 6
IPPROTO_UDP: int = 17
IPPROTO_IPIP: int = 4  # IP-in-IP encapsulation
IPPROTO_IPV6: int = 41  # IPv6-in-IPv4 encapsulation


class Protocol(IntEnum):
    """IP protocol values for VIP definitions."""

    TCP = 6
    UDP = 17


# =============================================================================
# VIP Flags
# =============================================================================


class VipFlags(IntFlag):
    """
    VIP behavior flags.

    These flags control how packets to a VIP are processed in the BPF program.
    Defined in katran/lib/bpf/balancer_structs.h
    """

    NONE = 0

    # Don't use client's source port for consistent hashing
    # Useful when clients use random source ports
    NO_SRC_PORT = 1 << 0  # F_HASH_NO_SRC_PORT

    # Bypass LRU cache for this VIP
    # Forces re-computation of backend selection for each packet
    NO_LRU = 1 << 1  # F_LRU_BYPASS

    # QUIC VIP - use QUIC connection ID for routing
    # Enables QUIC-aware load balancing
    QUIC_VIP = 1 << 2  # F_QUIC_VIP

    # Only use destination port for hashing
    # All packets to the same port go to same backend
    DPORT_HASH = 1 << 3  # F_HASH_DPORT_ONLY

    # Use source-based routing via LPM trie
    # Routes based on client IP prefix
    SRC_ROUTING = 1 << 4  # F_SRC_ROUTING

    # Local VIP - optimize for local delivery
    LOCAL_VIP = 1 << 5  # F_LOCAL_VIP

    # Use global LRU cache instead of per-CPU
    GLOBAL_LRU = 1 << 6  # F_GLOBAL_LRU

    # Use both source and destination ports for hashing
    HASH_SRC_DST_PORT = 1 << 7  # F_HASH_SRC_DST_PORT

    # Parse UDP stable routing header
    UDP_STABLE_ROUTING = 1 << 8  # F_UDP_STABLE_ROUTING_VIP

    # Enable UDP flow migration - check if real is down
    UDP_FLOW_MIGRATION = 1 << 9  # F_UDP_FLOW_MIGRATION


# =============================================================================
# Real (Backend) Flags
# =============================================================================


class RealFlags(IntFlag):
    """
    Backend server flags.

    These flags describe properties of backend servers.
    Defined in katran/lib/bpf/balancer_structs.h
    """

    NONE = 0

    # Backend uses IPv6 address
    IPV6 = 1 << 0  # F_IPV6

    # Backend is local (same machine as load balancer)
    LOCAL_REAL = 1 << 1  # F_LOCAL_REAL


# =============================================================================
# Packet Description Flags
# =============================================================================


class PacketFlags(IntFlag):
    """
    Internal packet processing flags.

    Used in packet_description structure during BPF processing.
    """

    NONE = 0

    # Packet is from ICMP error message
    ICMP = 1 << 0  # F_ICMP

    # TCP SYN flag is set
    SYN_SET = 1 << 1  # F_SYN_SET

    # TCP RST flag is set
    RST_SET = 1 << 2  # F_RST_SET


# =============================================================================
# Statistics Counter Indices
# =============================================================================


class StatsCounterIndex(IntEnum):
    """
    Indices for statistics counters in the stats map.

    The stats map is indexed by (vip_num * 2) + counter_offset.
    These are global counter indices (not per-VIP).
    """

    LRU_CNTRS = 0  # LRU cache hit counters
    LRU_MISS_CNTR = 1  # TCP SYN/non-SYN misses
    NEW_CONN_RATE_CNTR = 2  # New connection rate
    FALLBACK_LRU_CNTR = 3  # Fallback LRU hits
    ICMP_TOOBIG_CNTRS = 4  # ICMP PTB counters
    LPM_SRC_CNTRS = 5  # Source-based routing counters
    REMOTE_ENCAP_CNTRS = 6  # Remote encapsulation counters
    ENCAP_FAIL_CNTR = 7  # Encapsulation failure counters
    GLOBAL_LRU_CNTR = 8  # Global LRU counters
    CH_DROP_STATS = 9  # Consistent hash drop counters
    DECAP_CNTR = 10  # Decapsulation counters
    QUIC_ICMP_STATS = 11  # QUIC ICMP message counters
    ICMP_PTB_V6_STATS = 12  # IPv6 PTB counters
    ICMP_PTB_V4_STATS = 13  # IPv4 PTB counters
    XPOP_DECAP_SUCCESSFUL = 14  # Cross-PoP decap success
    UDP_FLOW_MIGRATION_STATS = 15  # UDP flow migration
    XDP_TOTAL_CNTR = 16  # Total XDP packets
    XDP_TX_CNTR = 17  # XDP_TX packets
    XDP_DROP_CNTR = 18  # XDP_DROP packets
    XDP_PASS_CNTR = 19  # XDP_PASS packets


class KatranFeature(IntFlag):
    """Config-driven feature enablement flags."""

    SRC_ROUTING = 1 << 0
    INLINE_DECAP = 1 << 1
    INTROSPECTION = 1 << 2
    GUE_ENCAP = 1 << 3
    DIRECT_HEALTHCHECKING = 1 << 4
    LOCAL_DELIVERY_OPTIMIZATION = 1 << 5
    FLOW_DEBUG = 1 << 6


class ModifyAction(Enum):
    """Action for batch modify operations."""

    ADD = "add"
    DEL = "del"


# Health Check Constants
HC_CTRL_MAP_SIZE = 4
HC_MAIN_INTF_POSITION = 3
HC_SRC_MAC_POS = 0
HC_DST_MAC_POS = 1
HC_STATS_SIZE = 1
V4_SRC_INDEX = 0
V6_SRC_INDEX = 1

# New Map Size Defaults
MAX_LPM_SRC = 3_000_000
MAX_DECAP_DST = 6
MAX_QUIC_REALS = 0x00FFFFFE


# =============================================================================
# Control Array Indices
# =============================================================================


class CtlArrayIndex(IntEnum):
    """
    Indices for the control array (ctl_array map).

    The control array stores global configuration like MAC addresses.
    """

    MAC_ADDRESS_POS = 0  # Default router MAC address
    IFINDEX_POS = 1  # Primary interface index


# =============================================================================
# QUIC Constants
# =============================================================================

QUIC_LONG_HEADER: int = 0x80
QUIC_SHORT_HEADER: int = 0x00
QUIC_CLIENT_INITIAL: int = 0x00
QUIC_0RTT: int = 0x10
QUIC_HANDSHAKE: int = 0x20
QUIC_RETRY: int = 0x30
QUIC_PACKET_TYPE_MASK: int = 0x30
QUIC_MIN_CONNID_LEN: int = 8  # Minimum connection ID length

QUIC_CONNID_VERSION_V1: int = 0x1
QUIC_CONNID_VERSION_V2: int = 0x2
QUIC_CONNID_VERSION_V3: int = 0x3

# =============================================================================
# TCP Server ID Routing (TPR) Constants
# =============================================================================

TCP_HDR_OPT_KIND_TPR: int = 0xB7  # TCP option kind for server ID
TCP_HDR_OPT_LEN_TPR: int = 6  # TCP option length
TCP_HDR_OPT_MAX_OPT_CHECKS: int = 15  # Max header options to check

# =============================================================================
# Timing Constants
# =============================================================================

ONE_SEC_NS: int = 1_000_000_000  # 1 second in nanoseconds
LRU_UDP_TIMEOUT_NS: int = 30_000_000_000  # 30 seconds in nanoseconds

# =============================================================================
# Packet Size Constants
# =============================================================================

MAX_PCKT_SIZE: int = 1514  # Max packet size (1500 IP + 14 ethernet)
ICMP_TOOBIG_SIZE: int = 98  # ICMP PTB message size (v4)
ICMP6_TOOBIG_SIZE: int = 262  # ICMP PTB message size (v6)
DEFAULT_TTL: int = 64  # TTL for outer IP headers

# =============================================================================
# GUE (Generic UDP Encapsulation) Constants
# =============================================================================

GUE_DPORT: int = 6080  # GUE UDP destination port
GUEV1_IPV6MASK: int = 0x30  # GUE IPv6 mask

# =============================================================================
# LRU Lookup Results
# =============================================================================


class LruLookupResult(IntEnum):
    """Results from LRU cache lookup in BPF."""

    DST_MATCH_IN_LRU = 0  # Entry matches current real_index
    DST_MISMATCH_IN_LRU = 1  # Entry differs from current real_index
    DST_NOT_FOUND_IN_LRU = 2  # Entry not found in LRU
    FURTHER_PROCESSING = -1  # Continue processing packet
