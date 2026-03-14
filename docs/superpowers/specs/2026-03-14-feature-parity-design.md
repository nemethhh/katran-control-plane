# Katran Control Plane Feature Parity Design

**Date:** 2026-03-14
**Status:** Draft
**Scope:** Close the feature gap between the Python control plane and Facebook's C++ reference implementation (excluding BPF loading).

## 1. Overview

The Python katran control plane currently implements VIP/backend management, consistent hashing (Maglev V2), basic stats/Prometheus metrics, and a REST API. The Facebook reference implementation has many additional control plane features that operate on BPF maps without requiring BPF program loading. This spec covers implementing those features.

### In Scope (10 features)

1. Health Check Manager (full HC system — 7 maps + manager)
2. LRU Management (search, list, delete, purge, analyze)
3. Source Routing (LPM trie maps + manager)
4. Inline Decapsulation (decap_dst map + manager)
5. QUIC Server ID (server_id_map + manager)
6. Down Real Tracking (HASH_OF_MAPS + manager)
7. All Additional Stats (full parity with reference)
8. Source IP for Encapsulation (pckt_srcs map)
9. Feature Flags (config-driven)
10. REST endpoints for all of the above

### Out of Scope

- BPF program loading/attaching/reloading
- gRPC API, CLI tool
- Flow debug / KatranMonitor / PCAP capture
- TCP Packet Router (separate BPF subsystem)
- Netlink operations

### Design Principles

- Mirror the reference implementation's API surface and behavior closely
- Follow Python best practices and existing project code style
- Config-driven feature enablement (no runtime BPF probing)
- Same layered pattern: BPF maps -> Managers -> Service -> REST API
- Shared real reference counting across VIP backends, source routing, and QUIC mappings

## 2. Approach: Foundation Then Vertical

Lay shared infrastructure first (types, constants, config, new BPF syscalls, map wrappers), then build each feature as a vertical slice (manager + service integration + REST + tests).

## 3. Foundation

### 3.1 New Constants (`constants.py`)

The existing `StatsCounterIndex` in `constants.py` already has indices 0-6 and 8-19. The only missing entry is:

```python
ENCAP_FAIL_CNTR = 7  # Encapsulation failure counters
```

This fills the gap between `REMOTE_ENCAP_CNTRS = 6` and `GLOBAL_LRU_CNTR = 8`.

**Stats counter to getter method mapping** (for implementation clarity):

| StatsCounterIndex | StatsManager method | Reference C++ |
|---|---|---|
| LRU_CNTRS (0) | get_lru_stats() | getLruStats() |
| LRU_MISS_CNTR (1) | get_lru_miss_stats() | getLruMissStats() |
| NEW_CONN_RATE_CNTR (2) | get_new_conn_rate_stats() | isUnderFlood() |
| FALLBACK_LRU_CNTR (3) | get_lru_fallback_stats() | getLruFallbackStats() |
| ICMP_TOOBIG_CNTRS (4) | get_icmp_toobig_stats() | getIcmpTooBigStats() |
| LPM_SRC_CNTRS (5) | get_src_routing_stats() | getSrcRoutingStats() |
| REMOTE_ENCAP_CNTRS (6) | get_inline_decap_stats() | getInlineDecapStats() |
| ENCAP_FAIL_CNTR (7) | get_encap_fail_stats() | getEncapFailStats() |
| GLOBAL_LRU_CNTR (8) | get_global_lru_stats() | getGlobalLruStats() |
| CH_DROP_STATS (9) | get_ch_drop_stats() | getChDropStats() |
| DECAP_CNTR (10) | get_decap_stats() | getDecapStats() |
| QUIC_ICMP_STATS (11) | get_quic_icmp_stats() | getQuicIcmpStats() |
| ICMP_PTB_V6_STATS (12) | get_icmp_ptb_v6_stats() | getIcmpPtbV6Stats() |
| ICMP_PTB_V4_STATS (13) | get_icmp_ptb_v4_stats() | getIcmpPtbV4Stats() |
| XPOP_DECAP_SUCCESSFUL (14) | get_xpop_decap_stats() | getXPopDecapSuccessfulStats() |
| UDP_FLOW_MIGRATION_STATS (15) | get_udp_flow_migration_stats() | getUdpFlowMigrationStats() |
| XDP_TOTAL_CNTR (16) | get_xdp_total_stats() | getXdpTotalStats() |
| XDP_TX_CNTR (17) | get_xdp_tx_stats() | getXdpTxStats() |
| XDP_DROP_CNTR (18) | get_xdp_drop_stats() | getXdpDropStats() |
| XDP_PASS_CNTR (19) | get_xdp_pass_stats() | getXdpPassStats() |

New `KatranFeature` flag enum:

```python
class KatranFeature(IntFlag):
    SRC_ROUTING = 1 << 0
    INLINE_DECAP = 1 << 1
    INTROSPECTION = 1 << 2
    GUE_ENCAP = 1 << 3
    DIRECT_HEALTHCHECKING = 1 << 4
    LOCAL_DELIVERY_OPTIMIZATION = 1 << 5
    FLOW_DEBUG = 1 << 6
```

New HC constants:

```python
HC_CTRL_MAP_SIZE = 4
HC_MAIN_INTF_POSITION = 3
HC_SRC_MAC_POS = 0
HC_DST_MAC_POS = 1
HC_STATS_SIZE = 1
```

General encap source IP position constants (used by both balancer and HC subsystems):

```python
V4_SRC_INDEX = 0
V6_SRC_INDEX = 1
```

New map size defaults:

```python
MAX_LPM_SRC = 3_000_000
MAX_DECAP_DST = 6
MAX_QUIC_REALS = 0x00FFFFFE
```

New `ModifyAction` enum:

```python
class ModifyAction(Enum):
    ADD = "add"
    DEL = "del"
```

### 3.2 New Types (`types.py`)

```python
@dataclass(frozen=True)
class V4LpmKey:
    prefixlen: int
    addr: str  # IPv4 address

@dataclass(frozen=True)
class V6LpmKey:
    prefixlen: int
    addr: str  # IPv6 address

# NOTE: HC keys use the existing VipKey type. The BPF hc_key struct has the
# same layout as vip_definition (16-byte address + 2-byte port + 1-byte proto
# + 1-byte padding = 20 bytes). The reference C++ uses VipKey for HC key
# operations (addHcKey/delHcKey). We reuse VipKey for the same reason.

@dataclass
class HcMac:
    mac: bytes  # 6 bytes

@dataclass
class HcRealDefinition:
    """Value type for hc_reals_map. Stores the actual backend address and flags.

    BPF layout: 16-byte address union + 1-byte flags + 3-byte padding = 20 bytes.

    BYTE ORDER NOTE: The C++ reference has a byte-order conditional in
    addHealthcheckerDst(). When tunnelBasedHCEncap is True (default),
    IPv4 addresses are written in host endian (parseAddrToInt). When
    directHealthchecking is enabled, addresses use network byte order
    (parseAddrToBe). The HealthCheckManager must accept a `tunnel_based_hc`
    flag in __init__ to control serialization behavior.

    NOTE: The existing HcRealsMap incorrectly stores u32 real_index values.
    It must be rewritten to store HcRealDefinition (hc_real_definition struct)
    matching the BPF map definition in healthchecking_maps.h.
    """
    address: str  # IPv4 or IPv6
    flags: int = 0  # V6DADDR = 1 << 0

@dataclass
class QuicReal:
    address: str
    id: int  # server ID (up to 24-bit)

@dataclass
class QuicPacketStats:
    """Per-CPU aggregated QUIC stats. Field order MUST match BPF lb_quic_packets_stats."""
    ch_routed: int = 0
    cid_initial: int = 0
    cid_invalid_server_id: int = 0
    cid_invalid_server_id_sample: int = 0  # sample of invalid server IDs
    cid_routed: int = 0
    cid_unknown_real_dropped: int = 0
    cid_v0: int = 0
    cid_v1: int = 0
    cid_v2: int = 0
    cid_v3: int = 0
    dst_match_in_lru: int = 0
    dst_mismatch_in_lru: int = 0
    dst_not_found_in_lru: int = 0

@dataclass
class HealthCheckProgStats:
    """HC program statistics. Used as both the BPF-level type (hc_stats struct
    deserialization in hc_stats_map wrapper) and the API response type.

    BPF field names use pckts_ prefix; Python uses packets_ for readability.
    The map wrapper handles the field name translation during deserialization.
    """
    packets_processed: int = 0
    packets_dropped: int = 0
    packets_skipped: int = 0
    packets_too_big: int = 0
    packets_dst_matched: int = 0

# LRU analysis types
@dataclass
class LruEntry:
    flow: FlowKey
    real_index: int
    atime: int  # nanoseconds
    atime_delta_sec: float
    cpu: int  # -1 for fallback

@dataclass
class LruEntries:
    entries: list[LruEntry]
    error: str = ""

@dataclass
class VipLruStats:
    entry_count: int = 0
    stale_real_count: int = 0
    atime_zero_count: int = 0
    atime_under_30s_count: int = 0
    atime_30_to_60s_count: int = 0
    atime_over_60s_count: int = 0

@dataclass
class LruAnalysis:
    total_entries: int = 0
    per_vip: dict[str, VipLruStats] = field(default_factory=dict)
    error: str = ""

@dataclass
class PurgeResponse:
    deleted_count: int = 0
    error: str = ""
```

### 3.3 Config Extensions (`config.py`)

The existing config uses **Pydantic BaseModel** (not dataclasses). New fields follow the same pattern:

```python
class MapConfig(BaseModel):
    # Existing fields...
    # New
    max_lpm_src: int = MAX_LPM_SRC       # 3,000,000
    max_decap_dst: int = MAX_DECAP_DST    # 6
    max_quic_reals: int = MAX_QUIC_REALS  # 0x00FFFFFE

class KatranConfig(BaseModel):
    # Existing fields...
    # New - KatranFeature IntFlag, serialized as int in YAML
    features: int = 0  # KatranFeature flags, validated in model_validator
    tunnel_based_hc: bool = True  # HC uses tunnel encap (affects address byte order)

    @field_validator("features", mode="before")
    @classmethod
    def validate_features(cls, v: Any) -> int:
        """Accept int, list of feature names, or KatranFeature."""
        if isinstance(v, list):
            result = KatranFeature(0)
            for name in v:
                result |= KatranFeature[name.upper()]
            return int(result)
        return int(v)
```

YAML config example:
```yaml
maps:
  max_lpm_src: 3000000
  max_decap_dst: 6
features:
  - src_routing
  - direct_healthchecking
  - inline_decap
```

The `_normalize_flat_config` function must also be updated to pass through `features` and new map fields.

### 3.4 New Exceptions (`exceptions.py`)

```python
class FeatureNotEnabledError(KatranError):
    def __init__(self, feature: str): ...

class HealthCheckError(KatranError): ...
class SrcRoutingError(KatranError): ...
class QuicMappingError(KatranError): ...
class DecapError(KatranError): ...
```

### 3.5 New BPF Syscalls (`map_manager.py`)

For HASH_OF_MAPS support (down real tracking). The existing `BpfCmd` enum already has `MAP_CREATE = 0`. Add:

```python
class BpfCmd(IntEnum):
    # Existing...
    MAP_GET_FD_BY_ID = 14  # NEW: get map FD from kernel map ID
```

New ctypes structures needed:

```python
class BpfAttrMapCreate(ctypes.Structure):
    """Attribute for BPF_MAP_CREATE syscall."""
    _fields_ = [
        ("map_type", ctypes.c_uint32),
        ("key_size", ctypes.c_uint32),
        ("value_size", ctypes.c_uint32),
        ("max_entries", ctypes.c_uint32),
        ("map_flags", ctypes.c_uint32),
    ]

class BpfAttrGetId(ctypes.Structure):
    """Attribute for BPF_MAP_GET_FD_BY_ID syscall."""
    _fields_ = [
        ("map_id", ctypes.c_uint32),
    ]
```

**Kernel bpf_attr union sizing:** These structures must be embedded within a properly-sized `bpf_attr` buffer, matching the existing pattern in `map_manager.py` for `BpfAttrMapElem`. The kernel validates the full command structure. Use a `ctypes.Union` or zero-padded byte array that is at least as large as the kernel expects for each command.

New module-level functions:

- `bpf_map_create(map_type, key_size, value_size, max_entries, flags) -> fd` — create inner maps dynamically
- `bpf_map_get_fd_by_id(map_id) -> fd` — convert kernel map ID (from outer map lookup) to usable FD. Requires `CAP_SYS_ADMIN` or `CAP_BPF`.

### 3.6 RealManager Public Ref Counting

Expose reference counting as public methods (currently private `_increase_ref_count`/`_decrease_ref_count`). Called by SrcRoutingManager and QuicManager for shared real reference counting.

```python
def increase_ref_count(self, address: str) -> int:
    """Increment ref count for a real, allocating if new. Returns real index."""
    ...

def decrease_ref_count(self, address: str) -> None:
    """Decrement ref count for a real, freeing if count reaches 0."""
    ...

def get_index_for_real(self, address: str) -> int | None:
    """Get the current BPF array index for a real address, or None if not allocated."""
    ...
```

These are thin public wrappers that parse the address string and delegate to the existing `_increase_ref_count(IpAddress)` / `_decrease_ref_count(IpAddress)`. `increase_ref_count` returns `RealMeta.num` (the real index), not the full `RealMeta`. The `get_index_for_real` method is needed by `QuicManager.revalidate_server_ids()`.

## 4. New BPF Map Wrappers

All in `src/katran/bpf/maps/`, each following existing `BpfMap[K, V]` / `PerCpuBpfMap[K, V]` pattern.

| Map | File | Base Class | Key | Value | BPF Type |
|-----|------|-----------|-----|-------|----------|
| lpm_src_v4 | lpm_src_map.py | BpfMap | V4LpmKey | c_uint32 (real index) | LPM_TRIE |
| lpm_src_v6 | lpm_src_map.py | BpfMap | V6LpmKey | c_uint32 (real index) | LPM_TRIE |
| decap_dst | decap_dst_map.py | BpfMap | address (16 bytes) | c_uint32 (flags) | HASH |
| server_id_map | server_id_map.py | BpfMap | c_uint32 (server ID) | c_uint32 (real index) | ARRAY or HASH |
| reals_stats | reals_stats_map.py | PerCpuBpfMap | c_uint32 (real index) | LbStats | PERCPU_ARRAY |
| lru_miss_stats | lru_miss_stats_map.py | PerCpuBpfMap | c_uint32 (real index) | c_uint32 | PERCPU_ARRAY |
| quic_stats_map | quic_stats_map.py | PerCpuBpfMap | c_uint32 (0) | QuicPacketStats | PERCPU_ARRAY |
| decap_vip_stats | decap_vip_stats_map.py | PerCpuBpfMap | c_uint32 (VIP index) | LbStats | PERCPU_ARRAY |
| server_id_stats | server_id_stats_map.py | PerCpuBpfMap | c_uint32 (VIP index) | LbStats | PERCPU_ARRAY |
| hc_key_map | hc_key_map.py | BpfMap | VipKey (same BPF layout as hc_key) | c_uint32 (HC key index) | HASH |
| hc_ctrl_map | hc_ctrl_map.py | BpfMap | c_uint32 | c_uint32 | ARRAY |
| hc_pckt_srcs_map | hc_pckt_srcs_map.py | BpfMap | c_uint32 (0=v4, 1=v6) | RealDefinition | ARRAY |
| hc_pckt_macs | hc_pckt_macs_map.py | BpfMap | c_uint32 (0=src, 1=dst) | HcMac | ARRAY |
| hc_stats_map | hc_stats_map.py | PerCpuBpfMap | c_uint32 (0) | HcStats | PERCPU_ARRAY |
| per_hckey_stats | per_hckey_stats_map.py | PerCpuBpfMap | c_uint32 (HC key idx) | c_uint64 | PERCPU_ARRAY |
| pckt_srcs | pckt_srcs_map.py | BpfMap | c_uint32 (0=v4, 1=v6) | RealDefinition | ARRAY |
| vip_to_down_reals | down_reals_map.py | BpfMap (special) | VipKey | inner map ID (u32) | HASH_OF_MAPS |

**Important map wrapper notes:**

- **LPM_TRIE maps** (`lpm_src_v4`, `lpm_src_v6`): `get_next_key` is not supported by the kernel for LPM tries (returns EOPNOTSUPP). Iteration via `items()` / `keys()` will fail. The `SrcRoutingManager.get_rules()` method returns from its in-memory `_lpm_mapping` dict, not from BPF map iteration.

- **hc_reals_map rewrite**: The existing `HcRealsMap` stores `u32 -> u32` (SO_MARK -> real_index). The BPF `hc_reals_map` in `healthchecking_maps.h` stores `u32 -> hc_real_definition` (20 bytes: 16-byte address + 1-byte flags + 3 padding). **The existing HcRealsMap must be rewritten** to use `HcRealDefinition` as its value type instead of `int`. This matches the reference implementation where `addHealthcheckerDst(somark, dst)` writes the actual IP address to the map. Add `hc_reals_map.py` to the Modified Files list.

- **decap_dst key format**: The key is a 16-byte `address` struct (same as `balancer_structs.h`). IPv4 addresses go in the first 4 bytes with 12 zero-padding bytes, matching the existing codebase convention for all address types.

- **lru_miss_stats per-CPU aggregation**: `LruMissStatsMap` is `PERCPU_ARRAY` with `c_uint32` values. Per-CPU values are aggregated by **summation** (matching the C++ reference pattern). `StatsManager.get_lru_miss_stats_for_real(index)` returns the summed count across all CPUs.

- **HASH_OF_MAPS workflow** (vip_to_down_reals): See section 10 for detailed inner map lifecycle.

## 5. Health Check Manager

**File:** `src/katran/lb/hc_manager.py`

Coordinates all HC maps. Thread-safe via RLock.

### Interface

```python
class HealthCheckManager:
    def __init__(
        self,
        hc_reals_map: HcRealsMap,  # rewritten to store HcRealDefinition
        hc_key_map: HcKeyMap,
        hc_ctrl_map: HcCtrlMap,
        hc_pckt_srcs_map: HcPcktSrcsMap,
        hc_pckt_macs: HcPcktMacsMap,
        hc_stats_map: HcStatsMap,
        per_hckey_stats: PerHcKeyStatsMap,
        max_vips: int = MAX_VIPS,
        tunnel_based_hc: bool = True,  # controls HC address byte order
    ): ...

    # Destination management (writes IP address to hc_reals_map, not index).
    # Byte order depends on tunnel_based_hc flag:
    #   tunnel_based_hc=True (default): IPv4 host endian, IPv6 network byte order
    #   tunnel_based_hc=False (direct): both in network byte order
    def add_hc_dst(self, somark: int, dst: str) -> None: ...
    def del_hc_dst(self, somark: int) -> None: ...
    def get_hc_dsts(self) -> dict[int, str]: ...

    # HC key management (uses VipKey, matching reference's use of VipKey)
    def add_hc_key(self, key: VipKey) -> int: ...  # returns index
    def del_hc_key(self, key: VipKey) -> None: ...
    def get_hc_keys(self) -> dict[VipKey, int]: ...

    # Source IP/MAC configuration
    def set_hc_src_ip(self, address: str) -> None: ...
    def set_hc_dst_mac(self, mac: str) -> None: ...
    def set_hc_src_mac(self, mac: str) -> None: ...

    # Control
    def set_hc_interface(self, ifindex: int) -> None: ...

    # Statistics
    def get_stats(self) -> HealthCheckProgStats: ...
    def get_packets_for_hc_key(self, key: VipKey) -> int: ...
```

### Internal State

- `_hc_key_to_index: dict[VipKey, int]` — mirrors hc_key_map
- `_index_allocator: IndexAllocator` — for HC key indices (0 to max_vips-1)
- `_somark_to_dst: dict[int, str]` — mirrors hc_reals_map (somark -> IP address string)

### Reference Mapping

| Reference C++ | Python |
|---|---|
| addHealthcheckerDst(somark, dst) | add_hc_dst(somark, dst) |
| delHealthcheckerDst(somark) | del_hc_dst(somark) |
| getHealthcheckersDst() | get_hc_dsts() |
| updateHcKeyMap(ADD, key) | add_hc_key(key) |
| updateHcKeyMap(DEL, key) | del_hc_key(key) |
| getPacketsProcessedForHcKey(key) | get_packets_for_hc_key(key) |
| getStatsForHealthCheckProgram() | get_stats() |

## 6. LRU Manager

**File:** `src/katran/lb/lru_manager.py`

Advanced LRU operations matching the reference implementation, which iterates **all per-CPU LRU maps** plus the fallback cache.

### Per-CPU LRU Access Model

The reference uses `lru_mapping` (BPF_MAP_TYPE_ARRAY_OF_MAPS) where each entry is a per-CPU LRU hash map. Operations iterate all inner maps.

The LruManager accepts:
- `fallback_lru: LruMap` — the existing `fallback_cache` (single LRU hash, always present)
- `per_cpu_lru_fds: list[int] | None` — FDs for per-CPU inner LRU maps (obtained from `lru_mapping` array-of-maps via `bpf_map_lookup_elem` at each CPU index, then `bpf_map_get_fd_by_id`). If None, only the fallback is used.

All search/list/delete/purge/analyze operations iterate all available LRU maps (per-CPU + fallback), matching the reference behavior.

### Interface

```python
class LruManager:
    def __init__(
        self,
        fallback_lru: LruMap,
        per_cpu_lru_fds: list[int] | None = None,  # from lru_mapping array-of-maps
        lru_miss_stats_map: LruMissStatsMap | None = None,
        vip_manager: VipManager | None = None,
        real_manager: RealManager | None = None,
    ): ...

    def search(self, dst_vip: VipKey, src_ip: str, src_port: int) -> LruEntries: ...
    def list(self, dst_vip: VipKey, limit: int = 100) -> LruEntries: ...
    def delete(self, dst_vip: VipKey, src_ip: str, src_port: int) -> list[str]: ...
    def purge_vip(self, dst_vip: VipKey) -> PurgeResponse: ...
    def purge_vip_for_real(self, dst_vip: VipKey, real_index: int) -> PurgeResponse: ...
    def analyze(self) -> LruAnalysis: ...
    def get_vip_lru_miss_stats(self, vip: VipKey) -> dict[str, int]: ...
```

### Per-CPU FD Acquisition

During `KatranService.start()`, if `lru_mapping` is pinned:

```python
per_cpu_fds = []
for cpu in range(num_cpus):
    inner_id = lru_mapping_map.lookup(cpu)  # returns inner map ID
    if inner_id is not None:
        fd = bpf_map_get_fd_by_id(inner_id)
        per_cpu_fds.append(fd)
```

If `lru_mapping` is not pinned (not all deployments use per-CPU LRU), the LruManager operates on the fallback cache only. This gracefully degrades while still providing all operations.

### Reference Mapping

| Reference C++ | Python |
|---|---|
| searchLru(vip, srcIp, srcPort) | search(dst_vip, src_ip, src_port) |
| listLru(vip, limit) | list(dst_vip, limit) |
| deleteLru(vip, srcIp, srcPort) | delete(dst_vip, src_ip, src_port) |
| purgeVipLru(vip) | purge_vip(dst_vip) |
| purgeVipLruForReal(vip, realPos) | purge_vip_for_real(dst_vip, real_index) |
| analyzeLru() | analyze() |
| getVipLruMissStats(vip) | get_vip_lru_miss_stats(vip) |

## 7. Source Routing Manager

**File:** `src/katran/lb/src_routing_manager.py`

Manages LPM trie BPF maps for source-based routing. Uses RealManager for shared reference counting.

### Interface

```python
class SrcRoutingManager:
    def __init__(
        self,
        lpm_src_v4_map: LpmSrcV4Map,
        lpm_src_v6_map: LpmSrcV6Map,
        real_manager: RealManager,
        max_lpm_src: int = MAX_LPM_SRC,
    ): ...

    def add_rules(self, srcs: list[str], dst: str) -> int: ...  # returns failure count
    def del_rules(self, srcs: list[str]) -> bool: ...
    def clear_all(self) -> None: ...
    def get_rules(self) -> dict[str, str]: ...  # "src/prefix" -> "dst_ip"
    def get_rule_count(self) -> int: ...
```

### Internal State

- `_lpm_mapping: dict[tuple[str, int], int]` — (network_addr, prefixlen) -> real_num

### Key Behavior

- **add_rules**: validate dst, validate each src as CIDR, check capacity, call real_manager.increase_ref_count(dst), write to lpm_src_v4/v6 map. Returns count of sources that failed **validation** (invalid CIDR format, wrong address family). BPF map write failures raise exceptions rather than incrementing the count. Returns 0 on full success.
- **del_rules**: lookup in _lpm_mapping, call real_manager.decrease_ref_count(), delete from BPF map
- **clear_all**: iterate all entries, decrease ref counts, delete from BPF maps, clear mapping
- **get_rules**: returns from in-memory `_lpm_mapping`, NOT from BPF map iteration (LPM trie maps don't support get_next_key)

## 8. Inline Decapsulation Manager

**File:** `src/katran/lb/decap_manager.py`

Simple set of decap destinations.

### Interface

```python
class DecapManager:
    def __init__(self, decap_dst_map: DecapDstMap, max_decap_dst: int = MAX_DECAP_DST): ...

    def add_dst(self, dst: str) -> None: ...
    def del_dst(self, dst: str) -> None: ...
    def get_dsts(self) -> list[str]: ...
    def get_dst_count(self) -> int: ...
```

### Internal State

- `_decap_dsts: set[str]` — mirrors BPF map

## 9. QUIC Server ID Manager

**File:** `src/katran/lb/quic_manager.py`

Manages QUIC connection server ID to backend real mappings. Uses RealManager for shared reference counting.

### Interface

```python
class QuicManager:
    def __init__(
        self,
        server_id_map: ServerIdMap,
        real_manager: RealManager,
        max_server_ids: int = MAX_QUIC_REALS,
    ): ...

    def modify_mapping(self, action: ModifyAction, quic_reals: list[QuicReal]) -> int: ...
    def get_mapping(self) -> list[QuicReal]: ...
    def invalidate_server_ids(self, server_ids: list[int]) -> None: ...
    def revalidate_server_ids(self, quic_reals: list[QuicReal]) -> None: ...
```

### Internal State

- `_quic_mapping: dict[int, str]` — server_id -> real_address

### Key Behavior

- modify_mapping(ADD): validate address, validate ID bounds (0 < id <= MAX_QUIC_REALS), increase_ref_count, write to server_id_map
- modify_mapping(DEL): lookup, decrease_ref_count, delete/zero from server_id_map
- invalidate_server_ids: write 0 to each ID in BPF map (without touching ref counts or in-memory mapping)
- revalidate_server_ids: look up real's current index, write back to BPF map

## 10. Down Real Tracking

**File:** `src/katran/lb/down_real_manager.py`

Manages per-VIP sets of down reals via BPF HASH_OF_MAPS.

### Interface

```python
class DownRealManager:
    def __init__(self, down_reals_map: VipToDownRealsMap, vip_manager: VipManager): ...

    def add_down_real(self, vip: VipKey, real_index: int) -> None: ...
    def check_real(self, vip: VipKey, real_index: int) -> bool: ...
    def remove_vip(self, vip: VipKey) -> None: ...
    def remove_real(self, vip: VipKey, real_index: int) -> None: ...
```

### HASH_OF_MAPS Workflow

The outer map stores VipKey -> inner_map_id. Inner maps are `BPF_MAP_TYPE_HASH` with key=`c_uint32` (real_index) and value=`c_uint8` (dummy marker, presence = down).

**add_down_real(vip, real_index):**

1. Validate VIP exists via vip_manager
2. Convert VipKey to 20-byte BPF key (vip_definition layout)
3. Lookup outer map: `bpf_map_lookup_elem(outer_fd, &vip_key)` -> inner_map_id (u32)
4. If ENOENT (no inner map for this VIP):
   a. Create new inner map: `bpf_map_create(BPF_MAP_TYPE_HASH, key_size=4, value_size=1, max_entries=MAX_REALS, flags=BPF_F_NO_PREALLOC)` -> inner_fd
   b. Update outer map: `bpf_map_update_elem(outer_fd, &vip_key, &inner_fd)`
   c. Use inner_fd directly (no re-lookup needed, matching C++ pattern)
5. Else (inner map exists):
   a. Get inner map FD: `bpf_map_get_fd_by_id(inner_map_id)` -> inner_fd
6. Write to inner map: `bpf_map_update_elem(inner_fd, &real_index, &dummy_u8_1)`
7. `close(inner_fd)` (must always close to avoid FD leak, use try/finally)

**check_real(vip, real_index):**

1. Validate VIP exists
2. Lookup outer map -> inner_map_id. Return False if ENOENT
3. `bpf_map_get_fd_by_id(inner_map_id)` -> inner_fd
4. `bpf_map_lookup_elem(inner_fd, &real_index)` -> found or ENOENT
5. `close(inner_fd)`
6. Return True if found, False if ENOENT

**remove_vip(vip):**

1. Validate VIP exists
2. `bpf_map_delete_elem(outer_fd, &vip_key)` — kernel cleans up inner map when last reference drops
3. Return silently on ENOENT

**remove_real(vip, real_index):**

1. Validate VIP exists
2. Lookup outer map -> inner_map_id. Return silently if ENOENT
3. `bpf_map_get_fd_by_id(inner_map_id)` -> inner_fd
4. `bpf_map_delete_elem(inner_fd, &real_index)` — return silently on ENOENT
5. `close(inner_fd)`

**FD Lifecycle:** Inner map FDs obtained via `bpf_map_get_fd_by_id` MUST be closed after use. Use Python context managers or try/finally to prevent FD leaks. The `VipToDownRealsMap` wrapper should provide a `get_inner_map(vip_key)` context manager that auto-closes.

## 11. Enhanced Statistics

**File:** `src/katran/lb/stats_manager.py`

Centralized stats access. All global stats read from stats_map at position `max_vips + StatsCounterIndex.XXX`.

### Interface

```python
class StatsManager:
    def __init__(
        self,
        stats_map: StatsMap,
        max_vips: int = MAX_VIPS,
        reals_stats_map: RealsStatsMap | None = None,
        lru_miss_stats_map: LruMissStatsMap | None = None,
        quic_stats_map: QuicStatsMap | None = None,
        decap_vip_stats_map: DecapVipStatsMap | None = None,
        server_id_stats_map: ServerIdStatsMap | None = None,
        hc_stats_map: HcStatsMap | None = None,
        per_hckey_stats: PerHcKeyStatsMap | None = None,
    ): ...

    # Per-VIP
    def get_vip_stats(self, vip_num: int) -> LbStats: ...
    def get_decap_stats_for_vip(self, vip_num: int) -> LbStats: ...
    def get_sid_routing_stats_for_vip(self, vip_num: int) -> LbStats: ...

    # Per-real
    def get_real_stats(self, real_index: int) -> LbStats: ...
    def get_reals_stats(self, indices: list[int]) -> dict[int, LbStats]: ...

    # Global stats (each reading from stats_map at max_vips + StatsCounterIndex)
    def get_lru_stats(self) -> LbStats: ...
    def get_lru_miss_stats(self) -> LbStats: ...
    def get_new_conn_rate_stats(self) -> LbStats: ...
    def get_lru_fallback_stats(self) -> LbStats: ...
    def get_global_lru_stats(self) -> LbStats: ...
    def get_icmp_toobig_stats(self) -> LbStats: ...
    def get_icmp_ptb_v4_stats(self) -> LbStats: ...
    def get_icmp_ptb_v6_stats(self) -> LbStats: ...
    def get_ch_drop_stats(self) -> LbStats: ...
    def get_encap_fail_stats(self) -> LbStats: ...
    def get_src_routing_stats(self) -> LbStats: ...
    def get_inline_decap_stats(self) -> LbStats: ...
    def get_decap_stats(self) -> LbStats: ...
    def get_xpop_decap_stats(self) -> LbStats: ...
    def get_udp_flow_migration_stats(self) -> LbStats: ...
    def get_quic_icmp_stats(self) -> LbStats: ...
    def get_xdp_total_stats(self) -> LbStats: ...
    def get_xdp_tx_stats(self) -> LbStats: ...
    def get_xdp_drop_stats(self) -> LbStats: ...
    def get_xdp_pass_stats(self) -> LbStats: ...
    def get_per_core_packets_stats(self) -> list[int]: ...

    # Feature-specific stats
    def get_quic_packet_stats(self) -> QuicPacketStats: ...
    def get_hc_program_stats(self) -> HealthCheckProgStats: ...
    def get_packets_for_hc_key(self, hc_key_index: int) -> int: ...
    def get_lru_miss_stats_for_real(self, real_index: int) -> int: ...
```

### Prometheus Collector Extensions

New metrics in `KatranMetricsCollector`:

```
# Per-real
katran_real_packets_total{address}
katran_real_bytes_total{address}

# New global counters
katran_ch_drops_total
katran_encap_failures_total
katran_lru_fallback_hits_total
katran_global_lru_hits_total
katran_decap_packets_total
katran_src_routing_packets_total
katran_quic_icmp_total
katran_icmp_ptb_v4_total
katran_icmp_ptb_v6_total
katran_xpop_decap_total
katran_udp_flow_migration_total

# QUIC detailed
katran_quic_ch_routed_total
katran_quic_cid_routed_total
katran_quic_cid_invalid_server_id_total
katran_quic_cid_unknown_real_dropped_total

# HC program
katran_hc_packets_processed_total
katran_hc_packets_dropped_total
katran_hc_packets_skipped_total
```

## 12. Source IP for Encapsulation

No dedicated manager. Methods on KatranService:

```python
def set_src_ip_for_encap(self, address: str) -> None:
    """Write source IP to pckt_srcs and hc_pckt_srcs_map. Auto-detects v4/v6.

    Writes to whichever maps were successfully opened. pckt_srcs exists when
    GUE_ENCAP or DECAP_STRICT_DESTINATION is compiled in; hc_pckt_srcs_map
    exists when DIRECT_HEALTHCHECKING is enabled. Fails only if neither
    map was opened.
    """
    from ipaddress import ip_address
    addr = ip_address(address)
    index = V4_SRC_INDEX if addr.version == 4 else V6_SRC_INDEX
    real_def = RealDefinition(address=addr)
    written = False
    if self._pckt_srcs_map is not None:
        self._pckt_srcs_map.set(index, real_def)
        written = True
    if self._hc_pckt_srcs_map is not None:
        self._hc_pckt_srcs_map.set(index, real_def)
        written = True
    if not written:
        raise FeatureNotEnabledError("GUE_ENCAP or DIRECT_HEALTHCHECKING")
```

**pckt_srcs map opening**: The `pckt_srcs` map is opened on a **best-effort** basis (not feature-flag-gated), since it may be present for GUE encap, decap strict destination, or other scenarios. Use `try_open` like other optional maps.

## 13. Feature Flags (Config-Driven)

Features declared in `KatranConfig.features`. Service checks at startup to decide which maps to open and which managers to instantiate:

```python
def _open_optional_feature_maps(self) -> None:
    features = self._config.features

    if KatranFeature.SRC_ROUTING in features:
        self._lpm_src_v4_map = LpmSrcV4Map(...)
        self._lpm_src_v6_map = LpmSrcV6Map(...)

    if KatranFeature.INLINE_DECAP in features:
        self._decap_dst_map = DecapDstMap(...)

    if KatranFeature.DIRECT_HEALTHCHECKING in features:
        # Open all 6 HC-specific maps
        self._hc_key_map = HcKeyMap(...)
        self._hc_ctrl_map = HcCtrlMap(...)
        self._hc_pckt_srcs_map = HcPcktSrcsMap(...)
        self._hc_pckt_macs = HcPcktMacsMap(...)
        self._hc_stats_map = HcStatsMap(...)
        self._per_hckey_stats = PerHcKeyStatsMap(...)

    # Best-effort maps (may exist depending on BPF compile flags)
    self._pckt_srcs_map = self._try_open(PcktSrcsMap, ...)
    self._server_id_map = self._try_open(ServerIdMap, ...)
    self._down_reals_map = self._try_open(VipToDownRealsMap, ...)

    # Stats maps always best-effort
    self._reals_stats_map = self._try_open(RealsStatsMap, ...)
    self._lru_miss_stats_map = self._try_open(LruMissStatsMap, ...)
    self._quic_stats_map = self._try_open(QuicStatsMap, ...)
    self._decap_vip_stats_map = self._try_open(DecapVipStatsMap, ...)
    self._server_id_stats_map = self._try_open(ServerIdStatsMap, ...)
```

Feature check at operation time:

```python
def _require_feature(self, feature: KatranFeature) -> None:
    if feature not in self._config.features:
        raise FeatureNotEnabledError(feature.name)

def has_feature(self, feature: KatranFeature) -> bool:
    return feature in self._config.features
```

## 14. Service Integration

KatranService initializes managers conditionally and delegates:

```python
def _initialize_managers(self) -> None:
    # Existing
    self._vip_manager = VipManager(...)
    self._real_manager = RealManager(...)

    # Always
    self._stats_manager = StatsManager(stats_map=..., ...)
    self._lru_manager = LruManager(...) if self._lru_map is not None else None

    # Feature-gated
    if KatranFeature.DIRECT_HEALTHCHECKING in features:
        self._hc_manager = HealthCheckManager(...)
    if KatranFeature.SRC_ROUTING in features:
        self._src_routing_manager = SrcRoutingManager(...)
    if KatranFeature.INLINE_DECAP in features:
        self._decap_manager = DecapManager(...)
    # Map-presence-gated (not feature-flag-gated).
    # These maps are always compiled into the BPF program (not conditional),
    # so we try to open them and instantiate managers if they exist.
    if self._server_id_map is not None:
        self._quic_manager = QuicManager(...)
    if self._down_reals_map is not None:
        self._down_real_manager = DownRealManager(...)
```

Delegation with feature checks:

```python
def add_src_routing_rules(self, srcs: list[str], dst: str) -> int:
    self._require_feature(KatranFeature.SRC_ROUTING)
    return self._src_routing_manager.add_rules(srcs, dst)
```

## 15. REST API Endpoints

All new endpoints in `src/katran/api/rest/app.py`, following existing patterns (Pydantic models, POST for mutations, addresses in bodies not URLs).

### Health Check
```
POST   /api/v1/hc/dst/add
POST   /api/v1/hc/dst/remove
GET    /api/v1/hc/dst
POST   /api/v1/hc/key/add
POST   /api/v1/hc/key/remove
GET    /api/v1/hc/keys
POST   /api/v1/hc/src-ip
POST   /api/v1/hc/src-mac
POST   /api/v1/hc/dst-mac
POST   /api/v1/hc/interface
GET    /api/v1/hc/stats
GET    /api/v1/hc/stats/key
```

### Source Routing
```
POST   /api/v1/src-routing/add
POST   /api/v1/src-routing/remove
POST   /api/v1/src-routing/clear
GET    /api/v1/src-routing
```

### Inline Decapsulation
```
POST   /api/v1/decap/dst/add
POST   /api/v1/decap/dst/remove
GET    /api/v1/decap/dst
```

### QUIC Server ID
```
POST   /api/v1/quic/mapping
GET    /api/v1/quic/mapping
POST   /api/v1/quic/invalidate
POST   /api/v1/quic/revalidate
```

### Down Real Tracking
```
POST   /api/v1/down-reals/add
POST   /api/v1/down-reals/remove
POST   /api/v1/down-reals/remove-vip
POST   /api/v1/down-reals/check
```

### LRU Management
```
POST   /api/v1/lru/search
POST   /api/v1/lru/list
POST   /api/v1/lru/delete
POST   /api/v1/lru/purge-vip
POST   /api/v1/lru/purge-real
GET    /api/v1/lru/analyze
```

### Encapsulation Source IP
```
POST   /api/v1/encap/src-ip
```

### Statistics
```
GET    /api/v1/stats/vip?address=...&port=...&protocol=...   -> per-VIP stats
GET    /api/v1/stats/real?index=...                           -> per-real stats
GET    /api/v1/stats/global                                   -> all global stats as JSON object
GET    /api/v1/stats/quic                                     -> QUIC packet stats
GET    /api/v1/stats/hc                                       -> HC program stats
GET    /api/v1/stats/per-cpu                                  -> per-CPU packet breakdown
```

### Features
```
GET    /api/v1/features
```

### Error Mapping

```
FeatureNotEnabledError -> 400
HealthCheckError       -> 400
SrcRoutingError        -> 400
QuicMappingError       -> 400
DecapError             -> 400
```

## 16. Testing Strategy

### Unit Tests (one per manager, mocked BPF maps)

| File | Tests |
|------|-------|
| test_hc_manager.py | HC dst CRUD, HC key CRUD, index allocation, src IP/MAC, stats, capacity limits |
| test_lru_manager.py | search/list/delete, purge by VIP/real, analyze with atime buckets, stale reals |
| test_src_routing_manager.py | add/del rules v4/v6, CIDR validation, real ref counting, capacity, clear_all |
| test_decap_manager.py | add/del dst, capacity limit (6), duplicates, v4/v6 |
| test_quic_manager.py | add/del mappings, ref counting, ID bounds, invalidate/revalidate |
| test_down_real_manager.py | add/check/remove real, remove VIP, inner map creation, idempotent removes |
| test_stats_manager.py | all stat getters, per-VIP/real/QUIC/HC stats, None map handling |
| test_new_map_wrappers.py | LPM serialization, HcKey serialization, HASH_OF_MAPS ops |
| test_feature_flags.py | feature-gated map opening, FeatureNotEnabledError |
| test_rest_api_new.py | all new endpoints, error responses, feature-gated 400s |

### Integration Tests (Docker, real BPF maps)

- HC map operations, LPM trie operations, server ID map, HASH_OF_MAPS inner maps, per-CPU stats

### E2E Tests (multi-container, real XDP traffic)

- Source routing traffic, inline decap, HC probe routing, down real + UDP flow migration

## 17. File Summary

### New Files (33)

```
src/katran/bpf/maps/
    lpm_src_map.py, decap_dst_map.py, server_id_map.py,
    reals_stats_map.py, lru_miss_stats_map.py, quic_stats_map.py,
    decap_vip_stats_map.py, server_id_stats_map.py,
    hc_key_map.py, hc_ctrl_map.py, hc_pckt_srcs_map.py,
    hc_pckt_macs_map.py, hc_stats_map.py, per_hckey_stats_map.py,
    pckt_srcs_map.py, down_reals_map.py

src/katran/lb/
    hc_manager.py, lru_manager.py, src_routing_manager.py,
    decap_manager.py, quic_manager.py, down_real_manager.py,
    stats_manager.py

tests/unit/
    test_hc_manager.py, test_lru_manager.py, test_src_routing_manager.py,
    test_decap_manager.py, test_quic_manager.py, test_down_real_manager.py,
    test_stats_manager.py, test_new_map_wrappers.py,
    test_feature_flags.py, test_rest_api_new.py
```

### Modified Files (10)

```
src/katran/core/types.py          # New types (LPM keys, HcRealDefinition, QuicReal, etc.)
src/katran/core/constants.py      # ENCAP_FAIL_CNTR, KatranFeature, HC constants, ModifyAction
src/katran/core/config.py         # features field, MapConfig extensions, flat config normalization
src/katran/core/exceptions.py     # FeatureNotEnabledError, HealthCheckError, etc.
src/katran/bpf/map_manager.py     # bpf_map_get_fd_by_id, bpf_map_create, BpfCmd.MAP_GET_FD_BY_ID
src/katran/bpf/maps/hc_reals_map.py  # REWRITE: value type u32 -> HcRealDefinition (20 bytes)
src/katran/lb/real_manager.py     # Public increase/decrease_ref_count, get_index_for_real
src/katran/service.py             # Feature-gated maps, new managers, delegation methods
src/katran/api/rest/app.py        # All new REST endpoints
src/katran/stats/collector.py     # Extended Prometheus metrics
```
