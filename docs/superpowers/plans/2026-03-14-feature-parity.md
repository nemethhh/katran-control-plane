# Feature Parity Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the feature gap between the Python control plane and Facebook's C++ reference implementation (10 features, 33 new files, 10 modified files).

**Architecture:** Foundation-first approach — shared types, constants, config, and BPF syscalls laid first, then vertical slices per feature (map wrappers → manager → service integration → REST API → tests). Same layered pattern as existing code: BPF maps → Managers → Service → REST API.

**Tech Stack:** Python 3.11+, ctypes BPF syscalls, FastAPI, Pydantic v2, pytest with MagicMock, structlog, prometheus_client

**Spec:** `docs/superpowers/specs/2026-03-14-feature-parity-design.md`

---

## File Structure

### New Files (33)

```
src/katran/bpf/maps/
    lpm_src_map.py          # LPM trie maps for source routing (V4 + V6)
    decap_dst_map.py        # Decap destination hash map
    server_id_map.py        # QUIC server ID → real index
    pckt_srcs_map.py        # Encap source IP array
    reals_stats_map.py      # Per-real per-CPU stats
    lru_miss_stats_map.py   # Per-real LRU miss counts
    quic_stats_map.py       # QUIC packet stats
    decap_vip_stats_map.py  # Decap per-VIP stats
    server_id_stats_map.py  # Server ID per-VIP stats
    hc_key_map.py           # HC key → index hash
    hc_ctrl_map.py          # HC control array
    hc_pckt_srcs_map.py     # HC packet source IPs
    hc_pckt_macs_map.py     # HC packet MACs
    hc_stats_map.py         # HC program per-CPU stats
    per_hckey_stats_map.py  # Per-HC-key packet counts
    down_reals_map.py       # VIP → down reals (HASH_OF_MAPS)

src/katran/lb/
    hc_manager.py           # Health check coordinator
    lru_manager.py          # Advanced LRU operations
    src_routing_manager.py  # Source-based routing via LPM
    decap_manager.py        # Inline decapsulation destinations
    quic_manager.py         # QUIC server ID mappings
    down_real_manager.py    # Per-VIP down real tracking
    stats_manager.py        # Centralized stats access

tests/unit/
    test_hc_manager.py
    test_lru_manager.py
    test_src_routing_manager.py
    test_decap_manager.py
    test_quic_manager.py
    test_down_real_manager.py
    test_stats_manager.py
    test_new_map_wrappers.py
    test_feature_flags.py
    test_rest_api_new.py
```

### Modified Files (10)

```
src/katran/core/types.py          # New types (LPM keys, HC types, QUIC types, LRU analysis)
src/katran/core/constants.py      # ENCAP_FAIL_CNTR, KatranFeature, HC/map constants, ModifyAction
src/katran/core/config.py         # features field, MapConfig extensions
src/katran/core/exceptions.py     # FeatureNotEnabledError + 4 domain exceptions
src/katran/bpf/map_manager.py     # bpf_map_create, bpf_map_get_fd_by_id
src/katran/bpf/maps/hc_reals_map.py  # REWRITE: value u32 → HcRealDefinition (20 bytes)
src/katran/lb/real_manager.py     # Public increase/decrease_ref_count, get_index_for_real
src/katran/service.py             # Feature-gated maps, new managers, delegation
src/katran/api/rest/app.py        # All new REST endpoints
src/katran/stats/collector.py     # Extended Prometheus metrics
```

---

## Chunk 1: Foundation

### Task 1: New Types

**Files:**
- Modify: `src/katran/core/types.py`
- Test: `tests/unit/test_types.py`

- [ ] **Step 1: Write failing tests for new types**

```python
# Append to tests/unit/test_types.py

class TestV4LpmKey:
    def test_roundtrip(self):
        key = V4LpmKey(prefixlen=24, addr="10.0.0.0")
        data = key.to_bytes()
        assert len(data) == 8
        restored = V4LpmKey.from_bytes(data)
        assert restored == key

    def test_host_route(self):
        key = V4LpmKey(prefixlen=32, addr="192.168.1.1")
        data = key.to_bytes()
        restored = V4LpmKey.from_bytes(data)
        assert restored.prefixlen == 32


class TestV6LpmKey:
    def test_roundtrip(self):
        key = V6LpmKey(prefixlen=64, addr="2001:db8::")
        data = key.to_bytes()
        assert len(data) == 20
        restored = V6LpmKey.from_bytes(data)
        assert restored == key


class TestHcRealDefinition:
    def test_ipv4_roundtrip(self):
        hrd = HcRealDefinition(address="10.0.0.1", flags=0)
        data = hrd.to_bytes()
        assert len(data) == 20
        restored = HcRealDefinition.from_bytes(data)
        assert restored.address == "10.0.0.1"

    def test_ipv6_with_flag(self):
        hrd = HcRealDefinition(address="2001:db8::1", flags=1)
        data = hrd.to_bytes()
        restored = HcRealDefinition.from_bytes(data)
        assert restored.flags == 1


class TestQuicPacketStats:
    def test_defaults(self):
        stats = QuicPacketStats()
        assert stats.ch_routed == 0
        assert stats.cid_routed == 0


class TestHealthCheckProgStats:
    def test_defaults(self):
        stats = HealthCheckProgStats()
        assert stats.packets_processed == 0
```

- [ ] **Step 2: Run test** → `.venv/bin/python3 -m pytest tests/unit/test_types.py::TestV4LpmKey -v` → FAIL (ImportError)

- [ ] **Step 3: Implement new types**

Add to `src/katran/core/types.py` after the `LbStats` class:

```python
# =============================================================================
# LPM Trie Key Structures
# =============================================================================

V4_LPM_KEY_SIZE = 8   # __u32 prefixlen + 4-byte addr
V6_LPM_KEY_SIZE = 20  # __u32 prefixlen + 16-byte addr


@dataclass(frozen=True)
class V4LpmKey:
    """BPF LPM trie key for IPv4: { __u32 prefixlen; __be32 addr; }"""

    prefixlen: int
    addr: str

    def to_bytes(self) -> bytes:
        return struct.pack("<I", self.prefixlen) + IPv4Address(self.addr).packed

    @classmethod
    def from_bytes(cls, data: bytes) -> V4LpmKey:
        if len(data) != V4_LPM_KEY_SIZE:
            raise SerializationError(
                "V4LpmKey", "deserialize", f"Expected {V4_LPM_KEY_SIZE} bytes, got {len(data)}"
            )
        prefixlen = struct.unpack("<I", data[:4])[0]
        addr = str(IPv4Address(data[4:8]))
        return cls(prefixlen=prefixlen, addr=addr)


@dataclass(frozen=True)
class V6LpmKey:
    """BPF LPM trie key for IPv6: { __u32 prefixlen; __be32 addr[4]; }"""

    prefixlen: int
    addr: str

    def to_bytes(self) -> bytes:
        return struct.pack("<I", self.prefixlen) + IPv6Address(self.addr).packed

    @classmethod
    def from_bytes(cls, data: bytes) -> V6LpmKey:
        if len(data) != V6_LPM_KEY_SIZE:
            raise SerializationError(
                "V6LpmKey", "deserialize", f"Expected {V6_LPM_KEY_SIZE} bytes, got {len(data)}"
            )
        prefixlen = struct.unpack("<I", data[:4])[0]
        addr = str(IPv6Address(data[4:20]))
        return cls(prefixlen=prefixlen, addr=addr)


# =============================================================================
# Health Check Types
# =============================================================================

HC_REAL_DEFINITION_SIZE = 20  # 16-byte addr + 1-byte flags + 3 padding


@dataclass
class HcMac:
    """6-byte MAC address for HC packet construction."""

    mac: bytes  # 6 bytes

    def to_bytes(self) -> bytes:
        if len(self.mac) != 6:
            raise SerializationError("HcMac", "serialize", "MAC must be 6 bytes")
        return self.mac + b"\x00" * 2  # pad to 8 bytes for BPF alignment

    @classmethod
    def from_bytes(cls, data: bytes) -> HcMac:
        return cls(mac=data[:6])

    @classmethod
    def from_string(cls, mac_str: str) -> HcMac:
        mac_bytes = bytes.fromhex(mac_str.replace(":", "").replace("-", ""))
        return cls(mac=mac_bytes)


@dataclass
class HcRealDefinition:
    """Value for hc_reals_map: 16-byte addr + 1-byte flags + 3 padding = 20 bytes.

    Byte order depends on tunnel_based_hc flag (handled by HealthCheckManager).
    """

    address: str
    flags: int = 0  # V6DADDR = 1 << 0

    def to_bytes(self, tunnel_based_hc: bool = True) -> bytes:
        addr = ip_address(self.address)
        if isinstance(addr, IPv6Address):
            addr_bytes = addr.packed
        else:
            if tunnel_based_hc:
                # Host endian (little-endian on x86)
                addr_bytes = struct.pack("<I", int(addr)) + b"\x00" * 12
            else:
                # Network byte order
                addr_bytes = addr.packed + b"\x00" * 12
        flags_bytes = struct.pack("BBBB", self.flags, 0, 0, 0)
        return addr_bytes + flags_bytes

    @classmethod
    def from_bytes(cls, data: bytes, tunnel_based_hc: bool = True) -> HcRealDefinition:
        if len(data) != HC_REAL_DEFINITION_SIZE:
            raise SerializationError(
                "HcRealDefinition", "deserialize",
                f"Expected {HC_REAL_DEFINITION_SIZE} bytes, got {len(data)}",
            )
        flags = data[16]
        is_v6 = bool(flags & 1)
        if is_v6:
            address = str(IPv6Address(data[:16]))
        else:
            if tunnel_based_hc:
                addr_int = struct.unpack("<I", data[:4])[0]
                address = str(IPv4Address(addr_int))
            else:
                address = str(IPv4Address(data[:4]))
        return cls(address=address, flags=flags)


@dataclass
class HealthCheckProgStats:
    """HC BPF program statistics (hc_stats struct)."""

    packets_processed: int = 0
    packets_dropped: int = 0
    packets_skipped: int = 0
    packets_too_big: int = 0
    packets_dst_matched: int = 0


# =============================================================================
# QUIC Types
# =============================================================================


@dataclass
class QuicReal:
    """QUIC server ID to backend mapping."""

    address: str
    id: int  # server ID (up to 24-bit)


@dataclass
class QuicPacketStats:
    """Per-CPU aggregated QUIC stats. Field order matches BPF lb_quic_packets_stats."""

    ch_routed: int = 0
    cid_initial: int = 0
    cid_invalid_server_id: int = 0
    cid_invalid_server_id_sample: int = 0
    cid_routed: int = 0
    cid_unknown_real_dropped: int = 0
    cid_v0: int = 0
    cid_v1: int = 0
    cid_v2: int = 0
    cid_v3: int = 0
    dst_match_in_lru: int = 0
    dst_mismatch_in_lru: int = 0
    dst_not_found_in_lru: int = 0


# =============================================================================
# LRU Analysis Types
# =============================================================================


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

- [ ] **Step 4: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_types.py -v` → PASS

- [ ] **Step 5: Commit** → `git commit -m "feat: add LPM, HC, QUIC, and LRU analysis types"`

---

### Task 2: New Constants

**Files:**
- Modify: `src/katran/core/constants.py`

- [ ] **Step 1: Write failing test**

```python
# tests/unit/test_feature_flags.py
from katran.core.constants import (
    KatranFeature, ModifyAction, StatsCounterIndex,
    HC_CTRL_MAP_SIZE, V4_SRC_INDEX, V6_SRC_INDEX,
    MAX_LPM_SRC, MAX_DECAP_DST, MAX_QUIC_REALS,
)


class TestKatranFeature:
    def test_flag_values(self):
        assert KatranFeature.SRC_ROUTING == 1
        assert KatranFeature.INLINE_DECAP == 2
        assert KatranFeature.DIRECT_HEALTHCHECKING == 16

    def test_combine_flags(self):
        features = KatranFeature.SRC_ROUTING | KatranFeature.INLINE_DECAP
        assert KatranFeature.SRC_ROUTING in features
        assert KatranFeature.DIRECT_HEALTHCHECKING not in features

    def test_from_int(self):
        features = KatranFeature(5)  # SRC_ROUTING | INTROSPECTION
        assert KatranFeature.SRC_ROUTING in features


class TestModifyAction:
    def test_values(self):
        assert ModifyAction.ADD.value == "add"
        assert ModifyAction.DEL.value == "del"


class TestNewConstants:
    def test_encap_fail_cntr(self):
        assert StatsCounterIndex.ENCAP_FAIL_CNTR == 7

    def test_hc_constants(self):
        assert HC_CTRL_MAP_SIZE == 4
        assert V4_SRC_INDEX == 0
        assert V6_SRC_INDEX == 1

    def test_map_size_defaults(self):
        assert MAX_LPM_SRC == 3_000_000
        assert MAX_DECAP_DST == 6
        assert MAX_QUIC_REALS == 0x00FFFFFE
```

- [ ] **Step 2: Run test** → `.venv/bin/python3 -m pytest tests/unit/test_feature_flags.py -v` → FAIL

- [ ] **Step 3: Add constants to `src/katran/core/constants.py`**

Add `ENCAP_FAIL_CNTR = 7` to `StatsCounterIndex` between `REMOTE_ENCAP_CNTRS = 6` and `GLOBAL_LRU_CNTR = 8`.

Add after `StatsCounterIndex`:

```python
# =============================================================================
# Feature Flags
# =============================================================================


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


# =============================================================================
# Health Check Constants
# =============================================================================

HC_CTRL_MAP_SIZE = 4
HC_MAIN_INTF_POSITION = 3
HC_SRC_MAC_POS = 0
HC_DST_MAC_POS = 1
HC_STATS_SIZE = 1

# Encap source IP position indices
V4_SRC_INDEX = 0
V6_SRC_INDEX = 1

# =============================================================================
# New Map Size Defaults
# =============================================================================

MAX_LPM_SRC = 3_000_000
MAX_DECAP_DST = 6
MAX_QUIC_REALS = 0x00FFFFFE
```

Also add `from enum import Enum, IntEnum, IntFlag` to the imports (add `Enum` to the existing import).

- [ ] **Step 4: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_feature_flags.py -v` → PASS

- [ ] **Step 5: Commit** → `git commit -m "feat: add KatranFeature flags, ModifyAction, HC and map size constants"`

---

### Task 3: Config Extensions

**Files:**
- Modify: `src/katran/core/config.py`
- Test: `tests/unit/test_config.py`

- [ ] **Step 1: Write failing test**

```python
# Append to tests/unit/test_config.py

class TestFeatureConfig:
    def test_features_from_int(self):
        cfg = KatranConfig.from_dict({"features": 5})
        assert cfg.features == 5

    def test_features_from_list(self):
        cfg = KatranConfig.from_dict({"features": ["src_routing", "inline_decap"]})
        assert cfg.features == 3  # 1 | 2

    def test_features_default_zero(self):
        cfg = KatranConfig()
        assert cfg.features == 0

    def test_tunnel_based_hc_default(self):
        cfg = KatranConfig()
        assert cfg.tunnel_based_hc is True

    def test_map_config_new_fields(self):
        cfg = KatranConfig.from_dict({
            "maps": {"max_lpm_src": 1000, "max_decap_dst": 10, "max_quic_reals": 100}
        })
        assert cfg.maps.max_lpm_src == 1000
        assert cfg.maps.max_decap_dst == 10
        assert cfg.maps.max_quic_reals == 100

    def test_map_config_defaults(self):
        cfg = KatranConfig()
        assert cfg.maps.max_lpm_src == 3_000_000
        assert cfg.maps.max_decap_dst == 6

    def test_flat_config_passes_features(self):
        cfg = KatranConfig.from_dict({"interface": "eth0", "features": 3})
        assert cfg.features == 3
```

- [ ] **Step 2: Run test** → FAIL

- [ ] **Step 3: Implement config changes**

In `src/katran/core/config.py`:

Add to imports:
```python
from katran.core.constants import (
    DEFAULT_LRU_SIZE, MAX_REALS, MAX_VIPS, RING_SIZE,
    MAX_LPM_SRC, MAX_DECAP_DST, MAX_QUIC_REALS, KatranFeature,
)
```

Add fields to `MapConfig`:
```python
class MapConfig(BaseModel):
    max_vips: int = MAX_VIPS
    max_reals: int = MAX_REALS
    lru_size: int = DEFAULT_LRU_SIZE
    ring_size: int = RING_SIZE
    max_lpm_src: int = MAX_LPM_SRC
    max_decap_dst: int = MAX_DECAP_DST
    max_quic_reals: int = MAX_QUIC_REALS

    @field_validator("ring_size")
    @classmethod
    def validate_ring_size_prime(cls, v: int) -> int:
        if not _is_prime(v):
            raise ValueError(f"ring_size must be prime, got {v}")
        return v
```

Add fields to `KatranConfig`:
```python
class KatranConfig(BaseModel):
    interface: InterfaceConfig = InterfaceConfig()
    bpf: BpfConfig = BpfConfig()
    maps: MapConfig = MapConfig()
    api: ApiConfig = ApiConfig()
    logging: LogConfig = LogConfig()
    features: int = 0
    tunnel_based_hc: bool = True

    @field_validator("features", mode="before")
    @classmethod
    def validate_features(cls, v: Any) -> int:
        if isinstance(v, list):
            result = KatranFeature(0)
            for name in v:
                result |= KatranFeature[name.upper()]
            return int(result)
        return int(v)

    @model_validator(mode="before")
    @classmethod
    def normalize_flat(cls, data: Any) -> Any:
        if isinstance(data, dict) and _is_flat_config(data):
            return _normalize_flat_config(data)
        return data
```

In `_normalize_flat_config`, add new map fields to the `"maps"` section:
```python
        "maps": {
            "max_vips": data.get("max_vips", MAX_VIPS),
            "max_reals": data.get("max_reals", MAX_REALS),
            "lru_size": data.get("lru_size", DEFAULT_LRU_SIZE),
            "ring_size": data.get("ring_size", RING_SIZE),
            "max_lpm_src": data.get("max_lpm_src", MAX_LPM_SRC),
            "max_decap_dst": data.get("max_decap_dst", MAX_DECAP_DST),
            "max_quic_reals": data.get("max_quic_reals", MAX_QUIC_REALS),
        },
```

And add at the end of the returned dict:
```python
        "features": data.get("features", 0),
        "tunnel_based_hc": data.get("tunnel_based_hc", True),
```

In `_FLAT_KEYS`, add `"features"`, `"tunnel_based_hc"`, `"max_lpm_src"`, `"max_decap_dst"`, `"max_quic_reals"`.

- [ ] **Step 4: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_config.py tests/unit/test_feature_flags.py -v` → PASS

- [ ] **Step 5: Commit** → `git commit -m "feat: add feature flags and map size config extensions"`

---

### Task 4: New Exceptions

**Files:**
- Modify: `src/katran/core/exceptions.py`

- [ ] **Step 1: Write failing test**

```python
# Append to tests/unit/test_feature_flags.py

from katran.core.exceptions import (
    KatranError, FeatureNotEnabledError, HealthCheckError, SrcRoutingError,
    QuicMappingError, DecapError,
)


class TestNewExceptions:
    def test_feature_not_enabled(self):
        err = FeatureNotEnabledError("SRC_ROUTING")
        assert "SRC_ROUTING" in str(err)
        assert isinstance(err, KatranError)

    def test_health_check_error(self):
        err = HealthCheckError("HC map full")
        assert isinstance(err, KatranError)

    def test_src_routing_error(self):
        err = SrcRoutingError("invalid CIDR")
        assert isinstance(err, KatranError)

    def test_quic_mapping_error(self):
        err = QuicMappingError("ID out of range")
        assert isinstance(err, KatranError)

    def test_decap_error(self):
        err = DecapError("max destinations reached")
        assert isinstance(err, KatranError)
```

- [ ] **Step 2: Run test** → FAIL

- [ ] **Step 3: Add exceptions to `src/katran/core/exceptions.py`**

```python
# =============================================================================
# Feature Errors
# =============================================================================


class FeatureNotEnabledError(KatranError):
    """Raised when an operation requires a feature that is not enabled."""

    def __init__(self, feature: str) -> None:
        self.feature = feature
        super().__init__(f"Feature not enabled: {feature}")


class HealthCheckError(KatranError):
    """Raised when a health check operation fails."""

    pass


class SrcRoutingError(KatranError):
    """Raised when a source routing operation fails."""

    pass


class QuicMappingError(KatranError):
    """Raised when a QUIC server ID mapping operation fails."""

    pass


class DecapError(KatranError):
    """Raised when an inline decapsulation operation fails."""

    pass
```

- [ ] **Step 4: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_feature_flags.py -v` → PASS

- [ ] **Step 5: Commit** → `git commit -m "feat: add feature-gated and domain-specific exceptions"`

---

### Task 5: BPF Syscall Extensions

**Files:**
- Modify: `src/katran/bpf/map_manager.py`

- [ ] **Step 1: Write failing test**

```python
# Append to tests/unit/test_map_manager.py

class TestBpfMapCreate:
    def test_bpf_attr_map_create_struct(self):
        from katran.bpf.map_manager import BpfAttrMapCreate
        attr = BpfAttrMapCreate()
        attr.map_type = 1  # HASH
        attr.key_size = 4
        attr.value_size = 4
        attr.max_entries = 100
        attr.map_flags = 0
        assert ctypes.sizeof(attr) == 20

    def test_bpf_attr_get_id_struct(self):
        from katran.bpf.map_manager import BpfAttrGetId
        attr = BpfAttrGetId()
        attr.map_id = 42
        assert ctypes.sizeof(attr) >= 4

    def test_bpf_cmd_get_fd_by_id(self):
        from katran.bpf.map_manager import BpfCmd
        assert BpfCmd.MAP_GET_FD_BY_ID == 14
```

- [ ] **Step 2: Run test** → FAIL

- [ ] **Step 3: Add to `src/katran/bpf/map_manager.py`**

Add `MAP_GET_FD_BY_ID = 14` to `BpfCmd`.

Add after `BpfAttrObjGet`:

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


# BPF map creation flags
BPF_F_NO_PREALLOC = 1


def bpf_map_create(
    map_type: int, key_size: int, value_size: int, max_entries: int, flags: int = 0
) -> int:
    """Create a new BPF map. Returns file descriptor.

    Used for creating inner maps for HASH_OF_MAPS dynamically.
    Requires CAP_SYS_ADMIN or CAP_BPF.
    """
    # Pad attr to kernel-expected size (at least 48 bytes for MAP_CREATE)
    buf = (ctypes.c_char * 128)()
    attr = BpfAttrMapCreate.from_buffer(buf)
    attr.map_type = map_type
    attr.key_size = key_size
    attr.value_size = value_size
    attr.max_entries = max_entries
    attr.map_flags = flags

    result = _bpf_syscall(BpfCmd.MAP_CREATE, attr, 128)
    if result < 0:
        raise MapOperationError(
            "map_create", f"type={map_type}", error_code=-result, message=os.strerror(-result)
        )
    return result


def bpf_map_get_fd_by_id(map_id: int) -> int:
    """Get a map FD from a kernel map ID. Returns file descriptor.

    Used after looking up an outer HASH_OF_MAPS entry (which returns an inner map ID).
    Requires CAP_SYS_ADMIN or CAP_BPF.
    """
    buf = (ctypes.c_char * 128)()
    attr = BpfAttrGetId.from_buffer(buf)
    attr.map_id = map_id

    result = _bpf_syscall(BpfCmd.MAP_GET_FD_BY_ID, attr, 128)
    if result < 0:
        raise MapOperationError(
            "get_fd_by_id", f"map_id={map_id}", error_code=-result, message=os.strerror(-result)
        )
    return result
```

- [ ] **Step 4: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_map_manager.py -v` → PASS

- [ ] **Step 5: Commit** → `git commit -m "feat: add bpf_map_create and bpf_map_get_fd_by_id syscalls"`

---

### Task 6: RealManager Public Ref Counting

**Files:**
- Modify: `src/katran/lb/real_manager.py`
- Test: `tests/unit/test_real_manager.py`

- [ ] **Step 1: Write failing tests**

```python
# Append to tests/unit/test_real_manager.py

class TestRealManagerPublicRefCounting:
    def test_increase_ref_count_new_real(self, real_manager):
        index = real_manager.increase_ref_count("10.0.0.100")
        assert index >= 1
        assert real_manager.get_real_ref_count("10.0.0.100") == 1

    def test_increase_ref_count_existing_real(self, real_manager):
        idx1 = real_manager.increase_ref_count("10.0.0.100")
        idx2 = real_manager.increase_ref_count("10.0.0.100")
        assert idx1 == idx2
        assert real_manager.get_real_ref_count("10.0.0.100") == 2

    def test_decrease_ref_count(self, real_manager):
        real_manager.increase_ref_count("10.0.0.100")
        real_manager.increase_ref_count("10.0.0.100")
        real_manager.decrease_ref_count("10.0.0.100")
        assert real_manager.get_real_ref_count("10.0.0.100") == 1

    def test_decrease_ref_count_to_zero_frees(self, real_manager):
        real_manager.increase_ref_count("10.0.0.100")
        real_manager.decrease_ref_count("10.0.0.100")
        assert real_manager.get_real_ref_count("10.0.0.100") == 0

    def test_get_index_for_real(self, real_manager):
        idx = real_manager.increase_ref_count("10.0.0.100")
        assert real_manager.get_index_for_real("10.0.0.100") == idx

    def test_get_index_for_real_unknown(self, real_manager):
        assert real_manager.get_index_for_real("10.0.0.100") is None
```

- [ ] **Step 2: Run test** → FAIL

- [ ] **Step 3: Add public methods to `src/katran/lb/real_manager.py`**

Add after `get_real_ref_count`:

```python
    def increase_ref_count(self, address: str) -> int:
        """Increment ref count for a real, allocating if new. Returns real index.

        Public wrapper for shared ref counting used by SrcRoutingManager
        and QuicManager.
        """
        with self._lock:
            ip_addr = _parse_ip_address(address)
            meta = self._increase_ref_count(ip_addr)
            return meta.num

    def decrease_ref_count(self, address: str) -> None:
        """Decrement ref count for a real, freeing if count reaches 0."""
        with self._lock:
            ip_addr = _parse_ip_address(address)
            self._decrease_ref_count(ip_addr)

    def get_index_for_real(self, address: str) -> int | None:
        """Get the current BPF array index for a real address, or None."""
        with self._lock:
            ip_addr = _parse_ip_address(address)
            meta = self._reals.get(ip_addr)
            return meta.num if meta is not None else None
```

- [ ] **Step 4: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_real_manager.py -v` → PASS

- [ ] **Step 5: Commit** → `git commit -m "feat: expose public ref counting on RealManager for shared real tracking"`

---

## Chunk 2: Standard Map Wrappers

All map wrappers follow the existing `BpfMap[K, V]` / `PerCpuBpfMap[K, V]` pattern with `MAP_NAME`, `_key_size`, `_value_size`, `_serialize_key/value`, `_deserialize_key/value`. See `src/katran/bpf/maps/vip_map.py` and `src/katran/bpf/maps/stats_map.py` for reference.

### Task 7: LPM Source Maps + Decap Dst + Server ID + Pckt Srcs

**Files:**
- Create: `src/katran/bpf/maps/lpm_src_map.py`
- Create: `src/katran/bpf/maps/decap_dst_map.py`
- Create: `src/katran/bpf/maps/server_id_map.py`
- Create: `src/katran/bpf/maps/pckt_srcs_map.py`
- Test: `tests/unit/test_new_map_wrappers.py`

- [ ] **Step 1: Write failing test for LPM + decap + server_id + pckt_srcs serialization**

```python
# tests/unit/test_new_map_wrappers.py
"""Unit tests for new BPF map wrapper serialization."""

import struct
from ipaddress import IPv4Address, IPv6Address

import pytest

from katran.core.types import (
    V4LpmKey, V6LpmKey, RealDefinition, HcRealDefinition, HcMac,
)


class TestLpmSrcV4MapSerialization:
    def test_serialize_key(self):
        from katran.bpf.maps.lpm_src_map import LpmSrcV4Map
        m = LpmSrcV4Map.__new__(LpmSrcV4Map)
        key = V4LpmKey(prefixlen=24, addr="10.0.0.0")
        data = m._serialize_key(key)
        assert len(data) == 8
        assert struct.unpack("<I", data[:4])[0] == 24

    def test_deserialize_key(self):
        from katran.bpf.maps.lpm_src_map import LpmSrcV4Map
        m = LpmSrcV4Map.__new__(LpmSrcV4Map)
        key = V4LpmKey(prefixlen=24, addr="10.0.0.0")
        data = m._serialize_key(key)
        restored = m._deserialize_key(data)
        assert restored == key

    def test_serialize_value(self):
        from katran.bpf.maps.lpm_src_map import LpmSrcV4Map
        m = LpmSrcV4Map.__new__(LpmSrcV4Map)
        data = m._serialize_value(42)
        assert struct.unpack("<I", data)[0] == 42


class TestLpmSrcV6MapSerialization:
    def test_serialize_key(self):
        from katran.bpf.maps.lpm_src_map import LpmSrcV6Map
        m = LpmSrcV6Map.__new__(LpmSrcV6Map)
        key = V6LpmKey(prefixlen=64, addr="2001:db8::")
        data = m._serialize_key(key)
        assert len(data) == 20

    def test_roundtrip(self):
        from katran.bpf.maps.lpm_src_map import LpmSrcV6Map
        m = LpmSrcV6Map.__new__(LpmSrcV6Map)
        key = V6LpmKey(prefixlen=48, addr="2001:db8:1::")
        assert m._deserialize_key(m._serialize_key(key)) == key


class TestDecapDstMapSerialization:
    def test_key_ipv4(self):
        from katran.bpf.maps.decap_dst_map import DecapDstMap
        m = DecapDstMap.__new__(DecapDstMap)
        data = m._serialize_key("10.0.0.1")
        assert len(data) == 16  # 16-byte address struct
        assert data[:4] == IPv4Address("10.0.0.1").packed
        assert data[4:] == b"\x00" * 12

    def test_key_ipv6(self):
        from katran.bpf.maps.decap_dst_map import DecapDstMap
        m = DecapDstMap.__new__(DecapDstMap)
        data = m._serialize_key("2001:db8::1")
        assert len(data) == 16
        assert data == IPv6Address("2001:db8::1").packed

    def test_value_roundtrip(self):
        from katran.bpf.maps.decap_dst_map import DecapDstMap
        m = DecapDstMap.__new__(DecapDstMap)
        data = m._serialize_value(1)
        assert m._deserialize_value(data) == 1


class TestServerIdMapSerialization:
    def test_key_roundtrip(self):
        from katran.bpf.maps.server_id_map import ServerIdMap
        m = ServerIdMap.__new__(ServerIdMap)
        data = m._serialize_key(12345)
        assert m._deserialize_key(data) == 12345

    def test_value_roundtrip(self):
        from katran.bpf.maps.server_id_map import ServerIdMap
        m = ServerIdMap.__new__(ServerIdMap)
        data = m._serialize_value(7)
        assert m._deserialize_value(data) == 7


class TestPcktSrcsMapSerialization:
    def test_key_roundtrip(self):
        from katran.bpf.maps.pckt_srcs_map import PcktSrcsMap
        m = PcktSrcsMap.__new__(PcktSrcsMap)
        data = m._serialize_key(0)
        assert m._deserialize_key(data) == 0

    def test_value_roundtrip(self):
        from katran.bpf.maps.pckt_srcs_map import PcktSrcsMap
        m = PcktSrcsMap.__new__(PcktSrcsMap)
        rd = RealDefinition(address=IPv4Address("10.0.0.1"))
        data = m._serialize_value(rd)
        restored = m._deserialize_value(data)
        assert restored.address == IPv4Address("10.0.0.1")
```

- [ ] **Step 2: Run test** → `.venv/bin/python3 -m pytest tests/unit/test_new_map_wrappers.py -v` → FAIL

- [ ] **Step 3: Implement `lpm_src_map.py`**

```python
# src/katran/bpf/maps/lpm_src_map.py
"""LPM trie map wrappers for source-based routing.

NOTE: LPM_TRIE maps do not support get_next_key (EOPNOTSUPP).
Do not call items()/keys()/values() — SrcRoutingManager uses in-memory state.
"""

from __future__ import annotations

import struct

from katran.bpf.map_manager import BpfMap
from katran.core.constants import MAX_LPM_SRC
from katran.core.types import V4LpmKey, V4_LPM_KEY_SIZE, V6LpmKey, V6_LPM_KEY_SIZE


class LpmSrcV4Map(BpfMap[V4LpmKey, int]):
    """lpm_src_v4 BPF LPM trie: V4LpmKey → real_index (u32)."""

    MAP_NAME = "lpm_src_v4"

    def __init__(
        self, pin_base_path: str, map_name: str | None = None,
        max_entries: int = MAX_LPM_SRC,
    ) -> None:
        super().__init__(pin_base_path, map_name)
        self._max_entries = max_entries

    @property
    def _key_size(self) -> int:
        return V4_LPM_KEY_SIZE

    @property
    def _value_size(self) -> int:
        return 4

    def _serialize_key(self, key: V4LpmKey) -> bytes:
        return key.to_bytes()

    def _deserialize_key(self, data: bytes) -> V4LpmKey:
        return V4LpmKey.from_bytes(data)

    def _serialize_value(self, value: int) -> bytes:
        return struct.pack("<I", value)

    def _deserialize_value(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])


class LpmSrcV6Map(BpfMap[V6LpmKey, int]):
    """lpm_src_v6 BPF LPM trie: V6LpmKey → real_index (u32)."""

    MAP_NAME = "lpm_src_v6"

    def __init__(
        self, pin_base_path: str, map_name: str | None = None,
        max_entries: int = MAX_LPM_SRC,
    ) -> None:
        super().__init__(pin_base_path, map_name)
        self._max_entries = max_entries

    @property
    def _key_size(self) -> int:
        return V6_LPM_KEY_SIZE

    @property
    def _value_size(self) -> int:
        return 4

    def _serialize_key(self, key: V6LpmKey) -> bytes:
        return key.to_bytes()

    def _deserialize_key(self, data: bytes) -> V6LpmKey:
        return V6LpmKey.from_bytes(data)

    def _serialize_value(self, value: int) -> bytes:
        return struct.pack("<I", value)

    def _deserialize_value(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])
```

- [ ] **Step 4: Implement `decap_dst_map.py`**

```python
# src/katran/bpf/maps/decap_dst_map.py
"""Decap destination map: 16-byte address → flags (u32)."""

from __future__ import annotations

import struct
from ipaddress import IPv4Address, IPv6Address, ip_address

from katran.bpf.map_manager import BpfMap
from katran.core.constants import MAX_DECAP_DST


class DecapDstMap(BpfMap[str, int]):
    """decap_dst BPF hash map: address (16 bytes) → flags (u32)."""

    MAP_NAME = "decap_dst"

    def __init__(
        self, pin_base_path: str, map_name: str | None = None,
        max_entries: int = MAX_DECAP_DST,
    ) -> None:
        super().__init__(pin_base_path, map_name)
        self._max_entries = max_entries

    @property
    def _key_size(self) -> int:
        return 16

    @property
    def _value_size(self) -> int:
        return 4

    def _serialize_key(self, key: str) -> bytes:
        addr = ip_address(key)
        if isinstance(addr, IPv6Address):
            return addr.packed
        return addr.packed + b"\x00" * 12

    def _deserialize_key(self, data: bytes) -> str:
        if any(data[4:16]):
            return str(IPv6Address(data[:16]))
        return str(IPv4Address(data[:4]))

    def _serialize_value(self, value: int) -> bytes:
        return struct.pack("<I", value)

    def _deserialize_value(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])
```

- [ ] **Step 5: Implement `server_id_map.py`**

```python
# src/katran/bpf/maps/server_id_map.py
"""QUIC server ID map: server_id (u32) → real_index (u32)."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import BpfMap
from katran.core.constants import MAX_QUIC_REALS


class ServerIdMap(BpfMap[int, int]):
    """server_id_map BPF map: server_id (u32) → real_index (u32)."""

    MAP_NAME = "server_id_map"

    def __init__(
        self, pin_base_path: str, map_name: str | None = None,
        max_entries: int = MAX_QUIC_REALS,
    ) -> None:
        super().__init__(pin_base_path, map_name)
        self._max_entries = max_entries

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return 4

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: int) -> bytes:
        return struct.pack("<I", value)

    def _deserialize_value(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])
```

- [ ] **Step 6: Implement `pckt_srcs_map.py`**

```python
# src/katran/bpf/maps/pckt_srcs_map.py
"""Packet source IP map: index (u32, 0=v4, 1=v6) → RealDefinition."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import BpfMap
from katran.core.types import REAL_DEFINITION_SIZE, RealDefinition


class PcktSrcsMap(BpfMap[int, RealDefinition]):
    """pckt_srcs BPF array: index (0=v4, 1=v6) → RealDefinition (20 bytes)."""

    MAP_NAME = "pckt_srcs"

    def __init__(self, pin_base_path: str, map_name: str | None = None) -> None:
        super().__init__(pin_base_path, map_name)

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return REAL_DEFINITION_SIZE

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: RealDefinition) -> bytes:
        return value.to_bytes()

    def _deserialize_value(self, data: bytes) -> RealDefinition:
        return RealDefinition.from_bytes(data)
```

- [ ] **Step 7: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_new_map_wrappers.py -v` → PASS

- [ ] **Step 8: Commit** → `git commit -m "feat: add LPM, decap, server_id, pckt_srcs map wrappers"`

---

### Task 8: Per-CPU Stats Map Wrappers

**Files:**
- Create: `src/katran/bpf/maps/reals_stats_map.py`
- Create: `src/katran/bpf/maps/lru_miss_stats_map.py`
- Create: `src/katran/bpf/maps/quic_stats_map.py`
- Create: `src/katran/bpf/maps/decap_vip_stats_map.py`
- Create: `src/katran/bpf/maps/server_id_stats_map.py`

- [ ] **Step 1: Write failing test**

```python
# Append to tests/unit/test_new_map_wrappers.py

class TestRealsStatsMapSerialization:
    def test_value_size(self):
        from katran.bpf.maps.reals_stats_map import RealsStatsMap
        m = RealsStatsMap.__new__(RealsStatsMap)
        assert m._value_size == 16  # LbStats

    def test_value_roundtrip(self):
        from katran.bpf.maps.reals_stats_map import RealsStatsMap
        from katran.core.types import LbStats
        m = RealsStatsMap.__new__(RealsStatsMap)
        val = LbStats(v1=42, v2=99)
        assert m._deserialize_value(m._serialize_value(val)) == val


class TestLruMissStatsMapSerialization:
    def test_value_size(self):
        from katran.bpf.maps.lru_miss_stats_map import LruMissStatsMap
        m = LruMissStatsMap.__new__(LruMissStatsMap)
        assert m._value_size == 4  # u32

    def test_value_roundtrip(self):
        from katran.bpf.maps.lru_miss_stats_map import LruMissStatsMap
        m = LruMissStatsMap.__new__(LruMissStatsMap)
        assert m._deserialize_value(m._serialize_value(123)) == 123


class TestQuicStatsMapSerialization:
    def test_value_size(self):
        from katran.bpf.maps.quic_stats_map import QuicStatsMap
        m = QuicStatsMap.__new__(QuicStatsMap)
        assert m._value_size == 104

    def test_value_roundtrip(self):
        from katran.bpf.maps.quic_stats_map import QuicStatsMap
        from katran.core.types import QuicPacketStats
        m = QuicStatsMap.__new__(QuicStatsMap)
        val = QuicPacketStats(ch_routed=1, cid_initial=2, cid_routed=5,
                              cid_v0=10, dst_match_in_lru=20)
        restored = m._deserialize_value(m._serialize_value(val))
        assert restored.ch_routed == 1
        assert restored.cid_routed == 5
        assert restored.dst_match_in_lru == 20


class TestDecapVipStatsMapSerialization:
    def test_value_size(self):
        from katran.bpf.maps.decap_vip_stats_map import DecapVipStatsMap
        m = DecapVipStatsMap.__new__(DecapVipStatsMap)
        assert m._value_size == 16


class TestServerIdStatsMapSerialization:
    def test_value_size(self):
        from katran.bpf.maps.server_id_stats_map import ServerIdStatsMap
        m = ServerIdStatsMap.__new__(ServerIdStatsMap)
        assert m._value_size == 16


class TestHcPcktSrcsMapSerialization:
    def test_value_size(self):
        from katran.bpf.maps.hc_pckt_srcs_map import HcPcktSrcsMap
        m = HcPcktSrcsMap.__new__(HcPcktSrcsMap)
        assert m._value_size == 20


class TestHcCtrlMapSerialization:
    def test_value_roundtrip(self):
        from katran.bpf.maps.hc_ctrl_map import HcCtrlMap
        m = HcCtrlMap.__new__(HcCtrlMap)
        assert m._deserialize_value(m._serialize_value(42)) == 42
```

- [ ] **Step 2: Run test** → FAIL

- [ ] **Step 3: Implement `reals_stats_map.py`**

```python
# src/katran/bpf/maps/reals_stats_map.py
"""Per-real statistics: real_index (u32) → LbStats (per-CPU)."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import PerCpuBpfMap
from katran.core.constants import MAX_REALS
from katran.core.types import LB_STATS_SIZE, LbStats


class RealsStatsMap(PerCpuBpfMap[int, LbStats]):
    """reals_stats BPF per-CPU array: real_index → LbStats."""

    MAP_NAME = "reals_stats"

    def __init__(
        self, pin_base_path: str, map_name: str | None = None,
        max_entries: int = MAX_REALS, num_cpus: int | None = None,
    ) -> None:
        super().__init__(pin_base_path, map_name, num_cpus)
        self._max_entries = max_entries

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return LB_STATS_SIZE

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: LbStats) -> bytes:
        return value.to_bytes()

    def _deserialize_value(self, data: bytes) -> LbStats:
        return LbStats.from_bytes(data)

    def _aggregate_values(self, values: list[LbStats]) -> LbStats:
        return LbStats.aggregate(values)
```

- [ ] **Step 4: Implement `lru_miss_stats_map.py`**

```python
# src/katran/bpf/maps/lru_miss_stats_map.py
"""Per-real LRU miss counts: real_index (u32) → count (u32, per-CPU)."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import PerCpuBpfMap
from katran.core.constants import MAX_REALS


class LruMissStatsMap(PerCpuBpfMap[int, int]):
    """lru_miss_stats BPF per-CPU array: real_index → miss count (u32)."""

    MAP_NAME = "lru_miss_stats"

    def __init__(
        self, pin_base_path: str, map_name: str | None = None,
        max_entries: int = MAX_REALS, num_cpus: int | None = None,
    ) -> None:
        super().__init__(pin_base_path, map_name, num_cpus)
        self._max_entries = max_entries

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return 4

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: int) -> bytes:
        return struct.pack("<I", value)

    def _deserialize_value(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _aggregate_values(self, values: list[int]) -> int:
        return sum(values)
```

- [ ] **Step 5: Implement `quic_stats_map.py`**

```python
# src/katran/bpf/maps/quic_stats_map.py
"""QUIC packet stats: key 0 (u32) → QuicPacketStats (per-CPU)."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import PerCpuBpfMap
from katran.core.types import QuicPacketStats

QUIC_STATS_SIZE = 104  # 13 u64 fields


class QuicStatsMap(PerCpuBpfMap[int, QuicPacketStats]):
    """quic_stats_map BPF per-CPU array: key 0 → QuicPacketStats."""

    MAP_NAME = "quic_stats_map"

    def __init__(
        self, pin_base_path: str, map_name: str | None = None,
        num_cpus: int | None = None,
    ) -> None:
        super().__init__(pin_base_path, map_name, num_cpus)

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return QUIC_STATS_SIZE

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: QuicPacketStats) -> bytes:
        return struct.pack(
            "<13Q",
            value.ch_routed, value.cid_initial, value.cid_invalid_server_id,
            value.cid_invalid_server_id_sample, value.cid_routed,
            value.cid_unknown_real_dropped, value.cid_v0, value.cid_v1,
            value.cid_v2, value.cid_v3, value.dst_match_in_lru,
            value.dst_mismatch_in_lru, value.dst_not_found_in_lru,
        )

    def _deserialize_value(self, data: bytes) -> QuicPacketStats:
        vals = struct.unpack("<13Q", data[:QUIC_STATS_SIZE])
        return QuicPacketStats(
            ch_routed=vals[0], cid_initial=vals[1], cid_invalid_server_id=vals[2],
            cid_invalid_server_id_sample=vals[3], cid_routed=vals[4],
            cid_unknown_real_dropped=vals[5], cid_v0=vals[6], cid_v1=vals[7],
            cid_v2=vals[8], cid_v3=vals[9], dst_match_in_lru=vals[10],
            dst_mismatch_in_lru=vals[11], dst_not_found_in_lru=vals[12],
        )

    def _aggregate_values(self, values: list[QuicPacketStats]) -> QuicPacketStats:
        result = QuicPacketStats()
        for v in values:
            result.ch_routed += v.ch_routed
            result.cid_initial += v.cid_initial
            result.cid_invalid_server_id += v.cid_invalid_server_id
            result.cid_invalid_server_id_sample = v.cid_invalid_server_id_sample
            result.cid_routed += v.cid_routed
            result.cid_unknown_real_dropped += v.cid_unknown_real_dropped
            result.cid_v0 += v.cid_v0
            result.cid_v1 += v.cid_v1
            result.cid_v2 += v.cid_v2
            result.cid_v3 += v.cid_v3
            result.dst_match_in_lru += v.dst_match_in_lru
            result.dst_mismatch_in_lru += v.dst_mismatch_in_lru
            result.dst_not_found_in_lru += v.dst_not_found_in_lru
        return result
```

- [ ] **Step 6: Implement `decap_vip_stats_map.py` and `server_id_stats_map.py`**

Both are identical to `RealsStatsMap` pattern (PerCpuBpfMap[int, LbStats]):

```python
# src/katran/bpf/maps/decap_vip_stats_map.py
"""Decap per-VIP stats: vip_index (u32) → LbStats (per-CPU)."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import PerCpuBpfMap
from katran.core.constants import MAX_VIPS
from katran.core.types import LB_STATS_SIZE, LbStats


class DecapVipStatsMap(PerCpuBpfMap[int, LbStats]):
    MAP_NAME = "decap_vip_stats"

    def __init__(
        self, pin_base_path: str, map_name: str | None = None,
        max_entries: int = MAX_VIPS, num_cpus: int | None = None,
    ) -> None:
        super().__init__(pin_base_path, map_name, num_cpus)
        self._max_entries = max_entries

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return LB_STATS_SIZE

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: LbStats) -> bytes:
        return value.to_bytes()

    def _deserialize_value(self, data: bytes) -> LbStats:
        return LbStats.from_bytes(data)

    def _aggregate_values(self, values: list[LbStats]) -> LbStats:
        return LbStats.aggregate(values)
```

```python
# src/katran/bpf/maps/server_id_stats_map.py
"""Server ID per-VIP stats: vip_index (u32) → LbStats (per-CPU)."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import PerCpuBpfMap
from katran.core.constants import MAX_VIPS
from katran.core.types import LB_STATS_SIZE, LbStats


class ServerIdStatsMap(PerCpuBpfMap[int, LbStats]):
    MAP_NAME = "server_id_stats"

    def __init__(
        self, pin_base_path: str, map_name: str | None = None,
        max_entries: int = MAX_VIPS, num_cpus: int | None = None,
    ) -> None:
        super().__init__(pin_base_path, map_name, num_cpus)
        self._max_entries = max_entries

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return LB_STATS_SIZE

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: LbStats) -> bytes:
        return value.to_bytes()

    def _deserialize_value(self, data: bytes) -> LbStats:
        return LbStats.from_bytes(data)

    def _aggregate_values(self, values: list[LbStats]) -> LbStats:
        return LbStats.aggregate(values)
```

- [ ] **Step 7: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_new_map_wrappers.py -v` → PASS

- [ ] **Step 8: Commit** → `git commit -m "feat: add per-CPU stats map wrappers (reals, lru_miss, quic, decap_vip, server_id)"`

---

## Chunk 3: HC Maps + Special Maps

### Task 9: HC Key Map + HC Control/MAC/Sources Maps

**Files:**
- Create: `src/katran/bpf/maps/hc_key_map.py`
- Create: `src/katran/bpf/maps/hc_ctrl_map.py`
- Create: `src/katran/bpf/maps/hc_pckt_srcs_map.py`
- Create: `src/katran/bpf/maps/hc_pckt_macs_map.py`

- [ ] **Step 1: Write failing test**

```python
# Append to tests/unit/test_new_map_wrappers.py

class TestHcKeyMapSerialization:
    def test_key_is_vipkey(self):
        from katran.bpf.maps.hc_key_map import HcKeyMap
        m = HcKeyMap.__new__(HcKeyMap)
        assert m._key_size == 20  # VipKey size

    def test_value_is_u32(self):
        from katran.bpf.maps.hc_key_map import HcKeyMap
        m = HcKeyMap.__new__(HcKeyMap)
        assert m._value_size == 4


class TestHcPcktMacsSerialization:
    def test_value_roundtrip(self):
        from katran.bpf.maps.hc_pckt_macs_map import HcPcktMacsMap
        from katran.core.types import HcMac
        m = HcPcktMacsMap.__new__(HcPcktMacsMap)
        mac = HcMac(mac=b"\xaa\xbb\xcc\xdd\xee\xff")
        data = m._serialize_value(mac)
        restored = m._deserialize_value(data)
        assert restored.mac == mac.mac
```

- [ ] **Step 2: Run test** → FAIL

- [ ] **Step 3: Implement HC maps**

```python
# src/katran/bpf/maps/hc_key_map.py
"""HC key map: VipKey (hc_key struct, same layout) → index (u32)."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import BpfMap
from katran.core.constants import MAX_VIPS
from katran.core.types import VIP_KEY_SIZE, VipKey


class HcKeyMap(BpfMap[VipKey, int]):
    """hc_key_map BPF hash: VipKey → HC key index (u32)."""

    MAP_NAME = "hc_key_map"

    def __init__(
        self, pin_base_path: str, map_name: str | None = None,
        max_entries: int = MAX_VIPS,
    ) -> None:
        super().__init__(pin_base_path, map_name)
        self._max_entries = max_entries

    @property
    def _key_size(self) -> int:
        return VIP_KEY_SIZE

    @property
    def _value_size(self) -> int:
        return 4

    def _serialize_key(self, key: VipKey) -> bytes:
        return key.to_bytes()

    def _deserialize_key(self, data: bytes) -> VipKey:
        return VipKey.from_bytes(data)

    def _serialize_value(self, value: int) -> bytes:
        return struct.pack("<I", value)

    def _deserialize_value(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])
```

```python
# src/katran/bpf/maps/hc_ctrl_map.py
"""HC control array: index (u32) → value (u32)."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import BpfMap
from katran.core.constants import HC_CTRL_MAP_SIZE


class HcCtrlMap(BpfMap[int, int]):
    MAP_NAME = "hc_ctrl_map"

    def __init__(self, pin_base_path: str, map_name: str | None = None) -> None:
        super().__init__(pin_base_path, map_name)

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return 4

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: int) -> bytes:
        return struct.pack("<I", value)

    def _deserialize_value(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])
```

```python
# src/katran/bpf/maps/hc_pckt_srcs_map.py
"""HC packet source IPs: index (0=v4, 1=v6) → RealDefinition."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import BpfMap
from katran.core.types import REAL_DEFINITION_SIZE, RealDefinition


class HcPcktSrcsMap(BpfMap[int, RealDefinition]):
    MAP_NAME = "hc_pckt_srcs_map"

    def __init__(self, pin_base_path: str, map_name: str | None = None) -> None:
        super().__init__(pin_base_path, map_name)

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return REAL_DEFINITION_SIZE

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: RealDefinition) -> bytes:
        return value.to_bytes()

    def _deserialize_value(self, data: bytes) -> RealDefinition:
        return RealDefinition.from_bytes(data)
```

```python
# src/katran/bpf/maps/hc_pckt_macs_map.py
"""HC packet MACs: index (0=src, 1=dst) → HcMac."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import BpfMap
from katran.core.types import HcMac

HC_MAC_VALUE_SIZE = 8  # 6 bytes MAC + 2 padding


class HcPcktMacsMap(BpfMap[int, HcMac]):
    MAP_NAME = "hc_pckt_macs"

    def __init__(self, pin_base_path: str, map_name: str | None = None) -> None:
        super().__init__(pin_base_path, map_name)

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return HC_MAC_VALUE_SIZE

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: HcMac) -> bytes:
        return value.to_bytes()

    def _deserialize_value(self, data: bytes) -> HcMac:
        return HcMac.from_bytes(data)
```

- [ ] **Step 4: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_new_map_wrappers.py -v` → PASS

- [ ] **Step 5: Commit** → `git commit -m "feat: add HC key, ctrl, pckt_srcs, pckt_macs map wrappers"`

---

### Task 10: HC Stats Maps + Per-HC-Key Stats

**Files:**
- Create: `src/katran/bpf/maps/hc_stats_map.py`
- Create: `src/katran/bpf/maps/per_hckey_stats_map.py`

- [ ] **Step 1: Write failing test**

```python
# Append to tests/unit/test_new_map_wrappers.py

class TestHcStatsMapSerialization:
    def test_value_size(self):
        from katran.bpf.maps.hc_stats_map import HcStatsMap, HC_STATS_VALUE_SIZE
        m = HcStatsMap.__new__(HcStatsMap)
        # 5 u64 fields = 40 bytes
        assert m._value_size == HC_STATS_VALUE_SIZE


class TestPerHcKeyStatsMapSerialization:
    def test_value_is_u64(self):
        from katran.bpf.maps.per_hckey_stats_map import PerHcKeyStatsMap
        m = PerHcKeyStatsMap.__new__(PerHcKeyStatsMap)
        assert m._value_size == 8
```

- [ ] **Step 2: Run test** → FAIL

- [ ] **Step 3: Implement HC stats maps**

```python
# src/katran/bpf/maps/hc_stats_map.py
"""HC program stats: key 0 → HealthCheckProgStats (per-CPU)."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import PerCpuBpfMap
from katran.core.types import HealthCheckProgStats

HC_STATS_VALUE_SIZE = 40  # 5 u64 fields


class HcStatsMap(PerCpuBpfMap[int, HealthCheckProgStats]):
    MAP_NAME = "hc_stats_map"

    def __init__(
        self, pin_base_path: str, map_name: str | None = None,
        num_cpus: int | None = None,
    ) -> None:
        super().__init__(pin_base_path, map_name, num_cpus)

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return HC_STATS_VALUE_SIZE

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: HealthCheckProgStats) -> bytes:
        return struct.pack(
            "<5Q",
            value.packets_processed, value.packets_dropped,
            value.packets_skipped, value.packets_too_big,
            value.packets_dst_matched,
        )

    def _deserialize_value(self, data: bytes) -> HealthCheckProgStats:
        vals = struct.unpack("<5Q", data[:HC_STATS_VALUE_SIZE])
        return HealthCheckProgStats(
            packets_processed=vals[0], packets_dropped=vals[1],
            packets_skipped=vals[2], packets_too_big=vals[3],
            packets_dst_matched=vals[4],
        )

    def _aggregate_values(self, values: list[HealthCheckProgStats]) -> HealthCheckProgStats:
        result = HealthCheckProgStats()
        for v in values:
            result.packets_processed += v.packets_processed
            result.packets_dropped += v.packets_dropped
            result.packets_skipped += v.packets_skipped
            result.packets_too_big += v.packets_too_big
            result.packets_dst_matched += v.packets_dst_matched
        return result
```

```python
# src/katran/bpf/maps/per_hckey_stats_map.py
"""Per-HC-key packet counts: hc_key_index (u32) → count (u64, per-CPU)."""

from __future__ import annotations

import struct

from katran.bpf.map_manager import PerCpuBpfMap
from katran.core.constants import MAX_VIPS


class PerHcKeyStatsMap(PerCpuBpfMap[int, int]):
    MAP_NAME = "per_hckey_stats"

    def __init__(
        self, pin_base_path: str, map_name: str | None = None,
        max_entries: int = MAX_VIPS, num_cpus: int | None = None,
    ) -> None:
        super().__init__(pin_base_path, map_name, num_cpus)
        self._max_entries = max_entries

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return 8

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: int) -> bytes:
        return struct.pack("<Q", value)

    def _deserialize_value(self, data: bytes) -> int:
        return int(struct.unpack("<Q", data)[0])

    def _aggregate_values(self, values: list[int]) -> int:
        return sum(values)
```

- [ ] **Step 4: Run tests** → PASS
- [ ] **Step 5: Commit** → `git commit -m "feat: add HC stats and per-HC-key stats map wrappers"`

---

### Task 11: HcRealsMap Rewrite

**Files:**
- Modify: `src/katran/bpf/maps/hc_reals_map.py` (full rewrite)

The existing HcRealsMap stores `u32 → u32`. The BPF map actually stores `u32 → hc_real_definition` (20 bytes). Rewrite to use `HcRealDefinition` as the value type.

- [ ] **Step 1: Write failing test**

```python
# Append to tests/unit/test_new_map_wrappers.py

class TestHcRealsMapRewrite:
    def test_value_size_is_20(self):
        from katran.bpf.maps.hc_reals_map import HcRealsMap
        m = HcRealsMap.__new__(HcRealsMap)
        assert m._value_size == 20  # HcRealDefinition, not u32

    def test_serialize_value_ipv4(self):
        from katran.bpf.maps.hc_reals_map import HcRealsMap
        from katran.core.types import HcRealDefinition
        m = HcRealsMap.__new__(HcRealsMap)
        m._tunnel_based_hc = True
        hrd = HcRealDefinition(address="10.0.0.1", flags=0)
        data = m._serialize_value(hrd)
        assert len(data) == 20

    def test_roundtrip_tunnel_mode(self):
        from katran.bpf.maps.hc_reals_map import HcRealsMap
        from katran.core.types import HcRealDefinition
        m = HcRealsMap.__new__(HcRealsMap)
        m._tunnel_based_hc = True
        hrd = HcRealDefinition(address="10.0.0.1", flags=0)
        restored = m._deserialize_value(m._serialize_value(hrd))
        assert restored.address == "10.0.0.1"
        assert restored.flags == 0

    def test_roundtrip_direct_mode(self):
        from katran.bpf.maps.hc_reals_map import HcRealsMap
        from katran.core.types import HcRealDefinition
        m = HcRealsMap.__new__(HcRealsMap)
        m._tunnel_based_hc = False
        hrd = HcRealDefinition(address="10.0.0.1", flags=0)
        restored = m._deserialize_value(m._serialize_value(hrd))
        assert restored.address == "10.0.0.1"


class TestHcStatsMapRoundtrip:
    def test_value_roundtrip(self):
        from katran.bpf.maps.hc_stats_map import HcStatsMap
        from katran.core.types import HealthCheckProgStats
        m = HcStatsMap.__new__(HcStatsMap)
        val = HealthCheckProgStats(packets_processed=10, packets_dropped=2,
                                    packets_skipped=3, packets_too_big=1,
                                    packets_dst_matched=4)
        restored = m._deserialize_value(m._serialize_value(val))
        assert restored.packets_processed == 10
        assert restored.packets_dst_matched == 4
```

- [ ] **Step 2: Run test** → FAIL (value_size is 4, not 20)

- [ ] **Step 3: Rewrite `src/katran/bpf/maps/hc_reals_map.py`**

```python
# src/katran/bpf/maps/hc_reals_map.py
"""Healthcheck reals map: SO_MARK (u32) → HcRealDefinition (20 bytes).

The BPF hc_reals_map stores the actual backend IP address (not an index)
in hc_real_definition format: 16-byte address + 1-byte flags + 3 padding.
"""

from __future__ import annotations

import struct

from katran.bpf.map_manager import BpfMap
from katran.core.constants import MAX_REALS
from katran.core.types import HC_REAL_DEFINITION_SIZE, HcRealDefinition


class HcRealsMap(BpfMap[int, HcRealDefinition]):
    """hc_reals_map BPF hash: SO_MARK (u32) → HcRealDefinition (20 bytes)."""

    MAP_NAME = "hc_reals_map"

    def __init__(
        self,
        pin_base_path: str,
        map_name: str | None = None,
        max_reals: int = MAX_REALS,
        tunnel_based_hc: bool = True,
    ) -> None:
        super().__init__(pin_base_path, map_name)
        self._max_reals = max_reals
        self._tunnel_based_hc = tunnel_based_hc

    @property
    def _key_size(self) -> int:
        return 4

    @property
    def _value_size(self) -> int:
        return HC_REAL_DEFINITION_SIZE

    def _serialize_key(self, key: int) -> bytes:
        return struct.pack("<I", key)

    def _deserialize_key(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])

    def _serialize_value(self, value: HcRealDefinition) -> bytes:
        return value.to_bytes(tunnel_based_hc=self._tunnel_based_hc)

    def _deserialize_value(self, data: bytes) -> HcRealDefinition:
        return HcRealDefinition.from_bytes(data, tunnel_based_hc=self._tunnel_based_hc)
```

- [ ] **Step 4: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_new_map_wrappers.py -v` → PASS
- [ ] **Step 5: Run existing tests** → `.venv/bin/python3 -m pytest tests/unit/ -v` → verify no regressions
- [ ] **Step 6: Commit** → `git commit -m "feat: rewrite HcRealsMap to store HcRealDefinition (20 bytes) instead of u32"`

---

### Task 12: Down Reals Map (HASH_OF_MAPS)

**Files:**
- Create: `src/katran/bpf/maps/down_reals_map.py`

This map uses HASH_OF_MAPS. The outer map key is VipKey, value is inner map ID (u32). Inner map operations use raw BPF syscalls via `bpf_map_get_fd_by_id`.

- [ ] **Step 1: Write failing test**

```python
# Append to tests/unit/test_new_map_wrappers.py

class TestDownRealsMapSerialization:
    def test_key_is_vipkey(self):
        from katran.bpf.maps.down_reals_map import VipToDownRealsMap
        m = VipToDownRealsMap.__new__(VipToDownRealsMap)
        assert m._key_size == 20

    def test_value_is_u32(self):
        from katran.bpf.maps.down_reals_map import VipToDownRealsMap
        m = VipToDownRealsMap.__new__(VipToDownRealsMap)
        assert m._value_size == 4
```

- [ ] **Step 2: Run test** → FAIL

- [ ] **Step 3: Implement `down_reals_map.py`**

```python
# src/katran/bpf/maps/down_reals_map.py
"""VIP-to-down-reals HASH_OF_MAPS wrapper.

Outer map: VipKey → inner_map_id (u32).
Inner maps: BPF_MAP_TYPE_HASH with real_index (u32) → dummy (u8).
Inner map lifecycle managed by DownRealManager.
"""

from __future__ import annotations

import struct

from katran.bpf.map_manager import BpfMap
from katran.core.constants import MAX_VIPS
from katran.core.types import VIP_KEY_SIZE, VipKey


class VipToDownRealsMap(BpfMap[VipKey, int]):
    """vip_to_down_reals BPF HASH_OF_MAPS: VipKey → inner map ID (u32)."""

    MAP_NAME = "vip_to_down_reals"

    def __init__(
        self, pin_base_path: str, map_name: str | None = None,
        max_entries: int = MAX_VIPS,
    ) -> None:
        super().__init__(pin_base_path, map_name)
        self._max_entries = max_entries

    @property
    def _key_size(self) -> int:
        return VIP_KEY_SIZE

    @property
    def _value_size(self) -> int:
        return 4  # inner map ID

    def _serialize_key(self, key: VipKey) -> bytes:
        return key.to_bytes()

    def _deserialize_key(self, data: bytes) -> VipKey:
        return VipKey.from_bytes(data)

    def _serialize_value(self, value: int) -> bytes:
        return struct.pack("<I", value)

    def _deserialize_value(self, data: bytes) -> int:
        return int(struct.unpack("<I", data)[0])
```

- [ ] **Step 4: Run tests** → PASS
- [ ] **Step 5: Commit** → `git commit -m "feat: add VipToDownRealsMap (HASH_OF_MAPS) wrapper"`

---

### Task 13: Module Exports Update

**Files:**
- Modify: `src/katran/bpf/maps/__init__.py`
- Modify: `src/katran/bpf/__init__.py`

- [ ] **Step 1: Update `src/katran/bpf/maps/__init__.py`**

```python
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
    "ChRingsMap", "CtlArray", "DecapDstMap", "DecapVipStatsMap",
    "VipToDownRealsMap", "HcCtrlMap", "HcKeyMap", "HcPcktMacsMap",
    "HcPcktSrcsMap", "HcRealsMap", "HcStatsMap", "LpmSrcV4Map",
    "LpmSrcV6Map", "LruMap", "LruMissStatsMap", "PcktSrcsMap",
    "PerHcKeyStatsMap", "QuicStatsMap", "RealsMap", "RealsStatsMap",
    "ServerIdMap", "ServerIdStatsMap", "StatsMap", "VipMap",
]
```

- [ ] **Step 2: Update `src/katran/bpf/__init__.py`** similarly (add all new map imports/exports).

- [ ] **Step 3: Run all unit tests** → `.venv/bin/python3 -m pytest tests/unit/ -v` → PASS

- [ ] **Step 4: Run lint** → `.venv/bin/python3 -m ruff check src/katran/bpf/maps/` → PASS

- [ ] **Step 5: Commit** → `git commit -m "feat: update bpf/maps exports for all new map wrappers"`

---

## Chunk 4: Simple Managers

### Task 14: Decap Manager

**Files:**
- Create: `src/katran/lb/decap_manager.py`
- Create: `tests/unit/test_decap_manager.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_decap_manager.py
from unittest.mock import MagicMock

import pytest

from katran.core.exceptions import DecapError


class TestDecapManager:
    @pytest.fixture
    def mock_map(self):
        return MagicMock()

    @pytest.fixture
    def manager(self, mock_map):
        from katran.lb.decap_manager import DecapManager
        return DecapManager(mock_map, max_decap_dst=6)

    def test_add_dst(self, manager, mock_map):
        manager.add_dst("10.0.0.1")
        mock_map.set.assert_called_once()
        assert manager.get_dst_count() == 1

    def test_add_dst_ipv6(self, manager, mock_map):
        manager.add_dst("2001:db8::1")
        assert manager.get_dst_count() == 1

    def test_add_dst_duplicate(self, manager):
        manager.add_dst("10.0.0.1")
        with pytest.raises(DecapError, match="already exists"):
            manager.add_dst("10.0.0.1")

    def test_add_dst_capacity(self, manager):
        for i in range(6):
            manager.add_dst(f"10.0.0.{i + 1}")
        with pytest.raises(DecapError, match="capacity"):
            manager.add_dst("10.0.0.7")

    def test_del_dst(self, manager, mock_map):
        manager.add_dst("10.0.0.1")
        manager.del_dst("10.0.0.1")
        mock_map.delete.assert_called_once()
        assert manager.get_dst_count() == 0

    def test_del_dst_not_found(self, manager):
        with pytest.raises(DecapError, match="not found"):
            manager.del_dst("10.0.0.99")

    def test_get_dsts(self, manager):
        manager.add_dst("10.0.0.1")
        manager.add_dst("10.0.0.2")
        dsts = manager.get_dsts()
        assert len(dsts) == 2
        assert "10.0.0.1" in dsts
```

- [ ] **Step 2: Run test** → FAIL

- [ ] **Step 3: Implement**

```python
# src/katran/lb/decap_manager.py
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
```

- [ ] **Step 4: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_decap_manager.py -v` → PASS
- [ ] **Step 5: Commit** → `git commit -m "feat: add DecapManager for inline decapsulation destinations"`

---

### Task 15: Source Routing Manager

**Files:**
- Create: `src/katran/lb/src_routing_manager.py`
- Create: `tests/unit/test_src_routing_manager.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_src_routing_manager.py
from unittest.mock import MagicMock

import pytest

from katran.core.exceptions import SrcRoutingError


class TestSrcRoutingManager:
    @pytest.fixture
    def mock_v4_map(self):
        return MagicMock()

    @pytest.fixture
    def mock_v6_map(self):
        return MagicMock()

    @pytest.fixture
    def mock_real_manager(self):
        mock = MagicMock()
        mock.increase_ref_count = MagicMock(return_value=5)
        mock.decrease_ref_count = MagicMock()
        return mock

    @pytest.fixture
    def manager(self, mock_v4_map, mock_v6_map, mock_real_manager):
        from katran.lb.src_routing_manager import SrcRoutingManager
        return SrcRoutingManager(mock_v4_map, mock_v6_map, mock_real_manager)

    def test_add_rules_v4(self, manager, mock_v4_map, mock_real_manager):
        failures = manager.add_rules(["10.0.0.0/24"], "192.168.1.1")
        assert failures == 0
        mock_real_manager.increase_ref_count.assert_called_once_with("192.168.1.1")
        mock_v4_map.set.assert_called_once()

    def test_add_rules_v6(self, manager, mock_v6_map, mock_real_manager):
        failures = manager.add_rules(["2001:db8::/32"], "2001:db8::1")
        assert failures == 0
        mock_v6_map.set.assert_called_once()

    def test_add_rules_invalid_cidr(self, manager):
        failures = manager.add_rules(["not-a-cidr"], "10.0.0.1")
        assert failures == 1

    def test_del_rules(self, manager, mock_v4_map, mock_real_manager):
        manager.add_rules(["10.0.0.0/24"], "192.168.1.1")
        result = manager.del_rules(["10.0.0.0/24"])
        assert result is True
        mock_real_manager.decrease_ref_count.assert_called_once()

    def test_get_rules(self, manager):
        manager.add_rules(["10.0.0.0/24"], "192.168.1.1")
        rules = manager.get_rules()
        assert "10.0.0.0/24" in rules

    def test_clear_all(self, manager, mock_real_manager):
        manager.add_rules(["10.0.0.0/24", "10.1.0.0/16"], "192.168.1.1")
        manager.clear_all()
        assert manager.get_rule_count() == 0

    def test_get_rule_count(self, manager):
        assert manager.get_rule_count() == 0
        manager.add_rules(["10.0.0.0/24"], "192.168.1.1")
        assert manager.get_rule_count() == 1
```

- [ ] **Step 2: Run test** → FAIL

- [ ] **Step 3: Implement**

```python
# src/katran/lb/src_routing_manager.py
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
        self._lpm_mapping: dict[tuple[str, int], int] = {}  # (network, prefixlen) → real_num
        self._lpm_dst: dict[tuple[str, int], str] = {}  # (network, prefixlen) → dst_address
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
                    lpm_key = V4LpmKey(prefixlen=network.prefixlen, addr=str(network.network_address))
                    self._v4_map.set(lpm_key, real_index)
                else:
                    lpm_key = V6LpmKey(prefixlen=network.prefixlen, addr=str(network.network_address))
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
                    lpm_key = V4LpmKey(prefixlen=network.prefixlen, addr=str(network.network_address))
                    self._v4_map.delete(lpm_key)
                else:
                    lpm_key = V6LpmKey(prefixlen=network.prefixlen, addr=str(network.network_address))
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
                        self._v4_map.delete(V4LpmKey(prefixlen=prefixlen, addr=network_addr))
                    else:
                        self._v6_map.delete(V6LpmKey(prefixlen=prefixlen, addr=network_addr))
                except Exception:
                    pass
            self._lpm_mapping.clear()
            self._lpm_dst.clear()

    def get_rules(self) -> dict[str, str]:
        """Returns 'src/prefix' → 'dst_ip' from in-memory state."""
        with self._lock:
            result = {}
            for (network_addr, prefixlen), dst in self._lpm_dst.items():
                result[f"{network_addr}/{prefixlen}"] = dst
            return result

    def get_rule_count(self) -> int:
        with self._lock:
            return len(self._lpm_mapping)
```

- [ ] **Step 4: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_src_routing_manager.py -v` → PASS
- [ ] **Step 5: Commit** → `git commit -m "feat: add SrcRoutingManager with LPM trie and shared ref counting"`

---

### Task 16: QUIC Server ID Manager

**Files:**
- Create: `src/katran/lb/quic_manager.py`
- Create: `tests/unit/test_quic_manager.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_quic_manager.py
from unittest.mock import MagicMock

import pytest

from katran.core.constants import ModifyAction
from katran.core.exceptions import QuicMappingError
from katran.core.types import QuicReal


class TestQuicManager:
    @pytest.fixture
    def mock_map(self):
        return MagicMock()

    @pytest.fixture
    def mock_real_manager(self):
        mock = MagicMock()
        mock.increase_ref_count = MagicMock(return_value=5)
        mock.decrease_ref_count = MagicMock()
        mock.get_index_for_real = MagicMock(return_value=5)
        return mock

    @pytest.fixture
    def manager(self, mock_map, mock_real_manager):
        from katran.lb.quic_manager import QuicManager
        return QuicManager(mock_map, mock_real_manager, max_server_ids=100)

    def test_add_mapping(self, manager, mock_map, mock_real_manager):
        reals = [QuicReal(address="10.0.0.1", id=1)]
        failures = manager.modify_mapping(ModifyAction.ADD, reals)
        assert failures == 0
        mock_real_manager.increase_ref_count.assert_called_once_with("10.0.0.1")
        mock_map.set.assert_called_once()

    def test_add_mapping_id_too_large(self, manager):
        reals = [QuicReal(address="10.0.0.1", id=200)]
        failures = manager.modify_mapping(ModifyAction.ADD, reals)
        assert failures == 1

    def test_del_mapping(self, manager, mock_map, mock_real_manager):
        manager.modify_mapping(ModifyAction.ADD, [QuicReal(address="10.0.0.1", id=1)])
        failures = manager.modify_mapping(ModifyAction.DEL, [QuicReal(address="10.0.0.1", id=1)])
        assert failures == 0
        mock_real_manager.decrease_ref_count.assert_called_once()

    def test_get_mapping(self, manager):
        manager.modify_mapping(ModifyAction.ADD, [QuicReal(address="10.0.0.1", id=1)])
        mappings = manager.get_mapping()
        assert len(mappings) == 1
        assert mappings[0].id == 1

    def test_invalidate_server_ids(self, manager, mock_map):
        manager.modify_mapping(ModifyAction.ADD, [QuicReal(address="10.0.0.1", id=1)])
        manager.invalidate_server_ids([1])
        # Should write 0 to BPF map without touching ref counts
        assert mock_map.set.call_count == 2  # once for add, once for invalidate

    def test_revalidate_server_ids(self, manager, mock_map, mock_real_manager):
        manager.modify_mapping(ModifyAction.ADD, [QuicReal(address="10.0.0.1", id=1)])
        mock_real_manager.get_index_for_real.return_value = 7
        manager.revalidate_server_ids([QuicReal(address="10.0.0.1", id=1)])
        # Should look up current index and write back to BPF
```

- [ ] **Step 2: Run test** → FAIL

- [ ] **Step 3: Implement**

```python
# src/katran/lb/quic_manager.py
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
        self._quic_mapping: dict[int, str] = {}  # server_id → real_address
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
            return [QuicReal(address=addr, id=sid) for sid, addr in self._quic_mapping.items()]

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
```

- [ ] **Step 4: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_quic_manager.py -v` → PASS
- [ ] **Step 5: Commit** → `git commit -m "feat: add QuicManager for server ID to backend mappings"`

---

## Chunk 5: Complex Managers

### Task 17: Health Check Manager

**Files:**
- Create: `src/katran/lb/hc_manager.py`
- Create: `tests/unit/test_hc_manager.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_hc_manager.py
from ipaddress import IPv4Address
from unittest.mock import MagicMock

import pytest

from katran.core.constants import Protocol
from katran.core.exceptions import HealthCheckError
from katran.core.types import VipKey


class TestHealthCheckManager:
    @pytest.fixture
    def mocks(self):
        return {
            "hc_reals_map": MagicMock(),
            "hc_key_map": MagicMock(),
            "hc_ctrl_map": MagicMock(),
            "hc_pckt_srcs_map": MagicMock(),
            "hc_pckt_macs": MagicMock(),
            "hc_stats_map": MagicMock(),
            "per_hckey_stats": MagicMock(),
        }

    @pytest.fixture
    def manager(self, mocks):
        from katran.lb.hc_manager import HealthCheckManager
        return HealthCheckManager(**mocks, max_vips=512, tunnel_based_hc=True)

    def test_add_hc_dst(self, manager, mocks):
        manager.add_hc_dst(1000, "10.0.0.1")
        mocks["hc_reals_map"].set.assert_called_once()
        assert manager.get_hc_dsts() == {1000: "10.0.0.1"}

    def test_del_hc_dst(self, manager, mocks):
        manager.add_hc_dst(1000, "10.0.0.1")
        manager.del_hc_dst(1000)
        mocks["hc_reals_map"].delete.assert_called_once()

    def test_del_hc_dst_not_found(self, manager):
        with pytest.raises(HealthCheckError):
            manager.del_hc_dst(9999)

    def test_add_hc_key(self, manager, mocks):
        key = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        idx = manager.add_hc_key(key)
        assert idx >= 0
        mocks["hc_key_map"].set.assert_called_once()

    def test_del_hc_key(self, manager, mocks):
        key = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        manager.add_hc_key(key)
        manager.del_hc_key(key)
        mocks["hc_key_map"].delete.assert_called_once()

    def test_set_hc_interface(self, manager, mocks):
        manager.set_hc_interface(42)
        mocks["hc_ctrl_map"].set.assert_called_once()

    def test_set_hc_src_mac(self, manager, mocks):
        manager.set_hc_src_mac("aa:bb:cc:dd:ee:ff")
        mocks["hc_pckt_macs"].set.assert_called_once()

    def test_add_hc_key_duplicate(self, manager):
        key = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        manager.add_hc_key(key)
        with pytest.raises(HealthCheckError, match="already exists"):
            manager.add_hc_key(key)

    def test_get_stats(self, manager, mocks):
        from katran.core.types import HealthCheckProgStats
        mocks["hc_stats_map"].get = MagicMock(return_value=HealthCheckProgStats(packets_processed=42))
        stats = manager.get_stats()
        assert stats.packets_processed == 42

    def test_get_packets_for_hc_key(self, manager, mocks):
        key = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        manager.add_hc_key(key)
        mocks["per_hckey_stats"].get = MagicMock(return_value=100)
        assert manager.get_packets_for_hc_key(key) == 100

    def test_set_hc_src_ip_v4(self, manager, mocks):
        manager.set_hc_src_ip("10.0.0.1")
        mocks["hc_pckt_srcs_map"].set.assert_called_once()

    def test_hc_dst_byte_order_tunnel(self):
        """Verify tunnel_based_hc flag is passed through to HcRealDefinition serialization."""
        from katran.lb.hc_manager import HealthCheckManager
        mocks = {k: MagicMock() for k in [
            "hc_reals_map", "hc_key_map", "hc_ctrl_map", "hc_pckt_srcs_map",
            "hc_pckt_macs", "hc_stats_map", "per_hckey_stats",
        ]}
        mgr = HealthCheckManager(**mocks, tunnel_based_hc=True)
        mgr.add_hc_dst(1000, "10.0.0.1")
        # The HcRealDefinition written should have been serialized with tunnel_based_hc=True
        # (handled by HcRealsMap which stores the flag)
        mocks["hc_reals_map"].set.assert_called_once()
```

- [ ] **Step 2: Run test** → FAIL

- [ ] **Step 3: Implement**

```python
# src/katran/lb/hc_manager.py
"""Health check manager coordinating all HC maps."""

from __future__ import annotations

import logging
from threading import RLock
from typing import TYPE_CHECKING

from katran.bpf.map_manager import IndexAllocator
from katran.core.constants import (
    HC_DST_MAC_POS, HC_MAIN_INTF_POSITION, HC_SRC_MAC_POS,
    MAX_VIPS, V4_SRC_INDEX, V6_SRC_INDEX,
)
from katran.core.exceptions import HealthCheckError
from katran.core.types import (
    HcMac, HcRealDefinition, HealthCheckProgStats, RealDefinition, VipKey,
)

if TYPE_CHECKING:
    from ipaddress import ip_address

    from katran.bpf.maps.hc_ctrl_map import HcCtrlMap
    from katran.bpf.maps.hc_key_map import HcKeyMap
    from katran.bpf.maps.hc_pckt_macs_map import HcPcktMacsMap
    from katran.bpf.maps.hc_pckt_srcs_map import HcPcktSrcsMap
    from katran.bpf.maps.hc_reals_map import HcRealsMap
    from katran.bpf.maps.hc_stats_map import HcStatsMap
    from katran.bpf.maps.per_hckey_stats_map import PerHcKeyStatsMap

logger = logging.getLogger(__name__)


class HealthCheckManager:
    def __init__(
        self,
        hc_reals_map: HcRealsMap,
        hc_key_map: HcKeyMap,
        hc_ctrl_map: HcCtrlMap,
        hc_pckt_srcs_map: HcPcktSrcsMap,
        hc_pckt_macs: HcPcktMacsMap,
        hc_stats_map: HcStatsMap,
        per_hckey_stats: PerHcKeyStatsMap,
        max_vips: int = MAX_VIPS,
        tunnel_based_hc: bool = True,
    ) -> None:
        self._hc_reals_map = hc_reals_map
        self._hc_key_map = hc_key_map
        self._hc_ctrl_map = hc_ctrl_map
        self._hc_pckt_srcs_map = hc_pckt_srcs_map
        self._hc_pckt_macs = hc_pckt_macs
        self._hc_stats_map = hc_stats_map
        self._per_hckey_stats = per_hckey_stats
        self._tunnel_based_hc = tunnel_based_hc
        self._hc_key_to_index: dict[VipKey, int] = {}
        self._index_allocator = IndexAllocator(max_vips)
        self._somark_to_dst: dict[int, str] = {}
        self._lock = RLock()

    def add_hc_dst(self, somark: int, dst: str) -> None:
        """Write HC destination to hc_reals_map.

        Byte order is handled by the HcRealsMap wrapper, which was initialized
        with tunnel_based_hc and passes it to HcRealDefinition.to_bytes()
        during serialization. See Task 11 (HcRealsMap rewrite).
        """
        with self._lock:
            from ipaddress import ip_address as parse_addr
            addr = parse_addr(dst)
            flags = 1 if addr.version == 6 else 0
            hrd = HcRealDefinition(address=dst, flags=flags)
            self._hc_reals_map.set(somark, hrd)
            self._somark_to_dst[somark] = dst

    def del_hc_dst(self, somark: int) -> None:
        with self._lock:
            if somark not in self._somark_to_dst:
                raise HealthCheckError(f"HC destination not found for somark {somark}")
            self._hc_reals_map.delete(somark)
            del self._somark_to_dst[somark]

    def get_hc_dsts(self) -> dict[int, str]:
        with self._lock:
            return dict(self._somark_to_dst)

    def add_hc_key(self, key: VipKey) -> int:
        with self._lock:
            if key in self._hc_key_to_index:
                raise HealthCheckError(f"HC key already exists: {key}")
            idx = self._index_allocator.allocate()
            self._hc_key_map.set(key, idx)
            self._hc_key_to_index[key] = idx
            return idx

    def del_hc_key(self, key: VipKey) -> None:
        with self._lock:
            if key not in self._hc_key_to_index:
                raise HealthCheckError(f"HC key not found: {key}")
            idx = self._hc_key_to_index[key]
            self._hc_key_map.delete(key)
            self._index_allocator.free(idx)
            del self._hc_key_to_index[key]

    def get_hc_keys(self) -> dict[VipKey, int]:
        with self._lock:
            return dict(self._hc_key_to_index)

    def set_hc_src_ip(self, address: str) -> None:
        from ipaddress import ip_address as parse_addr
        addr = parse_addr(address)
        index = V4_SRC_INDEX if addr.version == 4 else V6_SRC_INDEX
        real_def = RealDefinition(address=addr)
        self._hc_pckt_srcs_map.set(index, real_def)

    def set_hc_dst_mac(self, mac: str) -> None:
        self._hc_pckt_macs.set(HC_DST_MAC_POS, HcMac.from_string(mac))

    def set_hc_src_mac(self, mac: str) -> None:
        self._hc_pckt_macs.set(HC_SRC_MAC_POS, HcMac.from_string(mac))

    def set_hc_interface(self, ifindex: int) -> None:
        self._hc_ctrl_map.set(HC_MAIN_INTF_POSITION, ifindex)

    def get_stats(self) -> HealthCheckProgStats:
        result = self._hc_stats_map.get(0)
        return result if result is not None else HealthCheckProgStats()

    def get_packets_for_hc_key(self, key: VipKey) -> int:
        with self._lock:
            if key not in self._hc_key_to_index:
                raise HealthCheckError(f"HC key not found: {key}")
            idx = self._hc_key_to_index[key]
            result = self._per_hckey_stats.get(idx)
            return result if result is not None else 0
```

- [ ] **Step 4: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_hc_manager.py -v` → PASS
- [ ] **Step 5: Commit** → `git commit -m "feat: add HealthCheckManager coordinating all HC maps"`

---

### Task 18: LRU Manager

**Files:**
- Create: `src/katran/lb/lru_manager.py`
- Create: `tests/unit/test_lru_manager.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_lru_manager.py
import time
from ipaddress import IPv4Address
from unittest.mock import MagicMock

import pytest

from katran.core.constants import Protocol
from katran.core.types import FlowKey, RealPosLru, VipKey


class TestLruManager:
    @pytest.fixture
    def mock_lru(self):
        mock = MagicMock()
        mock.items = MagicMock(return_value=[])
        return mock

    @pytest.fixture
    def manager(self, mock_lru):
        from katran.lb.lru_manager import LruManager
        return LruManager(fallback_lru=mock_lru)

    def test_search_no_match(self, manager):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        result = manager.search(vip, "192.168.1.1", 12345)
        assert len(result.entries) == 0

    def test_purge_vip(self, manager, mock_lru):
        vip_key = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        flow = FlowKey(
            src_addr=IPv4Address("192.168.1.1"),
            dst_addr=IPv4Address("10.0.0.1"),
            src_port=12345, dst_port=80, protocol=Protocol.TCP,
        )
        mock_lru.items.return_value = [(flow, RealPosLru(pos=5, atime=0))]
        mock_lru.delete.return_value = True
        result = manager.purge_vip(vip_key)
        assert result.deleted_count == 1

    def test_analyze_empty(self, manager):
        result = manager.analyze()
        assert result.total_entries == 0

    def test_search_with_match(self, manager, mock_lru):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        flow = FlowKey(
            src_addr=IPv4Address("192.168.1.1"),
            dst_addr=IPv4Address("10.0.0.1"),
            src_port=12345, dst_port=80, protocol=Protocol.TCP,
        )
        mock_lru.items.return_value = [(flow, RealPosLru(pos=5, atime=100))]
        result = manager.search(vip, "192.168.1.1", 12345)
        assert len(result.entries) == 1
        assert result.entries[0].real_index == 5

    def test_list_with_limit(self, manager, mock_lru):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        flows = [
            (FlowKey(src_addr=IPv4Address(f"192.168.1.{i}"),
                      dst_addr=IPv4Address("10.0.0.1"),
                      src_port=i, dst_port=80, protocol=Protocol.TCP),
             RealPosLru(pos=1, atime=0))
            for i in range(10)
        ]
        mock_lru.items.return_value = flows
        result = manager.list(vip, limit=3)
        assert len(result.entries) == 3

    def test_delete(self, manager, mock_lru):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        flow = FlowKey(
            src_addr=IPv4Address("192.168.1.1"),
            dst_addr=IPv4Address("10.0.0.1"),
            src_port=12345, dst_port=80, protocol=Protocol.TCP,
        )
        mock_lru.items.return_value = [(flow, RealPosLru(pos=5, atime=0))]
        mock_lru.delete.return_value = True
        result = manager.delete(vip, "192.168.1.1", 12345)
        assert len(result) == 1

    def test_purge_vip_for_real(self, manager, mock_lru):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        flow1 = FlowKey(src_addr=IPv4Address("192.168.1.1"), dst_addr=IPv4Address("10.0.0.1"),
                        src_port=100, dst_port=80, protocol=Protocol.TCP)
        flow2 = FlowKey(src_addr=IPv4Address("192.168.1.2"), dst_addr=IPv4Address("10.0.0.1"),
                        src_port=200, dst_port=80, protocol=Protocol.TCP)
        mock_lru.items.return_value = [
            (flow1, RealPosLru(pos=5, atime=0)),
            (flow2, RealPosLru(pos=7, atime=0)),
        ]
        mock_lru.delete.return_value = True
        result = manager.purge_vip_for_real(vip, 5)
        assert result.deleted_count == 1  # only pos=5

    def test_analyze_with_entries(self, manager, mock_lru):
        flow = FlowKey(src_addr=IPv4Address("192.168.1.1"), dst_addr=IPv4Address("10.0.0.1"),
                       src_port=100, dst_port=80, protocol=Protocol.TCP)
        mock_lru.items.return_value = [(flow, RealPosLru(pos=5, atime=0))]
        result = manager.analyze()
        assert result.total_entries == 1
        assert len(result.per_vip) == 1

    def test_per_cpu_iteration_concatenates(self, mock_lru):
        """Verify _iter_all_lru_entries includes both per-CPU and fallback entries."""
        from unittest.mock import patch
        from katran.lb.lru_manager import LruManager

        fallback_flow = FlowKey(src_addr=IPv4Address("192.168.1.1"),
                                dst_addr=IPv4Address("10.0.0.1"),
                                src_port=100, dst_port=80, protocol=Protocol.TCP)
        mock_lru.items.return_value = [(fallback_flow, RealPosLru(pos=1, atime=0))]

        cpu_flow = FlowKey(src_addr=IPv4Address("192.168.1.2"),
                           dst_addr=IPv4Address("10.0.0.1"),
                           src_port=200, dst_port=80, protocol=Protocol.TCP)

        mgr = LruManager(fallback_lru=mock_lru, per_cpu_lru_fds=[42])
        with patch.object(mgr, '_iter_lru_fd', return_value=[(cpu_flow, RealPosLru(pos=2, atime=0))]):
            entries = mgr._iter_all_lru_entries()
            assert len(entries) == 2
            cpus = [e[2] for e in entries]
            assert 0 in cpus  # per-CPU entry
            assert -1 in cpus  # fallback entry
```

- [ ] **Step 2: Run test** → FAIL

- [ ] **Step 3: Implement**

```python
# src/katran/lb/lru_manager.py
"""Advanced LRU operations matching the reference implementation."""

from __future__ import annotations

import logging
import time
from threading import RLock
from typing import TYPE_CHECKING

from katran.core.types import (
    FlowKey, LruAnalysis, LruEntries, LruEntry, PurgeResponse,
    RealPosLru, VipKey, VipLruStats,
)

if TYPE_CHECKING:
    from katran.bpf.maps.lru_map import LruMap
    from katran.bpf.maps.lru_miss_stats_map import LruMissStatsMap
    from katran.lb.real_manager import RealManager
    from katran.lb.vip_manager import VipManager

logger = logging.getLogger(__name__)

ONE_SEC_NS = 1_000_000_000
THIRTY_SEC_NS = 30 * ONE_SEC_NS
SIXTY_SEC_NS = 60 * ONE_SEC_NS


class LruManager:
    def __init__(
        self,
        fallback_lru: LruMap,
        per_cpu_lru_fds: list[int] | None = None,
        lru_miss_stats_map: LruMissStatsMap | None = None,
        vip_manager: VipManager | None = None,
        real_manager: RealManager | None = None,
    ) -> None:
        self._fallback_lru = fallback_lru
        self._per_cpu_lru_fds = per_cpu_lru_fds
        self._lru_miss_stats_map = lru_miss_stats_map
        self._vip_manager = vip_manager
        self._real_manager = real_manager
        self._lock = RLock()

    def _iter_all_lru_entries(self) -> list[tuple[FlowKey, RealPosLru, int]]:
        """Iterate all LRU maps (per-CPU + fallback). Returns (flow, value, cpu) tuples."""
        entries = []
        # Iterate per-CPU LRU maps if available
        if self._per_cpu_lru_fds:
            for cpu, fd in enumerate(self._per_cpu_lru_fds):
                try:
                    for flow, value in self._iter_lru_fd(fd):
                        entries.append((flow, value, cpu))
                except Exception:
                    logger.warning("Failed to iterate per-CPU LRU map for CPU %d", cpu)
        # Always iterate fallback LRU
        for flow, value in self._fallback_lru.items():
            entries.append((flow, value, -1))
        return entries

    def _iter_lru_fd(self, fd: int) -> list[tuple[FlowKey, RealPosLru]]:
        """Iterate an LRU map by raw FD using BPF get_next_key + lookup."""
        import ctypes
        from katran.bpf.map_manager import BpfAttrMapElem, BpfCmd, _bpf_syscall
        from katran.core.types import FLOW_KEY_SIZE, REAL_POS_LRU_SIZE

        results = []
        key_buf = ctypes.create_string_buffer(FLOW_KEY_SIZE)
        next_key_buf = ctypes.create_string_buffer(FLOW_KEY_SIZE)
        value_buf = ctypes.create_string_buffer(REAL_POS_LRU_SIZE)

        attr = BpfAttrMapElem()
        attr.map_fd = fd
        attr.key = 0  # NULL for first key
        attr.value_or_next_key = ctypes.cast(next_key_buf, ctypes.c_void_p).value or 0
        result = _bpf_syscall(BpfCmd.MAP_GET_NEXT_KEY, attr, ctypes.sizeof(attr))

        while result >= 0:
            ctypes.memmove(key_buf, next_key_buf, FLOW_KEY_SIZE)
            attr2 = BpfAttrMapElem()
            attr2.map_fd = fd
            attr2.key = ctypes.cast(key_buf, ctypes.c_void_p).value or 0
            attr2.value_or_next_key = ctypes.cast(value_buf, ctypes.c_void_p).value or 0
            if _bpf_syscall(BpfCmd.MAP_LOOKUP_ELEM, attr2, ctypes.sizeof(attr2)) >= 0:
                flow = FlowKey.from_bytes(bytes(key_buf.raw))
                value = RealPosLru.from_bytes(bytes(value_buf.raw))
                results.append((flow, value))
            attr.key = ctypes.cast(key_buf, ctypes.c_void_p).value or 0
            result = _bpf_syscall(BpfCmd.MAP_GET_NEXT_KEY, attr, ctypes.sizeof(attr))
        return results

    def _delete_from_fd(self, fd: int, flow: FlowKey) -> bool:
        """Delete a flow entry from an LRU map by raw FD."""
        import ctypes
        from katran.bpf.map_manager import BpfAttrMapElem, BpfCmd, _bpf_syscall
        key_buf = ctypes.create_string_buffer(flow.to_bytes())
        attr = BpfAttrMapElem()
        attr.map_fd = fd
        attr.key = ctypes.cast(key_buf, ctypes.c_void_p).value or 0
        attr.value_or_next_key = 0
        return _bpf_syscall(BpfCmd.MAP_DELETE_ELEM, attr, ctypes.sizeof(attr)) >= 0

    def _matches_vip(self, flow: FlowKey, vip: VipKey) -> bool:
        return flow.dst_addr == vip.address and flow.dst_port == vip.port and flow.protocol == vip.protocol

    def search(self, dst_vip: VipKey, src_ip: str, src_port: int) -> LruEntries:
        from ipaddress import ip_address
        src_addr = ip_address(src_ip)
        entries = []
        now_ns = time.time_ns()
        with self._lock:
            for flow, value, cpu in self._iter_all_lru_entries():
                if (self._matches_vip(flow, dst_vip)
                        and flow.src_addr == src_addr
                        and flow.src_port == src_port):
                    delta = (now_ns - value.atime) / ONE_SEC_NS if value.atime else 0
                    entries.append(LruEntry(
                        flow=flow, real_index=value.pos,
                        atime=value.atime, atime_delta_sec=delta, cpu=cpu,
                    ))
        return LruEntries(entries=entries)

    def list(self, dst_vip: VipKey, limit: int = 100) -> LruEntries:
        entries = []
        now_ns = time.time_ns()
        with self._lock:
            for flow, value, cpu in self._iter_all_lru_entries():
                if self._matches_vip(flow, dst_vip):
                    delta = (now_ns - value.atime) / ONE_SEC_NS if value.atime else 0
                    entries.append(LruEntry(
                        flow=flow, real_index=value.pos,
                        atime=value.atime, atime_delta_sec=delta, cpu=cpu,
                    ))
                    if len(entries) >= limit:
                        break
        return LruEntries(entries=entries)

    def _delete_from_all(self, flow: FlowKey) -> bool:
        """Delete a flow from all LRU maps (per-CPU + fallback)."""
        deleted = False
        if self._per_cpu_lru_fds:
            for fd in self._per_cpu_lru_fds:
                if self._delete_from_fd(fd, flow):
                    deleted = True
        if self._fallback_lru.delete(flow):
            deleted = True
        return deleted

    def delete(self, dst_vip: VipKey, src_ip: str, src_port: int) -> list[str]:
        from ipaddress import ip_address
        src_addr = ip_address(src_ip)
        deleted = []
        with self._lock:
            for flow, value, cpu in self._iter_all_lru_entries():
                if (self._matches_vip(flow, dst_vip)
                        and flow.src_addr == src_addr
                        and flow.src_port == src_port):
                    if self._delete_from_all(flow):
                        deleted.append(f"cpu={cpu}")
        return deleted

    def purge_vip(self, dst_vip: VipKey) -> PurgeResponse:
        count = 0
        with self._lock:
            to_delete = []
            for flow, value, cpu in self._iter_all_lru_entries():
                if self._matches_vip(flow, dst_vip):
                    to_delete.append(flow)
            for flow in to_delete:
                if self._delete_from_all(flow):
                    count += 1
        return PurgeResponse(deleted_count=count)

    def purge_vip_for_real(self, dst_vip: VipKey, real_index: int) -> PurgeResponse:
        count = 0
        with self._lock:
            to_delete = []
            for flow, value, cpu in self._iter_all_lru_entries():
                if self._matches_vip(flow, dst_vip) and value.pos == real_index:
                    to_delete.append(flow)
            for flow in to_delete:
                if self._delete_from_all(flow):
                    count += 1
        return PurgeResponse(deleted_count=count)

    def analyze(self) -> LruAnalysis:
        now_ns = time.time_ns()
        analysis = LruAnalysis()
        with self._lock:
            for flow, value, cpu in self._iter_all_lru_entries():
                analysis.total_entries += 1
                vip_str = f"{flow.dst_addr}:{flow.dst_port}/{flow.protocol}"
                if vip_str not in analysis.per_vip:
                    analysis.per_vip[vip_str] = VipLruStats()
                stats = analysis.per_vip[vip_str]
                stats.entry_count += 1
                if value.atime == 0:
                    stats.atime_zero_count += 1
                else:
                    delta_ns = now_ns - value.atime
                    if delta_ns < THIRTY_SEC_NS:
                        stats.atime_under_30s_count += 1
                    elif delta_ns < SIXTY_SEC_NS:
                        stats.atime_30_to_60s_count += 1
                    else:
                        stats.atime_over_60s_count += 1
        return analysis

    def get_vip_lru_miss_stats(self, vip: VipKey) -> dict[str, int]:
        """Get per-real LRU miss stats for a VIP's backends."""
        if self._lru_miss_stats_map is None or self._vip_manager is None:
            return {}
        vip_obj = self._vip_manager.get_vip(
            address=str(vip.address), port=vip.port, protocol=vip.protocol,
        )
        if vip_obj is None:
            return {}
        result = {}
        for real in vip_obj.reals:
            miss_count = self._lru_miss_stats_map.get(real.index)
            if miss_count is not None:
                result[str(real.address)] = miss_count
        return result
```

- [ ] **Step 4: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_lru_manager.py -v` → PASS
- [ ] **Step 5: Commit** → `git commit -m "feat: add LruManager with search, list, purge, and analyze operations"`

---

### Task 19: Down Real Manager

**Files:**
- Create: `src/katran/lb/down_real_manager.py`
- Create: `tests/unit/test_down_real_manager.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_down_real_manager.py
from ipaddress import IPv4Address
from unittest.mock import MagicMock, patch

import pytest

from katran.core.constants import Protocol
from katran.core.types import VipKey


class TestDownRealManager:
    @pytest.fixture
    def mock_down_reals_map(self):
        mock = MagicMock()
        mock.get = MagicMock(return_value=None)
        mock.set = MagicMock()
        mock.delete = MagicMock(return_value=True)
        mock.fd = 100
        return mock

    @pytest.fixture
    def mock_vip_manager(self):
        mock = MagicMock()
        mock.get_vip = MagicMock(return_value=MagicMock())
        return mock

    @pytest.fixture
    def manager(self, mock_down_reals_map, mock_vip_manager):
        from katran.lb.down_real_manager import DownRealManager
        return DownRealManager(mock_down_reals_map, mock_vip_manager)

    def test_add_down_real_creates_inner_map(self, manager, mock_down_reals_map):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        # Outer map returns None (no inner map yet) - this triggers inner map creation
        # In unit test with mocks, we just verify the outer map interactions
        mock_down_reals_map.get.return_value = None
        # The actual bpf_map_create call would need to be mocked at module level
        with patch("katran.lb.down_real_manager.bpf_map_create", return_value=200):
            manager.add_down_real(vip, 5)

    def test_check_real_not_found(self, manager, mock_down_reals_map):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        mock_down_reals_map.get.return_value = None
        assert manager.check_real(vip, 5) is False

    def test_remove_vip(self, manager, mock_down_reals_map):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        manager.remove_vip(vip)
        mock_down_reals_map.delete.assert_called_once()

    def test_check_real_validates_vip(self, manager, mock_vip_manager):
        """VIP existence is validated before any operation."""
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        manager.check_real(vip, 5)
        mock_vip_manager.get_vip.assert_called()

    def test_remove_real(self, manager, mock_down_reals_map):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        mock_down_reals_map.get.return_value = None
        manager.remove_real(vip, 5)  # Should not raise even if no inner map

    def test_remove_vip_idempotent(self, manager, mock_down_reals_map):
        vip = VipKey(address=IPv4Address("10.0.0.1"), port=80, protocol=Protocol.TCP)
        mock_down_reals_map.delete.return_value = False
        manager.remove_vip(vip)  # Should not raise
```

- [ ] **Step 2: Run test** → FAIL

- [ ] **Step 3: Implement**

```python
# src/katran/lb/down_real_manager.py
"""Per-VIP down real tracking via HASH_OF_MAPS."""

from __future__ import annotations

import ctypes
import logging
import os
import struct
from threading import RLock
from typing import TYPE_CHECKING

from katran.bpf.map_manager import (
    BPF_F_NO_PREALLOC, BpfAttrMapElem, BpfCmd, BpfMapType,
    _bpf_syscall, bpf_map_create, bpf_map_get_fd_by_id,
)
from katran.core.constants import MAX_REALS
from katran.core.types import VipKey

if TYPE_CHECKING:
    from katran.bpf.maps.down_reals_map import VipToDownRealsMap
    from katran.lb.vip_manager import VipManager

logger = logging.getLogger(__name__)


class DownRealManager:
    def __init__(self, down_reals_map: VipToDownRealsMap, vip_manager: VipManager) -> None:
        self._map = down_reals_map
        self._vip_manager = vip_manager
        self._lock = RLock()

    def _get_or_create_inner_map(self, vip: VipKey) -> int:
        """Get inner map FD, creating if needed. Caller MUST close the FD."""
        inner_map_id = self._map.get(vip)
        if inner_map_id is not None:
            return bpf_map_get_fd_by_id(inner_map_id)
        # Create new inner map
        inner_fd = bpf_map_create(
            map_type=BpfMapType.HASH,
            key_size=4, value_size=1,
            max_entries=MAX_REALS,
            flags=BPF_F_NO_PREALLOC,
        )
        try:
            # Update outer map with inner FD
            # For HASH_OF_MAPS, the value written is the FD of the inner map
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

    def _validate_vip(self, vip: VipKey) -> None:
        """Validate VIP exists via vip_manager."""
        if self._vip_manager.get_vip(
            address=str(vip.address), port=vip.port, protocol=vip.protocol,
        ) is None:
            from katran.core.exceptions import VipNotFoundError
            raise VipNotFoundError(str(vip.address), vip.port, vip.protocol.name)

    def add_down_real(self, vip: VipKey, real_index: int) -> None:
        with self._lock:
            self._validate_vip(vip)
            inner_fd = self._get_or_create_inner_map(vip)
            try:
                self._write_inner(inner_fd, real_index, 1)
            finally:
                os.close(inner_fd)

    def check_real(self, vip: VipKey, real_index: int) -> bool:
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
        with self._lock:
            self._validate_vip(vip)
            self._map.delete(vip)

    def remove_real(self, vip: VipKey, real_index: int) -> None:
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
```

- [ ] **Step 4: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_down_real_manager.py -v` → PASS
- [ ] **Step 5: Commit** → `git commit -m "feat: add DownRealManager with HASH_OF_MAPS inner map lifecycle"`

---

## Chunk 6: Stats Manager + Service Integration

### Task 20: Enhanced Stats Manager

**Files:**
- Create: `src/katran/lb/stats_manager.py`
- Create: `tests/unit/test_stats_manager.py`

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_stats_manager.py
from unittest.mock import MagicMock

import pytest

from katran.core.types import LbStats, QuicPacketStats, HealthCheckProgStats


class TestStatsManager:
    @pytest.fixture
    def mock_stats_map(self):
        mock = MagicMock()
        mock.get = MagicMock(return_value=LbStats(v1=100, v2=200))
        mock.get_all_cpus = MagicMock(return_value=[LbStats(v1=50, v2=100), LbStats(v1=50, v2=100)])
        return mock

    @pytest.fixture
    def manager(self, mock_stats_map):
        from katran.lb.stats_manager import StatsManager
        return StatsManager(stats_map=mock_stats_map, max_vips=512)

    def test_get_vip_stats(self, manager, mock_stats_map):
        result = manager.get_vip_stats(0)
        assert result.v1 == 100

    def test_get_lru_stats(self, manager):
        result = manager.get_lru_stats()
        assert isinstance(result, LbStats)

    def test_get_xdp_total_stats(self, manager):
        result = manager.get_xdp_total_stats()
        assert isinstance(result, LbStats)

    def test_get_real_stats(self, manager):
        manager._reals_stats_map = MagicMock()
        manager._reals_stats_map.get = MagicMock(return_value=LbStats(v1=10, v2=20))
        result = manager.get_real_stats(1)
        assert result.v1 == 10

    def test_get_quic_packet_stats(self, manager):
        manager._quic_stats_map = MagicMock()
        manager._quic_stats_map.get = MagicMock(return_value=QuicPacketStats(ch_routed=5))
        result = manager.get_quic_packet_stats()
        assert result.ch_routed == 5

    def test_get_hc_program_stats(self, manager):
        manager._hc_stats_map = MagicMock()
        manager._hc_stats_map.get = MagicMock(return_value=HealthCheckProgStats(packets_processed=42))
        result = manager.get_hc_program_stats()
        assert result.packets_processed == 42

    def test_none_map_returns_default(self, manager):
        result = manager.get_quic_packet_stats()  # _quic_stats_map is None
        assert result.ch_routed == 0

    def test_get_per_core_packets_stats(self, manager, mock_stats_map):
        result = manager.get_per_core_packets_stats()
        assert isinstance(result, list)
```

- [ ] **Step 2: Run test** → FAIL

- [ ] **Step 3: Implement**

```python
# src/katran/lb/stats_manager.py
"""Centralized statistics access for all BPF stats maps."""

from __future__ import annotations

from typing import TYPE_CHECKING

from katran.core.constants import MAX_VIPS, StatsCounterIndex
from katran.core.types import HealthCheckProgStats, LbStats, QuicPacketStats

if TYPE_CHECKING:
    from katran.bpf.maps.decap_vip_stats_map import DecapVipStatsMap
    from katran.bpf.maps.hc_stats_map import HcStatsMap
    from katran.bpf.maps.lru_miss_stats_map import LruMissStatsMap
    from katran.bpf.maps.per_hckey_stats_map import PerHcKeyStatsMap
    from katran.bpf.maps.quic_stats_map import QuicStatsMap
    from katran.bpf.maps.reals_stats_map import RealsStatsMap
    from katran.bpf.maps.server_id_stats_map import ServerIdStatsMap
    from katran.bpf.maps.stats_map import StatsMap


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
    ) -> None:
        self._stats_map = stats_map
        self._max_vips = max_vips
        self._reals_stats_map = reals_stats_map
        self._lru_miss_stats_map = lru_miss_stats_map
        self._quic_stats_map = quic_stats_map
        self._decap_vip_stats_map = decap_vip_stats_map
        self._server_id_stats_map = server_id_stats_map
        self._hc_stats_map = hc_stats_map
        self._per_hckey_stats = per_hckey_stats

    def _global_index(self, counter: StatsCounterIndex) -> int:
        return self._max_vips + counter

    def _get_global(self, counter: StatsCounterIndex) -> LbStats:
        result = self._stats_map.get(self._global_index(counter))
        return result if result is not None else LbStats()

    # Per-VIP
    def get_vip_stats(self, vip_num: int) -> LbStats:
        result = self._stats_map.get(vip_num)
        return result if result is not None else LbStats()

    def get_decap_stats_for_vip(self, vip_num: int) -> LbStats:
        if self._decap_vip_stats_map is None:
            return LbStats()
        result = self._decap_vip_stats_map.get(vip_num)
        return result if result is not None else LbStats()

    def get_sid_routing_stats_for_vip(self, vip_num: int) -> LbStats:
        if self._server_id_stats_map is None:
            return LbStats()
        result = self._server_id_stats_map.get(vip_num)
        return result if result is not None else LbStats()

    # Per-real
    def get_real_stats(self, real_index: int) -> LbStats:
        if self._reals_stats_map is None:
            return LbStats()
        result = self._reals_stats_map.get(real_index)
        return result if result is not None else LbStats()

    def get_reals_stats(self, indices: list[int]) -> dict[int, LbStats]:
        return {idx: self.get_real_stats(idx) for idx in indices}

    # Global stats — one method per StatsCounterIndex
    def get_lru_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.LRU_CNTRS)

    def get_lru_miss_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.LRU_MISS_CNTR)

    def get_new_conn_rate_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.NEW_CONN_RATE_CNTR)

    def get_lru_fallback_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.FALLBACK_LRU_CNTR)

    def get_global_lru_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.GLOBAL_LRU_CNTR)

    def get_icmp_toobig_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.ICMP_TOOBIG_CNTRS)

    def get_icmp_ptb_v4_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.ICMP_PTB_V4_STATS)

    def get_icmp_ptb_v6_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.ICMP_PTB_V6_STATS)

    def get_ch_drop_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.CH_DROP_STATS)

    def get_encap_fail_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.ENCAP_FAIL_CNTR)

    def get_src_routing_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.LPM_SRC_CNTRS)

    def get_inline_decap_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.REMOTE_ENCAP_CNTRS)

    def get_decap_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.DECAP_CNTR)

    def get_xpop_decap_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.XPOP_DECAP_SUCCESSFUL)

    def get_udp_flow_migration_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.UDP_FLOW_MIGRATION_STATS)

    def get_quic_icmp_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.QUIC_ICMP_STATS)

    def get_xdp_total_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.XDP_TOTAL_CNTR)

    def get_xdp_tx_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.XDP_TX_CNTR)

    def get_xdp_drop_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.XDP_DROP_CNTR)

    def get_xdp_pass_stats(self) -> LbStats:
        return self._get_global(StatsCounterIndex.XDP_PASS_CNTR)

    def get_per_core_packets_stats(self) -> list[int]:
        per_cpu = self._stats_map.get_all_cpus(self._global_index(StatsCounterIndex.XDP_TOTAL_CNTR))
        return [s.v1 for s in per_cpu] if per_cpu else []

    # Feature-specific stats
    def get_quic_packet_stats(self) -> QuicPacketStats:
        if self._quic_stats_map is None:
            return QuicPacketStats()
        result = self._quic_stats_map.get(0)
        return result if result is not None else QuicPacketStats()

    def get_hc_program_stats(self) -> HealthCheckProgStats:
        if self._hc_stats_map is None:
            return HealthCheckProgStats()
        result = self._hc_stats_map.get(0)
        return result if result is not None else HealthCheckProgStats()

    def get_packets_for_hc_key(self, hc_key_index: int) -> int:
        if self._per_hckey_stats is None:
            return 0
        result = self._per_hckey_stats.get(hc_key_index)
        return result if result is not None else 0

    def get_lru_miss_stats_for_real(self, real_index: int) -> int:
        if self._lru_miss_stats_map is None:
            return 0
        result = self._lru_miss_stats_map.get(real_index)
        return result if result is not None else 0
```

- [ ] **Step 4: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_stats_manager.py -v` → PASS
- [ ] **Step 5: Update `src/katran/lb/__init__.py`** — add all new manager imports/exports.
- [ ] **Step 6: Commit** → `git commit -m "feat: add StatsManager with full stats parity (20 global + per-real + QUIC + HC)"`

---

### Task 21: Feature Flags + Service Integration

**Files:**
- Modify: `src/katran/service.py`

This is the largest modification — wire feature flags, optional maps, and all new managers into `KatranService`.

- [ ] **Step 1: Write failing test**

```python
# Append to tests/unit/test_feature_flags.py

class TestServiceFeatureGating:
    def test_require_feature_raises(self):
        from katran.core.config import KatranConfig
        from katran.core.constants import KatranFeature
        from katran.core.exceptions import FeatureNotEnabledError
        from katran.service import KatranService
        cfg = KatranConfig()  # features=0
        svc = KatranService(cfg)
        with pytest.raises(FeatureNotEnabledError):
            svc._require_feature(KatranFeature.SRC_ROUTING)

    def test_has_feature_false(self):
        from katran.core.config import KatranConfig
        from katran.core.constants import KatranFeature
        from katran.service import KatranService
        cfg = KatranConfig()
        svc = KatranService(cfg)
        assert svc.has_feature(KatranFeature.SRC_ROUTING) is False

    def test_has_feature_true(self):
        from katran.core.config import KatranConfig
        from katran.core.constants import KatranFeature
        from katran.service import KatranService
        cfg = KatranConfig.from_dict({"features": ["src_routing"]})
        svc = KatranService(cfg)
        assert svc.has_feature(KatranFeature.SRC_ROUTING) is True
```

- [ ] **Step 2: Run test** → FAIL

- [ ] **Step 3: Modify `src/katran/service.py`**

Add feature checking methods and new manager initialization. Key changes:

```python
# Add to KatranService class:

    def _require_feature(self, feature: KatranFeature) -> None:
        if not self.has_feature(feature):
            raise FeatureNotEnabledError(feature.name)

    def has_feature(self, feature: KatranFeature) -> bool:
        return bool(KatranFeature(self.config.features) & feature)

    def _try_open(self, map_cls: type, *args: Any, **kwargs: Any) -> Any:
        """Try to open an optional map, returning None on failure."""
        try:
            m = map_cls(*args, **kwargs)
            m.open()
            self._opened_maps.append(m)
            return m
        except Exception:
            logger.info("Optional map %s unavailable", map_cls.__name__)
            return None
```

Update `_open_maps` to open feature-gated and best-effort maps (per spec section 13).

Update `_initialize_managers` to create StatsManager, LruManager, and feature-gated managers (per spec section 14).

Add delegation methods:
```python
    def add_src_routing_rules(self, srcs: list[str], dst: str) -> int:
        self._require_feature(KatranFeature.SRC_ROUTING)
        return self._src_routing_manager.add_rules(srcs, dst)

    # ... similar for all other features
```

- [ ] **Step 4: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_feature_flags.py -v` → PASS
- [ ] **Step 5: Run all tests** → `.venv/bin/python3 -m pytest tests/unit/ -v` → PASS
- [ ] **Step 6: Commit** → `git commit -m "feat: add feature flags and wire all new managers into KatranService"`

---

## Chunk 7: REST API + Prometheus

### Task 22: REST API Endpoints

**Files:**
- Modify: `src/katran/api/rest/app.py`
- Create: `tests/unit/test_rest_api_new.py`

Add all new endpoints following existing patterns. Key principles:
- POST for mutations, GET for queries
- IPs in bodies/params, never URL paths
- Feature-gated endpoints return 400 FeatureNotEnabledError
- Pydantic request/response models

- [ ] **Step 1: Write failing tests**

```python
# tests/unit/test_rest_api_new.py
"""Tests for new REST API endpoints."""

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from katran.api.rest.app import create_app


@pytest.fixture
def mock_service():
    svc = MagicMock()
    svc.is_running = True
    svc.is_healthy = True
    svc.has_feature = MagicMock(return_value=True)
    return svc


@pytest.fixture
def client(mock_service):
    app = create_app(mock_service)
    return TestClient(app)


class TestSrcRoutingEndpoints:
    def test_add_src_routing(self, client, mock_service):
        mock_service.add_src_routing_rules = MagicMock(return_value=0)
        resp = client.post("/api/v1/src-routing/add", json={
            "srcs": ["10.0.0.0/24"], "dst": "192.168.1.1"
        })
        assert resp.status_code == 200

    def test_get_src_routing(self, client, mock_service):
        mock_service.get_src_routing_rules = MagicMock(return_value={"10.0.0.0/24": "192.168.1.1"})
        resp = client.get("/api/v1/src-routing")
        assert resp.status_code == 200


class TestDecapEndpoints:
    def test_add_decap_dst(self, client, mock_service):
        mock_service.add_decap_dst = MagicMock()
        resp = client.post("/api/v1/decap/dst/add", json={"address": "10.0.0.1"})
        assert resp.status_code == 200

    def test_get_decap_dsts(self, client, mock_service):
        mock_service.get_decap_dsts = MagicMock(return_value=["10.0.0.1"])
        resp = client.get("/api/v1/decap/dst")
        assert resp.status_code == 200


class TestQuicEndpoints:
    def test_add_quic_mapping(self, client, mock_service):
        mock_service.modify_quic_mapping = MagicMock(return_value=0)
        resp = client.post("/api/v1/quic/mapping", json={
            "action": "add", "mappings": [{"address": "10.0.0.1", "id": 1}]
        })
        assert resp.status_code == 200


class TestHcEndpoints:
    def test_add_hc_dst(self, client, mock_service):
        mock_service.add_hc_dst = MagicMock()
        resp = client.post("/api/v1/hc/dst/add", json={"somark": 1000, "dst": "10.0.0.1"})
        assert resp.status_code == 200

    def test_get_hc_stats(self, client, mock_service):
        from katran.core.types import HealthCheckProgStats
        mock_service.get_hc_stats = MagicMock(return_value=HealthCheckProgStats())
        resp = client.get("/api/v1/hc/stats")
        assert resp.status_code == 200


class TestStatsEndpoints:
    def test_get_global_stats(self, client, mock_service):
        from katran.core.types import LbStats
        mock_service.get_all_global_stats = MagicMock(return_value={
            "lru": {"v1": 0, "v2": 0},
        })
        resp = client.get("/api/v1/stats/global")
        assert resp.status_code == 200


class TestFeaturesEndpoint:
    def test_get_features(self, client, mock_service):
        mock_service.config = MagicMock()
        mock_service.config.features = 3
        resp = client.get("/api/v1/features")
        assert resp.status_code == 200
```

- [ ] **Step 2: Run test** → FAIL

- [ ] **Step 3: Add request/response models to `app.py`**

```python
# New request/response models in app.py

class SrcRoutingRequest(BaseModel):
    srcs: list[str]
    dst: str

class AddressRequest(BaseModel):
    address: str

class HcDstRequest(BaseModel):
    somark: int
    dst: str

class HcKeyRequest(BaseModel):
    address: str
    port: int
    protocol: str

class HcMacRequest(BaseModel):
    mac: str

class HcInterfaceRequest(BaseModel):
    ifindex: int

class QuicRealModel(BaseModel):
    address: str
    id: int

class QuicMappingRequest(BaseModel):
    action: str  # "add" or "del"
    mappings: list[QuicRealModel]

class QuicInvalidateRequest(BaseModel):
    server_ids: list[int]

class QuicRevalidateRequest(BaseModel):
    mappings: list[QuicRealModel]

class DownRealRequest(BaseModel):
    vip: VipId
    real_index: int

class SomarkRequest(BaseModel):
    somark: int

class LruSearchRequest(BaseModel):
    vip: VipId
    src_ip: str
    src_port: int

class LruListRequest(BaseModel):
    vip: VipId
    limit: int = 100

class LruPurgeRealRequest(BaseModel):
    vip: VipId
    real_index: int

class LruDeleteRequest(BaseModel):
    vip: VipId
    src_ip: str
    src_port: int

class StatsVipQuery(BaseModel):
    address: str
    port: int
    protocol: str
```

- [ ] **Step 4: Add endpoints to `create_app`**

Add all new endpoints following spec section 15. Key examples:

```python
    # --- Source Routing -----------------------------------------------

    @app.post("/api/v1/src-routing/add")
    def add_src_routing(req: SrcRoutingRequest, svc: Any = Depends(get_service)) -> dict:
        failures = svc.add_src_routing_rules(req.srcs, req.dst)
        return {"failures": failures}

    @app.get("/api/v1/src-routing")
    def get_src_routing(svc: Any = Depends(get_service)) -> dict:
        return svc.get_src_routing_rules()

    @app.post("/api/v1/src-routing/remove")
    def remove_src_routing(req: SrcRoutingRequest, svc: Any = Depends(get_service)) -> dict:
        svc.del_src_routing_rules(req.srcs)
        return {"status": "removed"}

    @app.post("/api/v1/src-routing/clear")
    def clear_src_routing(svc: Any = Depends(get_service)) -> dict:
        svc.clear_src_routing_rules()
        return {"status": "cleared"}

    # --- Decap --------------------------------------------------------

    @app.post("/api/v1/decap/dst/add")
    def add_decap_dst(req: AddressRequest, svc: Any = Depends(get_service)) -> dict:
        svc.add_decap_dst(req.address)
        return {"status": "added"}

    @app.post("/api/v1/decap/dst/remove")
    def remove_decap_dst(req: AddressRequest, svc: Any = Depends(get_service)) -> dict:
        svc.del_decap_dst(req.address)
        return {"status": "removed"}

    @app.get("/api/v1/decap/dst")
    def get_decap_dsts(svc: Any = Depends(get_service)) -> list[str]:
        return svc.get_decap_dsts()

    # --- QUIC ---------------------------------------------------------

    @app.post("/api/v1/quic/mapping")
    def modify_quic_mapping(req: QuicMappingRequest, svc: Any = Depends(get_service)) -> dict:
        from katran.core.constants import ModifyAction
        from katran.core.types import QuicReal
        action = ModifyAction(req.action)
        reals = [QuicReal(address=m.address, id=m.id) for m in req.mappings]
        failures = svc.modify_quic_mapping(action, reals)
        return {"failures": failures}

    @app.get("/api/v1/quic/mapping")
    def get_quic_mapping(svc: Any = Depends(get_service)) -> list[dict]:
        return [{"address": qr.address, "id": qr.id} for qr in svc.get_quic_mapping()]

    @app.post("/api/v1/quic/invalidate")
    def quic_invalidate(req: QuicInvalidateRequest, svc: Any = Depends(get_service)) -> dict:
        svc.invalidate_quic_server_ids(req.server_ids)
        return {"status": "invalidated"}

    @app.post("/api/v1/quic/revalidate")
    def quic_revalidate(req: QuicRevalidateRequest, svc: Any = Depends(get_service)) -> dict:
        from katran.core.types import QuicReal
        reals = [QuicReal(address=m.address, id=m.id) for m in req.mappings]
        svc.revalidate_quic_server_ids(reals)
        return {"status": "revalidated"}

    # --- Health Check -------------------------------------------------

    @app.post("/api/v1/hc/dst/add")
    def add_hc_dst(req: HcDstRequest, svc: Any = Depends(get_service)) -> dict:
        svc.add_hc_dst(req.somark, req.dst)
        return {"status": "added"}

    @app.post("/api/v1/hc/dst/remove")
    def remove_hc_dst(req: SomarkRequest, svc: Any = Depends(get_service)) -> dict:
        svc.del_hc_dst(req.somark)
        return {"status": "removed"}

    @app.get("/api/v1/hc/dst")
    def get_hc_dsts(svc: Any = Depends(get_service)) -> dict:
        return svc.get_hc_dsts()

    @app.post("/api/v1/hc/key/add")
    def add_hc_key(req: HcKeyRequest, svc: Any = Depends(get_service)) -> dict:
        proto = _parse_protocol(req.protocol)
        key = VipKey(address=ip_address(req.address), port=req.port, protocol=proto)
        idx = svc.add_hc_key(key)
        return {"index": idx}

    @app.post("/api/v1/hc/key/remove")
    def remove_hc_key(req: HcKeyRequest, svc: Any = Depends(get_service)) -> dict:
        proto = _parse_protocol(req.protocol)
        key = VipKey(address=ip_address(req.address), port=req.port, protocol=proto)
        svc.del_hc_key(key)
        return {"status": "removed"}

    @app.get("/api/v1/hc/keys")
    def get_hc_keys(svc: Any = Depends(get_service)) -> list[dict]:
        keys = svc.get_hc_keys()
        return [{"address": str(k.address), "port": k.port,
                 "protocol": k.protocol.name.lower(), "index": v} for k, v in keys.items()]

    @app.post("/api/v1/hc/src-ip")
    def set_hc_src_ip(req: AddressRequest, svc: Any = Depends(get_service)) -> dict:
        svc.set_hc_src_ip(req.address)
        return {"status": "set"}

    @app.post("/api/v1/hc/src-mac")
    def set_hc_src_mac(req: HcMacRequest, svc: Any = Depends(get_service)) -> dict:
        svc.set_hc_src_mac(req.mac)
        return {"status": "set"}

    @app.post("/api/v1/hc/dst-mac")
    def set_hc_dst_mac(req: HcMacRequest, svc: Any = Depends(get_service)) -> dict:
        svc.set_hc_dst_mac(req.mac)
        return {"status": "set"}

    @app.post("/api/v1/hc/interface")
    def set_hc_interface(req: HcInterfaceRequest, svc: Any = Depends(get_service)) -> dict:
        svc.set_hc_interface(req.ifindex)
        return {"status": "set"}

    @app.get("/api/v1/hc/stats")
    def get_hc_stats(svc: Any = Depends(get_service)) -> dict:
        stats = svc.get_hc_stats()
        return {
            "packets_processed": stats.packets_processed,
            "packets_dropped": stats.packets_dropped,
            "packets_skipped": stats.packets_skipped,
            "packets_too_big": stats.packets_too_big,
            "packets_dst_matched": stats.packets_dst_matched,
        }

    @app.get("/api/v1/hc/stats/key")
    def get_hc_key_stats(
        address: str = Query(...), port: int = Query(...), protocol: str = Query(...),
        svc: Any = Depends(get_service),
    ) -> dict:
        proto = _parse_protocol(protocol)
        key = VipKey(address=ip_address(address), port=port, protocol=proto)
        packets = svc.get_packets_for_hc_key(key)
        return {"packets": packets}

    # --- Stats --------------------------------------------------------

    @app.get("/api/v1/stats/vip")
    def get_vip_stats(
        address: str = Query(...), port: int = Query(...), protocol: str = Query(...),
        svc: Any = Depends(get_service),
    ) -> dict:
        proto = _parse_protocol(protocol)
        vip = _lookup_vip(svc, address, port, proto)
        stats = svc.get_vip_stats(vip.vip_num)
        return {"packets": stats.v1, "bytes": stats.v2}

    @app.get("/api/v1/stats/real")
    def get_real_stats(index: int = Query(...), svc: Any = Depends(get_service)) -> dict:
        stats = svc.get_real_stats(index)
        return {"packets": stats.v1, "bytes": stats.v2}

    @app.get("/api/v1/stats/global")
    def get_global_stats(svc: Any = Depends(get_service)) -> dict:
        return svc.get_all_global_stats()

    @app.get("/api/v1/stats/quic")
    def get_quic_stats(svc: Any = Depends(get_service)) -> dict:
        stats = svc.get_quic_packet_stats()
        return {f.name: getattr(stats, f.name) for f in stats.__dataclass_fields__.values()}

    @app.get("/api/v1/stats/hc")
    def get_hc_program_stats(svc: Any = Depends(get_service)) -> dict:
        stats = svc.get_hc_program_stats()
        return {
            "packets_processed": stats.packets_processed,
            "packets_dropped": stats.packets_dropped,
            "packets_skipped": stats.packets_skipped,
            "packets_too_big": stats.packets_too_big,
            "packets_dst_matched": stats.packets_dst_matched,
        }

    @app.get("/api/v1/stats/per-cpu")
    def get_per_cpu_stats(svc: Any = Depends(get_service)) -> list[int]:
        return svc.get_per_core_packets_stats()

    # --- Features -----------------------------------------------------

    @app.get("/api/v1/features")
    def get_features(svc: Any = Depends(get_service)) -> dict:
        from katran.core.constants import KatranFeature
        flags = KatranFeature(svc.config.features)
        return {
            "flags": int(flags),
            "enabled": [f.name for f in KatranFeature if f in flags],
        }

    # --- Encap Source IP ----------------------------------------------

    @app.post("/api/v1/encap/src-ip")
    def set_encap_src_ip(req: AddressRequest, svc: Any = Depends(get_service)) -> dict:
        svc.set_src_ip_for_encap(req.address)
        return {"status": "set"}

    # --- LRU ----------------------------------------------------------

    @app.post("/api/v1/lru/search")
    def lru_search(req: LruSearchRequest, svc: Any = Depends(get_service)) -> dict:
        proto = _parse_protocol(req.vip.protocol)
        vip_key = VipKey(address=ip_address(req.vip.address), port=req.vip.port, protocol=proto)
        result = svc.lru_search(vip_key, req.src_ip, req.src_port)
        return {"entries": len(result.entries), "error": result.error}

    @app.post("/api/v1/lru/list")
    def lru_list(req: LruListRequest, svc: Any = Depends(get_service)) -> dict:
        proto = _parse_protocol(req.vip.protocol)
        vip_key = VipKey(address=ip_address(req.vip.address), port=req.vip.port, protocol=proto)
        result = svc.lru_list(vip_key, req.limit)
        return {"entries": len(result.entries), "error": result.error}

    @app.post("/api/v1/lru/delete")
    def lru_delete(req: LruDeleteRequest, svc: Any = Depends(get_service)) -> dict:
        proto = _parse_protocol(req.vip.protocol)
        vip_key = VipKey(address=ip_address(req.vip.address), port=req.vip.port, protocol=proto)
        deleted = svc.lru_delete(vip_key, req.src_ip, req.src_port)
        return {"deleted": deleted}

    @app.post("/api/v1/lru/purge-vip")
    def lru_purge_vip(req: LruListRequest, svc: Any = Depends(get_service)) -> dict:
        proto = _parse_protocol(req.vip.protocol)
        vip_key = VipKey(address=ip_address(req.vip.address), port=req.vip.port, protocol=proto)
        result = svc.lru_purge_vip(vip_key)
        return {"deleted_count": result.deleted_count}

    @app.post("/api/v1/lru/purge-real")
    def lru_purge_real(req: LruPurgeRealRequest, svc: Any = Depends(get_service)) -> dict:
        proto = _parse_protocol(req.vip.protocol)
        vip_key = VipKey(address=ip_address(req.vip.address), port=req.vip.port, protocol=proto)
        result = svc.lru_purge_vip_for_real(vip_key, req.real_index)
        return {"deleted_count": result.deleted_count}

    @app.get("/api/v1/lru/analyze")
    def lru_analyze(svc: Any = Depends(get_service)) -> dict:
        result = svc.lru_analyze()
        return {"total_entries": result.total_entries, "per_vip": {}}

    # --- Down Reals ---------------------------------------------------

    @app.post("/api/v1/down-reals/add")
    def add_down_real(req: DownRealRequest, svc: Any = Depends(get_service)) -> dict:
        proto = _parse_protocol(req.vip.protocol)
        vip_key = VipKey(address=ip_address(req.vip.address), port=req.vip.port, protocol=proto)
        svc.add_down_real(vip_key, req.real_index)
        return {"status": "added"}

    @app.post("/api/v1/down-reals/remove")
    def remove_down_real(req: DownRealRequest, svc: Any = Depends(get_service)) -> dict:
        proto = _parse_protocol(req.vip.protocol)
        vip_key = VipKey(address=ip_address(req.vip.address), port=req.vip.port, protocol=proto)
        svc.remove_down_real(vip_key, req.real_index)
        return {"status": "removed"}

    @app.post("/api/v1/down-reals/remove-vip")
    def remove_down_reals_vip(req: VipId, svc: Any = Depends(get_service)) -> dict:
        proto = _parse_protocol(req.protocol)
        vip_key = VipKey(address=ip_address(req.address), port=req.port, protocol=proto)
        svc.remove_down_reals_vip(vip_key)
        return {"status": "removed"}

    @app.post("/api/v1/down-reals/check")
    def check_down_real(req: DownRealRequest, svc: Any = Depends(get_service)) -> dict:
        proto = _parse_protocol(req.vip.protocol)
        vip_key = VipKey(address=ip_address(req.vip.address), port=req.vip.port, protocol=proto)
        is_down = svc.check_down_real(vip_key, req.real_index)
        return {"is_down": is_down}
```

Add to error mapping:
```python
_KATRAN_ERROR_STATUS = {
    VipExistsError: 409,
    RealExistsError: 409,
    ResourceExhaustedError: 507,
    FeatureNotEnabledError: 400,
    HealthCheckError: 400,
    SrcRoutingError: 400,
    QuicMappingError: 400,
    DecapError: 400,
}
```

Add `from ipaddress import ip_address` and new exception imports at top.

- [ ] **Step 5: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_rest_api_new.py -v` → PASS
- [ ] **Step 6: Run all tests** → `.venv/bin/python3 -m pytest tests/unit/ -v` → PASS
- [ ] **Step 7: Commit** → `git commit -m "feat: add REST endpoints for all new features (HC, LRU, src-routing, decap, QUIC, down-reals, stats)"`

---

### Task 23: Prometheus Collector Extensions

**Files:**
- Modify: `src/katran/stats/collector.py`

- [ ] **Step 1: Write failing test**

```python
# tests/unit/test_prometheus_new.py
from unittest.mock import MagicMock, PropertyMock

import pytest

from katran.core.types import LbStats, QuicPacketStats, HealthCheckProgStats


@pytest.fixture
def mock_service():
    svc = MagicMock()
    svc.is_running = True
    svc._stats_manager = MagicMock()
    svc._stats_manager.get_ch_drop_stats.return_value = LbStats(v1=10, v2=0)
    svc._stats_manager.get_encap_fail_stats.return_value = LbStats(v1=5, v2=0)
    svc._stats_manager.get_real_stats.return_value = LbStats(v1=100, v2=2000)
    svc._stats_manager.get_quic_packet_stats.return_value = QuicPacketStats(ch_routed=50, cid_routed=30)
    svc._stats_manager.get_hc_program_stats.return_value = HealthCheckProgStats(packets_processed=42)
    svc.vip_manager = None  # skip VIP iteration
    svc.stats_map = None
    return svc


class TestExtendedGlobalMetrics:
    def test_ch_drops_metric(self, mock_service):
        from katran.stats.collector import KatranMetricsCollector
        collector = KatranMetricsCollector(mock_service)
        metrics = list(collector.collect())
        names = [m.name for m in metrics]
        assert "katran_ch_drops_total" in names

    def test_encap_failures_metric(self, mock_service):
        from katran.stats.collector import KatranMetricsCollector
        collector = KatranMetricsCollector(mock_service)
        metrics = list(collector.collect())
        names = [m.name for m in metrics]
        assert "katran_encap_failures_total" in names


class TestQuicDetailMetrics:
    def test_quic_ch_routed(self, mock_service):
        from katran.stats.collector import KatranMetricsCollector
        collector = KatranMetricsCollector(mock_service)
        metrics = list(collector.collect())
        names = [m.name for m in metrics]
        assert "katran_quic_ch_routed_total" in names


class TestHcProgramMetrics:
    def test_hc_packets_processed(self, mock_service):
        from katran.stats.collector import KatranMetricsCollector
        collector = KatranMetricsCollector(mock_service)
        metrics = list(collector.collect())
        names = [m.name for m in metrics]
        assert "katran_hc_packets_processed_total" in names
```

- [ ] **Step 2: Run test** → FAIL

- [ ] **Step 3: Add new metric collection methods to `KatranMetricsCollector`**

Add 4 new collection methods to `KatranMetricsCollector`:

```python
    def _collect_extended_global_stats(self) -> Generator[Any, None, None]:
        """Collect extended global statistics from StatsManager."""
        if not self.service.is_running:
            return
        stats_mgr = getattr(self.service, '_stats_manager', None)
        if stats_mgr is None:
            return
        try:
            metric_defs = [
                ("katran_ch_drops_total", "CH drop packets", stats_mgr.get_ch_drop_stats),
                ("katran_encap_failures_total", "Encap failure packets", stats_mgr.get_encap_fail_stats),
                ("katran_lru_fallback_hits_total", "LRU fallback hits", stats_mgr.get_lru_fallback_stats),
                ("katran_global_lru_hits_total", "Global LRU hits", stats_mgr.get_global_lru_stats),
                ("katran_decap_packets_total", "Decap packets", stats_mgr.get_decap_stats),
                ("katran_src_routing_packets_total", "Src routing packets", stats_mgr.get_src_routing_stats),
                ("katran_quic_icmp_total", "QUIC ICMP packets", stats_mgr.get_quic_icmp_stats),
                ("katran_icmp_ptb_v4_total", "ICMP PTB v4", stats_mgr.get_icmp_ptb_v4_stats),
                ("katran_icmp_ptb_v6_total", "ICMP PTB v6", stats_mgr.get_icmp_ptb_v6_stats),
                ("katran_xpop_decap_total", "XPop decap", stats_mgr.get_xpop_decap_stats),
                ("katran_udp_flow_migration_total", "UDP flow migration", stats_mgr.get_udp_flow_migration_stats),
            ]
            for name, desc, getter in metric_defs:
                stats = getter()
                metric = CounterMetricFamily(name, desc)
                metric.add_metric([], stats.v1)
                yield metric
        except Exception:
            log.warning("Failed to collect extended global stats", exc_info=True)

    def _collect_per_real_stats(self) -> Generator[Any, None, None]:
        """Collect per-real stats (packets + bytes per backend address)."""
        if not self.service.is_running:
            return
        stats_mgr = getattr(self.service, '_stats_manager', None)
        real_mgr = getattr(self.service, 'real_manager', None)
        if stats_mgr is None or real_mgr is None:
            return
        try:
            packets = CounterMetricFamily("katran_real_packets_total",
                                          "Packets forwarded per real", labels=["address"])
            bytes_metric = CounterMetricFamily("katran_real_bytes_total",
                                               "Bytes forwarded per real", labels=["address"])
            for address, meta in real_mgr._reals.items():
                real_stats = stats_mgr.get_real_stats(meta.num)
                packets.add_metric([str(address)], real_stats.v1)
                bytes_metric.add_metric([str(address)], real_stats.v2)
            yield packets
            yield bytes_metric
        except Exception:
            log.warning("Failed to collect per-real stats", exc_info=True)

    def _collect_quic_detail_stats(self) -> Generator[Any, None, None]:
        """Collect detailed QUIC packet statistics."""
        if not self.service.is_running:
            return
        stats_mgr = getattr(self.service, '_stats_manager', None)
        if stats_mgr is None:
            return
        try:
            qstats = stats_mgr.get_quic_packet_stats()
            quic_metrics = [
                ("katran_quic_ch_routed_total", "QUIC CH routed", qstats.ch_routed),
                ("katran_quic_cid_routed_total", "QUIC CID routed", qstats.cid_routed),
                ("katran_quic_cid_invalid_server_id_total", "QUIC invalid server ID", qstats.cid_invalid_server_id),
                ("katran_quic_cid_unknown_real_dropped_total", "QUIC unknown real dropped", qstats.cid_unknown_real_dropped),
            ]
            for name, desc, value in quic_metrics:
                metric = CounterMetricFamily(name, desc)
                metric.add_metric([], value)
                yield metric
        except Exception:
            log.warning("Failed to collect QUIC detail stats", exc_info=True)

    def _collect_hc_program_stats(self) -> Generator[Any, None, None]:
        """Collect HC BPF program statistics."""
        if not self.service.is_running:
            return
        stats_mgr = getattr(self.service, '_stats_manager', None)
        if stats_mgr is None:
            return
        try:
            hc = stats_mgr.get_hc_program_stats()
            hc_metrics = [
                ("katran_hc_packets_processed_total", "HC packets processed", hc.packets_processed),
                ("katran_hc_packets_dropped_total", "HC packets dropped", hc.packets_dropped),
                ("katran_hc_packets_skipped_total", "HC packets skipped", hc.packets_skipped),
            ]
            for name, desc, value in hc_metrics:
                metric = CounterMetricFamily(name, desc)
                metric.add_metric([], value)
                yield metric
        except Exception:
            log.warning("Failed to collect HC program stats", exc_info=True)
```

Add calls to all 4 new methods in `collect()`:
```python
            metrics.extend(self._collect_extended_global_stats())
            metrics.extend(self._collect_per_real_stats())
            metrics.extend(self._collect_quic_detail_stats())
            metrics.extend(self._collect_hc_program_stats())
```

- [ ] **Step 4: Run tests** → `.venv/bin/python3 -m pytest tests/unit/test_collector.py -v` → PASS
- [ ] **Step 5: Run lint** → `.venv/bin/python3 -m ruff check src/katran/` → PASS
- [ ] **Step 6: Run full test suite** → `.venv/bin/python3 -m pytest tests/unit/ -v` → ALL PASS
- [ ] **Step 7: Commit** → `git commit -m "feat: add extended Prometheus metrics for all new stats counters"`

---

## Summary

**Total: 23 tasks across 7 chunks.**

| Chunk | Tasks | Scope |
|-------|-------|-------|
| 1 | 1-6 | Foundation: types, constants, config, exceptions, BPF syscalls, RealManager |
| 2 | 7-8 | Standard map wrappers (9 files) |
| 3 | 9-13 | HC maps + HcReals rewrite + DownReals + exports (9 files) |
| 4 | 14-16 | Simple managers: Decap, SrcRouting, QUIC |
| 5 | 17-19 | Complex managers: HC, LRU, DownReal |
| 6 | 20-21 | StatsManager + Feature Flags + Service integration |
| 7 | 22-23 | REST API endpoints + Prometheus metrics |

**Parallelization opportunities:**
- Tasks 7-8 (all map wrappers) are independent of each other
- Tasks 14-16 (simple managers) are independent of each other
- Tasks 17-19 (complex managers) are independent of each other
- Tasks 22-23 (REST + Prometheus) can run in parallel
