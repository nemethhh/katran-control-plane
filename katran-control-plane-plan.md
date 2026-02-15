# Katran Control Plane Development Plan (Python)

## Overview

This document outlines a phased approach to building a production-ready Katran L4 load balancer control plane in Python. Each phase builds upon the previous, establishing a solid foundation before adding advanced features.

**Target:** Production-ready XDP-based L4 load balancer control plane
**Language:** Python 3.11+
**Key Dependencies:** `pyroute2`, `bcc`/`libbpf`, `grpcio`, `prometheus-client`

---

## Phase 1: Foundation & BPF Infrastructure
**Duration:** 2-3 weeks
**Goal:** Establish core BPF map management and data structure foundation

### 1.1 Project Structure Setup

```
katran-control-plane/
├── pyproject.toml
├── src/
│   └── katran/
│       ├── __init__.py
│       ├── core/                 # Core abstractions
│       │   ├── __init__.py
│       │   ├── types.py          # Data structures
│       │   ├── exceptions.py     # Custom exceptions
│       │   └── constants.py      # Constants & enums
│       ├── bpf/                  # BPF map management
│       │   ├── __init__.py
│       │   ├── map_manager.py    # Base map operations
│       │   ├── maps/             # Individual map wrappers
│       │   │   ├── __init__.py
│       │   │   ├── vip_map.py
│       │   │   ├── reals_map.py
│       │   │   ├── ch_rings_map.py
│       │   │   ├── lru_map.py
│       │   │   ├── stats_map.py
│       │   │   ├── hc_reals_map.py
│       │   │   └── ctl_array.py
│       │   └── loader.py         # XDP/TC program loader
│       ├── lb/                   # Load balancer logic
│       │   ├── __init__.py
│       │   ├── vip_manager.py
│       │   ├── real_manager.py
│       │   ├── maglev.py         # Consistent hashing
│       │   └── healthcheck.py
│       ├── api/                  # External interfaces
│       │   ├── __init__.py
│       │   ├── grpc/
│       │   └── rest/
│       ├── stats/                # Statistics collection
│       │   ├── __init__.py
│       │   ├── collector.py
│       │   └── prometheus.py
│       └── cli/                  # CLI tools
│           ├── __init__.py
│           └── main.py
├── tests/
│   ├── unit/
│   ├── integration/
│   └── conftest.py
├── bpf/                          # BPF program objects
│   ├── balancer.o
│   └── healthchecking_ipip.o
└── config/
    └── katran.yaml
```

### 1.2 Core Data Structures (`core/types.py`)

```python
# Task: Define all data structures matching BPF map layouts

from dataclasses import dataclass, field
from enum import IntFlag, IntEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Union
import struct

class Protocol(IntEnum):
    TCP = 6
    UDP = 17

class VipFlags(IntFlag):
    NONE = 0
    NO_SPORT = 0x01        # Don't use source port in hash
    NO_LRU = 0x02          # Bypass LRU cache
    QUIC_VIP = 0x04        # QUIC connection ID routing
    DPORT_HASH = 0x08      # Hash only destination port
    LOCAL_VIP = 0x10       # Local packet handling
    DIRECT_RETURN = 0x20   # Skip IPIP encapsulation

@dataclass(frozen=True)
class VipKey:
    """Key for vip_map - must match BPF struct vip_definition"""
    address: Union[IPv4Address, IPv6Address]
    port: int
    protocol: Protocol
    
    def to_bytes(self) -> bytes:
        """Serialize to BPF map key format"""
        # Implementation required
        pass
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'VipKey':
        """Deserialize from BPF map key format"""
        pass

@dataclass
class VipMeta:
    """Value for vip_map - must match BPF struct vip_meta"""
    flags: VipFlags
    vip_num: int  # Index for CH ring and stats
    
    def to_bytes(self) -> bytes:
        pass

@dataclass
class RealDefinition:
    """Backend server - must match BPF struct real_definition"""
    address: Union[IPv4Address, IPv6Address]
    flags: int = 0
    
    def to_bytes(self) -> bytes:
        pass

@dataclass
class Real:
    """Full backend server representation for control plane"""
    address: Union[IPv4Address, IPv6Address]
    weight: int = 100
    index: int = -1  # Index in reals array
    flags: int = 0

@dataclass
class Vip:
    """Full VIP representation for control plane"""
    key: VipKey
    flags: VipFlags = VipFlags.NONE
    vip_num: int = -1
    reals: list[Real] = field(default_factory=list)

@dataclass(frozen=True)
class FlowKey:
    """5-tuple flow key - must match BPF struct flow_key"""
    src_addr: Union[IPv4Address, IPv6Address]
    dst_addr: Union[IPv4Address, IPv6Address]
    src_port: int
    dst_port: int
    protocol: Protocol
```

### 1.3 BPF Map Base Manager (`bpf/map_manager.py`)

```python
# Task: Create base class for BPF map operations

from abc import ABC, abstractmethod
from typing import TypeVar, Generic, Optional, Iterator
import os

K = TypeVar('K')  # Key type
V = TypeVar('V')  # Value type

class BpfMapError(Exception):
    """Base exception for BPF map operations"""
    pass

class BpfMap(ABC, Generic[K, V]):
    """
    Abstract base class for BPF map wrappers.
    Provides type-safe interface for map operations.
    """
    
    def __init__(self, map_path: str, map_name: str):
        self.map_path = map_path
        self.map_name = map_name
        self._fd: Optional[int] = None
    
    @abstractmethod
    def _serialize_key(self, key: K) -> bytes:
        """Convert typed key to bytes for BPF"""
        pass
    
    @abstractmethod
    def _deserialize_key(self, data: bytes) -> K:
        """Convert bytes from BPF to typed key"""
        pass
    
    @abstractmethod
    def _serialize_value(self, value: V) -> bytes:
        """Convert typed value to bytes for BPF"""
        pass
    
    @abstractmethod
    def _deserialize_value(self, data: bytes) -> V:
        """Convert bytes from BPF to typed value"""
        pass
    
    def open(self) -> None:
        """Open pinned BPF map"""
        # Use bpf syscall or libbpf to open map
        pass
    
    def close(self) -> None:
        """Close map file descriptor"""
        pass
    
    def get(self, key: K) -> Optional[V]:
        """Lookup value by key"""
        pass
    
    def set(self, key: K, value: V, flags: int = 0) -> None:
        """Insert or update key-value pair"""
        pass
    
    def delete(self, key: K) -> bool:
        """Delete key from map"""
        pass
    
    def items(self) -> Iterator[tuple[K, V]]:
        """Iterate over all key-value pairs"""
        pass
    
    def __enter__(self):
        self.open()
        return self
    
    def __exit__(self, *args):
        self.close()


class PerCpuBpfMap(BpfMap[K, V]):
    """Base class for per-CPU BPF maps"""
    
    def get_all_cpus(self, key: K) -> list[V]:
        """Get values from all CPUs"""
        pass
    
    def aggregate(self, key: K, aggregator) -> V:
        """Aggregate per-CPU values"""
        pass
```

### 1.4 Individual Map Implementations

**Task:** Implement type-safe wrappers for each BPF map

```python
# bpf/maps/vip_map.py
class VipMap(BpfMap[VipKey, VipMeta]):
    """Wrapper for vip_map BPF hash map"""
    
    MAP_NAME = "vip_map"
    
    def _serialize_key(self, key: VipKey) -> bytes:
        # Pack VipKey into struct vip_definition format
        pass
    
    def add_vip(self, vip: Vip) -> int:
        """Add VIP, returns assigned vip_num"""
        pass
    
    def remove_vip(self, key: VipKey) -> bool:
        """Remove VIP"""
        pass
    
    def list_vips(self) -> list[VipKey]:
        """List all configured VIPs"""
        pass

# bpf/maps/reals_map.py  
class RealsMap(BpfMap[int, RealDefinition]):
    """Wrapper for reals BPF array map"""
    
    MAP_NAME = "reals"
    MAX_REALS = 4096
    
    def allocate_index(self) -> int:
        """Allocate next available backend index"""
        pass
    
    def free_index(self, index: int) -> None:
        """Free backend index for reuse"""
        pass

# bpf/maps/ch_rings_map.py
class ChRingsMap(BpfMap[int, int]):
    """Wrapper for ch_rings BPF array map"""
    
    MAP_NAME = "ch_rings"
    RING_SIZE = 65537  # Prime number
    
    def get_ring_base(self, vip_num: int) -> int:
        """Get base index for VIP's ring"""
        return vip_num * self.RING_SIZE
    
    def write_ring(self, vip_num: int, ring: list[int]) -> None:
        """Write complete ring for VIP"""
        pass
    
    def read_ring(self, vip_num: int) -> list[int]:
        """Read complete ring for VIP"""
        pass

# Similar implementations for:
# - LruMap (array of maps)
# - StatsMap (per-CPU array)
# - HcRealsMap (hash map)
# - CtlArray (array)
```

### 1.5 Phase 1 Deliverables Checklist

- [ ] Project structure created with proper packaging
- [ ] All core data structures defined with serialization
- [ ] BpfMap abstract base class implemented
- [ ] VipMap wrapper with full CRUD operations
- [ ] RealsMap wrapper with index allocation
- [ ] ChRingsMap wrapper with ring read/write
- [ ] StatsMap wrapper with per-CPU aggregation
- [ ] CtlArray wrapper for global settings
- [ ] HcRealsMap wrapper for healthcheck routing
- [ ] Unit tests for all data structure serialization
- [ ] Unit tests for map operations (mocked)
- [ ] Integration tests with actual BPF maps

### 1.6 Phase 1 Testing Strategy

```python
# tests/unit/test_types.py
def test_vip_key_serialization():
    """Verify VipKey serializes to correct BPF format"""
    key = VipKey(
        address=IPv4Address("10.200.1.1"),
        port=80,
        protocol=Protocol.TCP
    )
    data = key.to_bytes()
    assert len(data) == 20  # Match BPF struct size
    restored = VipKey.from_bytes(data)
    assert restored == key

# tests/integration/test_bpf_maps.py
@pytest.fixture
def bpf_maps(tmp_path):
    """Create test BPF maps"""
    # Use bpftool or libbpf to create maps for testing
    pass

def test_vip_map_crud(bpf_maps):
    """Test VIP map operations against real BPF map"""
    pass
```

---

## Phase 2: Core Load Balancing Logic
**Duration:** 2-3 weeks
**Goal:** Implement VIP/real management and Maglev consistent hashing

### 2.1 Maglev Consistent Hashing (`lb/maglev.py`)

```python
# Task: Implement Maglev algorithm for consistent hashing

from typing import Sequence
import hashlib

class MaglevHashRing:
    """
    Maglev consistent hashing implementation.
    
    Properties:
    - Minimal disruption: Adding/removing backends affects minimal keys
    - Uniform distribution: Keys distributed evenly across backends
    - O(1) lookup after ring construction
    """
    
    def __init__(self, ring_size: int = 65537):
        if not self._is_prime(ring_size):
            raise ValueError("Ring size must be prime")
        self.ring_size = ring_size
        self._ring: list[int] = []
    
    @staticmethod
    def _is_prime(n: int) -> bool:
        """Check if number is prime"""
        pass
    
    def _compute_permutation(
        self, 
        backend_id: bytes, 
        weight: int = 1
    ) -> tuple[int, int]:
        """
        Compute offset and skip for backend's permutation.
        Uses two hash functions for independent values.
        """
        h1 = int(hashlib.md5(backend_id).hexdigest(), 16)
        h2 = int(hashlib.sha1(backend_id).hexdigest(), 16)
        
        offset = h1 % self.ring_size
        skip = (h2 % (self.ring_size - 1)) + 1
        
        return offset, skip
    
    def build(self, backends: Sequence[tuple[int, int]]) -> list[int]:
        """
        Build Maglev ring from backends.
        
        Args:
            backends: List of (backend_index, weight) tuples
        
        Returns:
            Ring as list of backend indices
        """
        if not backends:
            return []
        
        ring = [-1] * self.ring_size
        
        # Generate permutations for each backend
        perms = []
        for idx, weight in backends:
            offset, skip = self._compute_permutation(
                idx.to_bytes(4, 'little'),
                weight
            )
            perms.append({
                'idx': idx,
                'weight': weight,
                'offset': offset,
                'skip': skip,
                'next_pos': 0,
                'count': 0
            })
        
        # Calculate target count per backend based on weight
        total_weight = sum(p['weight'] for p in perms)
        for p in perms:
            p['target'] = (p['weight'] * self.ring_size) // total_weight
        
        # Fill ring using round-robin with permutations
        filled = 0
        while filled < self.ring_size:
            for p in perms:
                if p['count'] >= p['target'] and filled < self.ring_size - len(perms):
                    continue
                    
                # Find next empty slot in this backend's permutation
                pos = (p['offset'] + p['next_pos'] * p['skip']) % self.ring_size
                while ring[pos] != -1:
                    p['next_pos'] += 1
                    pos = (p['offset'] + p['next_pos'] * p['skip']) % self.ring_size
                
                ring[pos] = p['idx']
                p['next_pos'] += 1
                p['count'] += 1
                filled += 1
                
                if filled >= self.ring_size:
                    break
        
        self._ring = ring
        return ring
    
    def lookup(self, hash_value: int) -> int:
        """Lookup backend for given hash value"""
        if not self._ring:
            raise RuntimeError("Ring not built")
        return self._ring[hash_value % self.ring_size]
    
    def get_ring(self) -> list[int]:
        """Get current ring contents"""
        return self._ring.copy()
```

### 2.2 VIP Manager (`lb/vip_manager.py`)

```python
# Task: Implement VIP lifecycle management

from threading import RLock
from typing import Optional
import logging

class VipManager:
    """
    Manages VIP lifecycle and coordinates with BPF maps.
    
    Responsibilities:
    - VIP CRUD operations
    - VIP number allocation
    - Ring management coordination
    - Thread-safe operations
    """
    
    def __init__(
        self,
        vip_map: VipMap,
        ch_rings_map: ChRingsMap,
        stats_map: StatsMap,
        max_vips: int = 512
    ):
        self._vip_map = vip_map
        self._ch_rings_map = ch_rings_map
        self._stats_map = stats_map
        self._max_vips = max_vips
        
        self._vips: dict[VipKey, Vip] = {}
        self._vip_num_allocator = IndexAllocator(max_vips)
        self._lock = RLock()
        self._log = logging.getLogger(__name__)
    
    def add_vip(
        self,
        address: str,
        port: int,
        protocol: Protocol,
        flags: VipFlags = VipFlags.NONE
    ) -> Vip:
        """
        Add new VIP.
        
        Raises:
            VipExistsError: If VIP already exists
            ResourceExhaustedError: If max VIPs reached
        """
        with self._lock:
            key = VipKey(
                address=ip_address(address),
                port=port,
                protocol=protocol
            )
            
            if key in self._vips:
                raise VipExistsError(f"VIP {key} already exists")
            
            vip_num = self._vip_num_allocator.allocate()
            
            vip = Vip(key=key, flags=flags, vip_num=vip_num)
            
            # Update BPF map
            meta = VipMeta(flags=flags, vip_num=vip_num)
            self._vip_map.set(key, meta)
            
            # Initialize empty ring
            empty_ring = [0] * self._ch_rings_map.RING_SIZE
            self._ch_rings_map.write_ring(vip_num, empty_ring)
            
            self._vips[key] = vip
            self._log.info(f"Added VIP {key} with vip_num={vip_num}")
            
            return vip
    
    def remove_vip(self, address: str, port: int, protocol: Protocol) -> bool:
        """Remove VIP and all associated backends"""
        with self._lock:
            key = VipKey(ip_address(address), port, protocol)
            
            if key not in self._vips:
                return False
            
            vip = self._vips[key]
            
            # Remove from BPF map
            self._vip_map.delete(key)
            
            # Free vip_num
            self._vip_num_allocator.free(vip.vip_num)
            
            del self._vips[key]
            self._log.info(f"Removed VIP {key}")
            
            return True
    
    def get_vip(self, address: str, port: int, protocol: Protocol) -> Optional[Vip]:
        """Get VIP by key"""
        key = VipKey(ip_address(address), port, protocol)
        return self._vips.get(key)
    
    def list_vips(self) -> list[Vip]:
        """List all VIPs"""
        return list(self._vips.values())
    
    def modify_flags(
        self,
        address: str,
        port: int,
        protocol: Protocol,
        flags: VipFlags
    ) -> bool:
        """Modify VIP flags"""
        with self._lock:
            key = VipKey(ip_address(address), port, protocol)
            vip = self._vips.get(key)
            if not vip:
                return False
            
            vip.flags = flags
            meta = VipMeta(flags=flags, vip_num=vip.vip_num)
            self._vip_map.set(key, meta)
            
            return True
```

### 2.3 Real (Backend) Manager (`lb/real_manager.py`)

```python
# Task: Implement backend server management

class RealManager:
    """
    Manages backend servers for VIPs.
    
    Responsibilities:
    - Backend CRUD operations
    - Weight management
    - Graceful draining
    - Ring rebuild coordination
    """
    
    def __init__(
        self,
        reals_map: RealsMap,
        ch_rings_map: ChRingsMap,
        vip_manager: VipManager,
        ring_builder: MaglevHashRing
    ):
        self._reals_map = reals_map
        self._ch_rings_map = ch_rings_map
        self._vip_manager = vip_manager
        self._ring_builder = ring_builder
        self._lock = RLock()
    
    def add_real(
        self,
        vip: Vip,
        address: str,
        weight: int = 100
    ) -> Real:
        """
        Add backend server to VIP.
        
        Triggers CH ring rebuild for the VIP.
        """
        with self._lock:
            # Allocate index in reals array
            idx = self._reals_map.allocate_index()
            
            real = Real(
                address=ip_address(address),
                weight=weight,
                index=idx
            )
            
            # Update reals BPF map
            real_def = RealDefinition(address=real.address)
            self._reals_map.set(idx, real_def)
            
            # Add to VIP's backend list
            vip.reals.append(real)
            
            # Rebuild CH ring
            self._rebuild_ring(vip)
            
            return real
    
    def remove_real(self, vip: Vip, address: str) -> bool:
        """Remove backend from VIP"""
        with self._lock:
            addr = ip_address(address)
            real = next((r for r in vip.reals if r.address == addr), None)
            
            if not real:
                return False
            
            # Remove from VIP
            vip.reals.remove(real)
            
            # Free index (but keep in reals map for existing connections)
            # Actual cleanup happens after drain period
            
            # Rebuild ring
            self._rebuild_ring(vip)
            
            return True
    
    def set_weight(self, vip: Vip, address: str, weight: int) -> bool:
        """
        Set backend weight.
        
        Weight 0 = drained (no new connections)
        """
        with self._lock:
            addr = ip_address(address)
            real = next((r for r in vip.reals if r.address == addr), None)
            
            if not real:
                return False
            
            real.weight = weight
            self._rebuild_ring(vip)
            
            return True
    
    def drain_real(self, vip: Vip, address: str) -> bool:
        """Drain backend (set weight to 0)"""
        return self.set_weight(vip, address, 0)
    
    def _rebuild_ring(self, vip: Vip) -> None:
        """Rebuild CH ring for VIP"""
        # Filter out drained backends
        active_backends = [
            (r.index, r.weight)
            for r in vip.reals
            if r.weight > 0
        ]
        
        if not active_backends:
            # All backends drained - use empty ring
            ring = [0] * self._ring_builder.ring_size
        else:
            ring = self._ring_builder.build(active_backends)
        
        # Write to BPF map
        self._ch_rings_map.write_ring(vip.vip_num, ring)
```

### 2.4 Phase 2 Deliverables Checklist

- [ ] MaglevHashRing implementation with weighted distribution
- [ ] Ring rebuild optimization (minimal writes)
- [ ] VipManager with full CRUD operations
- [ ] RealManager with backend management
- [ ] Graceful draining support
- [ ] Thread-safe operations with proper locking
- [ ] Index allocation/deallocation for VIPs and reals
- [ ] Unit tests for Maglev algorithm correctness
- [ ] Unit tests for ring distribution uniformity
- [ ] Integration tests for VIP/real operations

---

## Phase 2.1: Control Plane Service & E2E Testing Infrastructure
**Duration:** 2 weeks
**Goal:** Create runnable control plane service and end-to-end testing framework

**Rationale:** Before continuing with additional features (XDP loading, stats, APIs), we need a way to run and test the control plane as a complete system. This phase bridges unit/integration tests and full system testing.

### 2.1.1 Configuration Management (`core/config.py`)

```python
# Task: Implement configuration loading and validation
# Moved from Phase 8 as prerequisite for E2E testing

from pydantic import BaseModel, Field, validator
from pathlib import Path
from typing import Optional
import yaml

class BpfConfig(BaseModel):
    """BPF program configuration"""
    xdp_program: Path = Path("/usr/share/katran/balancer.bpf.o")
    hc_program: Path = Path("/usr/share/katran/healthchecking_ipip.o")
    pin_path: Path = Path("/sys/fs/bpf/katran")

    @validator('xdp_program', 'hc_program')
    def programs_must_exist(cls, v):
        if not v.exists():
            raise ValueError(f"BPF program not found: {v}")
        return v

class InterfaceConfig(BaseModel):
    """Network interface configuration"""
    name: str
    xdp_mode: str = "native"  # native, generic, or offload

    @validator('xdp_mode')
    def valid_xdp_mode(cls, v):
        if v not in ['native', 'generic', 'offload']:
            raise ValueError(f"Invalid XDP mode: {v}")
        return v

class MapConfig(BaseModel):
    """BPF map size configuration"""
    max_vips: int = Field(default=512, ge=1, le=4096)
    max_reals: int = Field(default=4096, ge=1, le=65536)
    lru_size: int = Field(default=1_000_000, ge=1000)
    ring_size: int = Field(default=65537)

    @validator('ring_size')
    def ring_size_must_be_prime(cls, v):
        # Simple primality check for common values
        if v not in [65537, 131071, 262147]:
            raise ValueError(f"Ring size must be prime (recommended: 65537)")
        return v

class ApiConfig(BaseModel):
    """API server configuration"""
    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = Field(default=8080, ge=1024, le=65535)

class LogConfig(BaseModel):
    """Logging configuration"""
    level: str = "INFO"
    format: str = "json"  # json or console

    @validator('level')
    def valid_log_level(cls, v):
        if v.upper() not in ['DEBUG', 'INFO', 'WARNING', 'ERROR']:
            raise ValueError(f"Invalid log level: {v}")
        return v.upper()

class KatranConfig(BaseModel):
    """Complete Katran control plane configuration"""

    interface: InterfaceConfig
    bpf: BpfConfig = BpfConfig()
    maps: MapConfig = MapConfig()
    api: ApiConfig = ApiConfig()
    logging: LogConfig = LogConfig()

    # Gateway configuration (required for IPIP encapsulation)
    default_gateway_mac: str = Field(
        ...,
        regex=r'^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$'
    )

    @classmethod
    def from_yaml(cls, path: Path) -> 'KatranConfig':
        """Load configuration from YAML file"""
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)

    @classmethod
    def from_dict(cls, data: dict) -> 'KatranConfig':
        """Load configuration from dictionary"""
        return cls(**data)

    def to_yaml(self, path: Path) -> None:
        """Save configuration to YAML file"""
        with open(path, 'w') as f:
            yaml.safe_dump(
                self.dict(exclude_none=True),
                f,
                default_flow_style=False
            )

# Example configuration file (config/katran.yaml)
EXAMPLE_CONFIG = """
interface:
  name: eth0
  xdp_mode: native

bpf:
  xdp_program: /usr/share/katran/balancer.bpf.o
  hc_program: /usr/share/katran/healthchecking_ipip.o
  pin_path: /sys/fs/bpf/katran

maps:
  max_vips: 512
  max_reals: 4096
  lru_size: 1000000
  ring_size: 65537

api:
  enabled: true
  host: 0.0.0.0
  port: 8080

logging:
  level: INFO
  format: json

default_gateway_mac: "00:1b:21:3c:9d:f8"
"""
```

### 2.1.2 Basic Logging Setup (`core/logging.py`)

```python
# Task: Implement structured logging
# Minimal setup for E2E testing (full implementation in Phase 8)

import logging
import sys
from typing import Optional

def setup_logging(level: str = "INFO", log_format: str = "console") -> None:
    """
    Configure basic logging for control plane.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        log_format: Format style (console or json)
    """

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)

    # Set formatter based on format type
    if log_format == "json":
        # Simple JSON formatting for now
        formatter = logging.Formatter(
            '{"time":"%(asctime)s","level":"%(levelname)s",'
            '"logger":"%(name)s","message":"%(message)s"}'
        )
    else:
        # Console formatting
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

    # Silence noisy libraries
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

def get_logger(name: str) -> logging.Logger:
    """Get logger instance for module"""
    return logging.getLogger(name)
```

### 2.1.3 Control Plane Service Coordinator (`service.py`)

```python
# Task: Implement main service coordinator

from pathlib import Path
from typing import Optional
import logging
import signal
import sys

from katran.core.config import KatranConfig
from katran.core.logging import setup_logging, get_logger
from katran.bpf.maps import (
    VipMap, RealsMap, ChRingsMap, StatsMap,
    CtlArray, HcRealsMap, LruMap
)
from katran.lb.vip_manager import VipManager
from katran.lb.real_manager import RealManager
from katran.lb.maglev import MaglevHashRing

log = get_logger(__name__)


class KatranService:
    """
    Main Katran control plane service coordinator.

    Responsibilities:
    - Initialize all components
    - Manage component lifecycle
    - Handle graceful shutdown
    - Coordinate between managers and BPF maps
    """

    def __init__(self, config: KatranConfig):
        self.config = config
        self._running = False
        self._maps_opened = False

        # BPF Maps (will be opened on start)
        self.vip_map: Optional[VipMap] = None
        self.reals_map: Optional[RealsMap] = None
        self.ch_rings_map: Optional[ChRingsMap] = None
        self.stats_map: Optional[StatsMap] = None
        self.ctl_array: Optional[CtlArray] = None
        self.hc_reals_map: Optional[HcRealsMap] = None
        self.lru_map: Optional[LruMap] = None

        # Managers (will be initialized on start)
        self.vip_manager: Optional[VipManager] = None
        self.real_manager: Optional[RealManager] = None

        # Ring builder
        self.ring_builder = MaglevHashRing(ring_size=config.maps.ring_size)

        log.info("Katran service initialized", extra={
            'interface': config.interface.name,
            'xdp_mode': config.interface.xdp_mode,
            'max_vips': config.maps.max_vips,
            'max_reals': config.maps.max_reals
        })

    def _open_maps(self) -> None:
        """Open all BPF maps"""
        log.info("Opening BPF maps", extra={'pin_path': str(self.config.bpf.pin_path)})

        pin_path = str(self.config.bpf.pin_path)

        self.vip_map = VipMap(pin_path)
        self.reals_map = RealsMap(pin_path, max_entries=self.config.maps.max_reals)
        self.ch_rings_map = ChRingsMap(
            pin_path,
            ring_size=self.config.maps.ring_size,
            max_vips=self.config.maps.max_vips
        )
        self.stats_map = StatsMap(pin_path, max_entries=self.config.maps.max_vips)
        self.ctl_array = CtlArray(pin_path)
        self.hc_reals_map = HcRealsMap(pin_path)
        self.lru_map = LruMap(pin_path)

        # Open all maps
        self.vip_map.open()
        self.reals_map.open()
        self.ch_rings_map.open()
        self.stats_map.open()
        self.ctl_array.open()
        self.hc_reals_map.open()
        self.lru_map.open()

        self._maps_opened = True
        log.info("BPF maps opened successfully")

    def _close_maps(self) -> None:
        """Close all BPF maps"""
        if not self._maps_opened:
            return

        log.info("Closing BPF maps")

        for map_obj in [
            self.vip_map, self.reals_map, self.ch_rings_map,
            self.stats_map, self.ctl_array, self.hc_reals_map, self.lru_map
        ]:
            if map_obj:
                try:
                    map_obj.close()
                except Exception as e:
                    log.error(f"Error closing map: {e}")

        self._maps_opened = False
        log.info("BPF maps closed")

    def _initialize_managers(self) -> None:
        """Initialize VIP and Real managers"""
        log.info("Initializing managers")

        self.vip_manager = VipManager(
            vip_map=self.vip_map,
            ch_rings_map=self.ch_rings_map,
            stats_map=self.stats_map,
            max_vips=self.config.maps.max_vips
        )

        self.real_manager = RealManager(
            reals_map=self.reals_map,
            ch_rings_map=self.ch_rings_map,
            vip_manager=self.vip_manager,
            ring_builder=self.ring_builder
        )

        log.info("Managers initialized")

    def start(self) -> None:
        """Start the control plane service"""
        if self._running:
            raise RuntimeError("Service already running")

        log.info("Starting Katran control plane service")

        try:
            # Open BPF maps
            self._open_maps()

            # Initialize managers
            self._initialize_managers()

            # TODO: Phase 3 will add XDP program loading here
            # TODO: Phase 4 will add statistics collector here
            # TODO: Phase 6 will add API servers here

            self._running = True
            log.info("Katran control plane service started successfully")

        except Exception as e:
            log.error(f"Failed to start service: {e}")
            self._cleanup()
            raise

    def stop(self) -> None:
        """Stop the control plane service"""
        if not self._running:
            return

        log.info("Stopping Katran control plane service")

        # TODO: Phase 4 - Stop statistics collector
        # TODO: Phase 6 - Stop API servers
        # TODO: Phase 3 - Unload XDP programs

        self._cleanup()
        self._running = False

        log.info("Katran control plane service stopped")

    def _cleanup(self) -> None:
        """Clean up resources"""
        self._close_maps()

    def is_running(self) -> bool:
        """Check if service is running"""
        return self._running


def main(config_path: Optional[Path] = None) -> int:
    """
    Main entry point for Katran control plane.

    Args:
        config_path: Path to configuration file

    Returns:
        Exit code
    """
    # Load configuration
    if config_path is None:
        config_path = Path("/etc/katran/katran.yaml")

    try:
        config = KatranConfig.from_yaml(config_path)
    except Exception as e:
        print(f"Failed to load configuration: {e}", file=sys.stderr)
        return 1

    # Setup logging
    setup_logging(
        level=config.logging.level,
        log_format=config.logging.format
    )

    log = get_logger(__name__)
    log.info("Katran control plane starting", extra={
        'config_file': str(config_path)
    })

    # Create service
    service = KatranService(config)

    # Setup signal handlers
    def signal_handler(signum, frame):
        log.info(f"Received signal {signum}, shutting down")
        service.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    try:
        # Start service
        service.start()

        # Keep running until signal received
        log.info("Service running, press Ctrl+C to stop")
        signal.pause()

    except Exception as e:
        log.error(f"Service error: {e}", exc_info=True)
        return 1
    finally:
        service.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

### 2.1.4 Minimal HTTP API for E2E Testing (`api/minimal.py`)

```python
# Task: Implement minimal API for E2E testing
# Full API implementation in Phase 6

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel
from typing import Optional, List
import logging

from katran.service import KatranService
from katran.core.types import Protocol, VipFlags
from katran.core.constants import PROTOCOL_MAP

log = logging.getLogger(__name__)

app = FastAPI(
    title="Katran Control Plane (Minimal E2E API)",
    version="0.1.0"
)

# Global service instance (set by create_app)
service: Optional[KatranService] = None


class AddVipRequest(BaseModel):
    address: str
    port: int
    protocol: str  # "tcp" or "udp"
    flags: List[str] = []

class AddRealRequest(BaseModel):
    address: str
    weight: int = 100

class VipResponse(BaseModel):
    address: str
    port: int
    protocol: str
    vip_num: int
    flags: List[str]
    backends: List[dict]


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    if service is None or not service.is_running():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service not running"
        )
    return {"status": "healthy", "service": "katran-control-plane"}


@app.post("/api/v1/vips", response_model=VipResponse)
async def add_vip(request: AddVipRequest):
    """Add new VIP"""
    if service is None:
        raise HTTPException(status_code=500, detail="Service not initialized")

    try:
        # Parse protocol
        protocol = PROTOCOL_MAP.get(request.protocol.lower())
        if protocol is None:
            raise HTTPException(status_code=400, detail=f"Invalid protocol: {request.protocol}")

        # Parse flags
        flags = VipFlags.NONE
        for flag_name in request.flags:
            try:
                flags |= VipFlags[flag_name.upper()]
            except KeyError:
                raise HTTPException(status_code=400, detail=f"Invalid flag: {flag_name}")

        # Add VIP
        vip = service.vip_manager.add_vip(
            address=request.address,
            port=request.port,
            protocol=protocol,
            flags=flags
        )

        return VipResponse(
            address=str(vip.key.address),
            port=vip.key.port,
            protocol=vip.key.protocol.name.lower(),
            vip_num=vip.vip_num,
            flags=[f.name.lower() for f in VipFlags if f in vip.flags],
            backends=[]
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        log.error(f"Error adding VIP: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/v1/vips/{address}/{port}/{protocol}")
async def remove_vip(address: str, port: int, protocol: str):
    """Remove VIP"""
    if service is None:
        raise HTTPException(status_code=500, detail="Service not initialized")

    try:
        proto = PROTOCOL_MAP.get(protocol.lower())
        if proto is None:
            raise HTTPException(status_code=400, detail=f"Invalid protocol: {protocol}")

        success = service.vip_manager.remove_vip(address, port, proto)
        if not success:
            raise HTTPException(status_code=404, detail="VIP not found")

        return {"success": True}

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Error removing VIP: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/vips")
async def list_vips():
    """List all VIPs"""
    if service is None:
        raise HTTPException(status_code=500, detail="Service not initialized")

    try:
        vips = service.vip_manager.list_vips()
        return {
            "vips": [
                {
                    "address": str(vip.key.address),
                    "port": vip.key.port,
                    "protocol": vip.key.protocol.name.lower(),
                    "vip_num": vip.vip_num,
                    "flags": [f.name.lower() for f in VipFlags if f in vip.flags],
                    "backends": [
                        {
                            "address": str(real.address),
                            "weight": real.weight,
                            "index": real.index
                        }
                        for real in vip.reals
                    ]
                }
                for vip in vips
            ]
        }
    except Exception as e:
        log.error(f"Error listing VIPs: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/vips/{address}/{port}/{protocol}/backends")
async def add_backend(address: str, port: int, protocol: str, request: AddRealRequest):
    """Add backend to VIP"""
    if service is None:
        raise HTTPException(status_code=500, detail="Service not initialized")

    try:
        proto = PROTOCOL_MAP.get(protocol.lower())
        if proto is None:
            raise HTTPException(status_code=400, detail=f"Invalid protocol: {protocol}")

        vip = service.vip_manager.get_vip(address, port, proto)
        if vip is None:
            raise HTTPException(status_code=404, detail="VIP not found")

        real = service.real_manager.add_real(
            vip=vip,
            address=request.address,
            weight=request.weight
        )

        return {
            "success": True,
            "backend": {
                "address": str(real.address),
                "weight": real.weight,
                "index": real.index
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Error adding backend: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/api/v1/vips/{vip_address}/{vip_port}/{protocol}/backends/{backend_address}")
async def remove_backend(vip_address: str, vip_port: int, protocol: str, backend_address: str):
    """Remove backend from VIP"""
    if service is None:
        raise HTTPException(status_code=500, detail="Service not initialized")

    try:
        proto = PROTOCOL_MAP.get(protocol.lower())
        if proto is None:
            raise HTTPException(status_code=400, detail=f"Invalid protocol: {protocol}")

        vip = service.vip_manager.get_vip(vip_address, vip_port, proto)
        if vip is None:
            raise HTTPException(status_code=404, detail="VIP not found")

        success = service.real_manager.remove_real(vip, backend_address)
        if not success:
            raise HTTPException(status_code=404, detail="Backend not found")

        return {"success": True}

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Error removing backend: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/api/v1/vips/{vip_address}/{vip_port}/{protocol}/backends/{backend_address}/drain")
async def drain_backend(vip_address: str, vip_port: int, protocol: str, backend_address: str):
    """Drain backend (set weight to 0)"""
    if service is None:
        raise HTTPException(status_code=500, detail="Service not initialized")

    try:
        proto = PROTOCOL_MAP.get(protocol.lower())
        if proto is None:
            raise HTTPException(status_code=400, detail=f"Invalid protocol: {protocol}")

        vip = service.vip_manager.get_vip(vip_address, vip_port, proto)
        if vip is None:
            raise HTTPException(status_code=404, detail="VIP not found")

        success = service.real_manager.drain_real(vip, backend_address)
        if not success:
            raise HTTPException(status_code=404, detail="Backend not found")

        return {"success": True, "message": "Backend drained"}

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Error draining backend: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


def create_app(katran_service: KatranService) -> FastAPI:
    """
    Create FastAPI app with service instance.

    Args:
        katran_service: Running KatranService instance

    Returns:
        FastAPI application
    """
    global service
    service = katran_service
    return app
```

### 2.1.5 E2E Test Infrastructure

**Docker Compose for E2E** (`tests/e2e/docker-compose.yml`):

```yaml
version: '3.8'

services:
  katran-e2e:
    build:
      context: ../..
      dockerfile: tests/e2e/Dockerfile
    privileged: true
    cap_add:
      - NET_ADMIN
      - SYS_ADMIN
      - BPF
    volumes:
      - /sys/fs/bpf:/sys/fs/bpf:rw
      - ../../src:/app/src:ro
      - ../../tests:/app/tests:ro
      - ./test-config.yaml:/etc/katran/katran.yaml:ro
    networks:
      - katran-test
    command: >
      sh -c "
        set -e
        echo 'Loading XDP program...'
        xdp-loader load -m skb -s xdp eth0 /app/katran-bpfs/balancer.bpf.o
        echo 'XDP loaded, maps pinned to /sys/fs/bpf/katran'
        ls -la /sys/fs/bpf/katran/
        echo 'Running E2E tests...'
        pytest -v /app/tests/e2e/
      "

networks:
  katran-test:
    driver: bridge
```

**E2E Test Dockerfile** (`tests/e2e/Dockerfile`):

```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    python3.11 python3-pip \
    xdp-tools \
    iproute2 \
    iputils-ping \
    tcpdump \
    bpftool \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY pyproject.toml ./
RUN pip3 install -e ".[dev]"

# Copy BPF programs
COPY katran-bpfs/ /app/katran-bpfs/

# Copy source and tests
COPY src/ /app/src/
COPY tests/ /app/tests/

CMD ["/bin/bash"]
```

**E2E Test Configuration** (`tests/e2e/test-config.yaml`):

```yaml
interface:
  name: eth0
  xdp_mode: skb

bpf:
  xdp_program: /app/katran-bpfs/balancer.bpf.o
  hc_program: /app/katran-bpfs/healthchecking_ipip.o
  pin_path: /sys/fs/bpf/katran

maps:
  max_vips: 128
  max_reals: 1024
  lru_size: 100000
  ring_size: 65537

api:
  enabled: true
  host: 0.0.0.0
  port: 8080

logging:
  level: DEBUG
  format: console

default_gateway_mac: "02:42:ac:14:00:02"
```

**E2E Test Fixtures** (`tests/e2e/conftest.py`):

```python
import pytest
import asyncio
import threading
import time
from pathlib import Path
from httpx import AsyncClient
import uvicorn

from katran.core.config import KatranConfig
from katran.core.logging import setup_logging
from katran.service import KatranService
from katran.api.minimal import create_app


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def katran_config():
    """Load E2E test configuration"""
    config_path = Path("/etc/katran/katran.yaml")
    return KatranConfig.from_yaml(config_path)


@pytest.fixture(scope="session")
def katran_service(katran_config):
    """Start Katran service for E2E tests"""
    # Setup logging
    setup_logging(
        level=katran_config.logging.level,
        log_format=katran_config.logging.format
    )

    # Create and start service
    service = KatranService(katran_config)
    service.start()

    yield service

    # Cleanup
    service.stop()


@pytest.fixture(scope="session")
def api_server(katran_service, katran_config):
    """Start API server in background thread"""
    app = create_app(katran_service)

    config = uvicorn.Config(
        app,
        host=katran_config.api.host,
        port=katran_config.api.port,
        log_level="info"
    )
    server = uvicorn.Server(config)

    # Run server in thread
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for server to start
    time.sleep(2)

    yield server

    # Cleanup (server will stop when thread ends)


@pytest.fixture
async def api_client(api_server, katran_config):
    """HTTP client for API testing"""
    base_url = f"http://{katran_config.api.host}:{katran_config.api.port}"
    async with AsyncClient(base_url=base_url) as client:
        yield client
```

**E2E Test Cases** (`tests/e2e/test_control_plane.py`):

```python
import pytest
from ipaddress import IPv4Address

from katran.core.types import Protocol, VipKey


@pytest.mark.asyncio
async def test_health_check(api_client):
    """Test health check endpoint"""
    response = await api_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


@pytest.mark.asyncio
async def test_add_and_remove_vip(api_client):
    """Test VIP lifecycle through API"""
    # Add VIP
    response = await api_client.post("/api/v1/vips", json={
        "address": "10.200.1.1",
        "port": 80,
        "protocol": "tcp",
        "flags": []
    })
    assert response.status_code == 200
    data = response.json()
    assert data["address"] == "10.200.1.1"
    assert data["port"] == 80
    assert data["protocol"] == "tcp"
    assert "vip_num" in data

    # List VIPs
    response = await api_client.get("/api/v1/vips")
    assert response.status_code == 200
    data = response.json()
    assert len(data["vips"]) >= 1

    # Remove VIP
    response = await api_client.delete("/api/v1/vips/10.200.1.1/80/tcp")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_add_backend_to_vip(api_client):
    """Test adding backend through API"""
    # Add VIP
    await api_client.post("/api/v1/vips", json={
        "address": "10.200.1.2",
        "port": 443,
        "protocol": "tcp"
    })

    # Add backend
    response = await api_client.post(
        "/api/v1/vips/10.200.1.2/443/tcp/backends",
        json={"address": "10.0.0.100", "weight": 100}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["backend"]["address"] == "10.0.0.100"
    assert data["backend"]["weight"] == 100

    # Verify in VIP list
    response = await api_client.get("/api/v1/vips")
    vips = response.json()["vips"]
    test_vip = next(v for v in vips if v["address"] == "10.200.1.2")
    assert len(test_vip["backends"]) == 1
    assert test_vip["backends"][0]["address"] == "10.0.0.100"

    # Cleanup
    await api_client.delete("/api/v1/vips/10.200.1.2/443/tcp")


@pytest.mark.asyncio
async def test_drain_backend(api_client):
    """Test backend draining"""
    # Setup VIP and backend
    await api_client.post("/api/v1/vips", json={
        "address": "10.200.1.3",
        "port": 8080,
        "protocol": "tcp"
    })
    await api_client.post(
        "/api/v1/vips/10.200.1.3/8080/tcp/backends",
        json={"address": "10.0.0.101", "weight": 100}
    )

    # Drain backend
    response = await api_client.put(
        "/api/v1/vips/10.200.1.3/8080/tcp/backends/10.0.0.101/drain"
    )
    assert response.status_code == 200

    # Verify weight is 0
    response = await api_client.get("/api/v1/vips")
    vips = response.json()["vips"]
    test_vip = next(v for v in vips if v["address"] == "10.200.1.3")
    backend = test_vip["backends"][0]
    assert backend["weight"] == 0

    # Cleanup
    await api_client.delete("/api/v1/vips/10.200.1.3/8080/tcp")


def test_service_initialization(katran_service):
    """Test service is properly initialized"""
    assert katran_service.is_running()
    assert katran_service.vip_manager is not None
    assert katran_service.real_manager is not None
    assert katran_service.vip_map is not None


def test_direct_vip_manager_operations(katran_service):
    """Test VIP manager operations directly"""
    vip = katran_service.vip_manager.add_vip(
        address="10.200.2.1",
        port=80,
        protocol=Protocol.TCP
    )

    assert vip.vip_num >= 0
    assert vip.key.address == IPv4Address("10.200.2.1")
    assert vip.key.port == 80

    # Verify in BPF map
    key = VipKey(IPv4Address("10.200.2.1"), 80, Protocol.TCP)
    meta = katran_service.vip_map.get(key)
    assert meta is not None
    assert meta.vip_num == vip.vip_num

    # Cleanup
    katran_service.vip_manager.remove_vip("10.200.2.1", 80, Protocol.TCP)
```

**E2E Test Runner** (`tests/e2e/run-tests.sh`):

```bash
#!/bin/bash
set -e

# E2E test runner for Katran control plane

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$PROJECT_ROOT"

echo "Building E2E test environment..."
docker-compose -f tests/e2e/docker-compose.yml build

echo "Running E2E tests..."
docker-compose -f tests/e2e/docker-compose.yml up --abort-on-container-exit --exit-code-from katran-e2e

echo "Cleaning up..."
docker-compose -f tests/e2e/docker-compose.yml down -v

echo "E2E tests completed successfully!"
```

### 2.1.6 Phase 2.1 Deliverables Checklist

- [ ] Configuration file support (YAML) with pydantic validation
- [ ] Configuration loading and validation tests
- [ ] Example configuration files
- [ ] Basic structured logging setup
- [ ] Control plane service coordinator (KatranService)
- [ ] Service lifecycle management (start/stop)
- [ ] Component initialization and wiring
- [ ] Minimal HTTP API with FastAPI
- [ ] Health check endpoint
- [ ] VIP management API endpoints (add/remove/list)
- [ ] Backend management API endpoints (add/remove/drain)
- [ ] E2E test infrastructure (Docker + Docker Compose)
- [ ] E2E test fixtures with service startup
- [ ] E2E API tests with real HTTP requests
- [ ] E2E tests with direct manager access

---

## Phase 3: XDP/TC Program Loading
**Duration:** 1-2 weeks
**Goal:** Load and manage XDP and TC BPF programs

### 3.1 XDP Program Loader (`bpf/loader.py`)

```python
# Task: Implement XDP and TC program loading

from enum import Enum
from pathlib import Path
import subprocess

class XdpMode(Enum):
    NATIVE = "native"      # Driver support required
    GENERIC = "generic"    # Slower, universal
    OFFLOAD = "offload"    # Hardware offload

class BpfLoader:
    """
    Loads XDP and TC BPF programs.
    
    Uses xdp-loader for XDP attachment (recommended)
    Uses tc command for TC program attachment
    """
    
    def __init__(
        self,
        xdp_program_path: Path,
        healthcheck_program_path: Path,
        interface: str,
        pin_path: Path = Path("/sys/fs/bpf/katran")
    ):
        self.xdp_program = xdp_program_path
        self.hc_program = healthcheck_program_path
        self.interface = interface
        self.pin_path = pin_path
        self._loaded = False
    
    def load_xdp(self, mode: XdpMode = XdpMode.NATIVE) -> None:
        """
        Load XDP program to interface.
        
        Uses xdp-loader for proper multi-program support.
        """
        # Ensure pin directory exists
        self.pin_path.mkdir(parents=True, exist_ok=True)
        
        cmd = [
            "xdp-loader", "load",
            "-m", mode.value,
            "-p", str(self.pin_path),
            self.interface,
            str(self.xdp_program)
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise BpfLoadError(f"XDP load failed: {result.stderr}")
    
    def unload_xdp(self) -> None:
        """Unload XDP program from interface"""
        cmd = ["xdp-loader", "unload", self.interface, "--all"]
        subprocess.run(cmd, capture_output=True)
    
    def load_tc_healthcheck(self) -> None:
        """
        Load TC BPF program for healthcheck forwarding.
        
        Attaches to clsact qdisc on egress.
        """
        # Create clsact qdisc if not exists
        subprocess.run([
            "tc", "qdisc", "add", "dev", self.interface,
            "clsact"
        ], capture_output=True)
        
        # Attach BPF program to egress
        cmd = [
            "tc", "filter", "add", "dev", self.interface,
            "egress", "bpf", "da",
            "obj", str(self.hc_program),
            "sec", "tc"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            raise BpfLoadError(f"TC load failed: {result.stderr}")
    
    def unload_tc_healthcheck(self) -> None:
        """Remove TC healthcheck program"""
        subprocess.run([
            "tc", "filter", "del", "dev", self.interface, "egress"
        ], capture_output=True)
    
    def load_all(self, mode: XdpMode = XdpMode.NATIVE) -> None:
        """Load both XDP and TC programs"""
        self.load_xdp(mode)
        self.load_tc_healthcheck()
        self._loaded = True
    
    def unload_all(self) -> None:
        """Unload all BPF programs"""
        self.unload_tc_healthcheck()
        self.unload_xdp()
        self._loaded = False
    
    def is_loaded(self) -> bool:
        """Check if programs are loaded"""
        return self._loaded
```

### 3.2 Phase 3 Deliverables Checklist

- [ ] XDP program loading via xdp-loader
- [ ] TC program loading for healthcheck
- [ ] Program unloading and cleanup
- [ ] Map pinning setup
- [ ] Error handling for load failures
- [ ] Interface validation
- [ ] Integration tests with actual BPF programs

---

## Phase 4: Statistics & Monitoring
**Duration:** 2 weeks
**Goal:** Implement statistics collection and Prometheus export

### 4.1 Statistics Collector (`stats/collector.py`)

```python
# Task: Implement per-CPU statistics aggregation

from dataclasses import dataclass
from typing import Dict
import time
import threading

@dataclass
class VipStats:
    packets: int = 0
    bytes: int = 0
    lru_hits: int = 0
    lru_misses: int = 0
    connections: int = 0  # Estimated from LRU misses

@dataclass
class GlobalStats:
    total_packets: int = 0
    total_bytes: int = 0
    total_lru_hits: int = 0
    total_lru_misses: int = 0
    vip_misses: int = 0

class StatsCollector:
    """
    Collects and aggregates statistics from BPF maps.
    
    Runs background thread for periodic collection.
    """
    
    def __init__(
        self,
        stats_map: StatsMap,
        lru_miss_map: LruMissStatsMap,
        vip_miss_map: VipMissStatsMap,
        vip_manager: VipManager,
        collection_interval: float = 1.0
    ):
        self._stats_map = stats_map
        self._lru_miss_map = lru_miss_map
        self._vip_miss_map = vip_miss_map
        self._vip_manager = vip_manager
        self._interval = collection_interval
        
        self._vip_stats: Dict[VipKey, VipStats] = {}
        self._global_stats = GlobalStats()
        self._lock = threading.RLock()
        self._running = False
        self._thread: threading.Thread = None
    
    def start(self) -> None:
        """Start background collection"""
        self._running = True
        self._thread = threading.Thread(target=self._collect_loop, daemon=True)
        self._thread.start()
    
    def stop(self) -> None:
        """Stop background collection"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5.0)
    
    def _collect_loop(self) -> None:
        """Background collection loop"""
        while self._running:
            self._collect()
            time.sleep(self._interval)
    
    def _collect(self) -> None:
        """Collect and aggregate stats from all maps"""
        with self._lock:
            # Collect per-VIP stats
            for vip in self._vip_manager.list_vips():
                stats = self._stats_map.aggregate(
                    vip.vip_num,
                    lambda values: VipStats(
                        packets=sum(v.v1 for v in values),
                        bytes=sum(v.v2 for v in values)
                    )
                )
                self._vip_stats[vip.key] = stats
            
            # Collect global stats
            # ... aggregate from maps ...
    
    def get_vip_stats(self, key: VipKey) -> VipStats:
        """Get stats for specific VIP"""
        with self._lock:
            return self._vip_stats.get(key, VipStats())
    
    def get_global_stats(self) -> GlobalStats:
        """Get global statistics"""
        with self._lock:
            return self._global_stats
    
    def get_all_stats(self) -> Dict[VipKey, VipStats]:
        """Get all VIP stats"""
        with self._lock:
            return self._vip_stats.copy()
```

### 4.2 Prometheus Exporter (`stats/prometheus.py`)

```python
# Task: Export metrics to Prometheus

from prometheus_client import Gauge, Counter, start_http_server

class PrometheusExporter:
    """
    Exports Katran metrics to Prometheus.
    
    Metrics:
    - katran_vip_packets_total
    - katran_vip_bytes_total
    - katran_lru_hit_ratio
    - katran_backends_active
    - katran_backends_draining
    """
    
    def __init__(self, stats_collector: StatsCollector, port: int = 9100):
        self._collector = stats_collector
        self._port = port
        
        # Define metrics
        self._vip_packets = Counter(
            'katran_vip_packets_total',
            'Total packets processed per VIP',
            ['vip_address', 'vip_port', 'protocol']
        )
        
        self._vip_bytes = Counter(
            'katran_vip_bytes_total',
            'Total bytes processed per VIP',
            ['vip_address', 'vip_port', 'protocol']
        )
        
        self._lru_hit_ratio = Gauge(
            'katran_lru_hit_ratio',
            'LRU cache hit ratio',
            ['vip_address', 'vip_port', 'protocol']
        )
        
        self._active_backends = Gauge(
            'katran_backends_active',
            'Number of active backends',
            ['vip_address', 'vip_port', 'protocol']
        )
    
    def start(self) -> None:
        """Start Prometheus HTTP server"""
        start_http_server(self._port)
        # Start update loop
    
    def _update_metrics(self) -> None:
        """Update all metrics from collector"""
        for key, stats in self._collector.get_all_stats().items():
            labels = {
                'vip_address': str(key.address),
                'vip_port': str(key.port),
                'protocol': key.protocol.name
            }
            
            self._vip_packets.labels(**labels).inc(stats.packets)
            self._vip_bytes.labels(**labels).inc(stats.bytes)
            # ... update other metrics
```

### 4.3 Phase 4 Deliverables Checklist

- [ ] Per-CPU statistics aggregation
- [ ] Background statistics collection thread
- [ ] Per-VIP statistics (packets, bytes, connections)
- [ ] Global statistics aggregation
- [ ] LRU hit/miss rate calculation
- [ ] Prometheus metrics export
- [ ] HTTP endpoint for metrics scraping
- [ ] Statistics reset capability
- [ ] Unit tests for aggregation logic
- [ ] Integration tests for Prometheus export

---

## Phase 5: Healthcheck Management
**Duration:** 1-2 weeks
**Goal:** Implement healthcheck routing and integration

### 5.1 Healthcheck Manager (`lb/healthcheck.py`)

```python
# Task: Manage SO_MARK to backend mappings

class HealthcheckManager:
    """
    Manages healthcheck forwarding configuration.
    
    Coordinates SO_MARK mappings for external health checkers.
    """
    
    def __init__(
        self,
        hc_reals_map: HcRealsMap,
        reals_map: RealsMap,
        real_manager: RealManager
    ):
        self._hc_map = hc_reals_map
        self._reals_map = reals_map
        self._real_manager = real_manager
        self._mappings: Dict[int, tuple[Vip, Real]] = {}
        self._next_mark = 1000  # Starting SO_MARK value
        self._lock = RLock()
    
    def add_healthcheck_dst(
        self,
        vip: Vip,
        real: Real,
        mark: Optional[int] = None
    ) -> int:
        """
        Add healthcheck routing for backend.
        
        Returns assigned SO_MARK value.
        """
        with self._lock:
            if mark is None:
                mark = self._allocate_mark()
            
            # Update BPF map
            self._hc_map.set(mark, real.index)
            
            self._mappings[mark] = (vip, real)
            
            return mark
    
    def remove_healthcheck_dst(self, mark: int) -> bool:
        """Remove healthcheck routing by SO_MARK"""
        with self._lock:
            if mark not in self._mappings:
                return False
            
            self._hc_map.delete(mark)
            del self._mappings[mark]
            
            return True
    
    def list_healthcheck_dsts(self) -> list[dict]:
        """List all healthcheck mappings"""
        with self._lock:
            return [
                {
                    'mark': mark,
                    'vip': str(vip.key),
                    'backend': str(real.address)
                }
                for mark, (vip, real) in self._mappings.items()
            ]
    
    def _allocate_mark(self) -> int:
        """Allocate next available SO_MARK"""
        mark = self._next_mark
        self._next_mark += 1
        return mark
```

### 5.2 Phase 5 Deliverables Checklist

- [ ] SO_MARK to backend mapping management
- [ ] Healthcheck destination CRUD operations
- [ ] Mark allocation strategy
- [ ] Integration with RealManager for draining
- [ ] Healthcheck statistics collection
- [ ] Unit tests for mapping operations
- [ ] Integration tests with TC program

---

## Phase 6: API Layer
**Duration:** 2-3 weeks
**Goal:** Implement gRPC and REST APIs

### 6.1 gRPC Service (`api/grpc/service.py`)

```protobuf
// api/grpc/katran.proto
syntax = "proto3";

package katran;

service KatranService {
    // VIP Management
    rpc AddVip(AddVipRequest) returns (VipResponse);
    rpc RemoveVip(VipIdentifier) returns (StatusResponse);
    rpc ListVips(Empty) returns (VipListResponse);
    rpc ModifyVip(ModifyVipRequest) returns (VipResponse);
    
    // Backend Management
    rpc AddReal(AddRealRequest) returns (RealResponse);
    rpc RemoveReal(RemoveRealRequest) returns (StatusResponse);
    rpc ModifyReal(ModifyRealRequest) returns (RealResponse);
    rpc ListReals(VipIdentifier) returns (RealListResponse);
    
    // Healthcheck
    rpc AddHealthcheckDst(HealthcheckRequest) returns (HealthcheckResponse);
    rpc RemoveHealthcheckDst(HealthcheckMarkRequest) returns (StatusResponse);
    rpc ListHealthcheckDsts(Empty) returns (HealthcheckListResponse);
    
    // Statistics
    rpc GetVipStats(VipIdentifier) returns (VipStatsResponse);
    rpc GetGlobalStats(Empty) returns (GlobalStatsResponse);
    
    // Introspection
    rpc LookupFlow(FlowRequest) returns (FlowResponse);
}

message AddVipRequest {
    string address = 1;
    uint32 port = 2;
    string protocol = 3;  // "tcp" or "udp"
    repeated string flags = 4;
}

message VipResponse {
    bool success = 1;
    string message = 2;
    Vip vip = 3;
}

// ... additional message definitions
```

```python
# api/grpc/service.py
import grpc
from concurrent import futures
from . import katran_pb2, katran_pb2_grpc

class KatranServicer(katran_pb2_grpc.KatranServiceServicer):
    """gRPC service implementation"""
    
    def __init__(
        self,
        vip_manager: VipManager,
        real_manager: RealManager,
        healthcheck_manager: HealthcheckManager,
        stats_collector: StatsCollector
    ):
        self._vip_mgr = vip_manager
        self._real_mgr = real_manager
        self._hc_mgr = healthcheck_manager
        self._stats = stats_collector
    
    def AddVip(self, request, context):
        try:
            protocol = Protocol[request.protocol.upper()]
            flags = VipFlags.NONE
            for flag_name in request.flags:
                flags |= VipFlags[flag_name.upper()]
            
            vip = self._vip_mgr.add_vip(
                address=request.address,
                port=request.port,
                protocol=protocol,
                flags=flags
            )
            
            return katran_pb2.VipResponse(
                success=True,
                vip=self._vip_to_proto(vip)
            )
        except Exception as e:
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(e))
            return katran_pb2.VipResponse(success=False, message=str(e))
    
    # ... additional method implementations

def serve(port: int, servicer: KatranServicer):
    """Start gRPC server"""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    katran_pb2_grpc.add_KatranServiceServicer_to_server(servicer, server)
    server.add_insecure_port(f'[::]:{port}')
    server.start()
    return server
```

### 6.2 REST API (`api/rest/app.py`)

```python
# Task: Implement REST API using FastAPI

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="Katran Control Plane", version="1.0.0")

class AddVipRequest(BaseModel):
    address: str
    port: int
    protocol: str
    flags: list[str] = []

class AddRealRequest(BaseModel):
    address: str
    weight: int = 100

@app.post("/api/v1/vips")
async def add_vip(request: AddVipRequest):
    """Add new VIP"""
    try:
        vip = vip_manager.add_vip(
            address=request.address,
            port=request.port,
            protocol=Protocol[request.protocol.upper()],
            flags=parse_flags(request.flags)
        )
        return {"success": True, "vip": vip_to_dict(vip)}
    except VipExistsError as e:
        raise HTTPException(status_code=409, detail=str(e))

@app.delete("/api/v1/vips/{address}/{port}/{protocol}")
async def remove_vip(address: str, port: int, protocol: str):
    """Remove VIP"""
    success = vip_manager.remove_vip(
        address, port, Protocol[protocol.upper()]
    )
    if not success:
        raise HTTPException(status_code=404, detail="VIP not found")
    return {"success": True}

@app.get("/api/v1/vips")
async def list_vips():
    """List all VIPs"""
    vips = vip_manager.list_vips()
    return {"vips": [vip_to_dict(v) for v in vips]}

@app.post("/api/v1/vips/{address}/{port}/{protocol}/backends")
async def add_real(
    address: str, port: int, protocol: str,
    request: AddRealRequest
):
    """Add backend to VIP"""
    vip = vip_manager.get_vip(address, port, Protocol[protocol.upper()])
    if not vip:
        raise HTTPException(status_code=404, detail="VIP not found")
    
    real = real_manager.add_real(vip, request.address, request.weight)
    return {"success": True, "backend": real_to_dict(real)}

@app.get("/api/v1/stats")
async def get_stats():
    """Get global statistics"""
    return stats_collector.get_global_stats().__dict__

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy"}
```

### 6.3 Phase 6 Deliverables Checklist

- [ ] Protocol buffer definitions
- [ ] gRPC service implementation
- [ ] REST API using FastAPI
- [ ] Input validation for all endpoints
- [ ] Error handling and status codes
- [ ] API authentication (optional)
- [ ] API rate limiting (optional)
- [ ] OpenAPI documentation
- [ ] Unit tests for API endpoints
- [ ] Integration tests for full API flow

---

## Phase 7: CLI Tool
**Duration:** 1 week
**Goal:** Command-line interface for operations

### 7.1 CLI Implementation (`cli/main.py`)

```python
# Task: Implement CLI using Click

import click
import grpc
from tabulate import tabulate

@click.group()
@click.option('--host', default='localhost', help='Control plane host')
@click.option('--port', default=50051, help='Control plane port')
@click.pass_context
def cli(ctx, host, port):
    """Katran Control Plane CLI"""
    ctx.ensure_object(dict)
    ctx.obj['channel'] = grpc.insecure_channel(f'{host}:{port}')
    ctx.obj['stub'] = KatranServiceStub(ctx.obj['channel'])

@cli.group()
def vip():
    """VIP management commands"""
    pass

@vip.command('add')
@click.option('--ip', required=True, help='VIP IP address')
@click.option('--port', required=True, type=int, help='VIP port')
@click.option('--proto', default='tcp', help='Protocol (tcp/udp)')
@click.option('--flag', multiple=True, help='VIP flags')
@click.pass_context
def vip_add(ctx, ip, port, proto, flag):
    """Add new VIP"""
    stub = ctx.obj['stub']
    response = stub.AddVip(AddVipRequest(
        address=ip, port=port, protocol=proto, flags=list(flag)
    ))
    if response.success:
        click.echo(f"Added VIP {ip}:{port}/{proto}")
    else:
        click.echo(f"Error: {response.message}", err=True)

@vip.command('list')
@click.pass_context
def vip_list(ctx):
    """List all VIPs"""
    stub = ctx.obj['stub']
    response = stub.ListVips(Empty())
    
    table = []
    for vip in response.vips:
        table.append([
            vip.address, vip.port, vip.protocol,
            len(vip.backends), ', '.join(vip.flags)
        ])
    
    click.echo(tabulate(
        table,
        headers=['Address', 'Port', 'Protocol', 'Backends', 'Flags']
    ))

@cli.group()
def real():
    """Backend management commands"""
    pass

@real.command('add')
@click.option('--vip', required=True, help='VIP (ip:port:proto)')
@click.option('--backend', required=True, help='Backend IP')
@click.option('--weight', default=100, type=int, help='Weight')
@click.pass_context
def real_add(ctx, vip, backend, weight):
    """Add backend to VIP"""
    # Parse VIP and add backend
    pass

@real.command('drain')
@click.option('--vip', required=True, help='VIP (ip:port:proto)')
@click.option('--backend', required=True, help='Backend IP')
@click.pass_context
def real_drain(ctx, vip, backend):
    """Drain backend (set weight to 0)"""
    pass

@cli.group()
def stats():
    """Statistics commands"""
    pass

@stats.command('show')
@click.option('--vip', help='Specific VIP (optional)')
@click.pass_context
def stats_show(ctx, vip):
    """Show statistics"""
    pass

if __name__ == '__main__':
    cli()
```

### 7.2 Phase 7 Deliverables Checklist

- [ ] VIP commands (add, remove, list, modify)
- [ ] Backend commands (add, remove, drain, list)
- [ ] Healthcheck commands (add, remove, list)
- [ ] Statistics commands (show, reset)
- [ ] Formatted table output
- [ ] JSON output option
- [ ] Error handling and user feedback
- [ ] Shell completion support
- [ ] Man page generation

---

## Phase 8: Production Hardening
**Duration:** 2-3 weeks
**Goal:** Production-ready features and reliability

**Note:** Basic configuration and logging were implemented in Phase 2.1. This phase focuses on advanced production features.

### 8.1 Hot Configuration Reload

```python
# Task: Implement hot reload capability
# Extends basic service from Phase 2.1

from typing import Set
from dataclasses import dataclass

@dataclass
class ConfigChange:
    """Represents a configuration change"""
    type: str  # 'vip_added', 'vip_removed', 'backend_changed', etc.
    old_value: any
    new_value: any

class ConfigDiffer:
    """Computes differences between configurations"""

    def diff(self, old_config: KatranConfig, new_config: KatranConfig) -> list[ConfigChange]:
        """
        Compute configuration changes.

        Returns list of atomic changes that can be applied.
        """
        changes = []

        # Check API configuration changes
        if old_config.api.port != new_config.api.port:
            changes.append(ConfigChange(
                type='api_port_changed',
                old_value=old_config.api.port,
                new_value=new_config.api.port
            ))

        # Check logging level changes
        if old_config.logging.level != new_config.logging.level:
            changes.append(ConfigChange(
                type='log_level_changed',
                old_value=old_config.logging.level,
                new_value=new_config.logging.level
            ))

        # Add more configuration comparisons...

        return changes


class KatranService:
    """Extended service with hot reload"""

    def reload_config(self, new_config_path: Path) -> bool:
        """
        Hot reload configuration without downtime.

        Args:
            new_config_path: Path to new configuration file

        Returns:
            True if reload successful, False otherwise
        """
        log.info("Starting configuration reload", config_path=str(new_config_path))

        try:
            # Load new configuration
            new_config = KatranConfig.from_yaml(new_config_path)

            # Validate new configuration
            new_config.validate()

            # Compute differences
            differ = ConfigDiffer()
            changes = differ.diff(self.config, new_config)

            if not changes:
                log.info("No configuration changes detected")
                return True

            log.info(f"Applying {len(changes)} configuration changes")

            # Apply changes atomically
            for change in changes:
                self._apply_config_change(change)

            # Update current config
            self.config = new_config

            log.info("Configuration reload completed successfully")
            return True

        except Exception as e:
            log.error("Configuration reload failed", error=str(e), exc_info=True)
            return False

    def _apply_config_change(self, change: ConfigChange) -> None:
        """Apply single configuration change"""
        if change.type == 'log_level_changed':
            # Update log level dynamically
            logging.getLogger().setLevel(change.new_value)
            log.info(f"Log level changed to {change.new_value}")

        elif change.type == 'api_port_changed':
            # Would require API server restart
            log.warning("API port change requires service restart")

        # Add more change handlers...
```

### 8.2 Advanced Structured Logging with Audit Trail

```python
# Task: Implement comprehensive structured logging
# Extends basic logging from Phase 2.1

import structlog
from typing import Optional

class AuditLogger:
    """
    Audit logger for tracking all configuration changes.

    Logs to separate audit log file for compliance.
    """

    def __init__(self, audit_log_path: Path):
        self.log = structlog.get_logger("audit")
        self._setup_audit_handler(audit_log_path)

    def _setup_audit_handler(self, path: Path) -> None:
        """Setup dedicated audit log file handler"""
        handler = logging.FileHandler(path)
        handler.setFormatter(
            logging.Formatter('%(message)s')  # structlog handles formatting
        )
        self.log.addHandler(handler)

    def log_vip_added(
        self,
        vip_key: VipKey,
        vip_num: int,
        user: Optional[str] = None,
        source_ip: Optional[str] = None
    ) -> None:
        """Log VIP addition"""
        self.log.info(
            "vip.added",
            action="vip_added",
            vip_address=str(vip_key.address),
            vip_port=vip_key.port,
            protocol=vip_key.protocol.name,
            vip_num=vip_num,
            user=user,
            source_ip=source_ip
        )

    def log_vip_removed(
        self,
        vip_key: VipKey,
        user: Optional[str] = None
    ) -> None:
        """Log VIP removal"""
        self.log.info(
            "vip.removed",
            action="vip_removed",
            vip_address=str(vip_key.address),
            vip_port=vip_key.port,
            protocol=vip_key.protocol.name,
            user=user
        )

    def log_backend_added(
        self,
        vip_key: VipKey,
        backend_address: str,
        weight: int,
        user: Optional[str] = None
    ) -> None:
        """Log backend addition"""
        self.log.info(
            "backend.added",
            action="backend_added",
            vip_address=str(vip_key.address),
            vip_port=vip_key.port,
            backend_address=backend_address,
            weight=weight,
            user=user
        )

    # Additional audit methods...


def setup_advanced_logging(config: KatranConfig) -> tuple[AuditLogger, structlog.BoundLogger]:
    """
    Setup comprehensive structured logging.

    Returns:
        Tuple of (audit_logger, main_logger)
    """
    # Configure structlog with advanced processors
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.CallsiteParameterAdder(
                parameters=[
                    structlog.processors.CallsiteParameter.FILENAME,
                    structlog.processors.CallsiteParameter.FUNC_NAME,
                    structlog.processors.CallsiteParameter.LINENO,
                ]
            ),
            structlog.processors.JSONRenderer()
            if config.logging.format == "json"
            else structlog.dev.ConsoleRenderer()
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Setup audit logger
    audit_log_path = Path("/var/log/katran/audit.log")
    audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    audit_logger = AuditLogger(audit_log_path)

    # Main logger
    main_logger = structlog.get_logger()

    return audit_logger, main_logger
```

### 8.3 Enhanced Graceful Shutdown

```python
# Task: Implement enhanced graceful shutdown
# Extends basic shutdown from Phase 2.1

class ShutdownCoordinator:
    """
    Coordinates graceful shutdown across all components.

    Ensures proper ordering and timeout handling.
    """

    def __init__(self, service: KatranService):
        self.service = service
        self.shutdown_timeout = 30.0
        self.drain_timeout = 20.0

    def shutdown(self) -> None:
        """
        Perform graceful shutdown with proper ordering.

        Steps:
        1. Stop accepting new API requests (return 503)
        2. Drain existing API connections
        3. Stop statistics collection
        4. Wait for in-flight operations
        5. Close BPF maps
        6. Unload XDP programs
        """
        log.info("Starting graceful shutdown")

        shutdown_start = time.time()

        try:
            # Phase 1: Stop accepting new requests
            log.info("Phase 1: Stopping API servers")
            self._stop_api_servers()

            # Phase 2: Drain connections
            log.info("Phase 2: Draining connections", timeout=self.drain_timeout)
            self._wait_for_drain(self.drain_timeout)

            # Phase 3: Stop statistics collection
            log.info("Phase 3: Stopping statistics collection")
            if self.service.stats_collector:
                self.service.stats_collector.stop()

            # Phase 4: Wait for in-flight operations
            log.info("Phase 4: Waiting for in-flight operations")
            self._wait_for_inflight_operations(timeout=5.0)

            # Phase 5: Close BPF maps
            log.info("Phase 5: Closing BPF maps")
            self.service._close_maps()

            # Phase 6: Unload XDP programs
            log.info("Phase 6: Unloading XDP programs")
            if self.service.loader:
                self.service.loader.unload_all()

            shutdown_duration = time.time() - shutdown_start
            log.info("Graceful shutdown completed", duration=shutdown_duration)

        except Exception as e:
            log.error("Error during shutdown", error=str(e), exc_info=True)
            raise

    def _stop_api_servers(self) -> None:
        """Stop API servers and return 503 for new requests"""
        # Implementation depends on Phase 6 API servers
        pass

    def _wait_for_drain(self, timeout: float) -> None:
        """Wait for existing connections to drain"""
        time.sleep(timeout)

    def _wait_for_inflight_operations(self, timeout: float) -> None:
        """Wait for any in-flight BPF map operations"""
        # Check if managers have pending operations
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not self._has_inflight_operations():
                return
            time.sleep(0.1)
```

### 8.4 Readiness and Liveness Probes

```python
# Task: Implement health probes for orchestration

from enum import Enum

class ServiceStatus(Enum):
    STARTING = "starting"
    READY = "ready"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"

class HealthProbes:
    """
    Health probes for Kubernetes/orchestration.

    - Liveness: Is the service alive? (should we restart?)
    - Readiness: Is the service ready for traffic? (should we route traffic?)
    """

    def __init__(self, service: KatranService):
        self.service = service
        self.status = ServiceStatus.STARTING

    def liveness(self) -> dict:
        """
        Liveness probe - indicates if service is alive.

        Returns 200 unless service is in unrecoverable state.
        """
        # Basic liveness check
        if not self.service.is_running():
            return {"status": "dead", "code": 503}

        # Check if critical components are functional
        try:
            # Can we access BPF maps?
            if self.service.vip_map:
                self.service.vip_map.get_fd()

            return {"status": "alive", "code": 200}
        except Exception as e:
            return {"status": "dead", "error": str(e), "code": 503}

    def readiness(self) -> dict:
        """
        Readiness probe - indicates if service is ready for traffic.

        Returns 200 only when service is fully initialized and healthy.
        """
        if not self.service.is_running():
            return {
                "status": "not_ready",
                "reason": "service_not_running",
                "code": 503
            }

        # Check all components are initialized
        checks = {
            "vip_manager": self.service.vip_manager is not None,
            "real_manager": self.service.real_manager is not None,
            "maps_open": self.service._maps_opened,
            "xdp_loaded": self.service.loader and self.service.loader.is_loaded() if hasattr(self.service, 'loader') else True,
        }

        if not all(checks.values()):
            failed = [k for k, v in checks.items() if not v]
            return {
                "status": "not_ready",
                "reason": "components_not_initialized",
                "failed_checks": failed,
                "code": 503
            }

        return {
            "status": "ready",
            "checks": checks,
            "code": 200
        }
```

### 8.5 Phase 8 Deliverables Checklist

- [ ] Hot configuration reload capability
- [ ] Configuration change diffing and atomic application
- [ ] Advanced structured logging with structlog
- [ ] Audit logging for all configuration changes
- [ ] Enhanced graceful shutdown coordinator
- [ ] Shutdown phase ordering and timeout handling
- [ ] Liveness probe endpoint
- [ ] Readiness probe endpoint
- [ ] Resource cleanup on failure
- [ ] Connection draining support
- [ ] Signal handler improvements (SIGHUP for reload)

---

## Phase 9: Testing & Quality
**Duration:** 2 weeks
**Goal:** Comprehensive testing and quality assurance

### 9.1 Testing Strategy

```python
# tests/unit/test_maglev.py
class TestMaglevHashRing:
    """Unit tests for Maglev algorithm"""
    
    def test_ring_size_must_be_prime(self):
        with pytest.raises(ValueError):
            MaglevHashRing(ring_size=100)  # Not prime
    
    def test_uniform_distribution(self):
        """Verify keys are distributed uniformly"""
        ring = MaglevHashRing(ring_size=65537)
        backends = [(i, 100) for i in range(5)]  # Equal weights
        ring.build(backends)
        
        # Count distribution
        counts = Counter(ring.get_ring())
        
        # Each backend should have ~20% of ring
        expected = 65537 / 5
        for backend_id, count in counts.items():
            assert abs(count - expected) / expected < 0.01  # Within 1%
    
    def test_minimal_disruption(self):
        """Verify adding backend causes minimal key changes"""
        ring = MaglevHashRing(ring_size=65537)
        
        # Initial ring with 3 backends
        backends = [(i, 100) for i in range(3)]
        ring.build(backends)
        initial_ring = ring.get_ring()
        
        # Add 4th backend
        backends.append((3, 100))
        ring.build(backends)
        new_ring = ring.get_ring()
        
        # Count changed positions
        changes = sum(1 for i, j in zip(initial_ring, new_ring) if i != j)
        
        # Should change ~25% (1/4 of keys)
        assert changes / 65537 < 0.30  # Within 30%

# tests/integration/test_vip_operations.py
class TestVipOperations:
    """Integration tests for VIP management"""
    
    @pytest.fixture
    def katran_service(self, bpf_test_env):
        """Create test service with real BPF maps"""
        return KatranService(test_config)
    
    def test_add_vip_creates_ring(self, katran_service):
        """Adding VIP should create empty CH ring"""
        vip = katran_service.vip_manager.add_vip(
            "10.200.1.1", 80, Protocol.TCP
        )
        
        # Verify ring exists
        ring = katran_service._ch_rings_map.read_ring(vip.vip_num)
        assert len(ring) == 65537
    
    def test_add_backend_updates_ring(self, katran_service):
        """Adding backend should update CH ring"""
        vip = katran_service.vip_manager.add_vip(
            "10.200.1.1", 80, Protocol.TCP
        )
        
        real = katran_service.real_manager.add_real(
            vip, "10.0.0.100", weight=100
        )
        
        # Verify ring contains backend
        ring = katran_service._ch_rings_map.read_ring(vip.vip_num)
        assert real.index in ring

# tests/integration/test_e2e.py
class TestEndToEnd:
    """End-to-end tests with packet forwarding"""
    
    def test_packet_forwarding(self, katran_service, packet_generator):
        """Test complete packet flow through XDP"""
        # Setup VIP and backend
        vip = katran_service.vip_manager.add_vip(
            "10.200.1.1", 80, Protocol.TCP
        )
        real = katran_service.real_manager.add_real(
            vip, "10.0.0.100", weight=100
        )
        
        # Send test packet
        packet_generator.send_tcp_syn(
            dst_ip="10.200.1.1",
            dst_port=80
        )
        
        # Verify forwarding (check for IPIP packet to backend)
        forwarded = packet_generator.capture_output()
        assert forwarded.is_ipip()
        assert forwarded.inner_dst == "10.200.1.1"
```

### 9.2 Phase 9 Deliverables Checklist

- [ ] Unit tests for all core components (>80% coverage)
- [ ] Integration tests with real BPF maps
- [ ] End-to-end packet forwarding tests
- [ ] Performance benchmarks
- [ ] Load testing
- [ ] Chaos testing (failure injection)
- [ ] Code linting (ruff, mypy)
- [ ] Security scanning
- [ ] Documentation generation

---

## Phase 10: Documentation & Deployment
**Duration:** 1-2 weeks
**Goal:** Complete documentation and deployment artifacts

### 10.1 Deliverables

- [ ] README with quick start guide
- [ ] Architecture documentation
- [ ] API reference documentation
- [ ] CLI reference documentation
- [ ] Configuration reference
- [ ] Troubleshooting guide
- [ ] Deployment guide (systemd, containers)
- [ ] Dockerfile and container images
- [ ] Helm chart (optional)
- [ ] Example configurations
- [ ] Runbook for operations

---

## Summary Timeline

| Phase | Duration | Key Deliverable |
|-------|----------|-----------------|
| 1. Foundation | 2-3 weeks | BPF map management |
| 2. Core LB Logic | 2-3 weeks | VIP/Real management, Maglev |
| 2.1. Service & E2E | 2 weeks | Control plane service, E2E testing |
| 3. XDP/TC Loading | 1-2 weeks | Program loading |
| 4. Statistics | 2 weeks | Monitoring & Prometheus |
| 5. Healthcheck | 1-2 weeks | HC routing |
| 6. API Layer | 2-3 weeks | gRPC & REST APIs |
| 7. CLI Tool | 1 week | Command-line interface |
| 8. Production | 2-3 weeks | Hardening & reliability |
| 9. Testing | 2 weeks | Comprehensive testing |
| 10. Documentation | 1-2 weeks | Docs & deployment |

**Total Estimated Duration:** 18-25 weeks

---

## Dependencies

```toml
# pyproject.toml
[project]
name = "katran-control-plane"
version = "1.0.0"
requires-python = ">=3.11"

dependencies = [
    "pyroute2>=0.7.0",        # Network interface management
    "grpcio>=1.50.0",         # gRPC framework
    "grpcio-tools>=1.50.0",   # Protocol buffer compiler
    "fastapi>=0.100.0",       # REST API framework
    "uvicorn>=0.23.0",        # ASGI server
    "prometheus-client>=0.17.0",  # Prometheus metrics
    "pydantic>=2.0.0",        # Data validation
    "click>=8.0.0",           # CLI framework
    "structlog>=23.0.0",      # Structured logging
    "pyyaml>=6.0",            # Configuration files
    "tabulate>=0.9.0",        # CLI table formatting
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pytest-asyncio>=0.21.0",
    "pytest-cov>=4.0.0",
    "ruff>=0.1.0",
    "mypy>=1.5.0",
    "black>=23.0.0",
]
```

---

## Risk Mitigation

| Risk | Mitigation |
|------|------------|
| BPF compatibility issues | Test on target kernel versions early |
| Performance bottlenecks | Profile early, benchmark each phase |
| API breaking changes | Version APIs, maintain compatibility |
| Memory leaks in BPF maps | Implement proper resource cleanup |
| Race conditions | Use proper locking, test concurrency |
| Configuration drift | Validate config, support reconciliation |
