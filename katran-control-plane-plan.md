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

### 8.1 Graceful Operations

```python
# Task: Implement graceful shutdown and hot reload

class KatranService:
    """Main service coordinator"""
    
    def __init__(self, config: Config):
        self._config = config
        self._running = False
        self._shutdown_event = threading.Event()
        
        # Initialize components
        self._loader = BpfLoader(...)
        self._vip_manager = VipManager(...)
        self._real_manager = RealManager(...)
        self._stats_collector = StatsCollector(...)
    
    def start(self) -> None:
        """Start all service components"""
        # Load BPF programs
        self._loader.load_all()
        
        # Open BPF maps
        self._open_maps()
        
        # Start statistics collection
        self._stats_collector.start()
        
        # Start API servers
        self._start_apis()
        
        self._running = True
        
        # Register signal handlers
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        signal.signal(signal.SIGINT, self._handle_shutdown)
    
    def _handle_shutdown(self, signum, frame):
        """Handle shutdown signal"""
        logging.info("Received shutdown signal, starting graceful shutdown")
        self._shutdown_event.set()
    
    def shutdown(self, timeout: float = 30.0) -> None:
        """Graceful shutdown"""
        logging.info("Starting graceful shutdown")
        
        # Stop accepting new connections
        # (signal to external load balancer)
        
        # Wait for drain period
        logging.info(f"Draining connections for {timeout}s")
        time.sleep(timeout)
        
        # Stop statistics collection
        self._stats_collector.stop()
        
        # Stop API servers
        self._stop_apis()
        
        # Close BPF maps
        self._close_maps()
        
        # Unload BPF programs
        self._loader.unload_all()
        
        logging.info("Shutdown complete")
    
    def reload_config(self, new_config: Config) -> None:
        """Hot reload configuration"""
        # Diff current vs new config
        # Apply changes atomically
        pass
```

### 8.2 Configuration Management

```python
# Task: Implement configuration loading and validation

from pydantic import BaseSettings, validator
import yaml

class KatranConfig(BaseSettings):
    """Katran configuration with validation"""
    
    # Interface configuration
    interface: str
    xdp_mode: str = "native"
    
    # BPF program paths
    xdp_program: str = "/usr/share/katran/balancer.o"
    hc_program: str = "/usr/share/katran/healthchecking_ipip.o"
    
    # Map configuration
    max_vips: int = 512
    max_reals: int = 4096
    lru_size: int = 1_000_000
    ring_size: int = 65537
    
    # API configuration
    grpc_port: int = 50051
    rest_port: int = 8080
    prometheus_port: int = 9100
    
    # Gateway configuration
    default_gateway_mac: str
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "json"
    
    @validator('ring_size')
    def ring_size_must_be_prime(cls, v):
        if not is_prime(v):
            raise ValueError('ring_size must be prime')
        return v
    
    @validator('interface')
    def interface_must_exist(cls, v):
        if not interface_exists(v):
            raise ValueError(f'interface {v} does not exist')
        return v
    
    @classmethod
    def from_yaml(cls, path: str) -> 'KatranConfig':
        """Load configuration from YAML file"""
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(**data)
```

### 8.3 Logging Infrastructure

```python
# Task: Implement structured logging

import structlog
import logging.config

def setup_logging(config: KatranConfig) -> None:
    """Configure structured logging"""
    
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
            if config.log_format == "json"
            else structlog.dev.ConsoleRenderer()
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

# Usage
log = structlog.get_logger()
log.info("vip_added", vip=str(vip.key), vip_num=vip.vip_num)
log.error("ring_rebuild_failed", vip=str(vip.key), error=str(e))
```

### 8.4 Phase 8 Deliverables Checklist

- [ ] Graceful startup sequence
- [ ] Graceful shutdown with draining
- [ ] Configuration file support (YAML)
- [ ] Configuration validation
- [ ] Hot reload capability
- [ ] Structured logging (JSON)
- [ ] Log levels and filtering
- [ ] Audit logging for changes
- [ ] Resource cleanup on failure
- [ ] Health check endpoint
- [ ] Readiness probe

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
| 3. XDP/TC Loading | 1-2 weeks | Program loading |
| 4. Statistics | 2 weeks | Monitoring & Prometheus |
| 5. Healthcheck | 1-2 weeks | HC routing |
| 6. API Layer | 2-3 weeks | gRPC & REST APIs |
| 7. CLI Tool | 1 week | Command-line interface |
| 8. Production | 2-3 weeks | Hardening & reliability |
| 9. Testing | 2 weeks | Comprehensive testing |
| 10. Documentation | 1-2 weeks | Docs & deployment |

**Total Estimated Duration:** 16-23 weeks

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
