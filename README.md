# Katran Control Plane

Python control plane for the Katran L4 XDP load balancer.

## Overview

This package provides a Python-based control plane for managing Katran's BPF maps, VIPs, and backend servers. It implements type-safe wrappers around Katran's BPF data structures and provides high-level APIs for load balancer configuration.

## Features (Phase 1 Complete)

- **Core Data Structures**: Type-safe Python representations of all Katran BPF structures
  - `VipKey`: VIP definition (address:port:protocol)
  - `VipMeta`: VIP metadata (flags, vip_num)
  - `RealDefinition`: Backend server definition
  - `FlowKey`: 5-tuple flow key for LRU cache
  - `LbStats`: Statistics counters

- **BPF Map Wrappers**: Type-safe access to Katran BPF maps
  - `VipMap`: VIP hash map management
  - `RealsMap`: Backend server array management
  - `ChRingsMap`: Consistent hash rings
  - `StatsMap`: Per-CPU statistics
  - `CtlArray`: Control configuration
  - `HcRealsMap`: Healthcheck routing
  - `LruMap`: LRU flow cache

- **Index Allocation**: Thread-safe index management for VIPs and backends

## Installation

```bash
# Development installation
pip install -e ".[dev]"

# Production installation
pip install .
```

## Requirements

- Python 3.11+
- Linux kernel with BPF support
- Katran BPF programs loaded

## Quick Start

```python
from katran.core import VipKey, Protocol, VipFlags, Vip
from katran.bpf import VipMap, RealsMap, ChRingsMap

# Open BPF maps
pin_path = "/sys/fs/bpf/katran"

with VipMap(pin_path) as vip_map:
    # Create a VIP
    vip = Vip.create(
        address="10.200.1.1",
        port=80,
        protocol="tcp",
        flags=VipFlags.NONE
    )

    # Add to BPF map
    vip_num = vip_map.add_vip(vip)
    print(f"Added VIP with vip_num={vip_num}")

    # List all VIPs
    for key in vip_map.list_vips():
        print(f"  {key}")
```

## Project Structure

```
katran-control-plane/
├── src/katran/
│   ├── core/           # Core types and constants
│   │   ├── types.py    # BPF data structures
│   │   ├── constants.py # Constants matching BPF headers
│   │   └── exceptions.py
│   ├── bpf/            # BPF map management
│   │   ├── map_manager.py  # Base map operations
│   │   └── maps/       # Individual map wrappers
│   ├── lb/             # Load balancer logic (Phase 2)
│   ├── api/            # gRPC and REST APIs (Phase 6)
│   ├── stats/          # Statistics collection (Phase 4)
│   └── cli/            # CLI tools (Phase 7)
├── tests/
│   ├── unit/           # Unit tests
│   └── integration/    # Integration tests
└── config/
    └── katran.yaml     # Sample configuration
```

## Testing

```bash
# Run all tests
pytest

# Run unit tests only
pytest tests/unit/

# Run with coverage
pytest --cov=katran tests/
```

## Development Status

This is Phase 1 of the Katran Control Plane implementation:

- [x] Phase 1: Foundation & BPF Infrastructure
  - [x] Project structure
  - [x] Core data structures with serialization
  - [x] BPF map base manager
  - [x] Individual map wrappers
  - [x] Unit tests for serialization

- [ ] Phase 2: Core Load Balancing Logic
- [ ] Phase 3: XDP/TC Program Loading
- [ ] Phase 4: Statistics & Monitoring
- [ ] Phase 5: Healthcheck Management
- [ ] Phase 6: API Layer
- [ ] Phase 7: CLI Tool
- [ ] Phase 8: Production Hardening

## License

Apache 2.0 - See LICENSE file for details.
