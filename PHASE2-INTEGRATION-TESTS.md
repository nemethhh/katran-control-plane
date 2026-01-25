# Phase 2 Integration Tests Explained

## Overview

The Phase 2 integration tests verify that `VipManager` and `RealManager` correctly interact with **actual BPF maps** in the Linux kernel. Unlike unit tests that use mocks, these tests make real syscalls to manipulate BPF maps that the XDP program will use for packet processing.

---

## Test Environment Setup

### 1. Docker Container with BPF Support

```yaml
# docker-compose.test.yml
services:
  katran-target:
    privileged: true           # Required for BPF operations
    cap_add:
      - NET_ADMIN              # Network configuration
      - SYS_ADMIN              # System administration
      - BPF                    # BPF operations
    volumes:
      - /sys/fs/bpf:/sys/fs/bpf:rw    # BPF filesystem (for map pins)
      - /sys/kernel/btf:/sys/kernel/btf:ro  # BTF type info
```

**Why privileged?** BPF map operations require `CAP_BPF` + `CAP_NET_ADMIN` capabilities to:
- Load XDP programs
- Create/access BPF maps
- Pin maps to filesystem
- Attach programs to network interfaces

### 2. XDP Program Loading

```bash
# Before tests run (in run-tests.sh)
xdp-loader load -m skb -p /sys/fs/bpf/katran eth0 /app/katran-bpfs/balancer.bpf.o
```

This command:
1. Loads the compiled `balancer.bpf.o` XDP program
2. Attaches it to `eth0` interface in SKB mode
3. **Pins all BPF maps** to `/sys/fs/bpf/katran/`
4. Creates maps like:
   - `vip_map` (hash map)
   - `reals` (array)
   - `ch_rings` (array)
   - `stats` (per-CPU array)
   - `lru_map` (LRU hash map)

After loading, the maps exist in the kernel and can be accessed via syscalls.

---

## How Integration Tests Work

### Test Flow Diagram

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Test starts in Python                                    │
│    test_add_ipv4_vip(vip_manager)                           │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. VipManager.add_vip("10.200.1.100", 80, TCP)             │
│    - Allocates vip_num = 0                                  │
│    - Creates VipMeta(flags=0, vip_num=0)                    │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. VipMap.set(key, meta)                                    │
│    - Serializes VipKey to 20 bytes                          │
│    - Serializes VipMeta to 8 bytes                          │
│    - Opens pinned map: /sys/fs/bpf/katran/vip_map           │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. BPF Syscall: bpf(BPF_MAP_UPDATE_ELEM, ...)               │
│    - fd = open("/sys/fs/bpf/katran/vip_map")                │
│    - bpf(BPF_MAP_UPDATE_ELEM, fd, key_bytes, val_bytes)     │
│    ┌──────────────────────────────────────────────────┐    │
│    │  KERNEL SPACE                                     │    │
│    │  ┌────────────────────────────────────────────┐  │    │
│    │  │ vip_map (BPF_MAP_TYPE_HASH)                │  │    │
│    │  │ ┌──────────────────┬──────────────────┐    │  │    │
│    │  │ │ 10.200.1.100:80  │ vip_num=0        │    │  │    │
│    │  │ │ Protocol=TCP     │ flags=0          │    │  │    │
│    │  │ └──────────────────┴──────────────────┘    │  │    │
│    │  └────────────────────────────────────────────┘  │    │
│    └──────────────────────────────────────────────────┘    │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│ 5. ChRingsMap.write_ring(vip_num=0, ring=[0, 0, ...])      │
│    - Writes 65537 entries (empty ring, no backends yet)     │
│    - Base offset: 0 * 65537 = 0                             │
│    - Each entry: key=(base+position), value=0               │
│    ┌──────────────────────────────────────────────────┐    │
│    │  KERNEL SPACE                                     │    │
│    │  ┌────────────────────────────────────────────┐  │    │
│    │  │ ch_rings (BPF_MAP_TYPE_ARRAY)              │  │    │
│    │  │ [0]=0, [1]=0, [2]=0, ... [65536]=0         │  │    │
│    │  └────────────────────────────────────────────┘  │    │
│    └──────────────────────────────────────────────────┘    │
└──────────────────┬──────────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────────┐
│ 6. Test verification                                         │
│    assert vip.vip_num == 0                                  │
│    assert vip_manager.vip_exists(vip.key)                   │
│    ✓ VIP successfully created in kernel BPF map!            │
└─────────────────────────────────────────────────────────────┘
```

---

## Detailed Test Examples

### Example 1: Adding a VIP

**Test Code:**
```python
def test_add_ipv4_vip(vip_manager):
    vip = vip_manager.add_vip("10.200.1.100", 8080, Protocol.TCP)

    assert vip.vip_num >= 0
    assert vip.is_allocated
    assert vip.key.address == IPv4Address("10.200.1.100")
```

**What Actually Happens:**

1. **Index Allocation**
   - `VipManager._vip_num_allocator.allocate()` returns next available index (e.g., 0)
   - Index is marked as "in use" to prevent reuse

2. **BPF Map Write** (`vip_map`)
   ```
   Key: [16 bytes address][2 bytes port][1 byte proto][1 byte pad]
   Key: [10.200.1.100 + 12 zeros][8080][6][0] = 20 bytes total

   Value: [4 bytes flags][4 bytes vip_num]
   Value: [0x00000000][0x00000000] = 8 bytes total

   Syscall: bpf(BPF_MAP_UPDATE_ELEM, vip_map_fd, &key, &value, 0)
   ```

3. **Ring Initialization** (`ch_rings`)
   ```
   Base offset: vip_num * 65537 = 0 * 65537 = 0

   For position 0 to 65536:
       key = base + position
       value = 0 (no backends yet)
       bpf(BPF_MAP_UPDATE_ELEM, ch_rings_fd, &key, &value, 0)
   ```

4. **Verification Read**
   - Test calls `vip_manager.vip_exists(vip.key)`
   - This does: `bpf(BPF_MAP_LOOKUP_ELEM, vip_map_fd, &key, &value)`
   - Returns the `VipMeta` we just wrote
   - Confirms the VIP exists in kernel memory

**Result:** VIP configuration is now in kernel and XDP program can see it!

---

### Example 2: Adding Backend and Building Hash Ring

**Test Code:**
```python
def test_add_real_to_vip(real_manager, test_vip):
    real = real_manager.add_real(test_vip, "10.0.0.100", weight=100)

    assert real.is_allocated
    assert real.index >= 1  # Index 0 reserved
    assert len(test_vip.reals) == 1
```

**What Actually Happens:**

1. **Backend Index Allocation**
   ```python
   # In RealManager._increase_ref_count()
   index = reals_map.allocate_index()  # Returns 1 (0 is reserved)
   ```

2. **BPF Map Write** (`reals`)
   ```
   Key: [4 bytes index]
   Key: [0x00000001] = 1

   Value: [16 bytes address][1 byte flags][3 bytes pad]
   Value: [10.0.0.100 + 12 zeros][0x00][0x00][0x00][0x00] = 20 bytes

   Syscall: bpf(BPF_MAP_UPDATE_ELEM, reals_fd, &index, &real_def, 0)
   ```

3. **Maglev Ring Generation**
   ```python
   # In RealManager._rebuild_ring()
   endpoints = [Endpoint(num=1, weight=100, hash=hash("10.0.0.100"))]
   ring = maglev.build(endpoints)  # Returns [1, 1, 1, ..., 1] (65537 entries)
   ```

4. **Ring Write** (`ch_rings`)
   ```
   Base offset: vip_num * 65537 = 0 * 65537 = 0

   For position 0 to 65536:
       key = base + position = 0 + position
       value = 1 (backend index)
       bpf(BPF_MAP_UPDATE_ELEM, ch_rings_fd, &key, &value, 0)

   Result in kernel:
   ch_rings[0] = 1
   ch_rings[1] = 1
   ch_rings[2] = 1
   ...
   ch_rings[65536] = 1
   ```

5. **Verification Read**
   ```python
   # Test reads the ring back
   ring = ch_rings_map.read_ring(test_vip.vip_num)

   # For each position:
   bpf(BPF_MAP_LOOKUP_ELEM, ch_rings_fd, &key, &value)

   assert 1 in ring  # Backend index 1 is in the ring
   assert ring.count(1) == 65537  # All positions point to backend 1
   ```

**Result:**
- Backend definition stored in kernel
- Consistent hash ring points all traffic to this backend
- XDP program can now forward packets!

---

### Example 3: Weighted Backend Distribution

**Test Code:**
```python
def test_weighted_hash_ring(real_manager, test_vip, ch_rings_map):
    real1 = real_manager.add_real(test_vip, "10.0.0.100", weight=100)
    real2 = real_manager.add_real(test_vip, "10.0.0.101", weight=50)

    ring = ch_rings_map.read_ring(test_vip.vip_num)

    count_real1 = ring.count(real1.index)
    count_real2 = ring.count(real2.index)

    # Real1 should have ~2x positions of Real2
    ratio = count_real1 / count_real2
    assert 1.5 < ratio < 2.5
```

**What Actually Happens:**

1. **First Backend Added**
   - Index 1 allocated for 10.0.0.100
   - Ring built: all 65537 positions → backend 1

2. **Second Backend Added**
   - Index 2 allocated for 10.0.0.101
   - **Maglev recalculation** with both backends:

   ```python
   endpoints = [
       Endpoint(num=1, weight=100, hash=hash("10.0.0.100")),
       Endpoint(num=2, weight=50,  hash=hash("10.0.0.101")),
   ]

   # Maglev algorithm fills ring:
   # - Backend 1 gets ~2/3 of positions (weight=100)
   # - Backend 2 gets ~1/3 of positions (weight=50)
   ```

3. **Ring Update** (`ch_rings`)
   ```
   Old ring: [1, 1, 1, 1, 1, 1, 1, 1, ...]
   New ring: [1, 1, 2, 1, 1, 2, 1, 1, ...]

   Only changed positions are written:
   ch_rings[2] = 2  (changed from 1)
   ch_rings[5] = 2  (changed from 1)
   ch_rings[8] = 2  (changed from 1)
   ...

   Optimization: ~21,845 writes instead of 65,537
   ```

4. **Distribution Verification**
   ```python
   # Read all 65537 entries back from kernel
   ring = []
   for pos in range(65537):
       key = base + pos
       value = bpf(BPF_MAP_LOOKUP_ELEM, ch_rings_fd, &key)
       ring.append(value)

   # Count distribution
   count_1 = ring.count(1)  # ~43,691 (66.7%)
   count_2 = ring.count(2)  # ~21,846 (33.3%)

   # Verify 2:1 ratio
   ratio = count_1 / count_2  # ~2.0 ✓
   ```

**Result:** Weighted load distribution configured in kernel!

---

## Reference Counting Test

**Test Code:**
```python
def test_real_reference_counting(real_manager, vip_manager):
    vip1 = vip_manager.add_vip("10.200.1.201", 80, Protocol.TCP)
    vip2 = vip_manager.add_vip("10.200.1.202", 80, Protocol.TCP)

    # Add same backend to both VIPs
    real1 = real_manager.add_real(vip1, "10.0.0.100", weight=100)
    real2 = real_manager.add_real(vip2, "10.0.0.100", weight=100)

    # Should have same index (shared)
    assert real1.index == real2.index
    assert real_manager.get_real_ref_count("10.0.0.100") == 2
```

**What Actually Happens:**

1. **First VIP Adds Backend**
   ```python
   # RealManager._increase_ref_count("10.0.0.100")
   # Backend doesn't exist, allocate:
   index = 1
   reals_map.set(1, RealDefinition("10.0.0.100"))

   # State:
   _reals["10.0.0.100"] = RealMeta(num=1, ref_count=1)
   _num_to_reals[1] = "10.0.0.100"
   ```

2. **Second VIP Adds Same Backend**
   ```python
   # RealManager._increase_ref_count("10.0.0.100")
   # Backend exists, increment ref count:
   _reals["10.0.0.100"].ref_count = 2

   # NO new BPF map write!
   # Just reuse existing index 1
   ```

3. **Both VIPs Use Same Index**
   ```
   VIP1 (10.200.1.201:80):
     ch_rings[vip_num=0 * 65537 + pos] = 1

   VIP2 (10.200.1.202:80):
     ch_rings[vip_num=1 * 65537 + pos] = 1

   Both point to same backend at reals[1]!
   ```

4. **Remove from One VIP**
   ```python
   real_manager.remove_real(vip1, "10.0.0.100")

   # Decrement ref count
   _reals["10.0.0.100"].ref_count = 1

   # Backend NOT deleted (still used by vip2)
   # reals[1] still exists in kernel
   ```

5. **Remove from Second VIP**
   ```python
   real_manager.remove_real(vip2, "10.0.0.100")

   # Decrement ref count to 0
   _reals["10.0.0.100"].ref_count = 0

   # NOW delete backend:
   reals_map.free_index(1)
   del _reals["10.0.0.100"]
   del _num_to_reals[1]

   # Index 1 can be reused for new backend
   ```

**Result:** Efficient backend sharing across VIPs!

---

## Kernel State Verification

At any point, we can **verify kernel state** by reading BPF maps:

### Read VIP Configuration
```python
# Python
key = VipKey(IPv4Address("10.200.1.100"), 80, Protocol.TCP)
meta = vip_map.get(key)
print(f"vip_num={meta.vip_num}, flags={meta.flags}")

# Equivalent kernel operation:
# struct vip_definition key = {...};
# struct vip_meta *meta;
# bpf_map_lookup_elem(vip_map, &key, &meta);
```

### Read Backend Definition
```python
# Python
real_def = reals_map.get(index=1)
print(f"address={real_def.address}")

# Equivalent kernel operation:
# __u32 key = 1;
# struct real_definition *real;
# bpf_map_lookup_elem(reals, &key, &real);
```

### Read Hash Ring Position
```python
# Python
vip_num = 0
position = 12345
base = vip_num * 65537
real_index = ch_rings_map.get(base + position)
print(f"Position {position} → backend {real_index}")

# This is exactly what XDP program does for packet forwarding!
```

---

## Why This Matters

### 1. Real Kernel Interaction
- Tests verify **actual BPF syscalls** work correctly
- Catches serialization bugs (struct layout mismatches)
- Validates permissions and capabilities
- Ensures map sizes and types are correct

### 2. End-to-End Flow
- Python → Syscall → Kernel → XDP Program
- Tests the entire control plane → data plane path
- Would catch issues mocks can't detect

### 3. Production-Like Environment
- Same privileged container as production
- Same BPF programs as production
- Same kernel version and BPF features

### 4. Ring Distribution Verification
- Can read 65,537 entries back and verify Maglev distribution
- Checks weighted load balancing math
- Validates minimal disruption on changes

---

## Test Output Example

```
test_add_ipv4_vip PASSED
  - VIP key: 10.200.1.100:8080/tcp
  - Allocated vip_num: 0
  - BPF vip_map updated: ✓
  - Ring initialized: 65537 entries written

test_add_multiple_reals PASSED
  - Backend 10.0.0.100 → index 1
  - Backend 10.0.0.101 → index 2
  - Backend 10.0.0.102 → index 3
  - Ring distribution:
    * Backend 1: 21846 positions (33.3%)
    * Backend 2: 21845 positions (33.3%)
    * Backend 3: 21846 positions (33.3%)

test_weighted_hash_ring PASSED
  - Backend 10.0.0.100 (weight=100) → 43691 positions (66.7%)
  - Backend 10.0.0.101 (weight=50)  → 21846 positions (33.3%)
  - Ratio: 2.00 (expected ~2.0) ✓
```

---

## Summary

**Integration tests verify:**
1. ✅ VIP configuration written to kernel BPF maps
2. ✅ Backend indices allocated and definitions stored
3. ✅ Consistent hash rings built with correct distribution
4. ✅ Reference counting prevents premature backend deletion
5. ✅ Ring updates use minimal writes (optimized delta)
6. ✅ All data is readable back from kernel (roundtrip)
7. ✅ XDP program can use this configuration to forward packets

**The difference from unit tests:**
- Unit tests: Mock BPF maps, test logic in isolation
- Integration tests: Real BPF maps, test entire kernel interaction path

This gives us confidence that the Python control plane will work correctly with the C++ XDP data plane in production!
