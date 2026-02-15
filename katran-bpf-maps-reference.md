# Katran BPF Maps: Complete Reference

## Overview

This document provides a comprehensive reference for all BPF maps used in Katran's XDP load balancer. These maps serve as the primary data structures for communication between the control plane (userspace) and data plane (kernel XDP program).

---

## Table of Contents

1. [Map Architecture](#map-architecture)
2. [Core Maps](#core-maps)
3. [Connection Tracking Maps](#connection-tracking-maps)
4. [Statistics Maps](#statistics-maps)
5. [Healthcheck Maps](#healthcheck-maps)
6. [Control Maps](#control-maps)
7. [Advanced Maps](#advanced-maps)
8. [Data Structures](#data-structures)
9. [Map Operations](#map-operations)
10. [Performance Considerations](#performance-considerations)

---

## Map Architecture

### Design Principles

1. **Per-CPU Design:** Minimize lock contention through per-CPU data structures
2. **Lock-Free:** Use atomic operations and per-CPU maps to avoid locks
3. **Memory Efficiency:** Pre-allocate where possible, use LRU for dynamic data
4. **Fast Lookup:** Optimize for read performance in hot path
5. **Bounded Resources:** All maps have maximum size limits

### Map Categories

```
Katran BPF Maps
├─ Configuration Maps (control plane → data plane)
│  ├─ vip_map          [VIP configurations]
│  ├─ reals            [Backend server IPs]
│  ├─ ch_rings         [Consistent hashing rings]
│  └─ ctl_array        [Global control settings]
├─ Connection Tracking (data plane state)
│  ├─ lru_mapping      [Per-CPU LRU caches]
│  └─ fallback_cache   [Global fallback LRU]
├─ Statistics (data plane → control plane)
│  ├─ stats            [Per-VIP statistics]
│  ├─ lru_miss_stats   [LRU miss counters]
│  └─ vip_miss_stats   [VIP lookup failures]
├─ Healthcheck (control plane config)
│  └─ hc_reals_map     [SO_MARK → backend mapping]
└─ Advanced (optional)
   ├─ server_id_map    [Load balancer instance ID]
   ├─ quic_mapping     [QUIC connection ID routing]
   └─ event_pipe       [Packet monitoring]
```

---

## Core Maps

### 1. vip_map (VIP Configuration)

**Purpose:** Stores all Virtual IP configurations - the primary lookup table for incoming packets.

**Map Type:** `BPF_MAP_TYPE_HASH`

**Structure:**
```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct vip_definition);     // VIP key (IP:port:proto)
    __type(value, struct vip_meta);         // VIP metadata
    __uint(max_entries, MAX_VIPS);          // Default: 512
    __uint(map_flags, NO_FLAGS);
} vip_map SEC(".maps");
```

**Key Structure:**
```c
struct vip_definition {
    union {
        __u32 vip;          // IPv4 address
        __u32 vipv6[4];     // IPv6 address
    };
    __u16 port;             // Port number
    __u8 proto;             // Protocol: 6=TCP, 17=UDP
    __u8 pad;               // Padding for alignment
};
```

**Value Structure:**
```c
struct vip_meta {
    __u32 flags;            // VIP behavior flags
    __u32 vip_num;          // Index for CH ring and stats
};
```

**VIP Flags:**
```c
#define F_HASH_NO_SRC_PORT  0x0001  // Don't use source port in hash
#define F_LRU_BYPASS        0x0002  // Skip LRU cache lookup
#define F_QUIC_VIP          0x0004  // QUIC connection ID routing
#define F_HASH_DPORT_ONLY   0x0008  // Hash only destination port
#define F_LOCAL_VIP         0x0010  // Local packet handling
#define F_DIRECT_RETURN     0x0020  // Skip IPIP encapsulation
```

**Operations:**
- **Control Plane:** Add, remove, modify VIP configurations
- **Data Plane:** Lookup VIP on every incoming packet

**Access Pattern:**
- Read: Every packet (hot path)
- Write: Configuration changes (cold path)

**Performance:**
- Lookup: O(1) hash table
- Memory: ~40 bytes per VIP entry

**Example:**
```c
// Control plane: Add VIP
struct vip_definition key = {
    .vip = inet_addr("10.200.1.1"),
    .port = htons(80),
    .proto = IPPROTO_TCP
};
struct vip_meta value = {
    .flags = 0,
    .vip_num = 0  // First VIP
};
bpf_map_update_elem(&vip_map, &key, &value, BPF_ANY);

// Data plane: Lookup VIP
struct vip_meta *vip_info = bpf_map_lookup_elem(&vip_map, &vip_key);
if (!vip_info) {
    return XDP_PASS;  // Not a VIP, pass to kernel
}
```

---

### 2. reals (Backend Servers Array)

**Purpose:** Stores IP addresses of all backend servers. Array indexed by backend ID.

**Map Type:** `BPF_MAP_TYPE_ARRAY`

**Structure:**
```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);                     // Backend index
    __type(value, struct real_definition);  // Backend IP
    __uint(max_entries, MAX_REALS);         // Default: 4096
    __uint(map_flags, NO_FLAGS);
} reals SEC(".maps");
```

**Value Structure:**
```c
struct real_definition {
    union {
        __u32 dst;          // IPv4 backend address
        __u32 dstv6[4];     // IPv6 backend address
    };
    __u8 flags;             // Backend flags (reserved)
    __u8 pad[3];            // Padding
};
```

**Backend Flags:**
```c
#define F_IPV6_BACKEND  0x01  // Backend is IPv6
```

**Operations:**
- **Control Plane:** Add/remove/modify backend servers
- **Data Plane:** Lookup backend IP by index from CH ring

**Access Pattern:**
- Read: After CH ring lookup (for every new connection)
- Write: When backends are added/removed

**Performance:**
- Lookup: O(1) array access
- Memory: ~20 bytes per backend

**Example:**
```c
// Control plane: Add backend
__u32 index = 0;
struct real_definition real = {
    .dst = inet_addr("10.0.0.100"),
    .flags = 0
};
bpf_map_update_elem(&reals, &index, &real, BPF_ANY);

// Data plane: Get backend IP
__u32 backend_idx = ch_ring_result;  // From CH ring lookup
struct real_definition *backend = bpf_map_lookup_elem(&reals, &backend_idx);
if (backend) {
    // Use backend->dst for IPIP encapsulation
}
```

---

### 3. ch_rings (Consistent Hashing Rings)

**Purpose:** Maglev consistent hashing rings for uniform backend selection with minimal disruption on changes.

**Map Type:** `BPF_MAP_TYPE_ARRAY`

**Structure:**
```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);                 // Ring position
    __type(value, __u32);               // Backend index
    __uint(max_entries, CH_RINGS_SIZE); // e.g., 65537 * num_vips
    __uint(map_flags, NO_FLAGS);
} ch_rings SEC(".maps");
```

**Ring Layout:**
```
VIP 0: positions 0 to RING_SIZE-1
VIP 1: positions RING_SIZE to 2*RING_SIZE-1
VIP N: positions N*RING_SIZE to (N+1)*RING_SIZE-1

Where RING_SIZE is typically 65537 (prime number)
```

**Operations:**
- **Control Plane:** Build/rebuild ring using Maglev algorithm
- **Data Plane:** Hash packet → lookup ring position → get backend index

**Access Pattern:**
- Read: For every new connection (cache miss)
- Write: When backends change for a VIP

**Performance:**
- Lookup: O(1) array access
- Rebuild: O(RING_SIZE * num_backends)
- Memory: 4 bytes per ring position

**Consistent Hashing Algorithm:**
```c
// Control plane: Build Maglev ring
void build_maglev_ring(__u32 vip_num, __u32 *backends, __u32 num_backends) {
    __u32 ring_size = 65537;  // Must be prime
    __u32 *ring = calloc(ring_size, sizeof(__u32));
    
    // Generate permutations for each backend
    for (int i = 0; i < num_backends; i++) {
        __u32 offset = hash1(backends[i]) % ring_size;
        __u32 skip = hash2(backends[i]) % (ring_size - 1) + 1;
        
        // Fill ring using permutation
        for (int j = 0; j < ring_size; j++) {
            __u32 pos = (offset + j * skip) % ring_size;
            if (ring[pos] == 0) {
                ring[pos] = backends[i];
            }
        }
    }
    
    // Write ring to BPF map
    __u32 base = vip_num * ring_size;
    for (int i = 0; i < ring_size; i++) {
        __u32 key = base + i;
        bpf_map_update_elem(&ch_rings, &key, &ring[i], BPF_ANY);
    }
}

// Data plane: Lookup in ring
__u32 lookup_backend(struct packet_info *pkt, struct vip_meta *vip) {
    __u32 hash = hash_packet(pkt);  // Hash 5-tuple
    __u32 ring_pos = hash % RING_SIZE;
    __u32 key = vip->vip_num * RING_SIZE + ring_pos;
    
    __u32 *backend_idx = bpf_map_lookup_elem(&ch_rings, &key);
    return backend_idx ? *backend_idx : 0;
}
```

---

## Connection Tracking Maps

### 4. lru_mapping (Per-CPU LRU Cache)

**Purpose:** Connection tracking with LRU eviction. Maps flow 5-tuple to backend selection.

**Map Type:** `BPF_MAP_TYPE_ARRAY_OF_MAPS` (outer) containing `BPF_MAP_TYPE_LRU_HASH` (inner)

**Structure:**
```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __type(key, __u32);                     // CPU index
    __type(value, __u32);                   // Inner map FD
    __uint(max_entries, MAX_SUPPORTED_CPUS);// e.g., 128
    __array(values, struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __type(key, struct flow_key);       // 5-tuple
        __type(value, struct real_pos_lru); // Backend info
        __uint(max_entries, LRU_SIZE);      // e.g., 1M per CPU
        __uint(map_flags, BPF_F_NO_COMMON_LRU);
    });
} lru_mapping SEC(".maps");
```

**Flow Key:**
```c
struct flow_key {
    union {
        __u32 src;          // IPv4 source
        __u32 srcv6[4];     // IPv6 source
    };
    union {
        __u32 dst;          // IPv4 destination
        __u32 dstv6[4];     // IPv6 destination
    };
    union {
        __u32 ports;        // Both ports as u32
        __u16 port16[2];    // [0]=src_port, [1]=dst_port
    };
    __u8 proto;             // Protocol
    __u8 flags;             // Reserved
};
```

**Value Structure:**
```c
struct real_pos_lru {
    __u32 pos;              // Backend index
    __u64 atime;            // Access time (for stats)
};
```

**Operations:**
- **Control Plane:** Initialize per-CPU maps, configure size
- **Data Plane:** Lookup/update on every packet

**Access Pattern:**
- Read: Every packet (hot path)
- Write: On new connections (cache misses)
- Eviction: Automatic LRU eviction when full

**Performance:**
- Lookup: O(1) hash table (lock-free per-CPU)
- Memory: ~48 bytes per flow entry
- Eviction: O(1) LRU

**Example:**
```c
// Data plane: LRU cache lookup
struct flow_key fkey;
// ... populate fkey from packet ...

__u32 cpu = bpf_get_smp_processor_id();
void *lru_map = bpf_map_lookup_elem(&lru_mapping, &cpu);
if (!lru_map) {
    goto fallback;
}

struct real_pos_lru *cached = bpf_map_lookup_elem(lru_map, &fkey);
if (cached) {
    // Cache hit - use cached backend
    backend_idx = cached->pos;
} else {
    // Cache miss - calculate via CH ring
    backend_idx = lookup_in_ch_ring(...);
    
    // Update cache
    struct real_pos_lru new_entry = {
        .pos = backend_idx,
        .atime = bpf_ktime_get_ns()
    };
    bpf_map_update_elem(lru_map, &fkey, &new_entry, BPF_ANY);
}
```

**Why Per-CPU:**
- Eliminates lock contention
- Scales linearly with CPU count
- Each CPU has independent LRU accounting
- RSS ensures flows hit same CPU

---

### 5. fallback_cache (Global Fallback LRU)

**Purpose:** Global LRU cache for edge cases when per-CPU lookup fails.

**Map Type:** `BPF_MAP_TYPE_LRU_HASH`

**Structure:**
```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct flow_key);
    __type(value, struct real_pos_lru);
    __uint(max_entries, DEFAULT_LRU_SIZE);  // Small, e.g., 10K
    __uint(map_flags, NO_FLAGS);
} fallback_cache SEC(".maps");
```

**Use Cases:**
- Per-CPU map allocation failure
- Cross-CPU flow migration (rare)
- Startup before per-CPU maps initialized
- Testing and debugging

**Performance:**
- Slower than per-CPU (global locking)
- Should rarely be used in production

---

## Statistics Maps

### 6. stats (Per-VIP Statistics)

**Purpose:** Collect packet and byte counters per VIP.

**Map Type:** `BPF_MAP_TYPE_PERCPU_ARRAY`

**Structure:**
```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);                     // VIP number
    __type(value, struct lb_stats);         // Counters
    __uint(max_entries, STATS_SIZE);        // Max VIPs
    __uint(map_flags, NO_FLAGS);
} stats SEC(".maps");
```

**Value Structure:**
```c
struct lb_stats {
    __u64 v1;   // Packets processed
    __u64 v2;   // Bytes processed
};
```

**Operations:**
- **Control Plane:** Read and aggregate per-CPU stats
- **Data Plane:** Increment counters on packet forwarding

**Access Pattern:**
- Read: Periodic statistics collection
- Write: Every forwarded packet

**Performance:**
- Update: Lock-free per-CPU increment
- Aggregation: O(num_cpus) for control plane

**Example:**
```c
// Data plane: Update stats
__u32 vip_num = vip_info->vip_num;
struct lb_stats *stat = bpf_map_lookup_elem(&stats, &vip_num);
if (stat) {
    stat->v1++;                    // Increment packet count
    stat->v2 += pkt_len;           // Add bytes
}

// Control plane: Aggregate per-CPU stats
__u64 total_packets = 0;
__u64 total_bytes = 0;
int num_cpus = sysconf(_SC_NPROCESSORS_ONLN);

for (int cpu = 0; cpu < num_cpus; cpu++) {
    struct lb_stats cpu_stat;
    bpf_map_lookup_elem_percpu(&stats, &vip_num, &cpu_stat, cpu);
    total_packets += cpu_stat.v1;
    total_bytes += cpu_stat.v2;
}
```

---

### 7. lru_miss_stats (LRU Miss Statistics)

**Purpose:** Track LRU cache miss rates for performance monitoring.

**Map Type:** `BPF_MAP_TYPE_PERCPU_ARRAY`

**Structure:**
```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);                     // Stats index
    __type(value, struct lru_stats);        // Miss counters
    __uint(max_entries, MAX_VIPS);
    __uint(map_flags, NO_FLAGS);
} lru_miss_stats SEC(".maps");
```

**Value Structure:**
```c
struct lru_stats {
    __u64 lru_misses;       // Total cache misses
    __u64 tcp_syns;         // TCP SYN packets (new connections)
    __u64 tcp_non_syns;     // TCP non-SYN packets
    __u64 udp_pkts;         // UDP packets
    __u64 fallback_hits;    // Global LRU cache hits
};
```

**Metrics:**
```
LRU Hit Rate = (total_packets - lru_misses) / total_packets
New Connection Rate = tcp_syns / total_tcp_packets
```

---

### 8. vip_miss_stats (VIP Lookup Failures)

**Purpose:** Track packets that don't match any configured VIP.

**Map Type:** `BPF_MAP_TYPE_PERCPU_ARRAY`

**Structure:**
```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);                   // Miss counter
    __uint(max_entries, 1);
    __uint(map_flags, NO_FLAGS);
} vip_miss_stats SEC(".maps");
```

**Use Case:**
- Detect misconfigurations
- Identify unauthorized traffic
- Security monitoring

---

## Healthcheck Maps

### 9. hc_reals_map (Healthcheck Routing)

**Purpose:** Map SO_MARK values to specific backend servers for healthcheck forwarding.

**Map Type:** `BPF_MAP_TYPE_HASH`

**Structure:**
```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);                     // SO_MARK value
    __type(value, __u32);                   // Backend index
    __uint(max_entries, MAX_REALS);
    __uint(map_flags, NO_FLAGS);
} hc_reals_map SEC(".maps");
```

**Operations:**
- **Control Plane:** Map healthcheck marks to backends
- **Data Plane (TC egress):** Lookup SO_MARK and route to backend

**Usage Flow:**
1. Healthcheck tool sets SO_MARK on socket
2. Packet exits via egress → TC BPF intercepts
3. TC program looks up SO_MARK in hc_reals_map
4. Gets backend index → lookups backend IP in reals map
5. Encapsulates in IPIP to specific backend

**Example:**
```c
// Control plane: Add healthcheck mapping
__u32 mark = 1000;      // SO_MARK value
__u32 backend_idx = 5;  // Backend server index
bpf_map_update_elem(&hc_reals_map, &mark, &backend_idx, BPF_ANY);

// TC egress program: Route healthcheck
__u32 mark = skb->mark;  // Get SO_MARK from packet
__u32 *backend_idx = bpf_map_lookup_elem(&hc_reals_map, &mark);
if (backend_idx) {
    // Forward to specific backend
    struct real_definition *backend = 
        bpf_map_lookup_elem(&reals, backend_idx);
    // ... IPIP encapsulation ...
}
```

---

## Control Maps

### 10. ctl_array (Global Control Settings)

**Purpose:** Runtime configuration and control parameters.

**Map Type:** `BPF_MAP_TYPE_ARRAY`

**Structure:**
```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);                     // Control index
    __type(value, struct ctl_value);        // Settings
    __uint(max_entries, CTL_MAP_SIZE);      // e.g., 16
    __uint(map_flags, NO_FLAGS);
} ctl_array SEC(".maps");
```

**Control Indices:**
```c
#define CTL_MAC_ADDR_POS    0   // Default gateway MAC
#define CTL_SERVER_ID_POS   1   // Load balancer instance ID
```

**Value Structure:**
```c
struct ctl_value {
    union {
        __u64 value;            // Generic value
        __u32 ifindex;          // Interface index
        __u8 mac[6];            // MAC address
    };
};
```

**Gateway MAC Configuration:**
```c
// Control plane: Set default gateway MAC
struct ctl_value mac_value;
memcpy(mac_value.mac, "\x52\x54\x00\x12\x35\x02", 6);
__u32 key = CTL_MAC_ADDR_POS;
bpf_map_update_elem(&ctl_array, &key, &mac_value, BPF_ANY);

// Data plane: Get gateway MAC for IPIP encapsulation
struct ctl_value *mac_val = bpf_map_lookup_elem(&ctl_array, &key);
if (mac_val) {
    memcpy(eth_hdr->h_dest, mac_val->mac, 6);
}
```

---

## Advanced Maps

### 11. server_id_map (Instance Identification)

**Purpose:** Unique identifier for each load balancer instance in distributed setups.

**Map Type:** `BPF_MAP_TYPE_ARRAY`

**Structure:**
```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);                   // Server ID
    __uint(max_entries, 1);
    __uint(map_flags, NO_FLAGS);
} server_id_map SEC(".maps");
```

**Use Cases:**
- Multi-datacenter deployments
- Packet tracing and debugging
- Distributed troubleshooting
- Server identification in IPIP header

---

### 12. quic_mapping (QUIC Connection ID Routing)

**Purpose:** Route QUIC connections based on connection ID instead of 5-tuple.

**Map Type:** `BPF_MAP_TYPE_LRU_HASH`

**Structure:**
```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct quic_connection_id); // Connection ID
    __type(value, __u32);                   // Backend index
    __uint(max_entries, QUIC_CACHE_SIZE);
    __uint(map_flags, NO_FLAGS);
} quic_mapping SEC(".maps");
```

**Connection ID Structure:**
```c
struct quic_connection_id {
    __u8 data[20];          // QUIC connection ID (up to 160 bits)
    __u8 len;               // Actual length
};
```

**Benefits:**
- Support connection migration
- Maintain connection on IP/port change
- Better for mobile clients

---

### 13. event_pipe (Packet Monitoring)

**Purpose:** Send sampled packets to userspace for monitoring and debugging.

**Map Type:** `BPF_MAP_TYPE_PERF_EVENT_ARRAY`

**Structure:**
```c
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);                     // CPU index
    __type(value, __u32);                   // FD
    __uint(max_entries, MAX_CPUS);
    __uint(map_flags, NO_FLAGS);
} event_pipe SEC(".maps");
```

**Event Structure:**
```c
struct packet_event {
    __u32 vip_num;
    __u32 backend_idx;
    __u8 decision;          // DROP, FORWARD, etc.
    __u16 pkt_len;
    __u8 packet_sample[64]; // First 64 bytes
};
```

**Usage:**
```c
// Data plane: Send packet sample
if (should_sample()) {
    struct packet_event event = {
        .vip_num = vip_info->vip_num,
        .backend_idx = backend_idx,
        .decision = XDP_TX
    };
    bpf_perf_event_output(ctx, &event_pipe, 
                          BPF_F_CURRENT_CPU, 
                          &event, sizeof(event));
}
```

---

## Data Structures

### Complete Type Definitions

```c
// VIP Definition (Key for vip_map)
struct vip_definition {
    union {
        __u32 vip;
        __u32 vipv6[4];
    };
    __u16 port;
    __u8 proto;
    __u8 pad;
} __attribute__((packed));

// VIP Metadata
struct vip_meta {
    __u32 flags;
    __u32 vip_num;
} __attribute__((packed));

// Backend Server Definition
struct real_definition {
    union {
        __u32 dst;
        __u32 dstv6[4];
    };
    __u8 flags;
    __u8 pad[3];
} __attribute__((packed));

// Flow Key (5-tuple)
struct flow_key {
    union {
        __u32 src;
        __u32 srcv6[4];
    };
    union {
        __u32 dst;
        __u32 dstv6[4];
    };
    union {
        __u32 ports;
        __u16 port16[2];
    };
    __u8 proto;
    __u8 flags;
} __attribute__((packed));

// LRU Cache Entry
struct real_pos_lru {
    __u32 pos;
    __u64 atime;
} __attribute__((packed));

// Statistics
struct lb_stats {
    __u64 v1;   // packets
    __u64 v2;   // bytes
} __attribute__((packed));

// Control Value
struct ctl_value {
    union {
        __u64 value;
        __u32 ifindex;
        __u8 mac[6];
    };
} __attribute__((packed));
```

---

## Map Operations

### Common Patterns

#### 1. VIP Lookup (Hot Path)
```c
// Build VIP key from packet
struct vip_definition vip_key;
vip_key.vip = ip_hdr->daddr;
vip_key.port = tcp_hdr->dest;
vip_key.proto = ip_hdr->protocol;

// Lookup VIP
struct vip_meta *vip_info = bpf_map_lookup_elem(&vip_map, &vip_key);
if (!vip_info) {
    return XDP_PASS;  // Not a VIP
}
```

#### 2. Backend Selection
```c
// 1. Try per-CPU LRU cache
struct flow_key flow;
// ... populate flow from packet ...

__u32 cpu = bpf_get_smp_processor_id();
void *lru = bpf_map_lookup_elem(&lru_mapping, &cpu);
struct real_pos_lru *cached = bpf_map_lookup_elem(lru, &flow);

if (cached) {
    backend_idx = cached->pos;  // Cache hit
} else {
    // 2. Calculate via consistent hash
    __u32 hash = hash_packet(&flow);
    __u32 ring_pos = hash % RING_SIZE;
    __u32 key = vip_info->vip_num * RING_SIZE + ring_pos;
    __u32 *idx = bpf_map_lookup_elem(&ch_rings, &key);
    backend_idx = *idx;
    
    // 3. Update LRU cache
    struct real_pos_lru new_entry = {.pos = backend_idx};
    bpf_map_update_elem(lru, &flow, &new_entry, BPF_ANY);
}

// 4. Get backend IP
struct real_definition *backend = 
    bpf_map_lookup_elem(&reals, &backend_idx);
```

#### 3. Statistics Update
```c
struct lb_stats *stat = bpf_map_lookup_elem(&stats, &vip_info->vip_num);
if (stat) {
    __sync_fetch_and_add(&stat->v1, 1);
    __sync_fetch_and_add(&stat->v2, pkt_len);
}
```

---

## Performance Considerations

### Memory Usage

| Map | Entries | Entry Size | Total Memory |
|-----|---------|------------|--------------|
| vip_map | 512 | ~40 B | ~20 KB |
| reals | 4096 | ~20 B | ~80 KB |
| ch_rings | 33M (512 VIPs) | 4 B | ~132 MB |
| lru_mapping | 8M (8 CPUs × 1M) | ~48 B | ~384 MB |
| stats | 512 × CPUs | 16 B | ~65 KB (8 CPUs) |
| hc_reals_map | 4096 | ~8 B | ~32 KB |
| **TOTAL** | | | **~600 MB** |

### Lookup Performance

| Operation | Complexity | Latency (ns) |
|-----------|-----------|--------------|
| vip_map lookup | O(1) | ~50 |
| LRU cache hit | O(1) | ~30 |
| CH ring lookup | O(1) | ~20 |
| reals array lookup | O(1) | ~20 |
| Statistics update | O(1) | ~10 |
| **Total (cache hit)** | | **~110** |
| **Total (cache miss)** | | **~130** |

### Optimization Tips

1. **Pre-allocation:** Pre-allocate all maps at startup to avoid runtime allocation
2. **Per-CPU Design:** Use per-CPU maps to eliminate locking
3. **Prime Ring Size:** Use prime numbers for CH ring to reduce collisions
4. **Batch Updates:** Update multiple backends atomically to minimize ring rebuilds
5. **Statistics Batching:** Collect statistics in batches to reduce syscalls

---

## Summary

Katran's BPF map architecture is designed for:
- **Performance:** Lock-free per-CPU design, O(1) lookups
- **Scalability:** Supports millions of concurrent connections
- **Flexibility:** Supports various protocols and routing strategies
- **Observability:** Comprehensive statistics and monitoring

The control plane must manage these maps carefully, ensuring atomic updates, proper memory management, and efficient access patterns to maintain line-rate packet forwarding performance.
