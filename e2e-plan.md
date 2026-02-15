# Multi-Container E2E Test Environment for Katran Control Plane

## Context

Currently E2E tests run in a single Docker container testing only control plane API → BPF map operations. The XDP load balancer (`katran-bpfs/balancer.bpf.o`) is loaded but no actual traffic flows through it.

We need a multi-container Docker Compose setup that validates the **full packet path**: client → XDP load balancer (IPIP encap + XDP_TX) → backend servers (IPIP decap) → DSR response to client.

## Network Architecture

```
Docker bridge: katran-e2e-net (10.200.0.0/24)

┌──────────────────┐  HTTP to VIP   ┌──────────────────┐  IPIP encap   ┌──────────────────┐
│   test-client    │ ─────────────▶ │    katran-lb     │ ───────────▶  │   backend-1      │
│  10.200.0.100    │                │   10.200.0.10    │               │   10.200.0.20    │
│  pytest runner   │  ◀─────────────│   XDP + API:8080 │               │   HTTP:80 + IPIP │
│                  │  (DSR bypass)  │                  │               ├──────────────────┤
│                  │◀───────────────┤                  │               │   backend-2      │
│                  │  direct reply  │                  │               │   10.200.0.21    │
└──────────────────┘                └──────────────────┘               │   HTTP:80 + IPIP │
                                                                      └──────────────────┘
```

### Packet Flow (IPIP + DSR)

1. Client sends TCP SYN to `10.200.0.10:80`
2. Packet arrives at LB container's `eth0` → XDP program intercepts
3. XDP: VIP lookup → Maglev consistent hash → select backend → IPIP encapsulate
   - Outer: `src=172.16.x.x (derived), dst=10.200.0.20, proto=4 (IPIP)`
   - Inner: original `src=client, dst=VIP` packet preserved
   - `dst_mac = gateway_mac` (from `ctl_array[0]`)
4. `XDP_TX` → packet exits eth0 → veth → Docker bridge → host kernel routes to backend
5. Backend: kernel IPIP decap (`tunl0`) → inner packet (`dst=VIP_IP`, which is on `tunl0`) → HTTP server
6. DSR response: backend replies `src=VIP_IP, dst=client_IP` → default route → bridge → client

## Implementation Plan

### 1. Make `hc_reals_map` optional in service (`src/katran/service.py`)

The XDP balancer doesn't include `hc_reals_map` (it's from a separate TC healthcheck program). Currently `_open_maps()` fails if any map is missing. Split into required + optional maps:

```python
REQUIRED_MAPS = [vip_map, reals_map, ch_rings_map, stats_map, ctl_array]
OPTIONAL_MAPS = [hc_reals_map, lru_map]  # graceful failure
```

### 2. Create `docker-compose.e2e.yml`

```yaml
services:
  katran-lb:       # 10.200.0.10 - XDP + control plane
  backend-1:       # 10.200.0.20 - IPIP decap + HTTP server
  backend-2:       # 10.200.0.21 - IPIP decap + HTTP server
  test-client:     # 10.200.0.100 - pytest runner
```

- `katran-lb`: privileged, BPF caps, mounts `/sys/fs/bpf`, `/sys/kernel/btf`, `/lib/modules`
- `backend-{1,2}`: privileged (needed for IPIP tunnel + sysctl), lightweight image
- `test-client`: same image as LB (has pytest + katran package), different entrypoint
- Network: bridge `10.200.0.0/24` with static IPs

### 3. Create `tests/e2e/Dockerfile` (LB + client image)

Based on existing `tests/integration/Dockerfile`. Add:
- `uvicorn` in pip install (to run control plane as HTTP server)

### 4. Create `tests/e2e/Dockerfile.backend`

Lightweight Ubuntu image with:
- `iproute2` (ip commands for IPIP tunnel)
- `kmod` (modprobe ipip)
- `python3` (simple HTTP server)
- `iputils-ping` (for debugging)

### 5. Create `tests/e2e/scripts/lb-entrypoint.sh`

Sequence:
1. `xdp-loader load -m skb eth0 /app/katran-bpfs/balancer.bpf.o`
2. Pin all BPF maps via `bpftool map pin` to `/sys/fs/bpf/katran/`
3. Discover gateway MAC: `ip neigh show $(ip route | awk '/default/{print $3}')`
4. Write gateway MAC to `ctl_array[0]` via `bpftool map update`
5. Exec `python3 /app/tests/e2e/scripts/run_control_plane.py`

### 6. Create `tests/e2e/scripts/run_control_plane.py`

```python
# Create KatranConfig, KatranService, start service, run uvicorn on 0.0.0.0:8080
```

### 7. Create `tests/e2e/scripts/backend-entrypoint.sh`

Sequence:
1. `modprobe ipip`
2. `ip link set tunl0 up`
3. Add test VIP IPs to tunl0: `ip addr add 10.200.0.10/32 dev tunl0`
4. Disable rp_filter: `sysctl -w net.ipv4.conf.all.rp_filter=0`
5. Exec `python3 /app/backend-server.py`

### 8. Create `tests/e2e/scripts/backend-server.py`

Simple HTTP server (stdlib `http.server`) that returns JSON identifying the backend:
```json
{"backend": "backend-1", "address": "10.200.0.20"}
```

### 9. Rewrite `tests/e2e/conftest.py`

Replace in-process ASGI fixtures with real HTTP client fixtures:
- `api_url` → `http://katran-lb:8080`
- `vip_url` → `http://10.200.0.10:80` (traffic through XDP)
- `api_client` → `httpx.Client` pointing to control plane
- `vip_client` → `httpx.Client` pointing to VIP (for traffic tests)
- Health-check wait loop (retry until LB is ready)
- Skip guard: check `KATRAN_E2E` env var (set in compose)

### 10. Rewrite `tests/e2e/test_control_plane.py`

Adapt existing tests from in-process ASGI to real HTTP calls against `katran-lb:8080`. Same test cases:
- Health check, VIP CRUD, Backend CRUD, drain, 404/409 errors

### 11. Create `tests/e2e/test_traffic_forwarding.py` (new)

Test actual packet forwarding:
- **test_basic_forwarding**: Add VIP + backend via API → send HTTP to VIP → verify response from backend
- **test_multi_backend_distribution**: Add 2 backends → send N requests → verify both backends receive traffic
- **test_drain_shifts_traffic**: Drain one backend → verify all traffic goes to remaining
- **test_remove_backend**: Remove backend → verify traffic redistributes
- **test_no_backend_drops**: VIP with no backends → verify connection refused/timeout

### 12. Create `tests/e2e/run-e2e.sh`

Orchestrator script:
1. `docker compose -f docker-compose.e2e.yml up -d --build`
2. Wait for `katran-lb` health endpoint
3. Wait for backends HTTP servers
4. `docker exec test-client pytest tests/e2e/ -v`
5. Capture results
6. `docker compose down -v`

### 13. Update `Makefile`

```makefile
E2E_COMPOSE := docker compose -f docker-compose.e2e.yml

e2e-test:
    ./tests/e2e/run-e2e.sh

e2e-test-debug:
    ./tests/e2e/run-e2e.sh --debug

e2e-shell:
    ./tests/e2e/run-e2e.sh --shell
```

## Files Summary

| Action | File | Purpose |
|--------|------|---------|
| Modify | `src/katran/service.py` | Make hc_reals_map optional |
| Create | `docker-compose.e2e.yml` | Multi-container compose |
| Create | `tests/e2e/Dockerfile` | LB + client image |
| Create | `tests/e2e/Dockerfile.backend` | Backend image |
| Create | `tests/e2e/scripts/lb-entrypoint.sh` | XDP load + control plane start |
| Create | `tests/e2e/scripts/run_control_plane.py` | uvicorn runner |
| Create | `tests/e2e/scripts/backend-entrypoint.sh` | IPIP + HTTP server start |
| Create | `tests/e2e/scripts/backend-server.py` | Identifying HTTP server |
| Create | `tests/e2e/run-e2e.sh` | Orchestrator script |
| Rewrite | `tests/e2e/conftest.py` | Multi-container fixtures |
| Rewrite | `tests/e2e/test_control_plane.py` | Real HTTP API tests |
| Create | `tests/e2e/test_traffic_forwarding.py` | XDP traffic forwarding tests |
| Modify | `Makefile` | E2E targets |

## Verification

```bash
make e2e-test
```

Expected: All tests pass, including:
- Control plane API CRUD operations
- Actual HTTP traffic forwarded through XDP to backends
- Load distribution across multiple backends
- Drain/remove backend traffic redistribution
