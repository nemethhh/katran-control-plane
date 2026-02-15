# Katran Control Plane - Task List

## Phase 1: Foundation & BPF Infrastructure
**Goal:** Establish core BPF map management and data structure foundation

- [x] Project structure created with proper packaging
- [x] All core data structures defined with serialization (`core/types.py`)
- [x] BpfMap abstract base class implemented (`bpf/map_manager.py`)
- [x] VipMap wrapper with full CRUD operations (`bpf/maps/vip_map.py`)
- [x] RealsMap wrapper with index allocation (`bpf/maps/reals_map.py`)
- [x] ChRingsMap wrapper with ring read/write (`bpf/maps/ch_rings_map.py`)
- [x] StatsMap wrapper with per-CPU aggregation (`bpf/maps/stats_map.py`)
- [x] CtlArray wrapper for global settings (`bpf/maps/ctl_array.py`)
- [x] HcRealsMap wrapper for healthcheck routing (`bpf/maps/hc_reals_map.py`)
- [x] LruMap wrapper (array of maps) (`bpf/maps/lru_map.py`)
- [x] Unit tests for all data structure serialization
- [x] Unit tests for map operations (mocked)
- [x] Integration tests with actual BPF maps (Docker Compose)

---

## Phase 2: Core Load Balancing Logic
**Goal:** Implement VIP/real management and Maglev consistent hashing

- [x] MaglevHashRing implementation with weighted distribution (`lb/maglev.py`)
- [x] Ring rebuild optimization (minimal writes)
- [x] VipManager with full CRUD operations (`lb/vip_manager.py`)
- [x] RealManager with backend management (`lb/real_manager.py`)
- [x] Graceful draining support
- [x] Thread-safe operations with proper locking
- [x] Index allocation/deallocation for VIPs and reals (in Phase 1 map_manager.py)
- [x] Unit tests for Maglev algorithm correctness
- [x] Unit tests for ring distribution uniformity
- [x] Unit tests for VIP/real manager operations
- [x] Integration tests for VIP/real operations (requires Docker environment)

---

## Phase 2.1: Control Plane Service & E2E Testing Infrastructure
**Goal:** Create runnable control plane service and end-to-end testing framework

- [x] Configuration file support (YAML) (`core/config.py`)
- [x] Configuration validation with pydantic
- [x] Basic structured logging setup
- [x] Control plane service coordinator (`service.py`)
- [x] Service lifecycle management (start/stop)
- [x] Component initialization and wiring
- [x] Minimal HTTP API for testing (FastAPI)
- [x] Health check endpoint (`/health`)
- [x] VIP management endpoints (add/remove/list)
- [x] Backend management endpoints (add/remove/drain)
- [x] E2E test infrastructure (Docker-based)
- [x] E2E test fixtures (start/stop control plane)
- [x] E2E tests with real packet forwarding
- [x] Test configuration files
- [x] Docker Compose for E2E environment

---

## Phase 3: Multi-Container E2E with XDP Traffic Forwarding
**Goal:** Validate the full packet path: client -> XDP (IPIP encap) -> backend (IPIP decap) -> DSR response

- [x] Make hc_reals_map/lru_map optional in KatranService
- [x] Multi-container Docker Compose (katran-lb, backend-1, backend-2, test-client)
- [x] LB Dockerfile and entrypoint (XDP load, map pin, gateway MAC, uvicorn)
- [x] Backend Dockerfile and entrypoint (IPIP decap, tunl0 VIP, arp_ignore, HTTP server)
- [x] BPF map pinning using program's map_ids (avoids stale maps on shared bpffs)
- [x] Port byte order fix (network byte order for VipKey/FlowKey serialization)
- [x] DSR ARP flux fix (arp_ignore=1, arp_announce=2 on backends)
- [x] E2E conftest with real HTTP client fixtures and KATRAN_E2E skip guard
- [x] Control plane API tests over real HTTP (health, VIP CRUD, backend CRUD, errors)
- [x] Traffic forwarding tests (single backend, multi-backend, drain, remove, no-backend)
- [x] Orchestrator script (run-e2e.sh) and Makefile targets

---

## Phase 4: XDP/TC Program Loading
**Goal:** Load and manage XDP and TC BPF programs

- [ ] XDP program loading via xdp-loader (`bpf/loader.py`)
- [ ] TC program loading for healthcheck
- [ ] Program unloading and cleanup
- [ ] Map pinning setup
- [ ] Error handling for load failures
- [ ] Interface validation
- [ ] Integration tests with actual BPF programs

---

## Phase 5: Statistics & Monitoring
**Goal:** Implement statistics collection and Prometheus export

- [ ] Per-CPU statistics aggregation (`stats/collector.py`)
- [ ] Background statistics collection thread
- [ ] Per-VIP statistics (packets, bytes, connections)
- [ ] Global statistics aggregation
- [ ] LRU hit/miss rate calculation
- [ ] Prometheus metrics export (`stats/prometheus.py`)
- [ ] HTTP endpoint for metrics scraping
- [ ] Statistics reset capability
- [ ] Unit tests for aggregation logic
- [ ] Integration tests for Prometheus export

---

## Phase 6: Healthcheck Management
**Goal:** Implement healthcheck routing and integration

- [ ] SO_MARK to backend mapping management (`lb/healthcheck.py`)
- [ ] Healthcheck destination CRUD operations
- [ ] Mark allocation strategy
- [ ] Integration with RealManager for draining
- [ ] Healthcheck statistics collection
- [ ] Unit tests for mapping operations
- [ ] Integration tests with TC program

---

## Phase 7: API Layer
**Goal:** Implement gRPC and REST APIs

- [ ] Protocol buffer definitions (`api/grpc/katran.proto`)
- [ ] gRPC service implementation (`api/grpc/service.py`)
- [ ] REST API using FastAPI (`api/rest/app.py`)
- [ ] Input validation for all endpoints
- [ ] Error handling and status codes
- [ ] API authentication (optional)
- [ ] API rate limiting (optional)
- [ ] OpenAPI documentation
- [ ] Unit tests for API endpoints
- [ ] Integration tests for full API flow

---

## Phase 8: CLI Tool
**Goal:** Command-line interface for operations

- [ ] VIP commands (add, remove, list, modify) (`cli/main.py`)
- [ ] Backend commands (add, remove, drain, list)
- [ ] Healthcheck commands (add, remove, list)
- [ ] Statistics commands (show, reset)
- [ ] Formatted table output
- [ ] JSON output option
- [ ] Error handling and user feedback
- [ ] Shell completion support
- [ ] Man page generation

---

## Phase 9: Production Hardening
**Goal:** Advanced production-ready features and reliability

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

## Phase 10: Testing & Quality
**Goal:** Comprehensive testing and quality assurance

- [ ] Unit tests for all core components (>80% coverage)
- [x] Integration tests with real BPF maps (Docker Compose infrastructure)
- [x] End-to-end tests with control plane service (Phase 2.1)
- [x] Packet forwarding verification tests (multi-container E2E)
- [ ] Performance benchmarks
- [ ] Load testing
- [ ] Chaos testing (failure injection)
- [ ] Code linting (ruff, mypy)
- [ ] Security scanning
- [ ] Documentation generation

---

## Phase 11: Documentation & Deployment
**Goal:** Complete documentation and deployment artifacts

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

## Summary

| Phase | Tasks | Status |
|-------|-------|--------|
| Phase 1: Foundation & BPF Infrastructure | 13 | 13/13 Complete ✅ |
| Phase 2: Core Load Balancing Logic | 11 | 11/11 Complete ✅ |
| Phase 2.1: Control Plane Service & E2E Testing | 15 | 15/15 Complete ✅ |
| Phase 3: Multi-Container E2E (XDP Traffic) | 11 | 11/11 Complete ✅ |
| Phase 4: XDP/TC Program Loading | 7 | Not Started |
| Phase 5: Statistics & Monitoring | 10 | Not Started |
| Phase 6: Healthcheck Management | 7 | Not Started |
| Phase 7: API Layer | 10 | Not Started |
| Phase 8: CLI Tool | 9 | Not Started |
| Phase 9: Production Hardening | 11 | Not Started |
| Phase 10: Testing & Quality | 9 | 3/9 Complete |
| Phase 11: Documentation & Deployment | 11 | Not Started |
| **Total** | **123** | **53/123** |
