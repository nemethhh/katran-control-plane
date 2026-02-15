# Phase 2.1: Control Plane Service & E2E Testing

## Context

Phases 1-2 are complete — all BPF map wrappers, VipManager, RealManager, and MaglevHashRing are implemented and tested. Phase 2.1 wires these components together into a runnable service with an HTTP API, enabling end-to-end testing before adding more features (XDP loading, stats, full API).

## Plan Doc Corrections

The plan document (`katran-control-plane-plan.md`) has several inaccuracies vs actual code:
- **VipManager** constructor: `(vip_map, ch_rings_map, max_vips)` — no `stats_map` param
- **RealManager** constructor: `(reals_map, ch_rings_map, ring_builder, max_reals)` — no `vip_manager` param
- **VipManager.remove_vip/get_vip** accept keyword args: `(key=None, address=None, port=None, protocol=None)`
- **No `PROTOCOL_MAP`** constant — protocol parsing uses `Protocol[name.upper()]`
- **Pydantic v2** — must use `@field_validator` not `@validator`

---

## Implementation Steps

### Step 1: Configuration Management

**Create** `src/katran/core/config.py`

- Pydantic v2 `BaseModel` with nested config groups: `InterfaceConfig`, `BpfConfig`, `MapConfig`, `ApiConfig`, `LogConfig`
- Top-level `KatranConfig` model with `from_yaml()` and `from_dict()` classmethods
- Auto-detect flat vs nested YAML format (existing `config/katran.yaml` is flat)
- `_normalize_flat_config()` converts flat keys to nested structure
- Validators: MAC format, XDP mode (including "skb"), ring_size primality, log level/format
- No path validation at load time (BPF programs may not exist on config-loading machine); provide `validate_paths()` method
- Use existing `ConfigurationError` from `core/exceptions.py`

### Step 2: Basic Logging

**Create** `src/katran/core/logging.py`

- `setup_logging(level, log_format)` — configures stdlib `logging` with console or JSON formatter
- `get_logger(name)` — thin wrapper for `logging.getLogger()`
- Silences noisy libraries (urllib3, asyncio, uvicorn.access)
- Minimal — no structlog (deferred to Phase 8)

### Step 3: Service Coordinator

**Create** `src/katran/service.py`

- `KatranService(config: KatranConfig)` — main coordinator
- `_open_maps()` — instantiates and opens all 7 BPF maps using correct constructors:
  - `VipMap(pin_path, max_vips=...)`
  - `RealsMap(pin_path, max_reals=...)`
  - `ChRingsMap(pin_path, ring_size=..., max_vips=...)`
  - `StatsMap(pin_path, max_vips=...)`
  - `CtlArray(pin_path)`
  - `HcRealsMap(pin_path)`
  - `LruMap(pin_path, max_entries=...)`
- `_initialize_managers()` — creates VipManager and RealManager with correct signatures
- `start()` / `stop()` lifecycle with cleanup on failure
- `is_running` and `is_healthy` properties
- All maps and managers stored as public attributes

### Step 4: Minimal HTTP API

**Create** `src/katran/api/minimal.py`

- `create_app(service)` factory pattern — stores service in `app.state.service`
- `get_service()` FastAPI dependency — returns service or raises 503
- Pydantic v2 request/response models: `AddVipRequest`, `AddRealRequest`, `VipResponse`, etc.
- Endpoints:
  - `GET /health` — 200 if running, 503 if not
  - `POST /api/v1/vips` (201) — add VIP
  - `GET /api/v1/vips` — list all VIPs with backends
  - `GET /api/v1/vips/{addr}/{port}/{proto}` — get single VIP
  - `DELETE /api/v1/vips/{addr}/{port}/{proto}` — remove VIP
  - `POST /api/v1/vips/{addr}/{port}/{proto}/backends` (201) — add backend
  - `DELETE /api/v1/vips/{...}/backends/{addr}` — remove backend
  - `PUT /api/v1/vips/{...}/backends/{addr}/drain` — drain backend
- Proper HTTP status codes: 201 create, 409 conflict, 404 not found, 503 unavailable
- Uses VipManager keyword args: `address=, port=, protocol=`
- Protocol parsing: `Protocol[request.protocol.upper()]`

### Step 5: Unit Tests

**Create** `tests/unit/test_config.py`
- Load existing flat `config/katran.yaml` — verify all fields parse
- Load nested format dict — verify all fields
- MAC validation (valid/invalid)
- XDP mode validation (native, generic, offload, skb)
- Ring size primality check
- Log level/format validation
- Flat format auto-detection
- Missing fields get defaults

**Create** `tests/unit/test_service.py`
- Mock all BPF map constructors and `.open()` methods via `unittest.mock.patch`
- Test `start()` opens maps and initializes managers
- Test `stop()` closes maps
- Test `is_running` state transitions
- Test `start()` when already running raises RuntimeError
- Test failed `start()` cleans up partially-opened maps

**Create** `tests/unit/test_minimal_api.py`
- Use `httpx.AsyncClient` with `ASGITransport(app=app)` — no server needed
- Mock `KatranService` with mock `vip_manager` and `real_manager`
- Test all endpoints: health, VIP CRUD, backend CRUD, drain
- Test error cases: 409 duplicate, 404 not found, 400 invalid protocol, 503 service down

### Step 6: E2E Test Infrastructure

**Create** `tests/e2e/__init__.py` (empty)

**Create** `tests/e2e/conftest.py`
- Session-scoped `KatranConfig` built from env vars (reuse integration test env)
- Session-scoped `KatranService` fixture (start/stop)
- `api_app` fixture via `create_app(katran_service)`
- Per-test `api_client` using `httpx.AsyncClient` with `ASGITransport`
- `is_bpf_available()` check — skip if not in Docker/BPF env

**Create** `tests/e2e/test_control_plane.py`
- Service initialization: verify `is_running`, managers not None
- Direct VIP operations via `katran_service.vip_manager`
- Direct backend operations via `katran_service.real_manager`
- API health check
- API VIP lifecycle (create, list, get, remove)
- API backend lifecycle (add, verify in list, drain, remove)
- API error cases (duplicate VIP 409, missing VIP 404)
- All tests clean up VIPs in finally blocks

### Step 7: Minor Updates

**Modify** `pyproject.toml`
- Add `httpx>=0.24.0` to dev dependencies
- Add `asyncio_mode = "auto"` to pytest config
- Add `markers = ["e2e: end-to-end tests requiring BPF environment"]`

**Modify** `src/katran/core/__init__.py` — add `KatranConfig`, `setup_logging`, `get_logger` exports

**Modify** `tests/integration/run-tests.sh` — add `tests/e2e/` to pytest path

**Create** `config/katran-nested.yaml` — example nested format config

**Update** `todo.md` — mark Phase 2.1 items as complete

---

## Files Summary

| Action | File | Purpose |
|--------|------|---------|
| Create | `src/katran/core/config.py` | Pydantic v2 config with flat/nested YAML support |
| Create | `src/katran/core/logging.py` | Minimal stdlib logging setup |
| Create | `src/katran/service.py` | Service coordinator wiring maps + managers |
| Create | `src/katran/api/minimal.py` | FastAPI endpoints for E2E testing |
| Create | `tests/unit/test_config.py` | Config loading/validation tests |
| Create | `tests/unit/test_service.py` | Service lifecycle tests (mocked maps) |
| Create | `tests/unit/test_minimal_api.py` | API endpoint tests (mocked service) |
| Create | `tests/e2e/__init__.py` | E2E test package |
| Create | `tests/e2e/conftest.py` | E2E fixtures (service, API client) |
| Create | `tests/e2e/test_control_plane.py` | E2E test cases |
| Create | `config/katran-nested.yaml` | Example nested config |
| Modify | `pyproject.toml` | Add httpx dev dep, pytest asyncio config |
| Modify | `src/katran/core/__init__.py` | Export config + logging |
| Modify | `tests/integration/run-tests.sh` | Include e2e tests in runner |
| Update | `todo.md` | Mark Phase 2.1 complete |

---

## Verification

1. **Unit tests**: `pytest tests/unit/test_config.py tests/unit/test_service.py tests/unit/test_minimal_api.py -v`
2. **All unit tests still pass**: `pytest tests/unit/ -v`
3. **E2E tests** (in Docker): `./tests/integration/run-tests.sh` (updated to include e2e)
4. **Config loading**: Load both `config/katran.yaml` (flat) and `config/katran-nested.yaml` (nested) and verify equivalence
