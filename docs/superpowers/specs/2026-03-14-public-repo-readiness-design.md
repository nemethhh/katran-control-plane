# Public Repository Readiness — Design Spec

**Date:** 2026-03-14
**Status:** Draft

## Goal

Prepare the katran-control-plane project for public release on GitHub. Add CI/CD via GitHub Actions, release automation via git tags, a runtime Docker image published to GHCR, and essential open-source scaffolding.

## Deliverables

| File | Action | Purpose |
|---|---|---|
| `.github/workflows/ci.yml` | Create | Lint, unit test, integration test, e2e test |
| `.github/workflows/release.yml` | Create | Build, GitHub Release, GHCR Docker push |
| `Dockerfile` | Create | Runtime-only container image |
| `LICENSE` | Create | Apache-2.0 full text |
| `.gitignore` | Edit | Add `samples/`, `dist/`, build artifacts |
| `samples/` | Delete | Remove vendored third-party sources |

No changes to existing source code, tests, compose files, or Makefile.

---

## 1. CI Workflow (`.github/workflows/ci.yml`)

### Trigger

```yaml
on:
  push:
    branches: ["**"]
  pull_request:
    branches: [main]
```

### Jobs

All four jobs run in parallel.

#### 1.1 `lint`

- **Runner:** `ubuntu-24.04`
- **Steps:**
  1. `actions/checkout@v4`
  2. `actions/setup-python@v5` with Python 3.11
  3. `make venv`
  4. `make lint` (runs `ruff check` + `mypy`)

#### 1.2 `unit-test`

- **Runner:** `ubuntu-24.04`
- **Matrix:** Python `[3.11, 3.12]`
- **Steps:**
  1. `actions/checkout@v4`
  2. `actions/setup-python@v5` with matrix Python version
  3. `make venv`
  4. `make unit-test-cov`
  5. `actions/upload-artifact@v4` — upload `htmlcov/` (optional, no external coverage service)

#### 1.3 `integration-test`

- **Runner:** `ubuntu-24.04`
- **Steps:**
  1. `actions/checkout@v4`
  2. `docker compose -f docker-compose.test.yml up --build -d`
  3. Run integration tests inside the container:
     `docker exec katran-target bash -c "cd /app && .venv/bin/python3 -m pytest tests/integration/ -v"`
  4. `docker compose -f docker-compose.test.yml down -v` (always, even on failure)

The compose file uses `privileged: true` and `cap_add: [NET_ADMIN, SYS_ADMIN, BPF]`. GitHub-hosted runners (kernel 6.14) support this. The container mounts `/sys/kernel/btf`, `/lib/modules`, and `/sys/fs/bpf` from the host.

#### 1.4 `e2e-test`

- **Runner:** `ubuntu-24.04`
- **Steps:**
  1. `actions/checkout@v4`
  2. `docker compose -f docker-compose.e2e.yml up -d --build`
  3. Wait for healthchecks:
     `docker compose -f docker-compose.e2e.yml exec test-client bash -c "until curl -sf http://katran-lb:8080/health; do sleep 2; done"`
  4. `docker exec katran-e2e-client .venv/bin/python3 -m pytest tests/e2e/ -v`
  5. `docker compose -f docker-compose.e2e.yml down -v` (always)

The e2e compose stands up 4 containers (lb, backend-1, backend-2, test-client) with a custom bridge network (IPv4 + IPv6). The lb container loads XDP and serves the API; the test-client runs pytest against the live system.

---

## 2. Release Workflow (`.github/workflows/release.yml`)

### Trigger

```yaml
on:
  push:
    tags: ["v*"]
```

### Permissions

```yaml
permissions:
  contents: write
  packages: write
```

### Jobs

Sequential: `build` -> `github-release` + `docker` (last two can be parallel).

#### 2.1 `build`

- **Runner:** `ubuntu-24.04`
- **Steps:**
  1. `actions/checkout@v4`
  2. Extract version from tag: `echo "VERSION=${GITHUB_REF#refs/tags/v}" >> $GITHUB_ENV`
  3. Inject version into `pyproject.toml` (replace `version = "1.0.0"`) and `src/katran/__init__.py` (replace `__version__ = "1.0.0"`)
  4. `actions/setup-python@v5` with Python 3.11
  5. `pip install build`
  6. `python -m build` (produces wheel + sdist in `dist/`)
  7. `actions/upload-artifact@v4` — upload `dist/`

#### 2.2 `github-release`

- **Needs:** `build`
- **Steps:**
  1. `actions/download-artifact@v4` — download `dist/`
  2. Create GitHub Release using `gh release create`:
     - Tag name from `${{ github.ref_name }}`
     - Auto-generated release notes (`--generate-notes`)
     - Attach `dist/*.whl` and `dist/*.tar.gz`

#### 2.3 `docker`

- **Needs:** `build`
- **Steps:**
  1. `actions/download-artifact@v4` — download `dist/`
  2. Log in to GHCR: `docker/login-action@v3` with `registry: ghcr.io`, `username: ${{ github.actor }}`, `password: ${{ secrets.GITHUB_TOKEN }}`
  3. Build + push using `docker/build-push-action@v6`:
     - Context: `.` (repo root, with `dist/` from artifact)
     - File: `Dockerfile`
     - Tags: `ghcr.io/${{ github.repository }}:<version>`, `ghcr.io/${{ github.repository }}:latest`
     - Push: `true`

### Version Injection Strategy

- The git tag (`v1.2.0`) is the single source of truth.
- The release workflow extracts the version and patches `pyproject.toml` + `__init__.py` before building. This happens in CI only — source files in the repo always read `1.0.0` as a dev placeholder.
- Local `pip install -e .` shows version `1.0.0`. Only released artifacts (wheel, sdist, Docker image) carry the real version.

---

## 3. Runtime Dockerfile

New file at repo root: `Dockerfile`

```dockerfile
FROM python:3.11-slim

COPY dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

EXPOSE 8080

ENTRYPOINT ["uvicorn", "katran.api.rest.app:create_app", \
            "--host", "0.0.0.0", "--port", "8080", "--factory"]
```

- Based on `python:3.11-slim` (~150MB).
- Installs the wheel built by CI (includes all dependencies).
- No BPF programs included. Users mount their own: `docker run -v /path/to/bpfs:/bpf ...`
- Exposes port 8080 for the REST API.

---

## 4. Open-Source Scaffolding

### 4.1 LICENSE

Apache-2.0 full text at repo root. Matches the `license = "Apache-2.0"` declaration in `pyproject.toml`.

### 4.2 .gitignore additions

```
samples/
dist/
*.whl
*.egg-info/
```

### 4.3 Remove `samples/`

Delete the `samples/` directory entirely from the repository. It contains vendored third-party sources (grpc, libbpf, etc.) that add bloat and are not needed for the control plane.

---

## Design Decisions

| Decision | Rationale |
|---|---|
| Privileged Docker in CI | GitHub-hosted runners (kernel 6.14) support BPF/XDP. Major projects (cilium/ebpf, libbpf) do this successfully. |
| Two workflows (ci + release) | Different triggers, different permissions, different failure modes. Easier to debug independently. |
| Tag-based versioning | Single source of truth. No manual version bumps. CI patches files at build time. |
| Runtime-only Docker image | Decouples control plane from BPF builds. Smaller image. Users mount their own programs. |
| No CONTRIBUTING/CHANGELOG | User preference for lean scaffolding. Can be added later. |
| Python matrix 3.11 + 3.12 | Matches pyproject.toml classifiers. Ensures forward compatibility. |

## Out of Scope

- PyPI publishing (not requested)
- Self-hosted runners (not needed — hosted runners support BPF)
- Multi-arch Docker images (can be added later)
- Changelog automation
- Dependabot / Renovate configuration
- Branch protection rules (GitHub settings, not code)
