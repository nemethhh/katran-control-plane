# Public Repository Readiness — Design Spec

**Date:** 2026-03-14
**Status:** Draft

## Goal

Prepare the katran-control-plane project for public release on GitHub. Add CI/CD via GitHub Actions, release automation via git tags, a runtime Docker image published to GHCR, local CI execution via `act`, and essential open-source scaffolding.

## Deliverables

| File | Action | Purpose |
|---|---|---|
| `.github/workflows/ci.yml` | Create | Lint, unit test, integration test, e2e test |
| `.github/workflows/release.yml` | Create | Build, GitHub Release, GHCR Docker push |
| `Dockerfile` | Create | Runtime-only container image |
| `.dockerignore` | Create | Keep Docker build context small |
| `.actrc` | Create | Default flags for local `act` execution |
| `LICENSE` | Create | Apache-2.0 full text |
| `.gitignore` | Edit | Add `dist/`, `*.whl`, clean up existing entries |
| `Makefile` | Edit | Add `ci-local` target for `act` |
| `samples/` | Delete | Remove vendored third-party sources |
| `katran-bpfs/` | Untrack | Remove from git (already in `.gitignore`); BPF programs now come from builder releases |

No changes to existing source code or test compose files.

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

### Workflow-level input

```yaml
env:
  KATRAN_BPF_VERSION: "v2026.03.14-4065efa8"
  KATRAN_BPF_REPO: "nemethhh/katran-bpf-builder"
  KATRAN_BPF_VARIANT: "decap-ipip"
```

The BPF version is pinned in the workflow file. To update, change `KATRAN_BPF_VERSION` and push. This value is the release tag from `nemethhh/katran-bpf-builder`.

### Reusable step: Download BPF programs

Used by `integration-test` and `e2e-test` jobs before `docker compose build`:

```
gh release download $KATRAN_BPF_VERSION --repo $KATRAN_BPF_REPO --pattern '*.zip' -D /tmp/katran-bpf
unzip /tmp/katran-bpf/*.zip -d /tmp/katran-bpf-extracted
mkdir -p katran-bpfs
cp /tmp/katran-bpf-extracted/$KATRAN_BPF_VARIANT/* katran-bpfs/
```

This populates `katran-bpfs/` in the workspace before Docker builds, so existing `COPY katran-bpfs/ ./katran-bpfs/` lines in Dockerfiles work unchanged.

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
  2. Download BPF programs (reusable step above)
  3. `make integration-test`

The Makefile's `integration-test` target invokes `tests/integration/run-tests.sh`, which handles the full lifecycle: `docker compose up`, XDP program loading via `xdp-loader`, BPF map pinning via `bpftool`, running pytest, and teardown. The script already handles cleanup on failure.

The compose file uses `privileged: true` and `cap_add: [NET_ADMIN, SYS_ADMIN, BPF]`. GitHub-hosted runners (kernel 6.14) support this. The container mounts `/sys/kernel/btf`, `/lib/modules`, and `/sys/fs/bpf` from the host.

#### 1.4 `e2e-test`

- **Runner:** `ubuntu-24.04`
- **Steps:**
  1. `actions/checkout@v4`
  2. Download BPF programs (reusable step above)
  3. `make e2e-multi`

The Makefile's `e2e-multi` target invokes `tests/e2e/run-e2e.sh`, which handles container orchestration, healthcheck waiting, pytest execution, and teardown. The `docker-compose.e2e.yml` already has `depends_on: condition: service_healthy` for proper startup ordering. The lb-entrypoint script handles XDP loading and map pinning.

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

Sequential: `build` -> `github-release` + `docker` (last two parallel).

#### 2.1 `build`

- **Runner:** `ubuntu-24.04`
- **Steps:**
  1. `actions/checkout@v4`
  2. Extract version from tag: `echo "VERSION=${GITHUB_REF#refs/tags/v}" >> $GITHUB_ENV`
  3. Inject version into `pyproject.toml` (replace `version = "1.0.0"`) and `src/katran/__init__.py` (replace `__version__ = "1.0.0"`) using `sed -i`
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
  1. `actions/checkout@v4` (for Dockerfile)
  2. `actions/download-artifact@v4` — download `dist/` into repo root
  3. Log in to GHCR: `docker/login-action@v3` with `registry: ghcr.io`, `username: ${{ github.actor }}`, `password: ${{ secrets.GITHUB_TOKEN }}`
  4. Build + push using `docker/build-push-action@v6`:
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

### `.dockerignore`

```
.venv/
.git/
tests/
katran-bpfs/
samples/
htmlcov/
.pytest_cache/
__pycache__/
*.egg-info/
```

Keeps the Docker build context to just `Dockerfile` + `dist/`.

---

## 4. BPF Builder Integration

### Source

BPF programs are built by [nemethhh/katran-bpf-builder](https://github.com/nemethhh/katran-bpf-builder) and published as GitHub Releases. Each release contains a zip with 4 build variants: `base/`, `decap-ipip/`, `decap-gue/`, `full/`.

### CI usage

- The `KATRAN_BPF_VERSION` env var in `ci.yml` pins the BPF build version.
- Integration and e2e jobs download the zip, extract the `decap-ipip` variant into `katran-bpfs/`.
- The Dockerfiles' existing `COPY katran-bpfs/ ./katran-bpfs/` picks them up from the build context unchanged.

### Local development

Developers download BPF programs manually:

```bash
gh release download v2026.03.14-4065efa8 --repo nemethhh/katran-bpf-builder --pattern '*.zip'
unzip katran-bpf-*.zip -d /tmp/katran-bpf
cp /tmp/katran-bpf/decap-ipip/* katran-bpfs/
```

The `katran-bpfs/` directory is already in `.gitignore`.

---

## 5. Open-Source Scaffolding

### 5.1 LICENSE

Apache-2.0 full text at repo root. Matches the `license = "Apache-2.0"` declaration in `pyproject.toml`.

### 5.2 .gitignore updates

Current `.gitignore` already has `samples` and `katran-bpfs`. Add:

```
dist/
*.whl
```

Replace `*/*.egg-info` with `*.egg-info/` (the existing pattern doesn't match all depths).

### 5.3 Remove `samples/`

Delete the `samples/` directory from git tracking. Contains vendored third-party sources (grpc, libbpf, etc.) not needed for the control plane.

### 5.4 Untrack `katran-bpfs/`

Run `git rm -r --cached katran-bpfs/` to remove the tracked `balancer.bpf.o`. The directory is already in `.gitignore`, so it will stay untracked after this.

---

## 6. Local CI via `act`

[nektos/act](https://github.com/nektos/act) runs GitHub Actions locally using Docker. This lets developers validate CI before pushing.

### `.actrc`

Default flags at repo root:

```
--privileged
--bind
```

- `--privileged`: Required for integration/e2e jobs that load BPF/XDP programs.
- `--bind`: Bind-mount the workspace instead of copying (faster, allows BPF filesystem mounts).

### Makefile targets

```makefile
ci-local:                  ## Run full CI locally via act
	act push --privileged

ci-local-lint:             ## Run lint job locally via act
	act push --privileged -j lint

ci-local-unit:             ## Run unit tests locally via act
	act push --privileged -j unit-test

ci-local-integration:      ## Run integration tests locally via act
	act push --privileged -j integration-test

ci-local-e2e:              ## Run e2e tests locally via act
	act push --privileged -j e2e-test
```

### Limitations

- `act` uses Docker-in-Docker for jobs that run `docker compose`. The host Docker socket must be available. `--bind` helps with volume mounts.
- The `release.yml` workflow is not intended for local execution (needs GHCR auth + tag context).
- BPF programs must be downloaded to `katran-bpfs/` before running integration/e2e jobs locally. The workflow's download step uses `gh release download`, which requires `gh` CLI and GitHub access inside the `act` container. The standard `act` images include `gh`.

---

## Design Decisions

| Decision | Rationale |
|---|---|
| Privileged Docker in CI | GitHub-hosted runners (kernel 6.14) support BPF/XDP. Major projects (cilium/ebpf, libbpf) do this successfully. |
| Two workflows (ci + release) | Different triggers, different permissions, different failure modes. Easier to debug independently. |
| Tag-based versioning | Single source of truth. No manual version bumps. CI patches files at build time. |
| Runtime-only Docker image | Decouples control plane from BPF builds. Smaller image. Users mount their own programs. |
| Use Makefile targets for integration/e2e | `run-tests.sh` and `run-e2e.sh` already handle XDP loading, map pinning, healthcheck waiting, and teardown. Replicating that in workflow YAML would be fragile. |
| BPF from builder releases | Decouples BPF compilation from control plane CI. Version pinned in workflow for reproducibility. |
| `decap-ipip` variant | E2e tests use IPIP encapsulation/decapsulation. Matches the test topology. |
| Local CI via `act` | Fast feedback loop. Developers validate CI before pushing. `.actrc` captures default flags so `act` just works. |
| No CONTRIBUTING/CHANGELOG | User preference for lean scaffolding. Can be added later. |
| Python matrix 3.11 + 3.12 | Matches pyproject.toml classifiers. Ensures forward compatibility. |

## Out of Scope

- PyPI publishing (not requested)
- Self-hosted runners (not needed — hosted runners support BPF)
- Multi-arch Docker images (can be added later)
- Changelog automation
- Dependabot / Renovate configuration
- Branch protection rules (GitHub settings, not code)
- Fixing the `katran-ctl` CLI entry point (`pyproject.toml` declares it but `src/katran/cli/main.py` doesn't exist yet — pre-existing issue, unrelated to this work)
