# Public Repository Readiness Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prepare katran-control-plane for public GitHub release with CI/CD, release automation, Docker image publishing, local CI via `act`, and essential open-source scaffolding.

**Architecture:** Two GitHub Actions workflows (CI + release) delegate to existing Makefile targets. BPF programs come from external builder releases. Runtime Docker image is a thin Python wheel container. Local CI via `act` with privileged Docker.

**Tech Stack:** GitHub Actions, Docker, `act` (nektos/act), Python build system (`python -m build`)

**Spec:** `docs/superpowers/specs/2026-03-14-public-repo-readiness-design.md`

---

## Chunk 1: Cleanup & Scaffolding

### Task 1: Remove `samples/` and untrack `katran-bpfs/`

**Files:**
- Delete: `samples/` (entire directory)
- Untrack: `katran-bpfs/` (already in `.gitignore`)

- [ ] **Step 1: Check current tracking status**

Run: `git ls-files samples/ katran-bpfs/`

If output is empty, both directories are already untracked (covered by `.gitignore`). If files are listed, proceed with `git rm`.

- [ ] **Step 2: Remove samples/ from filesystem**

Run: `rm -rf samples/`

The directory is already untracked by `.gitignore`. This just removes the local copy of vendored third-party sources.

- [ ] **Step 3: Untrack katran-bpfs/ if still tracked**

Run: `git rm -r --cached katran-bpfs/ 2>/dev/null || echo "Already untracked"`

If tracked files exist, this removes them from git while keeping local copies. If already untracked, this is a no-op.

- [ ] **Step 4: Commit (only if there are staged changes)**

```bash
git diff --cached --quiet || git commit -m "chore: remove samples/ and untrack katran-bpfs/

samples/ contained vendored third-party sources not needed for the control plane.
katran-bpfs/ now comes from nemethhh/katran-bpf-builder releases."
```

If nothing was tracked, skip the commit — Task 2 handles .gitignore.

---

### Task 2: Update `.gitignore`

**Files:**
- Modify: `.gitignore`

Current contents:
```
samples
katran-bpfs
.venv
.pytest_cache
__pycache__
htmlcov
.ruff_cache
.claude
*/*.egg-info
```

- [ ] **Step 1: Update .gitignore with build artifact patterns**

Replace the full file with:

```
# Vendored / external
samples/
katran-bpfs/

# Python
.venv/
__pycache__/
*.egg-info/
dist/
*.whl
build/

# Tools
.pytest_cache/
htmlcov/
.ruff_cache/
.coverage
.mypy_cache/

# IDE / local
.claude/
```

Key changes:
- Add trailing slashes for clarity (directories)
- Add `dist/`, `*.whl`, `build/` (build artifacts from `python -m build`)
- Add `.coverage`, `.mypy_cache/`
- Replace `*/*.egg-info` with `*.egg-info/` (matches at any depth)

- [ ] **Step 2: Commit**

```bash
git add .gitignore
git commit -m "chore: update .gitignore for build artifacts and consistency"
```

---

### Task 3: Add LICENSE file

**Files:**
- Create: `LICENSE`

- [ ] **Step 1: Create Apache-2.0 LICENSE file**

Write the full Apache License, Version 2.0 text to `LICENSE`. Use the standard text from https://www.apache.org/licenses/LICENSE-2.0.txt with the copyright line:

```
Copyright 2025 Katran Control Plane Authors
```

This matches the `license = {text = "Apache-2.0"}` in `pyproject.toml`.

- [ ] **Step 2: Commit**

```bash
git add LICENSE
git commit -m "chore: add Apache-2.0 LICENSE file"
```

---

## Chunk 2: CI Workflow

### Task 4: Create CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Create .github/workflows directory**

Run: `mkdir -p .github/workflows`

- [ ] **Step 2: Write ci.yml**

```yaml
name: CI

on:
  push:
    branches: ["**"]
  pull_request:
    branches: [main]

env:
  KATRAN_BPF_VERSION: "v2026.03.14-4065efa8"
  KATRAN_BPF_REPO: "nemethhh/katran-bpf-builder"
  KATRAN_BPF_VARIANT: "decap-ipip"

jobs:
  lint:
    name: Lint
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install dependencies
        run: make venv

      - name: Run linters
        run: make lint

  unit-test:
    name: Unit Tests (Python ${{ matrix.python-version }})
    runs-on: ubuntu-24.04
    strategy:
      matrix:
        python-version: ["3.11", "3.12"]
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: make venv

      - name: Run unit tests with coverage
        run: make unit-test-cov

      - name: Upload coverage report
        uses: actions/upload-artifact@v4
        if: matrix.python-version == '3.11'
        with:
          name: coverage-report
          path: htmlcov/

  integration-test:
    name: Integration Tests
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4

      - name: Download BPF programs
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh release download ${{ env.KATRAN_BPF_VERSION }} \
            --repo ${{ env.KATRAN_BPF_REPO }} \
            --pattern '*.zip' \
            -D /tmp/katran-bpf
          unzip /tmp/katran-bpf/*.zip -d /tmp/katran-bpf-extracted
          mkdir -p katran-bpfs
          cp /tmp/katran-bpf-extracted/${{ env.KATRAN_BPF_VARIANT }}/* katran-bpfs/

      - name: Run integration tests
        run: make integration-test

  e2e-test:
    name: E2E Tests
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4

      - name: Download BPF programs
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh release download ${{ env.KATRAN_BPF_VERSION }} \
            --repo ${{ env.KATRAN_BPF_REPO }} \
            --pattern '*.zip' \
            -D /tmp/katran-bpf
          unzip /tmp/katran-bpf/*.zip -d /tmp/katran-bpf-extracted
          mkdir -p katran-bpfs
          cp /tmp/katran-bpf-extracted/${{ env.KATRAN_BPF_VARIANT }}/* katran-bpfs/

      - name: Run E2E tests
        run: make e2e-multi
```

Key points:
- `GH_TOKEN` is set for `gh release download` to authenticate against the BPF builder repo.
- All 4 jobs run in parallel.
- Integration and e2e jobs download BPF programs into `katran-bpfs/` before `make` targets, which run Docker builds that `COPY katran-bpfs/` into containers.
- Makefile targets (`make integration-test`, `make e2e-multi`) delegate to shell scripts that handle the full lifecycle (XDP load, map pin, pytest, teardown).

- [ ] **Step 3: Validate YAML syntax**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))"`
Expected: No errors (valid YAML)

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add CI workflow for lint, unit, integration, and e2e tests"
```

---

## Chunk 3: Release Workflow & Docker

### Task 5: Create runtime Dockerfile and .dockerignore

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`

- [ ] **Step 1: Write Dockerfile**

```dockerfile
FROM python:3.11-slim

COPY dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

EXPOSE 8080

ENTRYPOINT ["uvicorn", "katran.api.rest.app:create_app", \
            "--host", "0.0.0.0", "--port", "8080", "--factory"]
```

This is a runtime-only image. No BPF programs — users mount their own via `-v /path/to/bpfs:/bpf`.

- [ ] **Step 2: Write .dockerignore**

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

- [ ] **Step 3: Commit**

```bash
git add Dockerfile .dockerignore
git commit -m "ci: add runtime Dockerfile and .dockerignore"
```

---

### Task 6: Create release workflow

**Files:**
- Create: `.github/workflows/release.yml`

- [ ] **Step 1: Write release.yml**

```yaml
name: Release

on:
  push:
    tags: ["v*"]

permissions:
  contents: write
  packages: write

jobs:
  build:
    name: Build Package
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4

      - name: Extract version from tag
        run: echo "VERSION=${GITHUB_REF#refs/tags/v}" >> $GITHUB_ENV

      - name: Inject version
        run: |
          sed -i "s/^version = \"1.0.0\"/version = \"${{ env.VERSION }}\"/" pyproject.toml
          sed -i "s/^__version__ = \"1.0.0\"/__version__ = \"${{ env.VERSION }}\"/" src/katran/__init__.py

      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Build wheel and sdist
        run: |
          pip install build
          python -m build

      - name: Upload dist artifacts
        uses: actions/upload-artifact@v4
        with:
          name: dist
          path: dist/

  github-release:
    name: GitHub Release
    needs: build
    runs-on: ubuntu-24.04
    steps:
      - name: Download dist artifacts
        uses: actions/download-artifact@v4
        with:
          name: dist
          path: dist/

      - name: Create GitHub Release
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          gh release create ${{ github.ref_name }} \
            --repo ${{ github.repository }} \
            --generate-notes \
            dist/*

  docker:
    name: Docker Image
    needs: build
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@v4

      - name: Download dist artifacts
        uses: actions/download-artifact@v4
        with:
          name: dist
          path: dist/

      - name: Extract version from tag
        run: echo "VERSION=${GITHUB_REF#refs/tags/v}" >> $GITHUB_ENV

      - name: Log in to GHCR
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push Docker image
        uses: docker/build-push-action@v6
        with:
          context: .
          file: Dockerfile
          push: true
          tags: |
            ghcr.io/${{ github.repository }}:${{ env.VERSION }}
            ghcr.io/${{ github.repository }}:latest
```

Key points:
- `build` job extracts version from tag, patches `pyproject.toml` and `__init__.py`, then builds wheel + sdist.
- `github-release` and `docker` jobs run in parallel after `build`.
- `github-release` creates a GitHub Release with auto-generated notes and attaches the wheel + sdist.
- `docker` builds the runtime image from the wheel and pushes to `ghcr.io/<owner>/katran-control-plane:<version>` and `:latest`.

- [ ] **Step 2: Validate YAML syntax**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml'))"`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: add release workflow for GitHub Release and GHCR Docker push"
```

---

## Chunk 4: Local CI via `act`

### Task 7: Add `act` support

**Files:**
- Create: `.actrc`
- Modify: `Makefile`

- [ ] **Step 1: Create .actrc**

```
--privileged
--bind
```

- `--privileged`: Required for BPF/XDP in integration/e2e jobs.
- `--bind`: Bind-mount workspace instead of copying (faster, allows BPF filesystem mounts).

- [ ] **Step 2: Add ci-local targets to Makefile**

Add these targets after the existing `e2e-multi-clean` target (before the `help` section). Insert before the `# ─── Help ───` line:

```makefile
# ─── Local CI (via act) ───────────────────────────────────────────────────

# Run full CI locally via act (requires: https://github.com/nektos/act)
ci-local:
	act push --privileged

# Run individual CI jobs locally
ci-local-lint:
	act push --privileged -j lint

ci-local-unit:
	act push --privileged -j unit-test

ci-local-integration:
	act push --privileged -j integration-test

ci-local-e2e:
	act push --privileged -j e2e-test
```

Also update the `.PHONY` declaration at the top of the Makefile to include the new targets:

```makefile
.PHONY: all install dev test unit-test e2e-test integration-test lint format clean \
        docker-build docker-test docker-debug docker-stop docker-clean \
        e2e-multi e2e-multi-debug e2e-multi-shell e2e-multi-stop e2e-multi-clean \
        ci-local ci-local-lint ci-local-unit ci-local-integration ci-local-e2e help
```

- [ ] **Step 3: Update help target**

Add these lines to the `help` target output, before the final empty line or after the E2E section:

```makefile
	@echo ""
	@echo "Local CI (requires act - https://github.com/nektos/act):"
	@echo "  ci-local             Run full CI locally"
	@echo "  ci-local-lint        Run lint job locally"
	@echo "  ci-local-unit        Run unit tests locally"
	@echo "  ci-local-integration Run integration tests locally"
	@echo "  ci-local-e2e         Run E2E tests locally"
```

- [ ] **Step 4: Verify Makefile syntax**

Run: `make help`
Expected: Help output with new "Local CI" section

- [ ] **Step 5: Commit**

```bash
git add .actrc Makefile
git commit -m "ci: add act support for local GitHub Actions execution"
```

---

## Chunk 5: Verification

### Task 8: Verify everything works together

- [ ] **Step 1: Verify file structure**

Run: `find .github Dockerfile .dockerignore .actrc LICENSE -type f 2>/dev/null | sort`

Expected:
```
.actrc
.dockerignore
.github/workflows/ci.yml
.github/workflows/release.yml
Dockerfile
LICENSE
```

- [ ] **Step 2: Verify samples/ is gone and katran-bpfs/ is untracked**

Run: `git ls-files samples/ katran-bpfs/`
Expected: No output (nothing tracked)

Run: `ls katran-bpfs/ 2>/dev/null`
Expected: Local files still exist (if previously downloaded)

- [ ] **Step 3: Verify .gitignore covers build artifacts**

Run: `git check-ignore dist/ build/ test.whl .coverage .mypy_cache/`
Expected: All paths listed (all ignored)

- [ ] **Step 4: Verify YAML workflows are valid**

Run:
```bash
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml')); print('ci.yml: OK')"
python3 -c "import yaml; yaml.safe_load(open('.github/workflows/release.yml')); print('release.yml: OK')"
```
Expected: Both OK

- [ ] **Step 5: Verify Makefile targets**

Run: `make help`
Expected: Output includes "Local CI" section with `ci-local` targets

- [ ] **Step 6: Run unit tests to ensure nothing broke**

Run: `make unit-test`
Expected: All tests pass

- [ ] **Step 7: Final commit summary**

Run: `git log --oneline -10`
Verify the commit history shows all tasks completed in order.
