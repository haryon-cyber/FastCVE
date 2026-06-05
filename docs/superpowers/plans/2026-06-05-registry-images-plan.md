# Registry Images Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create a build script and user-facing compose file so that FastCVE can be distributed as two pre-populated Docker images (fastcve-db + fastcve) via registry or `.tar.gz`.

**Architecture:** The PostgreSQL image ships a raw PGDATA snapshot (no init/restore at first start). The build script populates a temporary postgres container, snapshots the volume, and layers PGDATA into a custom `postgres:16-alpine` image. The fastcve app image is unchanged.

**Tech Stack:** bash, Docker, PostgreSQL 16, docker compose

---

### File Structure

- **Create:** `docker-compose.registry.yml` — stripped-down compose for end users (no volume, no build section, registry images)
- **Create:** `build-registry-images.sh` — the build script
- **Modify:** `.env` — update `FASTCVE_DB_IMAGE` default to registry image name

---

### Task 1: Create `docker-compose.registry.yml`

**Files:**
- Create: `docker-compose.registry.yml`

A clean compose file for end users who pull pre-built images. No `volumes:` for the DB (data comes from image). No `build:` section for fastcve (image pulled from registry).

- [ ] **Step 1: Write `docker-compose.registry.yml`**

```yaml
services:
  fastcve-db:
    image: "${FASTCVE_DB_IMAGE:-postgres:16-alpine3.19}"
    container_name: fastcve-db
    environment:
      - POSTGRES_USER=${FCDB_USER}
      - POSTGRES_PASSWORD=${FCDB_PASS}
      - POSTGRES_DB=vuln_db
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $$POSTGRES_USER"]
      interval: 5s
      timeout: 3s
      retries: 10
    networks:
      backend:
        aliases:
          - fastcve-db

  fastcve:
    image: "${FASTCVE_DOCKER_IMG}:${FASTCVE_DOCKER_TAG}"
    container_name: fastcve
    depends_on:
      fastcve-db:
        condition: service_healthy
    environment:
      - INP_ENV_NAME=${INP_ENV_NAME:-dev}
      - FCDB_USER=${FCDB_USER}
      - FCDB_PASS=${FCDB_PASS}
      - NVD_API_KEY=${NVD_API_KEY}
    command: ["/bin/sh", "-c", "python -m web.prestart && exec uvicorn web.app:app --host 0.0.0.0 --port 8000 --workers 4"]
    ports:
      - "8000:8000"
    networks:
      - backend

networks:
  backend:
```

- [ ] **Step 2: Verify the file is valid YAML**

Run: `python3 -c "import yaml; yaml.safe_load(open('docker-compose.registry.yml'))"`
Expected: no error

- [ ] **Step 3: Commit**

```bash
git add docker-compose.registry.yml
git commit -m "feat: add registry-compatible compose file (no DB volume)"
```

---

### Task 2: Create `build-registry-images.sh`

**Files:**
- Create: `build-registry-images.sh`

The core build script. It:
1. Sources `.env` for variables
2. Starts the stack with a temporary volume-mapped DB
3. Waits for health
4. Loads all CVE data
5. Stops the DB cleanly
6. Snapshots PGDATA from the volume
7. Builds the custom `fastcve-db` image with baked PGDATA
8. Builds/tags the `fastcve` app image
9. Exports both as `.tar.gz`
10. Optionally pushes to registry

- [ ] **Step 1: Write the script**

```bash
#!/usr/bin/env bash
# FastCVE Registry Images Builder
# Produces fastcve-db and fastcve Docker images with pre-populated PostgreSQL data.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"

# shellcheck source=/dev/null
source .env

REGISTRY="${REGISTRY:-registry.example.com/fastcve}"
TAG="${TAG:-$(date +%Y%m%d)}"
OUTPUT_DIR="${OUTPUT_DIR:-./dist}"

DB_IMAGE="${REGISTRY}-db"
APP_IMAGE="${REGISTRY}"

echo "=== Registry Images Builder ==="
echo "  Registry: ${REGISTRY}"
echo "  Tag:      ${TAG}"
echo ""

mkdir -p "${OUTPUT_DIR}"

# [1/6] Start stack with clean DB (purge old volume)
echo "=== [1/6] Starting stack ==="
docker compose down -v 2>/dev/null || true
docker compose up -d --build

echo "Waiting for DB..."
docker compose exec fastcve-db sh -c \
  'until pg_isready -U "$POSTGRES_USER"; do sleep 2; done'

# [2/6] Load all data
echo "=== [2/6] Loading data (this may take hours) ==="
docker compose exec fastcve python -m web.prestart
docker compose exec fastcve load \
  --data cve cvehist cpe cwe capec epss kev

# [3/6] Stop DB cleanly (flush + checkpoint)
echo "=== [3/6] Stopping DB cleanly ==="
docker compose stop fastcve-db

# [4/6] Snapshot PGDATA via the stopped container's volume
echo "=== [4/6] Snapshotting PGDATA ==="
SNAPSHOT_DIR="$(mktemp -d)"
DB_CONTAINER="$(docker compose ps -aq fastcve-db)"

docker run --rm \
  --volumes-from "${DB_CONTAINER}" \
  alpine \
  tar czf - -C /var/lib/postgresql/data . \
  > "${SNAPSHOT_DIR}/pgdata.tar.gz"

tar xzf "${SNAPSHOT_DIR}/pgdata.tar.gz" -C "${SNAPSHOT_DIR}"

# [5/6] Build the pre-populated DB image
echo "=== [5/6] Building DB image ==="

cat > "${SNAPSHOT_DIR}/Dockerfile" << 'DOCKERFILE'
FROM postgres:16-alpine3.19
COPY --chown=postgres:postgres pgdata/ /var/lib/postgresql/data/
DOCKERFILE

docker build \
  -t "${DB_IMAGE}:${TAG}" \
  -t "${DB_IMAGE}:latest" \
  -f "${SNAPSHOT_DIR}/Dockerfile" \
  "${SNAPSHOT_DIR}"

rm -rf "${SNAPSHOT_DIR}"

# Tag the app image
docker tag "${FASTCVE_DOCKER_IMG}:${FASTCVE_DOCKER_TAG}" "${APP_IMAGE}:${TAG}"
docker tag "${FASTCVE_DOCKER_IMG}:${FASTCVE_DOCKER_TAG}" "${APP_IMAGE}:latest"

# [6/6] Export .tar.gz
echo "=== [6/6] Exporting .tar.gz ==="
docker save "${DB_IMAGE}:${TAG}" | gzip > "${OUTPUT_DIR}/fastcve-db-${TAG}.tar.gz"
docker save "${APP_IMAGE}:${TAG}" | gzip > "${OUTPUT_DIR}/fastcve-app-${TAG}.tar.gz"

# Clean up
docker compose down -v 2>/dev/null || true

echo ""
echo "=== Done ==="
echo "  ${OUTPUT_DIR}/fastcve-db-${TAG}.tar.gz"
echo "  ${OUTPUT_DIR}/fastcve-app-${TAG}.tar.gz"

# Optional push
if [ "${PUSH:-false}" = "true" ]; then
  echo "=== Pushing ==="
  docker push "${DB_IMAGE}:${TAG}" && docker push "${DB_IMAGE}:latest"
  docker push "${APP_IMAGE}:${TAG}" && docker push "${APP_IMAGE}:latest"
fi
```

- [ ] **Step 2: Make the script executable**

Run: `chmod +x build-registry-images.sh`

- [ ] **Step 3: Verify shell syntax**

Run: `bash -n build-registry-images.sh`
Expected: no output (syntax OK)

- [ ] **Step 4: Commit**

```bash
git add build-registry-images.sh
git commit -m "feat: add build script for registry images with baked PGDATA"
```

---

### Task 3: Update `.env` defaults

**Files:**
- Modify: `.env`

Update the `.env` to include sensible defaults for the registry workflow. Existing vars remain; add `REGISTRY` default.

- [ ] **Step 1: Update `.env`**

```
FCDB_USER="fastcve_db_user"
FCDB_PASS="fastcve_db_pass"
INP_ENV_NAME="dev"
FASTCVE_DOCKER_IMG="registry.example.com/fastcve"
FASTCVE_DB_IMAGE="registry.example.com/fastcve-db:latest"
FASTCVE_DOCKER_TAG="latest"
NVD_API_KEY=
REGISTRY="registry.example.com/fastcve"
```

- [ ] **Step 2: Commit**

```bash
git add .env
git commit -m "chore: update .env defaults for registry image names"
```

---

### Task 4: Self-review

- [ ] **Check spec coverage:** Skim the spec doc, verify every requirement has a task. Confirm no gaps.

Spec says:
- "Two images in registry" → Task 2 builds & exports both ✅
- "User docker-compose.yml without volume" → Task 1 creates it ✅
- "Build script flow" → Task 2 covers it ✅
- ".env defaults" → Task 3 updates them ✅

- [ ] **Placeholder scan:** Search for TBD, TODO, "implement later", empty code blocks. Fix any found.

- [ ] **Type consistency:** Verify function names, variable names, file paths are consistent across all tasks.
