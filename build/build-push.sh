#!/usr/bin/env bash
# build-push.sh - ADMIN: build FastCVE images from source and push to the OVH registry.
# Produces fastcve-db and fastcve images with pre-populated PostgreSQL data.
# Run this on the build server (with registry credentials).
#
# Strategy: pull the previous registry images (DB already has data), start the
# stack, run an incremental data update, snapshot the updated DB, rebuild the
# app image from source, then push everything.  This avoids a full NVD reload.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"

# shellcheck source=/dev/null
source "${SCRIPT_DIR}/.env"

# Save dev compose vars before any registry override
DEV_DB_IMAGE="${FASTCVE_DB_IMAGE:-postgres:16-alpine3.19}"
DEV_APP_IMAGE="${FASTCVE_DOCKER_IMG:-binare/fastcve}"
DEV_APP_TAG="${FASTCVE_DOCKER_TAG:-latest}"

# Load registry overrides early (for DUMP_PATH), but reset compose vars after
DUMP_PATH=""
if [ -f "${SCRIPT_DIR}/.env.registry" ]; then
  set -a; source "${SCRIPT_DIR}/.env.registry"; set +a
  DUMP_PATH="${DUMP_PATH:-}"
fi

# Reset compose vars to dev values (registry would make compose pull instead of build)
FASTCVE_DB_IMAGE="${DEV_DB_IMAGE}"
FASTCVE_DOCKER_IMG="${DEV_APP_IMAGE}"
FASTCVE_DOCKER_TAG="${DEV_APP_TAG}"

LOCAL_APP_IMAGE="${FASTCVE_DOCKER_IMG}:${FASTCVE_DOCKER_TAG}"

SNAPSHOT_DIR=""
COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.yml}"

cleanup() {
  if [ -n "${SNAPSHOT_DIR}" ]; then
    rm -rf "${SNAPSHOT_DIR}"
  fi
  docker compose -f "${COMPOSE_FILE}" down --remove-orphans 2>/dev/null || true
  docker compose -f "${REGISTRY_COMPOSE}" down --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT INT TERM

REGISTRY="${REGISTRY:-registry.example.com/fastcve}"
TAG="${TAG:-$(date +%Y%m%d)}"
OUTPUT_DIR="${OUTPUT_DIR:-./dist}"

DB_IMAGE="${REGISTRY}-db"
APP_IMAGE="${REGISTRY}"
REGISTRY_COMPOSE="docker-compose.registry.yml"

echo "=== Registry Images Builder ==="
echo "  Registry: ${REGISTRY}"
echo "  Tag:      ${TAG}"
echo ""

mkdir -p "${OUTPUT_DIR}"

export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

# ---------------------------------------------------------------------------
# [0/7] Pull previous registry images (app cache + pre-populated DB data)
# ---------------------------------------------------------------------------
echo "=== [0/7] Pulling registry images ==="
docker pull "${REGISTRY}:latest" 2>/dev/null && \
  docker tag "${REGISTRY}:latest" "fastcve:latest" 2>/dev/null || true
docker pull "${REGISTRY}-db:latest" 2>/dev/null && \
  docker tag "${REGISTRY}-db:latest" "fastcve-db:latest" 2>/dev/null || true
echo "  Done"

# ---------------------------------------------------------------------------
# [1/7] Start the stack from the pulled images
# ---------------------------------------------------------------------------
echo "=== [1/7] Starting stack from registry images ==="
docker compose -f "${REGISTRY_COMPOSE}" down --remove-orphans 2>/dev/null || true
docker compose -f "${REGISTRY_COMPOSE}" up -d fastcve-db

echo "Waiting for DB..."
docker compose -f "${REGISTRY_COMPOSE}" exec fastcve-db sh -c \
  'until pg_isready -U "$POSTGRES_USER"; do sleep 2; done'

docker compose -f "${REGISTRY_COMPOSE}" up -d --no-deps fastcve
sleep 5

# ---------------------------------------------------------------------------
# [2/7] Incremental (or full) data update
# ---------------------------------------------------------------------------
HAS_DATA=false
if docker compose -f "${REGISTRY_COMPOSE}" exec -T fastcve-db \
    sh -c 'psql -U "$POSTGRES_USER" -d vuln_db -c "SELECT 1 FROM cve LIMIT 1" 2>/dev/null' &>/dev/null; then
  HAS_DATA=true
fi

if [ "$HAS_DATA" = true ]; then
  echo "=== [2/7] Incremental data update ==="
  docker compose -f "${REGISTRY_COMPOSE}" exec fastcve load \
    --data cve cpe cwe capec epss kev
else
  echo "=== [2/7] Loading all data from NVD (first run, this may take hours) ==="
  docker compose -f "${REGISTRY_COMPOSE}" exec fastcve load \
    --data cve cvehist cpe cwe capec epss kev
fi

# ---------------------------------------------------------------------------
# [3/7] Stop DB cleanly (flush + checkpoint)
# ---------------------------------------------------------------------------
echo "=== [3/7] Stopping DB cleanly ==="
docker compose -f "${REGISTRY_COMPOSE}" stop fastcve-db

# ---------------------------------------------------------------------------
# [4/7] Snapshot PGDATA via the stopped container's volume
# ---------------------------------------------------------------------------
echo "=== [4/7] Snapshotting PGDATA ==="
SNAPSHOT_DIR="$(mktemp -d)"
DB_CONTAINER="$(docker compose -f "${REGISTRY_COMPOSE}" ps -aq fastcve-db)"

if [ -z "${DB_CONTAINER}" ]; then
  echo "ERROR: No fastcve-db container found (was it stopped and removed?)"
  exit 1
fi

docker cp "${DB_CONTAINER}:/var/lib/postgresql/data/." "${SNAPSHOT_DIR}/pgdata"
rm -f "${SNAPSHOT_DIR}/pgdata/postmaster.pid"

docker compose -f "${REGISTRY_COMPOSE}" down --remove-orphans 2>/dev/null || true

if [ -f "${SCRIPT_DIR}/.env.registry" ]; then
  set -a; source "${SCRIPT_DIR}/.env.registry"; set +a
fi

# ---------------------------------------------------------------------------
# [5/7] Build fresh app image from source (layers cached via BuildKit)
# ---------------------------------------------------------------------------
echo "=== [5/7] Building app image ==="
docker compose -f "${COMPOSE_FILE}" build fastcve
docker tag "${LOCAL_APP_IMAGE}" "${APP_IMAGE}:${TAG}"
docker tag "${LOCAL_APP_IMAGE}" "${APP_IMAGE}:latest"

# ---------------------------------------------------------------------------
# [6/7] Build fresh DB image with updated snapshot
# ---------------------------------------------------------------------------
echo "=== [6/7] Building DB image ==="

cat > "${SNAPSHOT_DIR}/entrypoint.sh" << 'ENTRYPOINT'
#!/bin/bash
set -e

if [ ! "$(ls -A /var/lib/postgresql/data 2>/dev/null)" ]; then
    echo "[entrypoint] Volume empty, copying initial data..."
    cp -a /var/lib/postgresql/initial-data/. /var/lib/postgresql/data/
    chown -R postgres:postgres /var/lib/postgresql/data
else
    echo "[entrypoint] Volume has data, skipping copy."
fi

exec docker-entrypoint.sh "$@"
ENTRYPOINT
chmod +x "${SNAPSHOT_DIR}/entrypoint.sh"

cat > "${SNAPSHOT_DIR}/Dockerfile" << 'DOCKERFILE'
FROM postgres:16-alpine3.19
COPY --chown=postgres:postgres pgdata/ /var/lib/postgresql/initial-data/
COPY entrypoint.sh /usr/local/bin/custom-entrypoint.sh
ENTRYPOINT ["/usr/local/bin/custom-entrypoint.sh"]
CMD ["postgres"]
DOCKERFILE

docker build \
  -t "${DB_IMAGE}:${TAG}" \
  -t "${DB_IMAGE}:latest" \
  -f "${SNAPSHOT_DIR}/Dockerfile" \
  "${SNAPSHOT_DIR}"

# ---------------------------------------------------------------------------
# [7/7] Export .tar.gz
# ---------------------------------------------------------------------------
echo "=== [7/7] Exporting .tar.gz ==="
docker save "${DB_IMAGE}:${TAG}" | gzip > "${OUTPUT_DIR}/fastcve-db-${TAG}.tar.gz"
docker save "${APP_IMAGE}:${TAG}" | gzip > "${OUTPUT_DIR}/fastcve-app-${TAG}.tar.gz"

echo ""
echo "=== Done ==="
echo "  ${OUTPUT_DIR}/fastcve-db-${TAG}.tar.gz"
echo "  ${OUTPUT_DIR}/fastcve-app-${TAG}.tar.gz"

if [ "${PUSH:-true}" = "true" ]; then
  echo "=== Pushing ==="
  docker push "${DB_IMAGE}:${TAG}" && docker push "${DB_IMAGE}:latest"
  docker push "${APP_IMAGE}:${TAG}" && docker push "${APP_IMAGE}:latest"
fi
