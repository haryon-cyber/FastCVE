#!/usr/bin/env bash
# FastCVE Registry Images Builder
# Produces fastcve-db and fastcve Docker images with pre-populated PostgreSQL data.
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
}
trap cleanup EXIT INT TERM

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

# [1/6] Build app image, start only DB (app starts after dump restore)
echo "=== [1/6] Setting up ==="
docker compose -f "${COMPOSE_FILE}" down -v 2>/dev/null || true
docker compose -f "${COMPOSE_FILE}" build fastcve
docker compose -f "${COMPOSE_FILE}" up -d fastcve-db

echo "Waiting for DB..."
docker compose -f "${COMPOSE_FILE}" exec fastcve-db sh -c \
  'until pg_isready -U "$POSTGRES_USER"; do sleep 2; done'

# [2/6] Restore dump or full load
DUMP_PATH="${DUMP_PATH:-}"
if [ -n "${DUMP_PATH}" ] && [ -f "${DUMP_PATH}" ]; then
  echo "=== [2/6] Restoring from dump: ${DUMP_PATH} ==="
  docker compose -f "${COMPOSE_FILE}" cp "${DUMP_PATH}" fastcve-db:/tmp/fastcve_vuln_db.dump
  docker compose -f "${COMPOSE_FILE}" exec -T fastcve-db sh -c \
    "PGPASSWORD=\"\$POSTGRES_PASSWORD\" pg_restore -U \"\$POSTGRES_USER\" -d vuln_db /tmp/fastcve_vuln_db.dump"

  # Start app (prestart runs, creates/upgrades schema on top of restored data)
  echo "Starting app..."
  docker compose -f "${COMPOSE_FILE}" up -d --no-deps fastcve
  sleep 5

  # Incremental update (cvehist excluded: not in dump's fetch_status, would pull full history)
  docker compose -f "${COMPOSE_FILE}" exec fastcve load \
    --data cve cpe cwe capec epss kev
else
  echo "=== [2/6] Loading all data from NVD (this may take hours) ==="
  docker compose -f "${COMPOSE_FILE}" up -d --no-deps fastcve
  sleep 5
  docker compose -f "${COMPOSE_FILE}" exec fastcve load \
    --data cve cvehist cpe cwe capec epss kev
fi

# [3/6] Stop DB cleanly (flush + checkpoint)
echo "=== [3/6] Stopping DB cleanly ==="
docker compose -f "${COMPOSE_FILE}" stop fastcve-db

# [4/6] Snapshot PGDATA via the stopped container's volume
echo "=== [4/6] Snapshotting PGDATA ==="
SNAPSHOT_DIR="$(mktemp -d)"
DB_CONTAINER="$(docker compose -f "${COMPOSE_FILE}" ps -aq fastcve-db)"

if [ -z "${DB_CONTAINER}" ]; then
  echo "ERROR: No fastcve-db container found (was it stopped and removed?)"
  exit 1
fi

docker cp "${DB_CONTAINER}:/var/lib/postgresql/data/." "${SNAPSHOT_DIR}/pgdata"
# Remove stale PID file if any (can happen if container stopped forcefully)
rm -f "${SNAPSHOT_DIR}/pgdata/postmaster.pid"

# Now load registry overrides for tagging (after compose steps are done)
if [ -f "${SCRIPT_DIR}/.env.registry" ]; then
  set -a; source "${SCRIPT_DIR}/.env.registry"; set +a
fi

# [5/6] Build the pre-populated DB image
echo "=== [5/6] Building DB image ==="

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

# Tag the app image from local build to registry name
docker tag "${LOCAL_APP_IMAGE}" "${APP_IMAGE}:${TAG}"
docker tag "${LOCAL_APP_IMAGE}" "${APP_IMAGE}:latest"

# [6/6] Export .tar.gz
echo "=== [6/6] Exporting .tar.gz ==="
docker save "${DB_IMAGE}:${TAG}" | gzip > "${OUTPUT_DIR}/fastcve-db-${TAG}.tar.gz"
docker save "${APP_IMAGE}:${TAG}" | gzip > "${OUTPUT_DIR}/fastcve-app-${TAG}.tar.gz"

echo ""
echo "=== Done ==="
echo "  ${OUTPUT_DIR}/fastcve-db-${TAG}.tar.gz"
echo "  ${OUTPUT_DIR}/fastcve-app-${TAG}.tar.gz"

# Push to registry
if [ "${PUSH:-true}" = "true" ]; then
  echo "=== Pushing ==="
  docker push "${DB_IMAGE}:${TAG}" && docker push "${DB_IMAGE}:latest"
  docker push "${APP_IMAGE}:${TAG}" && docker push "${APP_IMAGE}:latest"
fi
