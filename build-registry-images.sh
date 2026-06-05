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
