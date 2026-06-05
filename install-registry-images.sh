#!/usr/bin/env bash
# Install FastCVE from local .tar.gz archives (air-gapped distribution)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"

TAG="${TAG:-latest}"
ARCHIVE_DIR="${ARCHIVE_DIR:-.}"

echo "=== Loading images ==="
APP_OUTPUT=$(docker load -i "${ARCHIVE_DIR}/fastcve-app-${TAG}.tar.gz")
DB_OUTPUT=$(docker load -i "${ARCHIVE_DIR}/fastcve-db-${TAG}.tar.gz")

# Extract image names from "Loaded image: ..." output
APP_IMAGE="${APP_OUTPUT#Loaded image: }"
DB_IMAGE="${DB_OUTPUT#Loaded image: }"

echo ""
echo "=== Starting stack ==="
echo "  App image: ${APP_IMAGE}"
echo "  DB image:  ${DB_IMAGE}"

FASTCVE_DOCKER_IMG="${APP_IMAGE%%:*}" \
FASTCVE_DOCKER_TAG="${APP_IMAGE##*:}" \
FASTCVE_DB_IMAGE="${DB_IMAGE}" \
  docker compose -f docker-compose.registry.yml up -d

echo ""
echo "=== Done ==="
echo "  FastCVE API: http://localhost:8000"
echo "  API docs:    http://localhost:8000/docs"
