#!/usr/bin/env bash
# Download FastCVE registry images from Harbor as .tar.gz archives
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"

if [ -f "${SCRIPT_DIR}/.env.registry" ]; then
  set -a; source "${SCRIPT_DIR}/.env.registry"; set +a
else
  echo "ERROR: .env.registry not found"
  echo "Create it with REGISTRY=your-harbor-url/fastcve/fastcve"
  exit 1
fi

TAG="${TAG:-latest}"
OUTPUT_DIR="${OUTPUT_DIR:-./dist}"

mkdir -p "${OUTPUT_DIR}"

echo "=== Downloading from registry ==="
echo "  Registry: ${REGISTRY}"
echo "  Tag:      ${TAG}"
echo ""

docker pull "${REGISTRY}:${TAG}"
docker pull "${REGISTRY}-db:${TAG}"

echo ""
echo "=== Exporting .tar.gz ==="
docker save "${REGISTRY}:${TAG}" | gzip > "${OUTPUT_DIR}/fastcve-app-${TAG}.tar.gz"
docker save "${REGISTRY}-db:${TAG}" | gzip > "${OUTPUT_DIR}/fastcve-db-${TAG}.tar.gz"

echo ""
echo "=== Done ==="
echo "  ${OUTPUT_DIR}/fastcve-app-${TAG}.tar.gz"
echo "  ${OUTPUT_DIR}/fastcve-db-${TAG}.tar.gz"
