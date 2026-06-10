#!/usr/bin/env bash
# Download FastCVE registry images from Harbor as .tar.gz archives
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "${SCRIPT_DIR}"

# Load registry config
if [ -f "${SCRIPT_DIR}/.env.registry" ]; then
  set -a; source "${SCRIPT_DIR}/.env.registry"; set +a
else
  echo "ERROR: .env.registry not found"
  echo "Create it with REGISTRY=your-harbor-url/fastcve/fastcve"
  exit 1
fi

# Auto-login if credentials file present (for read-only deployer access)
CRED_FILE="${SCRIPT_DIR}/registry-credentials.env"
if [ -f "${CRED_FILE}" ]; then
  set -a; source "${CRED_FILE}"; set +a
  if [ -n "${REGISTRY_URL:-}" ] && [ -n "${REGISTRY_USERNAME:-}" ] && [ -n "${REGISTRY_PASSWORD:-}" ]; then
    echo "${REGISTRY_PASSWORD}" | docker login "${REGISTRY_URL}" \
      --username "${REGISTRY_USERNAME}" --password-stdin 2>/dev/null
  fi
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
