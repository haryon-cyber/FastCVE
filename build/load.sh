#!/bin/bash
# load.sh - DEV: pull FastCVE images from the OVH registry.
# Use this on developer machines that HAVE access to the registry.
# After this script, run: docker compose -f docker-compose.registry.yml up -d
set -e

REGISTRY="3b008863.eu-west-par.container-registry.ovh.net/fastcve"

echo "[+] Pulling fastcve-db..."
docker pull "${REGISTRY}/fastcve-db:latest"
docker tag "${REGISTRY}/fastcve-db:latest" fastcve-db:latest

echo "[+] Pulling fastcve..."
docker pull "${REGISTRY}/fastcve:latest"
docker tag "${REGISTRY}/fastcve:latest" fastcve:latest

echo "[+] Images loaded:"
docker images | grep -E "^fastcve"

echo ""
echo "[+] Now run: docker compose -f docker-compose.registry.yml up -d"