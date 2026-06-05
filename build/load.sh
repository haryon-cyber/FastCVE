#!/bin/bash
set -e

REGISTRY="3b008863.eu-west-par.container-registry.ovh.net/fastcve"

echo "[+] Loading FastCVE images from registry..."

echo "[+] Pulling fastcve-db..."
docker pull "${REGISTRY}/fastcve-db:latest"
docker tag "${REGISTRY}/fastcve-db:latest" fastcve-db:latest

echo "[+] Pulling fastcve..."
docker pull "${REGISTRY}/fastcve:latest"
docker tag "${REGISTRY}/fastcve:latest" fastcve:latest

echo "[+] Images loaded:"
docker images | grep -E "^fastcve"

echo ""
echo "[+] Starting FastCVE..."
docker compose -f docker-compose.registry.yml up -d