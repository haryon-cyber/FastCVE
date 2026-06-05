#!/bin/bash
set -e

TAR_DIR="${1:-}"
USE_REGISTRY="${USE_REGISTRY:-false}"

if [ -n "$TAR_DIR" ]; then
    echo "[+] Loading FastCVE images from tar directory: $TAR_DIR"
    docker load -i "$TAR_DIR/fastcve-db-"*.tar.gz
    docker load -i "$TAR_DIR/fastcve-"*.tar.gz
elif [ "$USE_REGISTRY" = "true" ]; then
    REGISTRY="3b008863.eu-west-par.container-registry.ovh.net/fastcve"
    echo "[+] Pulling FastCVE images from registry..."
    echo "[+] Pulling fastcve-db..."
    docker pull "${REGISTRY}/fastcve-db:latest"
    docker tag "${REGISTRY}/fastcve-db:latest" fastcve-db:latest
    echo "[+] Pulling fastcve..."
    docker pull "${REGISTRY}/fastcve:latest"
    docker tag "${REGISTRY}/fastcve:latest" fastcve:latest
else
    echo "Usage: $0 <tar-directory>"
    echo "  or:  USE_REGISTRY=true $0"
    exit 1
fi

echo "[+] Images installed:"
docker images | grep -E "^fastcve"

echo ""
echo "[+] Starting FastCVE..."
docker compose -f docker-compose.registry.yml up -d