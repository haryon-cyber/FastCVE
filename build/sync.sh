#!/bin/bash
set -e

VERSION="${1:-$(date +%Y%m%d)}"
OUTPUT_DIR="${2:-./dist}"
MODE="${3:-import}"

case "$MODE" in
    export)
        echo "[+] Exporting volume (admin mode)..."
        docker compose -f docker-compose.registry.yml down
        mkdir -p "$OUTPUT_DIR"
        docker run --rm -v fastcve_data:/data -v "$(pwd)/$OUTPUT_DIR:/output" alpine tar czf "/output/fastcve-data-${VERSION}.tar.gz" -C /data .
        echo "[+] Exported: $OUTPUT_DIR/fastcve-data-${VERSION}.tar.gz"
        ;;
    import)
        echo "[+] Importing volume (client mode)..."
        docker compose -f docker-compose.registry.yml down
        docker volume create fastcve_data 2>/dev/null || true
        docker run --rm -v fastcve_data:/data -v "$(pwd)/$OUTPUT_DIR:/input" alpine sh -c "rm -rf /data/* && tar xzf /input/fastcve-data-${VERSION}.tar.gz -C /data"
        echo "[+] Volume imported."
        docker compose -f docker-compose.registry.yml up -d
        echo "[+] FastCVE started with updated data."
        ;;
    *)
        echo "Usage: $0 [VERSION] [export|import] [OUTPUT_DIR]"
        echo "  export - Admin: export volume to tar"
        echo "  import - Client: import volume from tar and start"
        exit 1
        ;;
esac