#!/bin/bash

# Deep Recon Docker Entrypoint
set -e

echo "=================================================="
echo "    Deep Recon Scanner - Docker Container"
echo "=================================================="
echo ""

# Display help if requested
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo "Usage:"
    echo "  docker run -it deep-recon <target>"
    echo "  docker run -it -v $(pwd)/scans:/app/scans deep-recon https://example.com"
    echo ""
    echo "Examples:"
    echo "  Scan a website:"
    echo "    docker run -it deep-recon https://example.com"
    echo ""
    echo "  Scan with volume mount for output:"
    echo "    docker run -it -v $(pwd)/scans:/app/scans deep-recon https://example.com"
    echo ""
    echo "  Scan with custom GeoIP database:"
    echo "    docker run -it -v $(pwd)/GeoLite2-City.mmdb:/app/data/GeoLite2-City.mmdb deep-recon https://example.com"
    echo ""
    echo "  Interactive shell:"
    echo "    docker run -it deep-recon /bin/bash"
    exit 0
fi

# Check if we're just running a shell
if [[ "$1" == "/bin/bash" || "$1" == "bash" || "$1" == "sh" ]]; then
    exec "$@"
fi

# Create directories for output
mkdir -p /app/scans
mkdir -p /app/reports
mkdir -p /app/logs

# Check for target
if [ $# -eq 0 ]; then
    echo "Error: No target specified"
    echo ""
    echo "Usage: docker run -it deep-recon <target_url>"
    echo "Example: docker run -it deep-recon https://example.com"
    exit 1
fi

TARGET="$1"
echo "[*] Target: $TARGET"
echo "[*] Starting scan..."
echo "[*] Output will be saved to /app/scans/"
echo ""

# Run the scan
cd /app
exec python3 deep_recon.py "$TARGET"