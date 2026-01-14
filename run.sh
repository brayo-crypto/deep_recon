#!/bin/bash

# Deep Recon Docker Runner
set -e

echo "=================================================="
echo "    Deep Recon Docker Runner"
echo "=================================================="

# Default values
IMAGE="deep-recon"
TAG="latest"
VOLUME_DIR="./scans"
TARGET=""
INTERACTIVE=true
NETWORK_MODE=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --image|-i)
            IMAGE="$2"
            shift 2
            ;;
        --tag|-t)
            TAG="$2"
            shift 2
            ;;
        --volume|-v)
            VOLUME_DIR="$2"
            shift 2
            ;;
        --network|-n)
            NETWORK_MODE="$2"
            shift 2
            ;;
        --detach|-d)
            INTERACTIVE=false
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [options] <target_url>"
            echo ""
            echo "Options:"
            echo "  --image, -i IMAGE     Docker image name (default: deep-recon)"
            echo "  --tag, -t TAG         Image tag (default: latest)"
            echo "  --volume, -v DIR      Volume directory for scans (default: ./scans)"
            echo "  --network, -n MODE    Network mode (host, bridge)"
            echo "  --detach, -d          Run in detached mode"
            echo "  --help, -h            Show this help"
            echo ""
            echo "Examples:"
            echo "  $0 https://example.com"
            echo "  $0 --volume /path/to/scans https://example.com"
            echo "  $0 --network host https://example.com"
            exit 0
            ;;
        *)
            if [[ -z "$TARGET" ]]; then
                TARGET="$1"
            fi
            shift
            ;;
    esac
done

# Check if target is provided
if [[ -z "$TARGET" ]]; then
    echo "Error: Target URL is required"
    echo ""
    echo "Usage: $0 [options] <target_url>"
    echo "Example: $0 https://example.com"
    exit 1
fi

# Create volume directory if it doesn't exist
mkdir -p "$VOLUME_DIR"

# Build Docker run command
CMD="docker run"

# Add interactive flags if needed
if [[ "$INTERACTIVE" == "true" ]]; then
    CMD="$CMD -it"
else
    CMD="$CMD -d"
fi

# Add network mode if specified
if [[ -n "$NETWORK_MODE" ]]; then
    CMD="$CMD --network $NETWORK_MODE"
fi

# Add volume mounts
CMD="$CMD -v $(realpath $VOLUME_DIR):/app/scans"
CMD="$CMD -v $(realpath $VOLUME_DIR)/reports:/app/reports"

# Add image and command
CMD="$CMD $IMAGE:$TAG $TARGET"

echo "[*] Running command:"
echo "    $CMD"
echo ""
echo "[*] Starting scan for: $TARGET"
echo "[*] Output will be saved to: $VOLUME_DIR"
echo ""

# Execute the command
eval $CMD

echo ""
echo "=================================================="
echo "    Scan completed!"
echo "=================================================="
echo ""
echo "📁 Output location: $VOLUME_DIR"
echo "📄 Reports: $VOLUME_DIR/reports/"
echo ""
echo "To view results:"
echo "  ls -la $VOLUME_DIR/"
echo "  cat $VOLUME_DIR/*_FULL_RECON_REPORT.txt | less"
echo ""