#!/bin/bash

# Build script for Deep Recon Docker image
set -e

echo "=================================================="
echo "    Building Deep Recon Docker Image"
echo "=================================================="

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed"
    echo "Please install Docker first: https://docs.docker.com/get-docker/"
    exit 1
fi

# Build options
IMAGE_NAME="deep-recon"
TAG="latest"
BUILD_ARGS=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --tag|-t)
            TAG="$2"
            shift 2
            ;;
        --no-cache)
            BUILD_ARGS="$BUILD_ARGS --no-cache"
            shift
            ;;
        --push)
            PUSH=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo "Options:"
            echo "  --tag, -t TAG     Set image tag (default: latest)"
            echo "  --no-cache        Build without cache"
            echo "  --push            Push to Docker Hub after build"
            echo "  --help, -h        Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

echo "[*] Building image: $IMAGE_NAME:$TAG"
echo "[*] This may take several minutes..."

# Build the image
docker build $BUILD_ARGS -t $IMAGE_NAME:$TAG .

echo ""
echo "✅ Build complete!"
echo ""

# Test the build
echo "[*] Testing the image..."
docker run --rm $IMAGE_NAME:$TAG --help

echo ""
echo "=================================================="
echo "    Usage Examples:"
echo "=================================================="
echo ""
echo "1. Quick scan:"
echo "   docker run -it deep-recon https://example.com"
echo ""
echo "2. Scan with volume mount:"
echo "   docker run -it -v \$(pwd)/scans:/app/scans deep-recon https://example.com"
echo ""
echo "3. Interactive shell:"
echo "   docker run -it deep-recon /bin/bash"
echo ""
echo "4. Using docker-compose:"
echo "   docker-compose run deep-recon https://example.com"
echo ""
echo "5. Multi-scan with script:"
echo "   for target in \$(cat targets.txt); do"
echo "     docker run --rm deep-recon \$target"
echo "   done"
echo ""

if [[ "$PUSH" == "true" ]]; then
    echo "[*] Pushing to Docker Hub..."
    docker tag $IMAGE_NAME:$TAG $IMAGE_NAME:$TAG
    docker push $IMAGE_NAME:$TAG
    echo "✅ Image pushed to Docker Hub"
fi