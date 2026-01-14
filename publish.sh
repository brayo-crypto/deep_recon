#!/bin/bash

# Docker Hub Publishing Script
set -e

echo "=================================================="
echo "    Publishing Deep Recon to Docker Hub"
echo "=================================================="

# Configuration
DOCKER_USERNAME="brayo-crypto"  # Change this to your Docker Hub username
IMAGE_NAME="deep-recon"
VERSION="1.0"

# Check if logged into Docker Hub
if ! docker info | grep -q "Username"; then
    echo "Please login to Docker Hub first:"
    echo "  docker login"
    exit 1
fi

# Build the image
echo "[*] Building image..."
docker build -t $IMAGE_NAME:$VERSION -t $IMAGE_NAME:latest .

# Tag for Docker Hub
echo "[*] Tagging image..."
docker tag $IMAGE_NAME:$VERSION $DOCKER_USERNAME/$IMAGE_NAME:$VERSION
docker tag $IMAGE_NAME:latest $DOCKER_USERNAME/$IMAGE_NAME:latest

# Push to Docker Hub
echo "[*] Pushing to Docker Hub..."
docker push $DOCKER_USERNAME/$IMAGE_NAME:$VERSION
docker push $DOCKER_USERNAME/$IMAGE_NAME:latest

echo ""
echo "✅ Published to Docker Hub!"
echo ""
echo "Users can now run with:"
echo "  docker run -it $DOCKER_USERNAME/$IMAGE_NAME https://example.com"
echo ""
echo "Or pull with:"
echo "  docker pull $DOCKER_USERNAME/$IMAGE_NAME"