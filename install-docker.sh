#!/bin/bash

# Deep Recon - Docker Installation Fix
set -e

echo "=================================================="
echo "    Deep Recon - Docker Installation"
echo "=================================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Clean up any existing installation
if [ -d "deep_recon" ]; then
    echo -e "${YELLOW}[!] Removing old installation...${NC}"
    rm -rf deep_recon
fi

# Check if Docker/Podman is available
if ! command -v docker &> /dev/null && ! command -v podman &> /dev/null; then
    echo -e "${RED}[-] Neither Docker nor Podman found!${NC}"
    
    # Try to install Docker
    echo "Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
    
    echo -e "${YELLOW}[!] Please log out and back in, or run: newgrp docker${NC}"
fi

# Clone repository
echo ""
echo "Cloning Deep Recon repository..."
git clone https://github.com/brayo-crypto/deep_recon.git

# Check if clone was successful
if [ ! -d "deep_recon" ]; then
    echo -e "${RED}[-] Failed to clone repository!${NC}"
    exit 1
fi

cd deep_recon

# Check for essential files
echo "Checking repository structure..."
ESSENTIAL_FILES=("Dockerfile" "deep_recon.py" "requirements.txt")
MISSING_FILES=0

for file in "${ESSENTIAL_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}[-] Missing: $file${NC}"
        MISSING_FILES=1
    fi
done

if [ $MISSING_FILES -eq 1 ]; then
    echo -e "${RED}[-] Repository incomplete!${NC}"
    exit 1
fi

echo -e "${GREEN}✓ All essential files present${NC}"

# Build the Docker image
echo ""
echo "Building Docker image..."
echo "This may take 5-10 minutes..."
echo ""

# Try Docker first, then Podman
if command -v docker &> /dev/null; then
    echo "Using Docker..."
    docker build -t deep-recon .
elif command -v podman &> /dev/null; then
    echo "Using Podman..."
    podman build -t deep-recon .
else
    echo -e "${RED}[-] No container runtime available!${NC}"
    exit 1
fi

# Check if build was successful
if [ $? -eq 0 ]; then
    echo ""
    echo -e "${GREEN}==================================================${NC}"
    echo -e "${GREEN}    BUILD SUCCESSFUL! 🎉${NC}"
    echo -e "${GREEN}==================================================${NC}"
    
    # Make scripts executable
    chmod +x run.sh build.sh 2>/dev/null || true
    
    echo ""
    echo "To run a scan:"
    echo "  ./run.sh https://example.com"
    echo ""
    echo "Or:"
    echo "  docker run -it -v \$(pwd)/scans:/app/scans deep-recon https://example.com"
    echo ""
    echo "Output will be saved to ./scans/"
else
    echo -e "${RED}[-] Build failed!${NC}"
    echo "Check the error messages above."
    exit 1
fi
