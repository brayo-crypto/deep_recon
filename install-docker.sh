#!/bin/bash

# Deep Recon - One Line Docker Installer
# Run: bash <(curl -s https://raw.githubusercontent.com/brayo-crypto/deep_recon/main/install-docker.sh)

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
NC='\033[0m' # No Color

# Check Docker installation
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker is not installed!${NC}"
    echo ""
    echo "Installing Docker..."
    
    # Detect OS
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Install Docker on Linux
        curl -fsSL https://get.docker.com -o get-docker.sh
        sudo sh get-docker.sh
        sudo usermod -aG docker $USER
        rm get-docker.sh
        echo -e "${YELLOW}Please log out and back in for Docker group changes to take effect${NC}"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        echo -e "${RED}Please install Docker Desktop for macOS:${NC}"
        echo "  https://docs.docker.com/desktop/install/mac-install/"
        exit 1
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        # Windows
        echo -e "${RED}Please install Docker Desktop for Windows:${NC}"
        echo "  https://docs.docker.com/desktop/install/windows-install/"
        exit 1
    else
        echo -e "${RED}Unsupported OS. Please install Docker manually.${NC}"
        exit 1
    fi
fi

# Check Docker Compose
if ! command -v docker-compose &> /dev/null; then
    echo -e "${YELLOW}Docker Compose not found, installing...${NC}"
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
fi

echo -e "${GREEN}✓ Docker is installed${NC}"

# Clone repository
if [ ! -d "deep_recon" ]; then
    echo "Cloning Deep Recon repository..."
    git clone https://github.com/brayo-crypto/deep_recon.git
    cd deep_recon
else
    echo "Updating Deep Recon repository..."
    cd deep_recon
    git pull origin main
fi

# Build Docker image
echo ""
echo "Building Docker image (this may take a few minutes)..."
chmod +x build.sh
./build.sh

echo ""
echo -e "${GREEN}==================================================${NC}"
echo -e "${GREEN}    INSTALLATION COMPLETE! 🎉${NC}"
echo -e "${GREEN}==================================================${NC}"
echo ""
echo -e "${BLUE}Usage Examples:${NC}"
echo ""
echo "1. Quick scan:"
echo -e "   ${YELLOW}./run.sh https://example.com${NC}"
echo ""
echo "2. With custom output directory:"
echo -e "   ${YELLOW}./run.sh --volume /path/to/scans https://example.com${NC}"
echo ""
echo "3. Using host network:"
echo -e "   ${YELLOW}./run.sh --network host https://example.com${NC}"
echo ""
echo "4. Build only:"
echo -e "   ${YELLOW}./build.sh${NC}"
echo ""
echo "5. Docker Compose:"
echo -e "   ${YELLOW}docker-compose run deep-recon https://example.com${NC}"
echo ""
echo -e "${BLUE}To get started:${NC}"
echo -e "   ${YELLOW}cd deep_recon${NC}"
echo -e "   ${YELLOW}./run.sh https://example.com${NC}"
echo ""