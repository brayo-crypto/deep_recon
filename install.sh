#!/bin/bash
set -e

echo "=================================================="
echo "  deep_recon Scanner - Dependency Installation"
echo "=================================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo -e "${RED}Please don't run this script as root${NC}"
    exit 1
fi

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check Python
echo -e "${YELLOW}[1/4] Checking Python...${NC}"
if command_exists python3; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    echo -e "${GREEN}✓ Python $PYTHON_VERSION found${NC}"
else
    echo -e "${RED}✗ Python 3 not found. Please install Python 3.8+${NC}"
    exit 1
fi

# Check Go
echo -e "${YELLOW}[2/4] Checking Go...${NC}"
if command_exists go; then
    GO_VERSION=$(go version | awk '{print $3}')
    echo -e "${GREEN}✓ Go $GO_VERSION found${NC}"
else
    echo -e "${RED}✗ Go not found${NC}"
    echo "Installing Go..."
    
    # Detect OS
    OS=$(uname -s)
    if [ "$OS" == "Linux" ]; then
        wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz
        sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
        rm go1.21.5.linux-amd64.tar.gz
        
        # Add to PATH
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
        source ~/.bashrc
        
    elif [ "$OS" == "Darwin" ]; then
        if command_exists brew; then
            brew install go
        else
            echo -e "${RED}Please install Homebrew first or manually install Go${NC}"
            exit 1
        fi
    fi
    
    echo -e "${GREEN}✓ Go installed${NC}"
fi

# Ensure Go bin is in PATH
export PATH=$PATH:/usr/local/go/bin
export PATH=$PATH:$HOME/go/bin

# Install Python dependencies
echo -e "${YELLOW}[3/4] Installing Python dependencies...${NC}"
pip3 install -r requirements.txt
echo -e "${GREEN}✓ Python dependencies installed${NC}"

# Install Go tools
echo -e "${YELLOW}[4/4] Installing Go-based tools...${NC}"
echo "This may take a few minutes..."

declare -a GO_TOOLS=(
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    "github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
    "github.com/projectdiscovery/katana/cmd/katana@latest"
    "github.com/tomnomnom/waybackurls@latest"
    "github.com/lc/gau/v2/cmd/gau@latest"
    "github.com/tomnomnom/assetfinder@latest"
)

for tool in "${GO_TOOLS[@]}"; do
    TOOL_NAME=$(echo $tool | awk -F'/' '{print $NF}' | cut -d'@' -f1)
    echo "  → Installing $TOOL_NAME..."
    go install -v "$tool" 2>&1 | grep -v "go: downloading" || true
done

echo -e "${GREEN}✓ Go tools installed${NC}"

# Update Nuclei templates
echo ""
echo -e "${YELLOW}Updating Nuclei templates...${NC}"
nuclei -update-templates -silent
echo -e "${GREEN}✓ Nuclei templates updated${NC}"

# Verify installations
echo ""
echo "=================================================="
echo "  Verifying Installation"
echo "=================================================="

declare -a REQUIRED_TOOLS=(
    "python3"
    "go"
    "subfinder"
    "httpx"
    "nuclei"
    "katana"
    "waybackurls"
    "gau"
    "assetfinder"
    "paramspider"
    "wafw00f"
    "openssl"
)

ALL_GOOD=true

for tool in "${REQUIRED_TOOLS[@]}"; do
    if command_exists "$tool"; then
        echo -e "${GREEN}✓${NC} $tool"
    else
        echo -e "${RED}✗${NC} $tool - NOT FOUND"
        ALL_GOOD=false
    fi
done

echo ""
if [ "$ALL_GOOD" = true ]; then
    echo -e "${GREEN}=================================================="
    echo "  Installation Complete! 🎉"
    echo "==================================================${NC}"
    echo ""
    echo "You can now run the scanner:"
    echo "  python3 deep_recon.py https://example.com"
else
    echo -e "${YELLOW}=================================================="
    echo "  Installation Completed with Warnings"
    echo "==================================================${NC}"
    echo ""
    echo "Some tools are missing. Please install them manually."
    echo "See the README.md for installation instructions."
fi

echo ""
