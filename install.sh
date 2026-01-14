#!/bin/bash

# ============================================================================
# Deep Recon -  Installation Script
# ============================================================================
# One-line installation: 
# bash <(curl -s https://raw.githubusercontent.com/brayo-crypto/deep_recon/main/install_all.sh)
# ============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Banner
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║           DEEP RECON - Complete Installation             ║"
echo "║             One Command, Everything Installed            ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    echo -e "${YELLOW}[!] Warning: Running as root. Installing system-wide.${NC}"
fi

# Function to check command existence
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print status
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

# Update system packages
print_status "Updating system packages..."
if command_exists apt-get; then
    sudo apt-get update -qq
    sudo apt-get upgrade -y -qq
elif command_exists yum; then
    sudo yum update -y -q
elif command_exists brew; then
    brew update -q
fi

# ============================================================================
# STEP 1: Install Python 3 if not present
# ============================================================================
print_status "Checking Python installation..."
if ! command_exists python3; then
    print_warning "Python 3 not found. Installing..."
    if command_exists apt-get; then
        sudo apt-get install -y python3 python3-pip python3-venv
    elif command_exists yum; then
        sudo yum install -y python3 python3-pip
    elif command_exists brew; then
        brew install python@3.11
    else
        print_error "Could not install Python automatically. Please install Python 3.8+ manually."
        exit 1
    fi
fi

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
print_success "Python $PYTHON_VERSION found"

# ============================================================================
# STEP 2: Install Go if not present
# ============================================================================
print_status "Checking Go installation..."
if ! command_exists go; then
    print_warning "Go not found. Installing..."
    
    if command_exists apt-get; then
        sudo apt-get install -y golang-go
    elif command_exists yum; then
        sudo yum install -y golang
    elif command_exists brew; then
        brew install go
    else
        # Manual Go installation
        GO_VERSION="1.21.5"
        OS=$(uname | tr '[:upper:]' '[:lower:]')
        ARCH=$(uname -m)
        
        case $ARCH in
            x86_64) ARCH="amd64" ;;
            aarch64) ARCH="arm64" ;;
            arm64) ARCH="arm64" ;;
            *) ARCH="386" ;;
        esac
        
        GO_TAR="go${GO_VERSION}.${OS}-${ARCH}.tar.gz"
        GO_URL="https://go.dev/dl/${GO_TAR}"
        
        print_status "Downloading Go ${GO_VERSION}..."
        curl -L $GO_URL -o /tmp/$GO_TAR
        
        print_status "Installing Go..."
        sudo tar -C /usr/local -xzf /tmp/$GO_TAR
        rm /tmp/$GO_TAR
        
        # Add to PATH
        export PATH=$PATH:/usr/local/go/bin
        export PATH=$PATH:$HOME/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
        
        if [ -f ~/.zshrc ]; then
            echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc
            echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.zshrc
        fi
    fi
fi

# Verify Go installation
GO_VERSION=$(go version 2>/dev/null | awk '{print $3}' || echo "Not found")
print_success "Go $GO_VERSION installed"

# Ensure Go binaries are in PATH
export PATH=$PATH:/usr/local/go/bin
export PATH=$PATH:$HOME/go/bin

# ============================================================================
# STEP 3: Install Python Dependencies
# ============================================================================
print_status "Installing Python dependencies..."

# Create virtual environment if not exists
if [ ! -d "venv" ]; then
    print_status "Creating Python virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
python3 -m pip install --upgrade pip

# Install Python packages
print_status "Installing required Python packages..."
python3 -m pip install --upgrade \
    requests \
    wafw00f \
    urllib3 \
    dnspython \
    python-nmap \
    geoip2 \
    colorama

# Install ParamSpider from GitHub
print_status "Installing ParamSpider..."
TEMP_DIR=$(mktemp -d)
cd $TEMP_DIR
git clone https://github.com/devanshbatham/ParamSpider --depth=1
cd ParamSpider
python3 -m pip install .
cd ..
rm -rf $TEMP_DIR
cd - > /dev/null

print_success "Python dependencies installed"

# ============================================================================
# STEP 4: Install Go Tools
# ============================================================================
print_status "Installing Go-based reconnaissance tools..."

# List of Go tools to install
declare -A GO_TOOLS=(
    ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
    ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
    ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
    ["assetfinder"]="github.com/tomnomnom/assetfinder@latest"
    ["gf"]="github.com/tomnomnom/gf@latest"
    ["qsreplace"]="github.com/tomnomnom/qsreplace@latest"
)

# Install each tool
for TOOL in "${!GO_TOOLS[@]}"; do
    if ! command_exists $TOOL; then
        print_status "Installing $TOOL..."
        go install ${GO_TOOLS[$TOOL]} 2>/dev/null || print_warning "Failed to install $TOOL"
    else
        print_success "$TOOL already installed"
    fi
done

print_success "Go tools installed"

# ============================================================================
# STEP 5: Install Additional System Tools
# ============================================================================
print_status "Installing additional system tools..."

if command_exists apt-get; then
    sudo apt-get install -y \
        nmap \
        openssl \
        whois \
        dnsutils \
        net-tools \
        git \
        curl \
        wget \
        jq \
        libpcap-dev
elif command_exists yum; then
    sudo yum install -y \
        nmap \
        openssl \
        whois \
        bind-utils \
        net-tools \
        git \
        curl \
        wget \
        jq \
        libpcap-devel
elif command_exists brew; then
    brew install \
        nmap \
        openssl \
        whois \
        bind \
        git \
        curl \
        wget \
        jq \
        libpcap
fi

# ============================================================================
# STEP 6: Download GeoIP Database
# ============================================================================
print_status "Setting up GeoIP database..."

# Create data directory
mkdir -p data

# Download GeoLite2 City database (requires free MaxMind account)
if [ ! -f "data/GeoLite2-City.mmdb" ]; then
    print_warning "GeoIP database not found."
    print_warning "Sign up for a free MaxMind account at: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
    print_warning "Then download GeoLite2-City.mmdb and place it in the 'data/' directory"
fi

# ============================================================================
# STEP 7: Update Nuclei Templates
# ============================================================================
print_status "Updating Nuclei templates..."
if command_exists nuclei; then
    nuclei -update-templates -silent
    print_success "Nuclei templates updated"
else
    print_warning "Nuclei not found, skipping template update"
fi

# ============================================================================
# STEP 8: Fix File Permissions and Create Symlinks
# ============================================================================
print_status "Setting up file permissions..."

# Make scripts executable
chmod +x *.py 2>/dev/null || true
chmod +x *.sh 2>/dev/null || true

# Create symlink for easy access
if [ ! -f "/usr/local/bin/deep-recon" ]; then
    print_status "Creating symlink for deep-recon..."
    sudo ln -sf "$(pwd)/deep_recon.py" /usr/local/bin/deep-recon 2>/dev/null || \
    ln -sf "$(pwd)/deep_recon.py" ~/.local/bin/deep-recon 2>/dev/null || \
    print_warning "Could not create symlink. Use './deep_recon.py' to run."
fi

# ============================================================================
# STEP 9: Test Installations
# ============================================================================
print_status "Verifying installations..."

declare -A TOOLS=(
    ["python3"]="Python 3"
    ["pip3"]="Python pip"
    ["go"]="Go language"
    ["nmap"]="Nmap scanner"
    ["subfinder"]="Subdomain finder"
    ["httpx"]="HTTP probe"
    ["nuclei"]="Vulnerability scanner"
    ["katana"]="Web crawler"
    ["waybackurls"]="Wayback URL extractor"
    ["gau"]="URL discovery"
    ["assetfinder"]="Asset finder"
    ["paramspider"]="Parameter spider"
    ["wafw00f"]="WAF detector"
)

ALL_GOOD=true

for cmd in "${!TOOLS[@]}"; do
    if command_exists "$cmd"; then
        print_success "${TOOLS[$cmd]} ✓"
    else
        print_error "${TOOLS[$cmd]} ✗ (NOT FOUND)"
        ALL_GOOD=false
    fi
done

# ============================================================================
# FINAL SETUP
# ============================================================================
echo ""
echo -e "${BLUE}==================================================${NC}"
if [ "$ALL_GOOD" = true ]; then
    echo -e "${GREEN}          INSTALLATION COMPLETE! 🎉${NC}"
else
    echo -e "${YELLOW}    INSTALLATION COMPLETE WITH WARNINGS${NC}"
fi
echo -e "${BLUE}==================================================${NC}"
echo ""

# Create activation script
cat > activate_recon.sh << 'EOF'
#!/bin/bash
# Activate Deep Recon environment
source venv/bin/activate 2>/dev/null
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
echo "Deep Recon environment activated!"
echo "Run: deep-recon https://example.com"
EOF

chmod +x activate_recon.sh

# Usage instructions
echo -e "${GREEN}USAGE:${NC}"
echo "1. Activate the environment:"
echo "   ${YELLOW}source venv/bin/activate${NC}"
echo "   or run: ${YELLOW}./activate_recon.sh${NC}"
echo ""
echo "2. Scan a target:"
echo "   ${YELLOW}python3 deep_recon.py https://example.com${NC}"
echo "   or: ${YELLOW}deep-recon https://example.com${NC}"
echo ""
echo "3. For multiple targets, create a file and use:"
echo "   ${YELLOW}python3 deep_recon.py -f targets.txt${NC}"
echo ""
echo -e "${BLUE}==================================================${NC}"
echo -e "${GREEN}Troubleshooting:${NC}"
echo "- If tools are not found, restart your terminal"
echo "- Or run: ${YELLOW}source ~/.bashrc${NC}"
echo "- Check PATH: ${YELLOW}echo \$PATH | grep go${NC}"
echo ""
echo -e "${BLUE}==================================================${NC}"
echo -e "${YELLOW}Note:${NC} For GeoIP location features, download GeoLite2-City.mmdb"
echo "from MaxMind (free account required) and place in 'data/' directory"
echo -e "${BLUE}==================================================${NC}"
