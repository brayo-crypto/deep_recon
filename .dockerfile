# Deep Recon Docker Image
# Build: docker build -t deep-recon .
# Run: docker run -it deep-recon https://example.com

FROM python:3.11-slim as base

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    nmap \
    openssl \
    whois \
    dnsutils \
    net-tools \
    jq \
    libpcap-dev \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go
ENV GO_VERSION=1.21.5
RUN wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm go${GO_VERSION}.linux-amd64.tar.gz

ENV GOPATH=/go
ENV PATH=$PATH:/usr/local/go/bin:/go/bin

# Install Go tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/tomnomnom/waybackurls@latest && \
    go install github.com/lc/gau/v2/cmd/gau@latest && \
    go install github.com/tomnomnom/assetfinder@latest && \
    go install github.com/tomnomnom/gf@latest && \
    go install github.com/tomnomnom/qsreplace@latest

# Update Nuclei templates
RUN nuclei -update-templates -silent

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Install paramspider from GitHub
RUN git clone https://github.com/devanshbatham/ParamSpider /tmp/paramspider && \
    cd /tmp/paramspider && \
    pip install . && \
    cd / && rm -rf /tmp/paramspider

# Create app directory
WORKDIR /app

# Copy application files
COPY deep_recon.py recon_logger.py ./
COPY requirements.txt ./

# Create data directory for GeoIP
RUN mkdir -p /app/data

# Set up entry point
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["--help"]

# Labels
LABEL maintainer="Yobra/Brayo <yobra8752>"
LABEL version="1.0"
LABEL description="Deep Recon - Comprehensive Website Intelligence & Reconnaissance Tool"