# Deep Recon - Minimal Dockerfile
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git curl wget nmap openssl whois dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz \
    && rm go1.21.5.linux-amd64.tar.gz

ENV PATH=$PATH:/usr/local/go/bin

# Install Go tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest \
    && go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && go install github.com/tomnomnom/waybackurls@latest \
    && go install github.com/lc/gau/v2/cmd/gau@latest \
    && go install github.com/tomnomnom/assetfinder@latest

# Update Nuclei templates
RUN nuclei -update-templates -silent

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install paramspider
RUN git clone https://github.com/devanshbatham/ParamSpider /tmp/paramspider \
    && cd /tmp/paramspider \
    && pip install . \
    && cd / && rm -rf /tmp/paramspider

# Create app directory
WORKDIR /app

# Copy application
COPY deep_recon.py recon_logger.py ./

# Create scan directory
RUN mkdir -p /app/scans

# Entrypoint
ENTRYPOINT ["python3", "deep_recon.py"]
