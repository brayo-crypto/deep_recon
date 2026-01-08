# Deep Recon

<div align="center">

![Version](https://img.shields.io/badge/version-1.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

**Comprehensive Website Intelligence & Reconnaissance Tool**

</div>

## 📋 Overview

Deep Recon is an automated reconnaissance tool designed for security researchers and penetration testers. It performs comprehensive information gathering on target websites, including subdomain enumeration, URL discovery, parameter extraction, technology detection, and vulnerability scanning.


**I hashed many details so that it could be simple for me to modify the code and dont get lost in it.**
**GG fellow sec**

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is intended for legal security research and authorized penetration testing only. Users are responsible for ensuring they have explicit permission to scan target systems. Unauthorized scanning of systems you don't own or have permission to test is illegal.

The author is not responsible for misuse or damage caused by this tool. Use responsibly and ethically.

## ✨ Features

- **Technology Detection**: Identifies web servers, frameworks, CMS platforms, and frontend technologies
- **WAF Detection**: Detects Web Application Firewalls protecting the target
- **Security Headers Analysis**: Evaluates security header implementation
- **SSL/TLS Analysis**: Examines certificate configuration
- **URL Discovery**: Combines crawling and archive sources (Wayback, GAU)
- **API Endpoint Discovery**: Identifies REST and GraphQL endpoints
- **Parameter Extraction**: Discovers and categorizes parameters by vulnerability type
- **Subdomain Enumeration**: Passive subdomain discovery with live host filtering
- **Third-party Resource Detection**: Maps external dependencies and CDNs
- **Vulnerability Scanning**: Automated CVE and misconfiguration detection using Nuclei
- **Comprehensive Reporting**: Generates detailed reports with actionable findings

## 🔧 Prerequisites

### Python Requirements
- Python 3.8 or higher
- pip package manager

### External Tools Required

The following tools must be installed and available in your PATH:

| Tool | Purpose | Installation |
|------|---------|--------------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Subdomain enumeration | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP probing | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Vulnerability scanning | `go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest` |
| [katana](https://github.com/projectdiscovery/katana) | Web crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | Archive URL extraction | `go install github.com/tomnomnom/waybackurls@latest` |
| [gau](https://github.com/lc/gau) | GetAllUrls aggregator | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Subdomain discovery | `go install github.com/tomnomnom/assetfinder@latest` |
| [paramspider](https://github.com/devanshbatham/ParamSpider) | Parameter discovery | `pip install paramspider` |
| [wafw00f](https://github.com/EnableSecurity/wafw00f) | WAF detection | `pip install wafw00f` |

### System Tools
- `openssl` - For SSL/TLS analysis (usually pre-installed on Linux/macOS)

## 📦 Installation

### 1. Clone the repository
```bash
git clone https://github.com/brayo-crypto/deep_recon.git
cd deep_recon
```

### 2. Install Python dependencies
```bash
pip install -r requirements.txt
```

### 3. Install Go tools (if not already installed)

**Install Go** (if needed):
```bash
# Linux
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
export PATH=$PATH:~/go/bin

# macOS
brew install go
```

**Install all Go-based tools**:
```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/assetfinder@latest
```

**Install Python-based tools**:
```bash
pip install paramspider wafw00f
```

### 4. Update Nuclei templates (recommended)
```bash
nuclei -update-templates
```

## 🚀 Usage

### Basic Usage
```bash
python3 deep_recon.py <target_url>
```

### Examples
```bash
# Scan with HTTPS (recommended)
python3 deep_recon.py https://example.com

# Scan with automatic HTTPS (will add https://)
python3 deep_recon.py example.com
```

## 📊 Output

The tool generates a comprehensive report file:
- **Filename**: `{domain}_FULL_RECON_REPORT.txt`
- **Format**: Plain text with organized sections
- **Contents**: All findings from 10 reconnaissance modules

### Report Sections:
1. Technology Stack
2. Web Application Firewall (WAF)
3. Security Headers
4. SSL/TLS Configuration
5. Subdomains Discovered (with live hosts and 403 bypass opportunities)
6. URL Discovery (categorized by vulnerability type)
7. Parameters Discovered (with testing recommendations)
8. API Endpoints
9. Third-party Resources & CDNs
10. Vulnerabilities Detected (Nuclei findings)
11. Executive Summary

## 🎯 Key Features Explained

### Vulnerability-Focused Categorization
The tool automatically categorizes findings by vulnerability type:
- **XSS-prone**: URLs and parameters likely vulnerable to Cross-Site Scripting
- **SQLi-prone**: Endpoints potentially vulnerable to SQL Injection
- **LFI-prone**: Parameters that might allow Local File Inclusion
- **IDOR-prone**: Parameters susceptible to Insecure Direct Object References
- **SSRF-prone**: Endpoints potentially vulnerable to Server-Side Request Forgery
- **Open Redirect**: Parameters that might allow URL redirection attacks

### 403 Forbidden Detection
Highlights subdomains returning 403 status codes with bypass techniques, as these often indicate:
- Admin panels
- Internal tools
- Staging/development environments
- API endpoints with weak authentication

## ⏱️ Scan Duration

Expected scan times vary by target size:
- **Small sites**: 5-10 minutes
- **Medium sites**: 15-30 minutes
- **Large sites**: 30-60+ minutes

Factors affecting duration:
- Number of subdomains
- URL count in archives
- Nuclei template coverage
- Network latency

## 🛠️ Troubleshooting

### Common Issues

**"Command not found" errors**
- Ensure all external tools are installed and in your PATH
- Verify Go binaries are in `~/go/bin` and this directory is in PATH

**No subdomains found**
- Check internet connectivity
- Some targets may not have subdomains in public datasets
- Try running subfinder manually to verify it works

**Nuclei scan returns no results**
- Update Nuclei templates: `nuclei -update-templates`
- Some targets may have no known vulnerabilities

**Timeout errors**
- Large scans may timeout; consider increasing timeout values in code
- Check network stability

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

### To Contribute:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/Features`)
3. Commit your changes (`git commit -m 'Add some Features'`)
4. Push to the branch (`git push origin feature/Features`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Yobra/Brayo**
- Discord: yobra8752
- GitHub: [@brayo-crypto](https://github.com/yourusername)

## 🙏 Acknowledgments

This tool leverages several excellent open-source projects:
- [ProjectDiscovery](https://github.com/projectdiscovery) - subfinder, httpx, nuclei, katana
- [tomnomnom](https://github.com/tomnomnom) - waybackurls, assetfinder
- [lc](https://github.com/lc) - gau
- [devanshbatham](https://github.com/devanshbatham) - ParamSpider
- [EnableSecurity](https://github.com/EnableSecurity) - wafw00f

## ⭐ Star History

If you find this tool useful, please consider giving it a star on GitHub!

---

<div align="center">
Made with ❤️ by Yobra | For Educational & Authorized Testing Only
</div>
