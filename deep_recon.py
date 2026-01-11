#
"""
made by Yobra/Brayo
my discord is @Yobra8752
notee:For authorized security testing only,I am not responsible for whatever you choose to do with this tool so use your brain
"""

import subprocess
import requests
import json
import re
from urllib.parse import urlparse
from datetime import datetime

class DeepReconScanner:
    def __init__(self, target):
        self.target = target.rstrip('/')
        self.domain = urlparse(target).netloc
        self.results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'findings': {}
        }
    
    def run_command(self, cmd, timeout=300):
        """Execute shell command and return output"""
        try:
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.stdout if result.returncode == 0 else result.stderr
        except Exception as e:
            return f"Error: {str(e)}"
    
    def banner(self):
        """Print banner"""
        print("""
╔══════════════════════════════════════════════════════════════╗
║           DEEP RECON SCANNER v1.0                            ║
║           Comprehensive Website Intelligence                 ║
╚══════════════════════════════════════════════════════════════╝
        """)
        print(f"[*] Target: {self.target}")
        print(f"[*] Domain: {self.domain}")
        print(f"[*] Scan started: {self.results['scan_time']}\n")
    
    def tech_detection(self):
        """Detect technologies, frameworks, and CMS"""
        print("\n[1/10] 🔍 Technology Detection")
        print("=" * 60)
        
        techs = {}
        
        # Manual detection from HTTP response
        try:
            resp = requests.get(self.target, timeout=10, verify=False)
            headers = resp.headers
            
            # Server detection
            techs['server'] = headers.get('Server', 'Unknown')
            techs['x_powered_by'] = headers.get('X-Powered-By', 'Not found')
            
            # Framework detection from headers
            if 'X-AspNet-Version' in headers:
                techs['framework'] = f"ASP.NET {headers['X-AspNet-Version']}"
            elif 'X-Drupal-Cache' in headers:
                techs['cms'] = 'Drupal'
            elif 'X-Generator' in headers:
                techs['generator'] = headers['X-Generator']
            
            # Content analysis
            html = resp.text.lower()
            
            # CMS detection patterns
            if 'wp-content' in html or 'wordpress' in html:
                techs['cms'] = 'WordPress'
            elif 'joomla' in html:
                techs['cms'] = 'Joomla'
            elif 'drupal' in html:
                techs['cms'] = 'Drupal'
            elif '/typo3' in html:
                techs['cms'] = 'TYPO3'
            
            # This the framework detection
            if 'react' in html:
                techs['frontend'] = 'React'
            elif 'vue' in html:
                techs['frontend'] = 'Vue.js'
            elif 'angular' in html:
                techs['frontend'] = 'Angular'
            
            print(f"  ✓ Server: {techs.get('server', 'Unknown')}")
            print(f"  ✓ Powered By: {techs.get('x_powered_by', 'Not disclosed')}")
            print(f"  ✓ CMS: {techs.get('cms', 'Not detected')}")
            print(f"  ✓ Frontend: {techs.get('frontend', 'Not detected')}")
            
        except Exception as e:
            print(f"  ✗ Error: {e}")
        
        self.results['findings']['technologies'] = techs
    
    def waf_detection(self):
        """Web Application Firewall DeTeCtIoN"""
        print("\n[2/10] 🛡️  WAF Detection")
        print("=" * 60)
        
        # Use wafw00f if available
        output = self.run_command(f"wafw00f {self.target} -o /dev/null 2>&1")
        
        if 'behind' in output.lower():
            waf = re.search(r'behind (.+?)(?:\n|$)', output, re.IGNORECASE)
            waf_name = waf.group(1).strip() if waf else "Detected (unknown)"
            print(f"  ⚠️  WAF Detected: {waf_name}")
            self.results['findings']['waf'] = waf_name
        else:
            print("  ✓ No WAF detected")
            self.results['findings']['waf'] = None
    
    def security_headers(self):
        """Analyze security headers"""
        print("\n[3/10] 🔐 Security Headers Analysis")
        print("=" * 60)
        
        try:
            resp = requests.get(self.target, timeout=10, verify=False)
            headers = resp.headers
            
            security_headers = {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                'Content-Security-Policy': headers.get('Content-Security-Policy'),
                'X-Frame-Options': headers.get('X-Frame-Options'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                'X-XSS-Protection': headers.get('X-XSS-Protection'),
                'Referrer-Policy': headers.get('Referrer-Policy'),
                'Permissions-Policy': headers.get('Permissions-Policy'),
            }
            
            for header, value in security_headers.items():
                if value:
                    print(f"  ✓ {header}: {value[:50]}...")
                else:
                    print(f"  ✗ {header}: MISSING")
            
            self.results['findings']['security_headers'] = security_headers
            
        except Exception as e:
            print(f"  ✗ Error: {e}")
    
    def ssl_analysis(self):
        """Analyze SSL/TLS configuration"""
        print("\n[4/10] 🔒 SSL/TLS Certificate Analysis")
        print("=" * 60)
        
        # Use testssl.sh if available, otherwise basic check
        output = self.run_command(f"echo | openssl s_client -connect {self.domain}:443 2>/dev/null")
        
        if output:
            # Extract certificate info
            if 'Certificate chain' in output:
                print("  ✓ SSL Certificate: Valid")
                
                # Extract issuer
                issuer = re.search(r'issuer=(.+?)(?:\n|$)', output)
                if issuer:
                    print(f"  ✓ Issuer: {issuer.group(1).strip()}")
                
                # Extract expiry
                expiry = re.search(r'expire date: (.+?)(?:\n|$)', output, re.IGNORECASE)
                if expiry:
                    print(f"  ✓ Expires: {expiry.group(1).strip()}")
                
                self.results['findings']['ssl'] = 'Valid'
            else:
                print("  ✗ SSL Certificate: Invalid or not found")
                self.results['findings']['ssl'] = 'Invalid'
        else:
            print("  ⚠️  Could not analyze SSL")
    
    def url_discovery(self):
        """Discover URLs using multiple methods"""
        print("\n[5/10] 🔎 URL Discovery (Crawling + Archive)")
        print("=" * 60)
        
        urls = set()
        
        # Method 1: Katana (JS-aware crawler)
        print("  → Running Katana crawler...")
        katana_out = self.run_command(f"katana -u {self.target} -d 2 -silent")
        if katana_out:
            found = katana_out.strip().split('\n')
            urls.update(found)
            print(f"    ✓ Found {len(found)} URLs via crawling")
        
        # Method 2: Wayback URLs (historical)
        print("  → Checking Wayback Machine...")
        wayback_out = self.run_command(f"echo {self.domain} | waybackurls")
        if wayback_out:
            found = wayback_out.strip().split('\n')
            urls.update(found)
            print(f"    ✓ Found {len(found)} URLs via archives")
        
        # Method 3: GAU (GetAllUrls)
        print("  → Running GAU...")
        gau_out = self.run_command(f"echo {self.domain} | gau --blacklist png,jpg,gif,svg")
        if gau_out:
            found = gau_out.strip().split('\n')
            urls.update(found)
            print(f"    ✓ Found {len(found)} URLs via GAU")
        
        print(f"\n  📊 Total unique URLs discovered: {len(urls)}")
        
        # Categorize URLs by potential vulnerability
        xss_urls = []
        sqli_urls = []
        lfi_urls = []
        upload_urls = []
        
        for url in urls:
            url_lower = url.lower()
            
            # XSS-prone URLs (have input parameters)
            if any(keyword in url_lower for keyword in ['search', 'query', 'q=', 'keyword', 'name=', 'msg=', 'comment=']):
                xss_urls.append(url)
            
            # SQLi-prone URLs
            if any(keyword in url_lower for keyword in ['id=', 'userid=', 'product=', 'cat=', 'item=', 'page=']):
                sqli_urls.append(url)
            
            # LFI-prone URLs
            if any(keyword in url_lower for keyword in ['file=', 'path=', 'doc=', 'page=', 'include=', 'dir=']):
                lfi_urls.append(url)
            
            # File upload endpoints
            if any(keyword in url_lower for keyword in ['upload', 'attach', 'file-upload', 'add-file']):
                upload_urls.append(url)
        
        # Show categorized counts
        if xss_urls:
            print(f"  🎯 XSS-prone URLs: {len(xss_urls)}")
        if sqli_urls:
            print(f"  🎯 SQLi-prone URLs: {len(sqli_urls)}")
        if lfi_urls:
            print(f"  🎯 LFI-prone URLs: {len(lfi_urls)}")
        if upload_urls:
            print(f"  🎯 File Upload URLs: {len(upload_urls)}")
        
        self.results['findings']['urls'] = {
            'count': len(urls),
            'list': sorted(urls),
            'categorized': {
                'xss': xss_urls[:100],  # Limit to first 100
                'sqli': sqli_urls[:100],
                'lfi': lfi_urls[:100],
                'upload': upload_urls[:50]
            }
        }
    
    def api_discovery(self):
        """Discover API endpoints"""
        print("\n[6/10] 🔌 API Endpoint Discovery")
        print("=" * 60)
        
        # Look for common API patterns in URLs
        urls = self.results['findings'].get('urls', {}).get('list', [])
        
        api_patterns = ['/api/', '/v1/', '/v2/', '/graphql', '/rest/', '/json', '/xml']
        api_endpoints = []
        
        for url in urls:
            if any(pattern in url.lower() for pattern in api_patterns):
                api_endpoints.append(url)
        
        if api_endpoints:
            print(f"  ✓ Found {len(api_endpoints)} potential API endpoints")
            
            # Show sample
            print("\n  Sample endpoints:")
            for endpoint in api_endpoints[:5]:
                print(f"    • {endpoint}")
            
            self.results['findings']['api_endpoints'] = {
                'count': len(api_endpoints),
                'list': api_endpoints
            }
        else:
            print("  ⚠️  No API endpoints detected")
            self.results['findings']['api_endpoints'] = {'count': 0, 'list': []}
    
    def parameter_discovery(self):
        """Extract all parameters from URLs"""
        print("\n[7/10] 📝 Parameter Discovery")
        print("=" * 60)
        
        # Use ParamSpider
        print("  → Running ParamSpider...")
        param_out = self.run_command(f"paramspider -d {self.domain} --exclude png,jpg,gif,svg,css,woff --level high")
        
        # Also extract from discovered URLs
        params = set()
        urls = self.results['findings'].get('urls', {}).get('list', [])
        for url in urls:
            if '?' in url:
                query = urlparse(url).query
                for param in query.split('&'):
                    if '=' in param:
                        param_name = param.split('=')[0]
                        params.add(param_name)
        
        # Categorize parameters by vulnerability type
        xss_params = []
        sqli_params = []
        lfi_params = []
        idor_params = []
        ssrf_params = []
        redirect_params = []
        
        # XSS indicators
        xss_keywords = ['search', 'query', 'q', 'keyword', 'name', 'msg', 'message', 'comment', 'text', 'title', 'content', 'description', 'email']
        # SQLi indicators
        sqli_keywords = ['id', 'userid', 'user', 'product_id', 'cat', 'category', 'pid', 'item', 'order', 'page']
        # LFI indicators
        lfi_keywords = ['file', 'path', 'doc', 'document', 'folder', 'dir', 'page', 'include', 'template', 'view']
        # IDOR indicators
        idor_keywords = ['id', 'user_id', 'userid', 'account', 'profile', 'order_id', 'ticket', 'invoice', 'document_id']
        # SSRF indicators
        ssrf_keywords = ['url', 'uri', 'link', 'src', 'href', 'redirect', 'proxy', 'api', 'callback', 'webhook']
        # Open Redirect indicators
        redirect_keywords = ['redirect', 'url', 'next', 'redir', 'return', 'returnto', 'go', 'goto', 'continue', 'dest', 'destination']
        
        for param in params:
            param_lower = param.lower()
            
            # Categorize (param can be in multiple categories)
            if any(keyword in param_lower for keyword in xss_keywords):
                xss_params.append(param)
            if any(keyword in param_lower for keyword in sqli_keywords):
                sqli_params.append(param)
            if any(keyword in param_lower for keyword in lfi_keywords):
                lfi_params.append(param)
            if any(keyword in param_lower for keyword in idor_keywords):
                idor_params.append(param)
            if any(keyword in param_lower for keyword in ssrf_keywords):
                ssrf_params.append(param)
            if any(keyword in param_lower for keyword in redirect_keywords):
                redirect_params.append(param)
        
        if params:
            print(f"  ✓ Found {len(params)} unique parameters")
            
            # Show categorized findings
            if xss_params:
                print(f"  🎯 XSS-prone parameters: {len(xss_params)}")
            if sqli_params:
                print(f"  🎯 SQLi-prone parameters: {len(sqli_params)}")
            if lfi_params:
                print(f"  🎯 LFI-prone parameters: {len(lfi_params)}")
            if idor_params:
                print(f"  🎯 IDOR-prone parameters: {len(idor_params)}")
            if ssrf_params:
                print(f"  🎯 SSRF-prone parameters: {len(ssrf_params)}")
            if redirect_params:
                print(f"  🎯 Open Redirect-prone parameters: {len(redirect_params)}")
            
            self.results['findings']['parameters'] = {
                'count': len(params),
                'list': sorted(params),
                'categorized': {
                    'xss': sorted(list(set(xss_params))),
                    'sqli': sorted(list(set(sqli_params))),
                    'lfi': sorted(list(set(lfi_params))),
                    'idor': sorted(list(set(idor_params))),
                    'ssrf': sorted(list(set(ssrf_params))),
                    'open_redirect': sorted(list(set(redirect_params)))
                }
            }
        else:
            print("  ⚠️  No parameters discovered")
            self.results['findings']['parameters'] = {
                'count': 0, 
                'list': [],
                'categorized': {
                    'xss': [],
                    'sqli': [],
                    'lfi': [],
                    'idor': [],
                    'ssrf': [],
                    'open_redirect': []
                }
            }
    
    def third_party_resources(self):
        """Identify external resources and dependencies"""
        print("\n[8/10] 🔗 Third-Party Resources & CDNs")
        print("=" * 60)
        
        try:
            resp = requests.get(self.target, timeout=10, verify=False)
            html = resp.text
            
            # Extract external resources
            external_domains = set()
            
            # Script sources
            scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)', html, re.IGNORECASE)
            for script in scripts:
                domain = urlparse(script).netloc
                if domain and domain != self.domain:
                    external_domains.add(domain)
            
            # Link hrefs (CSS, etc)
            links = re.findall(r'<link[^>]+href=["\']([^"\']+)', html, re.IGNORECASE)
            for link in links:
                domain = urlparse(link).netloc
                if domain and domain != self.domain:
                    external_domains.add(domain)
            
            # Image sources
            imgs = re.findall(r'<img[^>]+src=["\']([^"\']+)', html, re.IGNORECASE)
            for img in imgs:
                domain = urlparse(img).netloc
                if domain and domain != self.domain:
                    external_domains.add(domain)
            
            if external_domains:
                print(f"  ✓ Found {len(external_domains)} external domains")
                
                # Categorize
                cdns = [d for d in external_domains if 'cdn' in d.lower() or 'cloudflare' in d.lower()]
                analytics = [d for d in external_domains if any(x in d.lower() for x in ['analytics', 'google', 'facebook', 'hotjar'])]
                
                if cdns:
                    print(f"\n  📦 CDNs ({len(cdns)}):")
                    for cdn in cdns[:5]:
                        print(f"    • {cdn}")
                
                if analytics:
                    print(f"\n  📊 Analytics/Tracking ({len(analytics)}):")
                    for tracker in analytics[:5]:
                        print(f"    • {tracker}")
                
                self.results['findings']['third_party'] = {
                    'total': len(external_domains),
                    'cdns': cdns,
                    'analytics': analytics,
                    'all': list(external_domains)
                }
            else:
                print("  ℹ️  No external resources detected")
                
        except Exception as e:
            print(f"  ✗ Error: {e}")
    
    def subdomain_enumeration(self):
        """Enumerate subdomains"""
        print("\n[9/10] 🌐 Subdomain Enumeration")
        print("=" * 60)
        
        subdomains = set()
        
        # Method 1: Subfinder (passive)
        print("  → Running Subfinder (passive)...")
        subfinder_out = self.run_command(f"subfinder -d {self.domain} -silent")
        if subfinder_out:
            found = [s.strip() for s in subfinder_out.strip().split('\n') if s.strip()]
            subdomains.update(found)
            print(f"    ✓ Found {len(found)} subdomains")
        
        # Method 2: Assetfinder
        print("  → Running Assetfinder...")
        asset_out = self.run_command(f"assetfinder --subs-only {self.domain}")
        if asset_out:
            found = [s.strip() for s in asset_out.strip().split('\n') if s.strip()]
            subdomains.update(found)
            print(f"    ✓ Found {len(found)} subdomains")
        
        if subdomains:
            print(f"\n  📊 Total unique subdomains: {len(subdomains)}")
            
            # Filter with httpx to find alive hosts
            print("\n  → Filtering live hosts with httpx...")
            print("  ⏳ This may take a few minutes...")
            
            # Create temp file for httpx
            import tempfile
            import os
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as tmp:
                tmp.write('\n'.join(sorted(subdomains)))
                tmp_path = tmp.name
            
            # Use httpx to filter alive hosts with detailed probing
            httpx_cmd = f"cat {tmp_path} | httpx -silent -threads 50 -timeout 10 -status-code -title -tech-detect -follow-redirects -mc 200,201,202,301,302,400,401,403,404,500"
            alive = self.run_command(httpx_cmd, timeout=600)
            
            # Clean up temp file
            os.unlink(tmp_path)
            
            alive_hosts = []
            alive_details = []
            forbidden_hosts = []  # 403 responses
            
            if alive and alive.strip():
                lines = [line.strip() for line in alive.strip().split('\n') if line.strip()]
                
                for line in lines:
                    # Extract URL from httpx output
                    parts = line.split()
                    if parts:
                        url = parts[0]
                        alive_hosts.append(url)
                        alive_details.append(line)
                        
                        # Check if it's a 403 Forbidden
                        if '[403]' in line or '403' in line:
                            forbidden_hosts.append(line)
                
                print(f"  ✓ {len(alive_hosts)} subdomains are live and responding")
                
                if forbidden_hosts:
                    print(f"  🔒 {len(forbidden_hosts)} hosts returned 403 Forbidden (HIGH VALUE!)")
                    print("\n  Sample 403 hosts:")
                    for host in forbidden_hosts[:3]:
                        print(f"    🎯 {host}")
                
                # Show sample live hosts with details
                print("\n  Sample live hosts:")
                for detail in alive_details[:5]:
                    print(f"    • {detail}")
            else:
                print("  ⚠️  No live hosts found or httpx failed")
                
            self.results['findings']['subdomains'] = {
                'total': len(subdomains),
                'alive': len(alive_hosts),
                'forbidden_count': len(forbidden_hosts),
                'list': sorted(subdomains),
                'live_list': alive_hosts,
                'live_details': alive_details,
                'forbidden_list': forbidden_hosts
            }
        else:
            print("  ⚠️  No subdomains found")
            self.results['findings']['subdomains'] = {
                'total': 0, 
                'alive': 0,
                'forbidden_count': 0,
                'list': [], 
                'live_list': [],
                'live_details': [],
                'forbidden_list': []
            }
    
    def vulnerability_scan(self):
        """Scan for known vulnerabilities"""
        print("\n[10/10] 🚨 Vulnerability Scanning (Nuclei)")
        print("=" * 60)
        
        # Run Nuclei with CVE templates
        print("  → Running Nuclei with CVE + exposed-panels templates...")
        print("  ⏳ This may take a while...\n")
        
        nuclei_cmd = f"nuclei -u {self.target} -tags cve,exposure,misconfig -severity critical,high,medium -silent"
        nuclei_out = self.run_command(nuclei_cmd, timeout=3600)
        
        if nuclei_out and nuclei_out.strip():
            vulns = nuclei_out.strip().split('\n')
            print(f"  ⚠️  Found {len(vulns)} potential issues!")
            
            # Show critical/high
            print("\n  🚨 Sample findings:")
            for vuln in vulns[:5]:
                print(f"    • {vuln}")
            
            self.results['findings']['vulnerabilities'] = {
                'count': len(vulns),
                'list': vulns
            }
        else:
            print("  ✓ No critical vulnerabilities detected")
            self.results['findings']['vulnerabilities'] = {'count': 0, 'list': []}
    
    def generate_report(self):
        """Generate final comprehensive report in ONE file"""
        print("\n" + "=" * 60)
        print("📋 GENERATING MASTER REPORT")
        print("=" * 60)
        
        findings = self.results['findings']
        
        # Create ONE master report file
        report_file = f'{self.domain}_FULL_RECON_REPORT.txt'
        
        with open(report_file, 'w', encoding='utf-8') as f:
            # Header
            f.write("="*100 + "\n")
            f.write(f"  DEEP RECONNAISSANCE REPORT - {self.target}\n")
            f.write(f"  Scan Date: {self.results['scan_time']}\n")
            f.write("="*100 + "\n\n")
            
            # 1. TECHNOLOGIES
            f.write("\n" + "="*100 + "\n")
            f.write("  [1/10] TECHNOLOGY STACK\n")
            f.write("="*100 + "\n")
            techs = findings.get('technologies', {})
            f.write(f"  Server: {techs.get('server', 'Unknown')}\n")
            f.write(f"  Powered By: {techs.get('x_powered_by', 'Not disclosed')}\n")
            f.write(f"  CMS: {techs.get('cms', 'Not detected')}\n")
            f.write(f"  Frontend Framework: {techs.get('frontend', 'Not detected')}\n")
            
            # 2. WAF
            f.write("\n" + "="*100 + "\n")
            f.write("  [2/10] WEB APPLICATION FIREWALL (WAF)\n")
            f.write("="*100 + "\n")
            waf = findings.get('waf')
            f.write(f"  WAF Detected: {waf if waf else 'None'}\n")
            
            # 3. SECURITY HEADERS
            f.write("\n" + "="*100 + "\n")
            f.write("  [3/10] SECURITY HEADERS\n")
            f.write("="*100 + "\n")
            headers = findings.get('security_headers', {})
            for header, value in headers.items():
                status = "✓ PRESENT" if value else "✗ MISSING"
                f.write(f"  {header}: {status}\n")
                if value:
                    f.write(f"    → {value}\n")
            
            # 4. SSL/TLS
            f.write("\n" + "="*100 + "\n")
            f.write("  [4/10] SSL/TLS CONFIGURATION\n")
            f.write("="*100 + "\n")
            ssl = findings.get('ssl', 'Not analyzed')
            f.write(f"  Status: {ssl}\n")
            
            # 5. SUBDOMAINS
            f.write("\n" + "="*100 + "\n")
            f.write("  [5/10] SUBDOMAINS DISCOVERED\n")
            f.write("="*100 + "\n")
            subdomains = findings.get('subdomains', {})
            f.write(f"  Total Found: {subdomains.get('total', 0)}\n")
            f.write(f"  Live Hosts: {subdomains.get('alive', 0)}\n")
            f.write(f"  🔒 403 Forbidden: {subdomains.get('forbidden_count', 0)}\n\n")
            
            # Write 403 FORBIDDEN section first (HIGH VALUE)
            forbidden_list = subdomains.get('forbidden_list', [])
            if forbidden_list:
                f.write("  🎯 403 FORBIDDEN HOSTS (HIGH PRIORITY - BYPASS OPPORTUNITIES!):\n")
                f.write("  " + "="*95 + "\n")
                for i, host in enumerate(forbidden_list, 1):
                    f.write(f"    {i}. {host}\n")
                f.write("\n  💡 403s often indicate:\n")
                f.write("     - Admin panels\n")
                f.write("     - Internal tools\n")
                f.write("     - Staging/dev environments\n")
                f.write("     - API endpoints with weak auth\n")
                f.write("     - Misconfigured access controls\n")
                f.write("\n  🔓 Bypass techniques to try:\n")
                f.write("     - Path manipulation (/../, /./)\n")
                f.write("     - HTTP method tampering (POST, PUT, PATCH)\n")
                f.write("     - Header injection (X-Original-URL, X-Rewrite-URL)\n")
                f.write("     - Case manipulation (/Admin vs /admin)\n")
                f.write("     - Trailing slash bypass (/admin/ vs /admin)\n")
                f.write("     - URL encoding (%2e%2e%2f)\n\n")
            
            # Write all subdomains
            sub_list = subdomains.get('list', [])
            if sub_list:
                f.write("  All Subdomains Found:\n")
                for i, sub in enumerate(sub_list, 1):
                    f.write(f"    {i}. {sub}\n")
                
                # Write live subdomains with details
                live_list = subdomains.get('live_list', [])
                live_details = subdomains.get('live_details', [])
                
                if live_list:
                    f.write(f"\n  ✓ Live Subdomains ({len(live_list)}):\n")
                    if live_details:
                        # Use detailed info from httpx
                        for i, detail in enumerate(live_details, 1):
                            f.write(f"    {i}. {detail}\n")
                    else:
                        # Fallback to just URLs
                        for i, sub in enumerate(live_list, 1):
                            f.write(f"    {i}. {sub}\n")
            
            # 6. URLS
            f.write("\n" + "="*100 + "\n")
            f.write("  [6/10] URL DISCOVERY\n")
            f.write("="*100 + "\n")
            urls = findings.get('urls', {})
            f.write(f"  Total URLs Found: {urls.get('count', 0)}\n\n")
            
            # Write categorized URLs first
            categorized = urls.get('categorized', {})
            
            xss_urls = categorized.get('xss', [])
            if xss_urls:
                f.write(f"  🎯 XSS-PRONE URLS ({len(xss_urls)}):\n")
                f.write("  " + "="*95 + "\n")
                for url in xss_urls[:50]:  # First 50
                    f.write(f"  {url}\n")
                if len(xss_urls) > 50:
                    f.write(f"\n  ... and {len(xss_urls) - 50} more XSS-prone URLs\n")
                f.write("\n")
            
            sqli_urls = categorized.get('sqli', [])
            if sqli_urls:
                f.write(f"  🎯 SQLi-PRONE URLS ({len(sqli_urls)}):\n")
                f.write("  " + "="*95 + "\n")
                for url in sqli_urls[:50]:
                    f.write(f"  {url}\n")
                if len(sqli_urls) > 50:
                    f.write(f"\n  ... and {len(sqli_urls) - 50} more SQLi-prone URLs\n")
                f.write("\n")
            
            lfi_urls = categorized.get('lfi', [])
            if lfi_urls:
                f.write(f"  🎯 LFI-PRONE URLS ({len(lfi_urls)}):\n")
                f.write("  " + "="*95 + "\n")
                for url in lfi_urls[:50]:
                    f.write(f"  {url}\n")
                if len(lfi_urls) > 50:
                    f.write(f"\n  ... and {len(lfi_urls) - 50} more LFI-prone URLs\n")
                f.write("\n")
            
            upload_urls = categorized.get('upload', [])
            if upload_urls:
                f.write(f"  🎯 FILE UPLOAD URLS ({len(upload_urls)}):\n")
                f.write("  " + "="*95 + "\n")
                for url in upload_urls:
                    f.write(f"  {url}\n")
                f.write("\n")
            
            # Write all URLs (limited sample)
            url_list = urls.get('list', [])
            if url_list:
                display_count = min(100, len(url_list))
                f.write(f"  All URLs (showing first {display_count} of {len(url_list)}):\n")
                for i, url in enumerate(url_list[:display_count], 1):
                    f.write(f"    {i}. {url}\n")
                if len(url_list) > 100:
                    f.write(f"\n  ... and {len(url_list) - 100} more URLs\n")
            
            # 7. PARAMETERS
            f.write("\n" + "="*100 + "\n")
            f.write("  [7/10] PARAMETERS DISCOVERED\n")
            f.write("="*100 + "\n")
            params = findings.get('parameters', {})
            f.write(f"  Total Parameters: {params.get('count', 0)}\n\n")
            
            # Write categorized parameters
            categorized = params.get('categorized', {})
            
            xss_params = categorized.get('xss', [])
            if xss_params:
                f.write(f"  🎯 XSS-PRONE PARAMETERS ({len(xss_params)}):\n")
                f.write("  " + "="*95 + "\n")
                for param in xss_params:
                    f.write(f"  {param}\n")
                f.write("\n  💡 Test with: <script>alert(1)</script>, <img src=x onerror=alert(1)>\n\n")
            
            sqli_params = categorized.get('sqli', [])
            if sqli_params:
                f.write(f"  🎯 SQLi-PRONE PARAMETERS ({len(sqli_params)}):\n")
                f.write("  " + "="*95 + "\n")
                for param in sqli_params:
                    f.write(f"  {param}\n")
                f.write("\n  💡 Test with: ' OR '1'='1, 1' UNION SELECT NULL--\n\n")
            
            lfi_params = categorized.get('lfi', [])
            if lfi_params:
                f.write(f"  🎯 LFI-PRONE PARAMETERS ({len(lfi_params)}):\n")
                f.write("  " + "="*95 + "\n")
                for param in lfi_params:
                    f.write(f"  {param}\n")
                f.write("\n  💡 Test with: ../../../etc/passwd, ../../../../windows/win.ini\n\n")
            
            idor_params = categorized.get('idor', [])
            if idor_params:
                f.write(f"  🎯 IDOR-PRONE PARAMETERS ({len(idor_params)}):\n")
                f.write("  " + "="*95 + "\n")
                for param in idor_params:
                    f.write(f"  {param}\n")
                f.write("\n  💡 Test with: Change ID values, enumerate sequential IDs\n\n")
            
            ssrf_params = categorized.get('ssrf', [])
            if ssrf_params:
                f.write(f"  🎯 SSRF-PRONE PARAMETERS ({len(ssrf_params)}):\n")
                f.write("  " + "="*95 + "\n")
                for param in ssrf_params:
                    f.write(f"  {param}\n")
                f.write("\n  💡 Test with: http://169.254.169.254/latest/meta-data/, http://localhost:80\n\n")
            
            redirect_params = categorized.get('open_redirect', [])
            if redirect_params:
                f.write(f"  🎯 OPEN REDIRECT-PRONE PARAMETERS ({len(redirect_params)}):\n")
                f.write("  " + "="*95 + "\n")
                for param in redirect_params:
                    f.write(f"  {param}\n")
                f.write("\n  💡 Test with: //evil.com, https://evil.com, javascript:alert(1)\n\n")
            
            # Write all parameters
            param_list = params.get('list', [])
            if param_list:
                f.write("  All Parameters:\n")
                for i, param in enumerate(param_list, 1):
                    f.write(f"    {i}. {param}\n")
            
            # 8. API ENDPOINTS
            f.write("\n" + "="*100 + "\n")
            f.write("  [8/10] API ENDPOINTS\n")
            f.write("="*100 + "\n")
            apis = findings.get('api_endpoints', {})
            f.write(f"  Total API Endpoints: {apis.get('count', 0)}\n\n")
            
            # Write all APIs
            api_list = apis.get('list', [])
            if api_list:
                f.write("  API Endpoints Found:\n")
                for i, api in enumerate(api_list, 1):
                    f.write(f"    {i}. {api}\n")
            
            # 9. THIRD-PARTY RESOURCES
            f.write("\n" + "="*100 + "\n")
            f.write("  [9/10] THIRD-PARTY RESOURCES & CDNs\n")
            f.write("="*100 + "\n")
            third_party = findings.get('third_party', {})
            f.write(f"  Total External Domains: {third_party.get('total', 0)}\n\n")
            
            cdns = third_party.get('cdns', [])
            if cdns:
                f.write("  CDNs:\n")
                for i, cdn in enumerate(cdns, 1):
                    f.write(f"    {i}. {cdn}\n")
                f.write("\n")
            
            analytics = third_party.get('analytics', [])
            if analytics:
                f.write("  Analytics/Tracking Services:\n")
                for i, tracker in enumerate(analytics, 1):
                    f.write(f"    {i}. {tracker}\n")
                f.write("\n")
            
            all_external = third_party.get('all', [])
            if all_external:
                f.write("  All External Domains:\n")
                for i, domain in enumerate(all_external, 1):
                    f.write(f"    {i}. {domain}\n")
            
            # 10. VULNERABILITIES
            f.write("\n" + "="*100 + "\n")
            f.write("  [10/10] VULNERABILITIES DETECTED (Nuclei)\n")
            f.write("="*100 + "\n")
            vulns = findings.get('vulnerabilities', {})
            vuln_count = vulns.get('count', 0)
            targets_scanned = vulns.get('targets_scanned', 1)
            f.write(f"  Targets Scanned: {targets_scanned} (main target + live subdomains)\n")
            f.write(f"  Total Issues Found: {vuln_count}\n\n")
            
            if vuln_count > 0:
                f.write("  ⚠️  VULNERABILITY FINDINGS:\n")
                vuln_list = vulns.get('list', [])
                for i, vuln in enumerate(vuln_list, 1):
                    f.write(f"    {i}. {vuln}\n")
            else:
                f.write("  ✓ No critical vulnerabilities detected by automated scan\n")
                f.write("  💡 Manual testing still recommended\n")
            
            # SUMMARY
            f.write("\n" + "="*100 + "\n")
            f.write("  EXECUTIVE SUMMARY\n")
            f.write("="*100 + "\n")
            f.write(f"  Target: {self.target}\n")
            f.write(f"  Domain: {self.domain}\n")
            f.write(f"  Scan Date: {self.results['scan_time']}\n\n")
            f.write(f"  Attack Surface:\n")
            f.write(f"    • Subdomains: {findings.get('subdomains', {}).get('total', 0)}\n")
            f.write(f"    • Live Hosts: {findings.get('subdomains', {}).get('alive', 0)}\n")
            f.write(f"    • 🔒 403 Forbidden Hosts: {findings.get('subdomains', {}).get('forbidden_count', 0)}\n")
            f.write(f"    • URLs: {findings.get('urls', {}).get('count', 0)}\n")
            f.write(f"    • Parameters: {findings.get('parameters', {}).get('count', 0)}\n")
            f.write(f"    • API Endpoints: {findings.get('api_endpoints', {}).get('count', 0)}\n\n")
            f.write(f"  Security Posture:\n")
            f.write(f"    • WAF: {findings.get('waf', 'None')}\n")
            f.write(f"    • Automated Vulns Found: {vuln_count}\n")
            f.write(f"    • Interesting Parameters: {len(findings.get('parameters', {}).get('interesting', []))}\n\n")
            f.write(f"  Technology Stack:\n")
            f.write(f"    • Server: {techs.get('server', 'Unknown')}\n")
            f.write(f"    • CMS: {techs.get('cms', 'Not detected')}\n")
            f.write(f"    • Frontend: {techs.get('frontend', 'Not detected')}\n")
            f.write("\n" + "="*100 + "\n")
            f.write("  END OF REPORT\n")
            f.write("="*100 + "\n")
        
        print(f"\n✅ MASTER REPORT SAVED!")
        print(f"📄 File: {report_file}")
        print(f"📊 All findings in ONE document - NO separate files!")
        print(f"\n💡 Read it with: cat {report_file}")
        print(f"💡 Or open in editor: nano {report_file}\n")
    
    def run_full_scan(self):
        """Execute all recon modules"""
        self.banner()
        
        try:
            self.tech_detection()
            self.waf_detection()
            self.security_headers()
            self.ssl_analysis()
            self.url_discovery()
            self.api_discovery()
            self.parameter_discovery()
            self.third_party_resources()
            self.subdomain_enumeration()
            self.vulnerability_scan()
            
            self.generate_report()
            
        except KeyboardInterrupt:
            print("\n\n⚠️  Scan interrupted by user")
            self.generate_report()
        except Exception as e:
            print(f"\n❌ Error during scan: {e}")

def main():
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python3 deep_recon.py <target_url>")
        print("Example: python3 deep_recon.py https://example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Validate URL
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    scanner = DeepReconScanner(target)
    scanner.run_full_scan()

if __name__ == '__main__':
    main()
