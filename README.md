# clicker
🛠️ Clicker — Black-box Reconnaissance &amp; Vulnerability Assessment Pipeline

Clicker is a comprehensive automation tool for black-box penetration testing, designed to perform thorough reconnaissance and vulnerability assessment on target domains. The tool executes 11 sequential phases combining passive and active techniques to discover subdomains, open ports, technologies, and potential security vulnerabilities.

🎯 Key Features
🔍 Phase 1: Passive Subdomain Enumeration
Aggregates subdomains from multiple sources:
subfinder, sublist3r, chaos, assetfinder
crt.sh, certspotter, VirusTotal, waybackurls, gau
Auto-filters high-value subdomains (admin, api, login, dev, staging, etc.)
Merges and deduplicates results into allsubs.txt

🌐 Phase 2: Response Filtering
Probes discovered subdomains using httpx/httpx-toolkit
Categorizes responses: 200/302 (alive), 403 (forbidden), 404 (not found)
Extracts detailed host information (status code, title, tech stack, IP)
Outputs clean list to success-response.txt

🔧 Phase 3: Technology Detection & IP Extraction
Identifies web technologies, frameworks, and server software via httpx -td
Extracts unique IP addresses from responses
Filters final alive hosts for subsequent scanning

🔓 Phase 4: Port Scanning
Resolves subdomains to IPs using dnsx
Filters out CDN/WAF IPs using cdncheck
Performs comprehensive port scanning with naabu (100+ common ports)
Auto-formats JSON output to readable table: domain:port/protocol → service (version)
Runs nmap -sC -sV vulnerability scripts on open ports
Optional Shodan enrichment for discovered IPs

📸 Phase 5: Screenshots (Optional)
Captures visual snapshots of alive web hosts using:
aquatone → Generates aquatone.html report
gowitness → Creates SQLite database with screenshots

🕵️ Phase 6: Content Discovery
Harvests historical and live URLs from:
waybackurls, gau, katana, waymore
Merges, deduplicates, and outputs to final-urls.txt
Ready for fuzzing, parameter discovery, or manual review

🚨 Phase 7: LeakIX Exposure Check
Queries LeakIX API for exposed services and misconfigurations
Smart filtering: Only saves output file if real findings exist
Checks for exposed databases, open ports, and leaked credentials

🔑 Phase 8: JavaScript Recon & Secret Discovery
Extracts .js files from discovered URLs
Scans for hardcoded secrets using:
mantra — API keys, tokens, credentials
SecretFinder — Fallback pattern-based scanner
Filters noise and outputs potential secrets to secrets-found.txt

🎭 Phase 9: Subdomain Takeover Detection
Tests 404-responding subdomains for takeover vulnerabilities
Uses subzy, subjack, and nuclei takeover templates
Reports vulnerable subdomains pointing to unclaimed services

🛡️ Phase 10: WAF Detection
Detects Web Application Firewalls using wafw00f
Clean output format: URL | WAF Name (e.g., ModSecurity, Cloudflare)
Highlights protected vs. unprotected endpoints

💥 Phase 11: Nuclei Vulnerability Scan
Runs ProjectDiscovery's nuclei against alive hosts
Supports custom template paths (--nt /path/to/templates)
Auto-searches common template locations if not specified
Filters by severity: critical, high, medium, low
Outputs structured JSONL for further processing


⚙️ Command-Line Options

# Basic usage
python3 clicker.py -t example.com

# Multiple targets from file
python3 clicker.py --targets-file targets.txt

# Custom workspace directory
python3 clicker.py -t example.com --workspace ./my_scan

# Show summary after each phase
python3 clicker.py -t example.com --show-phase-results

# Show FULL output content in terminal (verbose mode)
python3 clicker.py -t example.com --verbose
# or short form:
python3 clicker.py -t example.com -v

# Use custom Nuclei templates
python3 clicker.py -t example.com --nt /opt/my-templates

# Export reports in multiple formats
python3 clicker.py -t example.com --report-format both --pdf

# Skip resource-intensive phases
python3 clicker.py -t example.com --skip-screenshots --skip-js

# Debug mode: keep all intermediate files
python3 clicker.py -t example.com --keep-sources

📦 Full Option Reference


-t, --target Single target domain
--targets-file File containing one domain per line
--workspace Output directory (default: clicker_output)
--api-file API keys configuration file (default: clicker_api.env)
--report-format Report format: txt, html, or both (default: both)
--pdf Generate PDF report (requires reportlab)
--skip-screenshots Skip screenshot phase
--skip-js Skip JavaScript secret scanning
--keep-sources Keep intermediate source files (debug mode)
--nt, --nuclei-templates Custom path for Nuclei templates
--show-phase-results Display summary statistics after each phase
--verbose, -v Display full file contents in terminal after each phase
