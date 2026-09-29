```markdown
# 🔍 Clicker — Black-box Recon & Bug Bounty Pipeline

**Version v2.0** | Python 3.8+ | Platform Linux | License MIT

Automated reconnaissance pipeline for security researchers & bug hunters
Follow updates: [@403_linux](https://instagram.com/403_linux)

---

## 📋 Table of Contents

- [✨ Features](#-features)
- [🆕 What's New in v2.0](#-whats-new-in-v20)
- [🔧 Requirements](#-requirements)
- [📦 Installation](#-installation)
- [🚀 Quick Start](#-quick-start)
- [⚙️ Options & Arguments](#️-options--arguments)
- [🛡️ Proxy Support](#️-proxy-support)
- [🧠 Smart Features](#-smart-features)
- [🎯 IDOR Testing Module](#-idor-testing-module)
- [📊 Output Structure](#-output-structure)
- [📁 Project Structure](#-project-structure)
- [🛠️ API Keys Setup](#️-api-keys-setup)
- [🔄 Phases Overview](#-phases-overview)
- [📝 Examples](#-examples)
- [⚠️ Disclaimer](#️-disclaimer)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## ✨ Features

### 🔍 Reconnaissance
- **Passive Subdomain Enumeration**: 12+ sources (Subfinder, Sublist3r, Chaos, Assetfinder, crt.sh, WaybackURLs, GAU, VirusTotal, waymore+unfurl)
- **Active Subdomain Discovery**: Bruteforce with puredns, permutation scanning with altdns+shuffledns, DNS enumeration with dnsrecon
- **DNS Resolution**: Pre-filter with dnsx before HTTP probing (5x speed boost)
- **Response Filtering**: Extended status codes (200,201,202,204,301,302,303,307,308) + custom ports (80,443,8000,8080,8443,8888)
- **Technology Detection**: Stack fingerprinting, IP extraction, and CDN detection
- **DNS Enrichment**: SPF/DMARC records, A/AAAA/CNAME analysis

### 🎯 Attack Surface Mapping
- **Port Scanning**: Comprehensive port discovery with naabu + service detection with nmap -sC
- **Screenshot Capture**: Visual reconnaissance with aquatone or gowitness
- **Content Discovery**: URL enumeration via waybackurls, gau, katana, waymore with `--providers` + **uro normalization**
- **Sensitive Files Discovery**: Passive filtering + active dirsearch + ffuf fuzzing with 45+ extensions
- **JS Recon**: JavaScript file extraction + secret/API key detection with trufflehog, mantra, and regex patterns

### 🛡️ Security Checks
- **LeakIX Integration**: Exposure check for misconfigured services & leaked data
- **Subdomain Takeover**: Detection with subzy, subjack, and nuclei takeover templates
- **WAF Detection**: 3-layer detection (httpx + wafw00f + header analysis)
- **Vulnerability Scanning**: Nuclei + CORS + exposed files checks
- **Shodan Enrichment**: IP intelligence lookup (requires API key)
- **IDOR Testing**: Full module with auto-login, session extraction, and A/B/anon comparison

### 📈 Reporting & UX
- **Multi-format Reports**: JSON, TXT, HTML
- **Scored Findings**: Automatic severity scoring (critical/high/medium)
- **Verbose Mode**: Real-time terminal output with color-coded results
- **Smart Cleanup**: Auto-remove empty files & temporary artifacts
- **Progress Tracking**: Visual progress bars for each phase

### 🔄 Reliability
- **Checkpoint System**: `--resume` flag to continue interrupted scans
- **Auto-Fallback Wordlists**: Automatically downloads resolvers.txt and wordlists if missing
- **Quick Probe**: Fast target liveness check (skip dead targets with `--force` to override)
- **Scope Management**: `--scope-file` for in/out-of-scope rules
- **Signal Handling**: Ctrl+C skips current phase only (doesn't kill scan)

---

## 🆕 What's New in v2.0

### 🎉 Major Additions

| Feature | Description |
|---|---|
| **IDOR Testing Module** | Full standalone IDOR testing with auto-login, session handling, and A vs B vs anon comparison |
| **Quick Probe (Phase 0)** | Fast pre-scan check to skip dead targets |
| **DNS Resolution (Phase 4)** | Pre-filter subdomains with dnsx before httpx (5x faster) |
| **Sensitive Files (Phase 12)** | Passive filtering + active dirsearch + ffuf with 45+ extensions |
| **Scope Management** | `--scope-file` supports include/exclude patterns |
| **Extended HTTP Probes** | Ports: 80,443,8000,8080,8443,8888 / Status codes: 200-308 |
| **uro URL Normalization** | Reduce URL count by 30-70% |

### 🔧 Improvements

- **subfinder -recursive** — discovers deeper subdomains
- **waymore --providers** — adds wayback, commoncrawl, otx, urlscan sources
- **waymore + unfurl domains** — extracts subdomains from archived URLs
- **gau --blacklist** — faster filtering
- **katana JS extraction** — merges JS files from crawler
- **jsluice + xnLinkFinder** — deep JS endpoint mining (in IDOR module)
- **Nuclei optimization** — 3x faster with better rate limiting

### 🐛 Bug Fixes

- **Command injection** — full validation + shlex.quote() everywhere
- **Session resume** — proper checkpoint with domain tracking
- **Signal handler** — Ctrl+C now skips only current phase
- **"Retrying without proxy" false positive** — fixed
- **KeyError on skipped phases** — safe() helper added
- **Missing r"..." in shell commands** — fixed

---

## 🔧 Requirements

### 🐍 Python Dependencies

```bash
python3 >= 3.8
```

### 🛠️ External Tools

#### Reconnaissance Tools

| Tool | Purpose | Installation |
|---|---|---|
| **subfinder** | Passive subdomain enumeration | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **sublist3r** | Subdomain enumeration | `pip install sublist3r` |
| **chaos** | ProjectDiscovery subdomain DB | `go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest` |
| **assetfinder** | Subdomain discovery | `go install github.com/tomnomnom/assetfinder@latest` |
| **github-subdomains** | GitHub subdomain search | `go install github.com/gwen001/github-subdomains@latest` |
| **findomain** | Fast subdomain finder | Download releases |
| **puredns** | Accurate subdomain bruteforce | `go install github.com/d3mondev/puredns/v2@latest` |
| **altdns** | Subdomain permutation generator | `pip install py-altdns` |
| **shuffledns** | DNS bruteforce wrapper | `go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest` |
| **dnsrecon** | DNS enumeration suite | `pip install dnsrecon` |
| **dnsx** | DNS resolution & probing | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| **cdncheck** | CDN/WAF detection | `go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest` |

#### HTTP & Content Discovery

| Tool | Purpose | Installation |
|---|---|---|
| **httpx** | HTTP probing & tech detection | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **waybackurls** | Archive URL extraction | `go install github.com/tomnomnom/waybackurls@latest` |
| **gau** | GetAllURLs from archives | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| **waymore** | Advanced URL mining | `pip install waymore` |
| **katana** | Advanced crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| **uro** | URL deduplication | `pip install uro` |
| **unfurl** | URL component extraction | `go install github.com/tomnomnom/unfurl@latest` |
| **ffuf** | Web fuzzing toolkit | `go install github.com/ffuf/ffuf/v2/cmd/ffuf@latest` |
| **dirsearch** | Directory brute-forcing | `pip install dirsearch` |

#### Vulnerability Scanning

| Tool | Purpose | Installation |
|---|---|---|
| **naabu** | Fast port scanner | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| **nmap** | Service/version detection | `sudo apt install nmap` |
| **nuclei** | Vulnerability scanner | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| **subzy** | Subdomain takeover | `go install github.com/PentestPad/subzy@latest` |
| **subjack** | Subdomain takeover | `go install github.com/haccer/subjack@latest` |
| **wafw00f** | WAF detection | `pip install wafw00f` |
| **trufflehog** | Secret scanner | `go install github.com/trufflesecurity/trufflehog/v3@latest` |
| **mantra** | JS secret scanner | `go install github.com/brosck/mantra@latest` |
| **gitleaks** | Git secret scanner | `go install github.com/gitleaks/gitleaks/v8@latest` |

#### Screenshots

| Tool | Purpose | Installation |
|---|---|---|
| **aquatone** | Screenshot capture | `go install github.com/michenriksen/aquatone@latest` |
| **gowitness** | Screenshot capture | `go install github.com/sensepost/gowitness@latest` |

#### Utilities

| Tool | Purpose | Installation |
|---|---|---|
| **curl** | HTTP requests | `sudo apt install curl` |
| **jq** | JSON parsing | `sudo apt install jq` |
| **dig** | DNS queries | `sudo apt install dnsutils` |
| **proxychains4** | TCP proxy routing | `sudo apt install proxychains4` |

#### IDOR Module (Optional)

| Tool | Purpose | Installation |
|---|---|---|
| **jsluice** | JS URL/secret extraction | `go install github.com/BishopFox/jsluice/cmd/jsluice@latest` |
| **xnLinkFinder** | JS endpoint mining | `pip install xnLinkFinder` |

---

## 📦 Installation

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/darkzone-964/clicker.git
cd clicker
```

### 2️⃣ Install External Tools

```bash
# Quick install for Kali/Debian
sudo apt update && sudo apt install -y nmap curl jq dnsutils proxychains4

# Install Go tools (requires Go >= 1.21)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/trufflesecurity/trufflehog/v3@latest
# ... install other tools as needed

# Python tools
pip install sublist3r waymore uro dirsearch wafw00f xnLinkFinder
```

### 3️⃣ Make Executable

```bash
chmod +x clicker.py
```

---

## 🚀 Quick Start

### Basic Scan

```bash
python3 clicker.py -t example.com -v
```

### Full Bug Bounty Scan

```bash
python3 clicker.py -t example.com \
  --hybrid-proxy \
  --report-format both \
  --scope-file scope.txt \
  -v
```

### Skip Heavy Phases

```bash
python3 clicker.py -t example.com \
  --skip-screenshots \
  --skip-js \
  --skip-fuzz \
  --skip-active-subs \
  -v
```

### Scan Local Target (e.g., crAPI)

```bash
python3 clicker.py -t 127.0.0.1.nip.io:8888 \
  --skip-js \
  --skip-screenshots \
  -v
```

### Resume Interrupted Scan

```bash
python3 clicker.py -t example.com --resume -v
```

---

## ⚙️ Options & Arguments

| Argument | Short | Description | Default |
|---|---|---|---|
| `--target` | `-t` | Single target domain | Required |
| `--targets-file` | | File with one domain per line | Required |
| `--scope-file` | | Scope file (include/exclude patterns) | None |
| `--workspace` | | Output directory | `clicker_output` |
| `--api-file` | | API keys file | `clicker_api.env` |
| `--report-format` | | Report format: txt, html, both | both |
| `--skip-screenshots` | | Skip screenshot phase | False |
| `--skip-js` | | Skip JS recon phase | False |
| `--skip-active-subs` | | Skip active subdomain enum | False |
| `--skip-vuln` | | Skip vulnerability scanning | False |
| `--skip-fuzz` | | Skip dirsearch/ffuf | False |
| `--skip-idor` | | Skip IDOR testing | False |
| `--resume` | | Resume from checkpoint | False |
| `--force` | | Force scan even if Quick Probe says dead | False |
| `--wordlist` | | Wordlist for active bruteforce | SecLists default |
| `--resolvers` | | Resolvers file | SecLists default |
| `--keep-sources` | | Keep intermediate files | False |
| `--verbose` | `-v` | Detailed output | False |
| `--proxy` | | Single proxy | None |
| `--proxy-list` | | Path to proxy list | None |
| `--auto-proxy` | | Auto-fetch proxies | False |
| `--rotate-proxy` | | Rotate per target | False |
| `--proxychains` | | Route all via proxychains4 | False |
| `--hybrid-proxy` | | Smart proxy (recommended) | False |

---

## 🛡️ Proxy Support

### Modes

| Mode | Command | Behavior |
|---|---|---|
| **Direct** | (none) | All tools connect directly |
| **Manual** | `--proxy IP:PORT` | HTTP tools use proxy |
| **Auto-Fetch** | `--auto-proxy` | Fetch from public APIs |
| **Rotate** | `--rotate-proxy` | Change proxy per target |
| **Proxychains** | `--proxychains` | All tools (incl. nmap/naabu) |
| **Hybrid ⭐** | `--hybrid-proxy` | Passive direct, Active via proxy |

### Hybrid Mode Logic

```
Passive Tools (subfinder, gau, etc.)  → DIRECT (fast)
Active Tools  (httpx, nuclei, etc.)   → PROXY (anonymous)
Network Tools (nmap, naabu, dnsx)     → DIRECT (env cleanup)
If command fails → Auto-retry without proxy
```

### Proxy List Format

```
185.162.128.45:8080
user:pass@45.12.34.56:9090
socks5://127.0.0.1:1080
```

---

## 🧠 Smart Features

### 🔹 Early WAF Detection (Phase 2)

Runs immediately after passive enumeration, optimizes all subsequent phases.

| WAF Type | httpx Options | naabu Rate |
|---|---|---|
| Cloudflare | `-timeout 10 -retries 1` | 100 |
| Akamai | `-timeout 15 -retries 2` | 80 |
| Imperva | `-timeout 20 -retries 2` | 50 |
| Default | `-timeout 10 -retries 1` | 200 |

### 🔹 Three-Layer WAF Detection

```
Layer 1: httpx tech detection
   ↓
Layer 2: wafw00f (batched)
   ↓
Layer 3: Manual header analysis
```

### 🔹 Scope Management

Create `scope.txt`:

```
# Include patterns
*.example.com
example.com
api.example.com

# Exclude patterns (prefix with !)
!blog.example.com
!*.cdn.example.com
```

Run:

```bash
python3 clicker.py --targets-file targets.txt --scope-file scope.txt
```

### 🔹 Smart Resume

```json
{
  "domain": "example.com",
  "completed_phases": ["quick", "passive", "waf", "active"],
  "timestamp": "2026-01-15T10:30:00",
  "extra": {"waf_type": "cloudflare"}
}
```

### 🔹 Ctrl+C Handling

Press Ctrl+C during any phase:
- ✅ Skips current phase only
- ✅ Continues to next phase
- ✅ Preserves all completed results

### 🔹 Quick Probe

Fast target check before full scan:
- DNS resolution
- HTTPS/HTTP probe
- WAF hint from headers
- Decision: skip if dead (override with `--force`)

---

## 🎯 IDOR Testing Module

### Overview

Standalone IDOR testing module (`idor_module.py`) with:
- **Discovery**: Extracts candidates from URLs, JS files, API docs, GraphQL
- **Unauthenticated Scan**: Tests without login first
- **Auto-Login**: Tries common login patterns
- **Authenticated Testing**: A vs B vs anon comparison

### Workflow

```
Phase 16: IDOR Discovery (passive)
    ├─ Level 1: Extract from URLs
    ├─ Level 2: JS mining (jsluice)
    ├─ Level 3: API docs (Swagger/OpenAPI)
    └─ Level 4: GraphQL endpoints
        ↓
Phase 17: Unauthenticated Scan
    ├─ Test without any auth
    ├─ Detect missing-auth
    └─ Method tampering
        ↓
Prompt: "Test with authentication? [y/N]"
        ↓
Phase 18: Auto-Login (A + B)
        ↓
Phase 19: Authenticated Testing
    └─ A vs B vs anon comparison
```

### Interactive Flow

When IDOR phase runs:

```
════════════════════════════════════════════
  IDOR Discovery Complete
════════════════════════════════════════════
  Candidates : 47
  UUIDs      : 8
  Parameters : 23
  API docs   : 2
  GraphQL    : 0

[?] Continue with AUTHENTICATED testing?
Requires TWO accounts you own on the target.

  Test with authentication? [y/N]: y

[*] Account A credentials
  Email: attacker@test.com
  Password: ****

[*] Account B credentials
  Email: victim@test.com
  Password: ****

[+] Both sessions established
🔥 CONFIRMED IDOR: http://target.com/api/v1/users/1002
```

### Detection Rules

| A | B | anon | Verdict |
|---|---|---|---|
| 200 | 200 | 401/403 | ✅ CONFIRMED (cross-account) |
| 200 | 403 | 401/403 | ⚠️ SUSPICIOUS (verify ownership) |
| 200 | 200 | 200 | ⚪ Public resource (not IDOR) |
| 401/403 | 401/403 | 401/403 | ✅ Protected |

### Playbook Generation

Always generates `PLAYBOOK.md` with:
- Bypass checklist (25+ techniques)
- All candidates sorted by likelihood
- Confirmed findings
- Manual test steps

---

## 📊 Output Structure

```
clicker_output/
├── example.com/
│   ├── quick/
│   │   └── probe.txt                    # Quick probe results
│   ├── passive/
│   │   ├── allsubs.txt                  # All subdomains
│   │   ├── allsubs_final.txt            # Merged passive+active
│   │   └── high_value_subs.txt          # Sensitive-prefix subdomains
│   ├── waf/
│   │   └── waf-detected.txt             # Detected WAF type
│   ├── dns/
│   │   ├── resolved.txt                 # dnsx resolution
│   │   ├── dns-resolved.txt             # A/AAAA/CNAME records
│   │   ├── spf.txt                      # SPF record
│   │   └── dmarc.txt                    # DMARC record
│   ├── active/
│   │   ├── alive.txt                    # Live hosts
│   │   ├── alive-final.txt              # Final live hosts
│   │   ├── success-response.txt         # 200/302 hosts
│   │   ├── 403subs.txt                  # 403 hosts
│   │   ├── 404subs.txt                  # 404 hosts
│   │   ├── ips.txt                      # Extracted IPs
│   │   ├── real-ips.txt                 # Non-CDN IPs
│   │   └── open-ports-full.txt          # Port scan results
│   ├── vulns/
│   │   ├── nuclei-results.txt           # Nuclei findings
│   │   ├── cors.txt                     # CORS issues
│   │   └── exposed-files.txt            # Exposed files
│   ├── leakix/
│   │   ├── leakix-ips.txt               # IP exposure
│   │   └── leakix-domains.txt           # Domain exposure
│   ├── urls/
│   │   ├── final-urls.txt               # All URLs
│   │   └── clean_urls.txt               # Filtered URLs
│   ├── sensitive/
│   │   ├── sensitive_files_passive.txt  # From URLs
│   │   ├── dirsearch.json               # Active scan
│   │   └── ffuf_*.json                  # Fuzzing results
│   ├── js/
│   │   ├── jsfiles.txt                  # JS files
│   │   └── secrets-found.txt            # Secrets
│   ├── idor/
│   │   ├── candidates.txt               # IDOR candidates
│   │   ├── uuids.txt                    # Extracted UUIDs
│   │   ├── params.txt                   # Parameter names
│   │   ├── unauth_confirmed.json        # Missing-auth findings
│   │   ├── auth_confirmed.json          # Cross-account findings
│   │   └── PLAYBOOK.md                  # Manual playbook
│   ├── takeover/
│   │   ├── subzy-results.txt
│   │   └── subjack-results.json
│   └── screenshots/
│       ├── aquatone/
│       └── gowitness/
├── report.json                          # Full JSON
├── report.txt                           # Text report
└── report.html                          # Interactive HTML
```

---

## 📁 Project Structure

```
clicker/
├── clicker.py              # Main executable
├── idor_module.py          # IDOR testing module (optional)
├── clicker_api.env         # API keys (auto-generated)
├── CHANGELOG.md            # Version history
└── README.md               # This file
```

---

## 🛠️ API Keys Setup

Optional API integrations for enhanced results:

| Key | Service | Purpose |
|---|---|---|
| `CHAOS_API_KEY` | Chaos | Subdomain database |
| `VT_API_KEY` | VirusTotal | Subdomain enum |
| `GITHUB_TOKEN` | GitHub | Subdomain search |
| `SHODAN_API` | Shodan | IP intelligence |
| `LEAKIX_API` | LeakIX | Exposure checks |

**Stored in `clicker_api.env`** with `chmod 600`. Never share this file.

---

## 🔄 Phases Overview

Clicker executes **17 sequential phases** per target:

| # | Phase | Description |
|---|---|---|
| 0 | Quick Probe | Fast liveness check |
| 1 | Passive Subdomain Enum | 12+ sources |
| 2 | WAF Detection | 3-layer detection |
| 3 | Active Subdomain Enum | puredns + altdns + dnsrecon |
| 4 | DNS Resolution | Pre-filter with dnsx |
| 5 | Response Filtering | Extended status codes |
| 6 | Technology Detection | httpx + IP extraction |
| 7 | Subdomain Takeover | subzy + subjack + nuclei |
| 8 | Vulnerability Scanning | nuclei + CORS + exposed |
| 9 | Port Scanning | naabu + nmap |
| 10 | LeakIX | Exposure check |
| 11 | Content Discovery | gau + katana + waymore + uro |
| 12 | Sensitive Files | dirsearch + ffuf |
| 13 | JS Recon | trufflehog + mantra |
| 14 | **IDOR Testing** | Discovery + Auth + A/B/anon |
| 15 | Screenshots | gowitness + aquatone |
| 16 | DNS Enrichment | SPF/DMARC check |

---

## 📝 Examples

### 1. Basic Scan

```bash
python3 clicker.py -t example.com -v
```

### 2. Bug Bounty with Scope

```bash
python3 clicker.py --targets-file targets.txt \
  --scope-file scope.txt \
  --hybrid-proxy --auto-proxy \
  --report-format both \
  -v
```

### 3. Fast Scan (Skip Heavy Phases)

```bash
python3 clicker.py -t example.com \
  --skip-screenshots \
  --skip-js \
  --skip-fuzz \
  --skip-active-subs \
  --report-format txt
```

### 4. IDOR Testing on Local Target

```bash
python3 clicker.py -t 127.0.0.1.nip.io:8888 \
  --skip-js --skip-screenshots -v
```

### 5. Resume Interrupted Scan

```bash
python3 clicker.py -t example.com --resume -v
```

### 6. Force Scan on Apparently Dead Target

```bash
python3 clicker.py -t example.com --force -v
```

### 7. View Reports

```bash
# View top findings
cat clicker_output/report.txt

# Open HTML report
firefox clicker_output/report.html

# View IDOR playbook
cat clicker_output/example.com/idor/PLAYBOOK.md
```

---

## ⚠️ Disclaimer

### 🔒 Educational & Authorized Use Only

Clicker is designed for **security researchers, penetration testers, and bug bounty hunters**.

- **Always** obtain explicit written permission before scanning
- **Never** scan targets outside your authorized scope
- **Unauthorized scanning** may violate laws (CFAA, GDPR, CMA, etc.)
- Authors assume **no liability** for misuse

### 🌐 Proxy & Rate Limiting

- Proxies don't guarantee anonymity
- Free proxies may log your traffic
- Respect target infrastructure — avoid DoS
- Some bug bounty programs **prohibit automated testing** — check rules first

### 🎯 IDOR Testing Notice

The IDOR module sends authenticated requests to compare account responses:
- **Only use on programs that explicitly allow automation**
- **Keep audit logs** for legal protection
- **Never** use on third-party accounts you don't own
- Rate limiting is enforced (2 req/s default)

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push: `git push origin feature/amazing-feature`
5. Open Pull Request

### 🐛 Reporting Issues

Use the GitHub Issues tab with:
- OS, Python version
- Command used
- Full error output

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` for details.

```
MIT License

Copyright (c) 2024-2026 Clicker Tool (@403_linux)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

**Made with ❤️ by [@403_linux](https://instagram.com/403_linux)**

⭐ **Star this repo if you find it useful!**
```
