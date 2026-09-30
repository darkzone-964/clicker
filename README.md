```markdown
![Version](https://img.shields.io/badge/Version-2.2.0-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.8+-yellow?style=for-the-badge&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge&logo=linux)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

```
  .__  .__        __
____ |  | |__| ____ |  | __ ___________
_/ ___\|  | |  |/ ___\|  |/ // __ \_  __ \
\  \___|  |_|  \  \___|    <\  ___/|  | \/
 \___  >____/__|\___  >__|_ \\___  >__|
     \/             \/     \/    \/
```

### Next-Gen Black-box Recon & Bug Bounty Pipeline

**Automated, Intelligent, and WAF-Aware Reconnaissance for Security Researchers.**

[**Get Started »**](#-quick-start) · [Follow @403_linux](https://instagram.com/403_linux)

---

## 📑 Table of Contents

- [🌟 Why Clicker?](#-why-clicker)
- [🧠 AI-Powered Orchestration](#-ai-powered-orchestration)
- [⚡ Key Features](#-key-features)
- [🚀 Quick Start](#-quick-start)
- [️ Advanced Usage](#️-advanced-usage)
- [📂 Output Structure](#-output-structure)
- [🔄 Reconnaissance Phases](#-reconnaissance-phases)
- [⚠️ Disclaimer](#️-disclaimer)

---

## 🌟 Why Clicker?

Traditional recon tools are either too noisy, too slow, or require manual tuning for every target. **Clicker v2.2** bridges this gap by combining **high-yield OSINT sources** with an **intelligent AI Orchestrator** that dynamically adapts to the target's environment (e.g., detecting WAFs and auto-adjusting rate limits), ensuring maximum coverage with minimal noise.

---

## 🧠 AI-Powered Orchestration

Clicker features a built-in `ai_orchestrator.py` that acts as a smart middleware between the pipeline and execution tools:

1. **Dynamic Command Review:** Before executing tools (like `puredns` or `httpx`), the AI reads the tool's actual `--help` output.
2. **Context-Aware Optimization:** It evaluates the default command against the target's context (e.g., Cloudflare detected). If needed, it injects safe optimizations (e.g., `--rate-limit 10`).
3. **Anti-Hallucination Protocol:** Strict validation ensures the AI *never* invents fake flags. 
4. **Zero-Downtime Fallback:** If the AI fails or returns an invalid command, the system instantly reverts to a verified, hard-coded safe command.

---

## ⚡ Key Features

| Category | Capabilities |
| :--- | :--- |
| **🔍 Passive Recon** | Streamlined, high-yield discovery using `subfinder`, `chaos`, and `waymore+unfurl`. |
| **🎯 Active Discovery** | Intelligent bruteforce (`puredns` + `massdns`), permutations (`altdns`), and AXFR checks (`dnsrecon`). |
| **️ WAF Awareness** | Auto-detects Cloudflare/Akamai and dynamically adjusts tool timeouts and rate limits to prevent IP bans. |
| **️ Vulnerability Checks** | Subdomain takeover (`subzy`, `nuclei`), sensitive file fuzzing (`ffuf`, `dirsearch`), and JS secret extraction (`trufflehog`). |
| **🔐 IDOR Module** | Dedicated, configurable phase for testing Insecure Direct Object References with session persistence. |
| **🌐 Smart Proxying** | Hybrid proxy mode: Routes HTTP tools through proxies while keeping DNS/Port scanners on direct connections for speed. |

---

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/darkzone-964/clicker.git
cd clicker

# Install system dependencies (Debian/Ubuntu/Kali)
sudo apt update && sudo apt install python3-pip massdns -y

# Install Python-based tools (recommended via pipx to avoid conflicts)
pipx install waymore

# Make the script executable
chmod +x clicker.py
```

### 2. API Setup

On the first run, Clicker will interactively prompt you to securely save your API keys (Chaos, VirusTotal, GitHub, etc.) into `clicker_api.env`.

### 3. Execute

```bash
# Basic verbose scan
python3 clicker.py -t example.com -v

# Scan multiple targets from a file
python3 clicker.py --targets-file targets.txt --verbose
```

---

## ⚙️ Advanced Usage

**🛡️ Stealth / Passive-Only Mode**  
*(Ideal for strict bug bounty programs that prohibit active scanning)*

```bash
python3 clicker.py -t example.com --skip-active-subs --skip-vuln --skip-fuzz
```

**🎯 IDOR Testing with Custom Authentication**  
*(Requires prior recon data or runs alongside)*

```bash
python3 clicker.py -t example.com --idor-only \
  --idor-login-url "https://example.com/api/login" \
  --idor-login-json '{"email":"%%EMAIL%%","password":"%%PASS%%"}'
```

**🌐 Hybrid Proxy Rotation**  
*(Fetches fresh proxies and rotates them, but keeps DNS tools direct)*

```bash
python3 clicker.py -t example.com --auto-proxy --rotate-proxy --hybrid-proxy
```

---

## 📂 Output Structure

Clicker organizes findings logically for easy triage and reporting:

```
clicker_output/
└── target.com/
    ├── passive/          # Raw & merged subdomain lists, high-value targets
    ├── waf/              # WAF detection results and headers
    ├── active_subs/      # puredns, altdns, and dnsrecon outputs
    ├── dns/              # Resolved IPs, SPF, and DMARC records
    ├── active/           # httpx alive hosts, 403/404 filters, tech fingerprints
    ├── vulns/            # Nuclei findings, CORS misconfigurations, exposed files
    ├── js/               # Discovered JS files and extracted secrets/keys
    ├── screenshots/      # Visual recon (Gowitness / Aquatone)
    └── report.json       # Comprehensive, machine-readable summary
```

---

##  Reconnaissance Phases

> *Clicker automatically skips phases based on program policies or target viability.*

1. **Quick Probe:** Validates DNS and basic HTTP connectivity.
2. **Passive Enumeration:** OSINT gathering (Subfinder, Chaos, Waymore).
3. **WAF Detection:** Identifies protective layers to tune subsequent phases.
4. **Active Enumeration:** Bruteforcing and permutation scanning.
5. **DNS Resolution:** Validates all discovered subdomains via `dnsx`.
6. **Response Filtering:** Probes alive hosts and categorizes by HTTP status.
7. **Tech Detection:** Fingerprints technologies and extracts backend IPs.
8. **Takeover Check:** Scans for vulnerable subdomain configurations.
9. **Vulnerability Scanning:** Targeted Nuclei templates and CORS checks.
10. **Content Discovery:** Crawls for URLs, JS files, and sensitive endpoints.
11. **IDOR Testing:** Authenticated logic testing (Optional).

---

## ⚠️ Disclaimer

This tool is designed for **authorized security testing, penetration testing, and bug bounty hunting only**. 

The developer assumes no liability for any misuse or damage caused by this program. **Always ensure you have explicit, written permission** before scanning any target or domain.

---

Built with ❤️ by [@403_linux](https://instagram.com/403_linux)
```

