```markdown
# 🔍 Clicker — Black-box Recon & Bug Bounty Pipeline

![Version](https://img.shields.io/badge/version-2.3-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![Platform](https://img.shields.io/badge/platform-Linux-orange)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

```
  .__  .__        __                 
____ |  | |__| ____ |  | __ ___________ 
_/ ___\|  | |  |/ ___\|  |/ // __ \_  __ \
\  \___|  |_|  \  \___|    <\  ___/|  | \/
 \___  >____/__|\___  >__|_ \\___  >__|   
     \/             \/     \/    \/       
```

**Next-Gen Black-box Recon & Bug Bounty Pipeline**  
*Automated, Intelligent, and WAF-Aware Reconnaissance for Security Researchers.*

[Get Started »](#-quick-start) · [Follow @403_linux](https://instagram.com/403_linux)

---

## 📑 Table of Contents

- [🌟 Why Clicker?](#-why-clicker)
- [🧠 AI-Powered Orchestration](#-ai-powered-orchestration)
- [⚡ Key Features](#-key-features)
- [🚀 Quick Start](#-quick-start)
- [⚙️ Advanced Usage](#️-advanced-usage)
- [🎯 IDOR Testing Module](#-idor-testing-module)
- [📂 Output Structure](#-output-structure)
- [🔄 Reconnaissance Phases](#-reconnaissance-phases)
- [🛠️ Project Structure](#️-project-structure)
- [⚠️ Disclaimer](#️-disclaimer)

---

## 🌟 Why Clicker?

Traditional recon tools are either too noisy, too slow, or require manual tuning for every target. **Clicker v2.3** bridges this gap by combining high-yield OSINT sources with an intelligent AI Orchestrator that dynamically adapts to the target's environment (e.g., detecting WAFs and auto-adjusting rate limits), ensuring maximum coverage with minimal noise.

---

## 🧠 AI-Powered Orchestration

Clicker features a built-in AI layer that acts as smart middleware between the pipeline and execution tools:

### 🤖 AI Modules

| Module | Purpose |
|---|---|
| **`ai_orchestrator.py`** | Dynamic command review + WAF-aware optimization |
| **`ai_executor.py`** | Execute AI-proposed custom reconnaissance phases |
| **`ai_retry.py`** | Auto-fix failed commands (empty output / non-zero exit) |
| **`ai_thinker.py`** | Per-phase reflection & analysis |
| **`ai_verifier.py`** | Verify findings with 14 fast-checks + AI fallback |
| **`ai_bypass.py`** | AI-powered WAF bypass for blocked IDOR findings |
| **`ai_memory.py`** | Historical context from past runs |
| **`ai_loop.py`** | Multi-model orchestration loop |
| **`ai_planner.py`** | Strategic planning for complex targets |

### Core Principles

- **Dynamic Command Review** — Before executing tools (like `puredns` or `httpx`), AI reads the tool's actual `--help` output.
- **Context-Aware Optimization** — Evaluates the default command against target's context (e.g., Cloudflare detected → injects `--rate-limit 10`).
- **Anti-Hallucination Protocol** — Strict validation ensures AI never invents fake flags.
- **Speed Guard** — Rejects AI changes that slow down critical tools by >30%.
- **Zero-Downtime Fallback** — If AI fails or returns invalid command, system reverts to a verified safe command.
- **AI Memory** — Learns from past runs to prefer commands that succeeded before.

---

## ⚡ Key Features

| Category | Capabilities |
|---|---|
| 🔍 **Passive Recon** | Streamlined high-yield discovery via `subfinder`, `chaos`, `waymore+unfurl` |
| 🎯 **Active Discovery** | Intelligent bruteforce (`puredns` + `massdns`), permutations (`altdns`), AXFR (`dnsrecon`) |
| 🛡️ **WAF Awareness** | Auto-detects Cloudflare/Akamai/Imperva and dynamically adjusts timeouts & rate limits |
| 🕷️ **Playwright Capture** | Headless browser captures network traffic on SPA/Flutter/React targets |
| 🎯 **IDOR Module** | Complete 40+ technique suite: numeric fuzzing, UUID testing, JWT manipulation, HPP, race conditions, bypass checklist |
| 🚨 **Vulnerability Checks** | Subdomain takeover (`subzy`, `nuclei`), sensitive files (`ffuf`, `dirsearch`), JS secrets (`trufflehog`, `jsluice`) |
| 🌐 **Smart Proxying** | Hybrid mode: HTTP tools via proxy, DNS/port scanners direct for speed |
| 🤖 **AI Bypass Engine** | When target returns 401/403/405/500 → AI generates + tests 12 categories of bypasses |
| ✅ **AI Verifier** | 14 fast-check rules + AI fallback for uncertain findings → 0 uncertain |
| 📱 **Telegram Integration** | Interactive I/O + real-time findings alerts |

---

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/darkzone-964/clicker.git
cd clicker

# Install system dependencies (Debian/Ubuntu/Kali)
sudo apt update && sudo apt install -y python3-pip massdns nmap curl jq dnsutils

# Install Python-based tools (recommended via pipx)
pipx install waymore
pipx install uro

# Make the script executable
chmod +x clicker.py
```

### 2. API Setup

On the first run, Clicker will interactively prompt you to save API keys (Chaos, VirusTotal, GitHub, Shodan, LeakIX) into `clicker_api.env`. Keep this file private (`chmod 600`).

### 3. Execute

```bash
# Basic verbose scan
python3 clicker.py -t example.com -v

# Scan multiple targets
python3 clicker.py --targets-file targets.txt --verbose
```

---

## ⚙️ Advanced Usage

### 🛡️ Stealth / Passive-Only Mode
*Ideal for strict bug bounty programs that prohibit active scanning.*

```bash
python3 clicker.py -t example.com --skip-active-subs --skip-vuln
```

### 🎯 IDOR Testing with Custom Authentication
*Works with any backend — REST, GraphQL, Firebase, Cloud Functions.*

```bash
python3 clicker.py -t example.com --idor-only \
  --idor-login-url "https://example.com/api/login" \
  --idor-login-json '{"email":"%EMAIL%","password":"%PASS%"}' \
  --idor-a-email "attacker@example.com" \
  --idor-a-pass "PassA123!" \
  --idor-b-email "victim@example.com" \
  --idor-b-pass "PassB123!"
```

### 🕷️ Playwright Auto-Capture (SPA Targets)

```bash
python3 clicker.py -t example.com --idor-only \
  --idor-pw-visible \
  --idor-login-url "https://api.example.com/login" \
  --idor-login-json '{"data":{"email":"%EMAIL%","password":"%PASS%"}}' \
  --idor-a-email "a@example.com" --idor-a-pass "PassA" \
  --idor-b-email "b@example.com" --idor-b-pass "PassB"
```

**Auto-close behavior:** The browser closes automatically after:
- Minimum 15s wait
- Login URL + 3 API calls captured
- 8s of quiet (no new requests)
- OR 180s hard max

### 🌐 Hybrid Proxy Rotation

```bash
python3 clicker.py -t example.com --auto-proxy --rotate-proxy --hybrid-proxy
```

### 📋 Scope File

```bash
python3 clicker.py --targets-file targets.txt --scope-file scope.txt
```

`scope.txt` format:
```
# Include
*.example.com
example.com
api.example.com

# Exclude (prefix with !)
!blog.example.com
!*.cdn.example.com
```

---

## 🎯 IDOR Testing Module

The IDOR module implements the full **OWASP IDOR testing methodology** with 40+ automated checks across 5 phases.

### 📋 Discovery Levels

| Level | Technique | Tools |
|---|---|---|
| **1** | URL-based candidates | `grep`, custom regex |
| **2** | JS mining | `jsluice`, `xnLinkFinder` |
| **3** | API docs | Swagger/OpenAPI parser |
| **4** | GraphQL discovery | `graphw00f`, custom |
| **5** | Extended collection | gf patterns, arjun, paramspider |

### 🧪 Testing Suite (B1-B22)

| Group | Tests |
|---|---|
| **Basic (B1-B10)** | HPP, Object Ref, Numeric Fuzz, State-changing, Vertical/Horizontal PrivEsc, Mass Assignment, Method Tamper, Pagination, Predictable IDs, Auth Validation, JWT, Time Window, File Ops, Search IDOR, Path/Body Conflict, Cross-Location, Error-Based |
| **Advanced (B11-B19)** | Config IDOR, Lifecycle Mismatch, GraphQL Nested, Auth Validation Logic, Error-Based Disclosure, Clairvoyance, wpscan, Race Conditions, HPP URL+Body |
| **New in v2.3 (B20-B22)** | **B20** Rate Limiting Check, **B21** Intermittent Behavior, **B22** Rule-Based Bypass Checklist |

### 🚨 AI Bypass Engine (`ai_bypass.py`)

When a finding returns **401/403/405/429/500** → AI generates 12-15 bypass attempts across 12 categories:

```
url_encoding · case_manipulation · path_confusion
header_injection · param_pollution · content_type
http_method · unicode_tricks · null_byte
chunked_encoding · http2_tricks · wrapper
```

All bypasses are validated, then tested **in parallel** (10 workers). Successful bypasses become new findings.

### ✅ AI Verifier (`ai_verifier.py`)

Every finding goes through:
1. **Fast-check rules** (14 types) — instant verdict
2. **AI fallback** — if fast-check returns "uncertain"

**Result:** 0 uncertain findings, 0 false positives passed through.

---

## 📂 Output Structure

```
clicker_output/
└── target.com/
    ├── quick/              # Quick probe results
    ├── passive/            # Subdomain lists, high-value targets
    ├── waf/                # WAF detection
    ├── active_subs/        # puredns, altdns, dnsrecon
    ├── dns/                # DNS records, SPF, DMARC
    ├── active/             # httpx alive, 403/404, tech, IPs, ports
    ├── vulns/              # Nuclei, CORS, exposed files
    ├── js/                 # JS files + secrets
    ├── urls/               # All URLs from gau, katana, waymore
    ├── sensitive/          # Sensitive files discovery
    ├── screenshots/        # Visual recon (Gowitness/Aquatone)
    ├── idor/               # ⭐ IDOR findings
    │   ├── candidates.txt          # All IDOR candidates
    │   ├── auth_confirmed.json     # Confirmed IDOR findings
    │   ├── unauth_confirmed.json   # Unauth findings
    │   ├── advanced2_confirmed.json
    │   ├── BYPASS_CHECKLIST.md     # Manual bypass checklist
    │   ├── PLAYBOOK.md             # Full testing playbook
    │   ├── ai_bypasses.json        # AI-generated bypasses
    │   ├── AI_BYPASSES.md
    │   └── _js_cache/              # Cached JS files
    ├── ai_thoughts/        # AI analysis per phase
    └── report.json         # ⭐ Complete machine-readable report
```

---

## 🔄 Reconnaissance Phases

Clicker executes phases sequentially per target, skipping based on policy or viability.

| # | Phase | Description |
|---|---|---|
| 0 | **Quick Probe** | DNS + basic HTTP connectivity check |
| 1 | **Passive Enumeration** | OSINT (Subfinder, Chaos, Waymore, crt.sh) |
| 2 | **WAF Detection** | 3-layer detection (httpx + wafw00f + headers) |
| 3 | **Active Enumeration** | puredns + altdns + dnsrecon |
| 4 | **DNS Resolution** | dnsx validation of all subdomains |
| 5 | **Response Filtering** | httpx alive hosts, categorized by status |
| 6 | **Technology Detection** | Fingerprint + extract backend IPs |
| 7 | **Takeover Check** | subzy + subjack + nuclei takeover |
| 8 | **Vulnerability Scan** | Nuclei + CORS + exposed files |
| 9 | **Port Scanning** | naabu + nmap -sC |
| 10 | **LeakIX** | Exposure check (requires API key) |
| 11 | **Content Discovery** | gau + katana + waymore + uro |
| 12 | **Sensitive Files** | dirsearch + ffuf |
| 13 | **JS Recon** | trufflehog + mantra + jsluice |
| 14 | **IDOR Testing** | 40+ techniques (see above) |
| 15 | **Screenshots** | gowitness / aquatone |

---

## 🛠️ Project Structure

```
clicker/
├── clicker.py                       # Main pipeline
├── ai_orchestrator.py               # AI command optimization
├── ai_executor.py                   # Custom phase execution
├── ai_retry.py                      # Smart retry for failed commands
├── ai_thinker.py                    # Per-phase reflection
├── ai_verifier.py                   # Finding verification (fast-check + AI)
├── ai_bypass.py                     # ⭐ AI-powered bypass engine
├── ai_memory.py                     # Historical context
├── ai_loop.py                       # Multi-model orchestration
├── ai_planner.py                    # Strategic planning
├── ai_handoff.py                    # Inter-module handoff
│
├── idor_module.py                   # IDOR orchestrator
├── idor_collection.py               # 14 collection functions
├── idor_testing.py                  # B1-B10
├── idor_testing_advanced.py         # Additional tests
├── idor_testing_advanced2.py        # B11-B19
├── idor_testing_advanced2_fix.py    # ⭐ B20-B22 + fixes
├── idor_playwright.py               # Network capture (SPA)
├── idor_smart.py                    # JS extraction
├── idor_utils.py                    # Shared helpers
│
├── state.py                         # State management
├── telegram_io.py                   # Telegram integration
├── test_coverage.py                 # Coverage test for all techniques
│
├── clicker_api.env                  # API keys (gitignored)
└── README.md                        # This file
```

---

## 📊 Current Status (v2.3)

| Aspect | Status |
|---|---|
| IDOR Methodology Coverage | ✅ **100%** (37/37 items) |
| AI Verification | ✅ 0 uncertain findings |
| AI Bypass Engine | ✅ Working (triggers on 401/403/405/500) |
| Playwright Capture | ✅ Auto-close after quiet period |
| WAF-Aware Optimization | ✅ 3 categories (aggressive/moderate/lenient) |
| Speed Guard | ✅ Rejects AI slowdowns >30% |
| Anti-Hallucination | ✅ 7 validation checks per AI command |
| Tested on | Juice Shop (34 findings), crAPI, Firebase targets |

---

## ⚠️ Disclaimer

**This tool is designed for authorized security testing, penetration testing, and bug bounty hunting only.**

The developer assumes no liability for any misuse or damage caused by this program. Always ensure you have explicit, written permission before scanning any target or domain.

---

**Built with ❤️ by [@403_linux](https://instagram.com/403_linux)**
```
