markdown
# 📜 Changelog

All notable changes to the Clicker project will be documented in this file.

This project follows [Semantic Versioning](https://semver.org/).

---

## [v2.3] - 2026-10-09

### 🚀 Added

- **AI Bypass Engine (`ai_bypass.py`)**: Automatic WAF bypass for blocked IDOR findings. Triggers only when target returns `401/403/405/429/500`. Generates 12-15 bypass attempts across 12 categories: `url_encoding`, `case_manipulation`, `path_confusion`, `header_injection`, `param_pollution`, `content_type`, `http_method`, `unicode_tricks`, `null_byte`, `chunked_encoding`, `http2_tricks`, `wrapper`.
- **Parallel Bypass Testing**: 10 concurrent workers with 4s timeout per request (was 12s sequential).
- **B20 — Rate Limiting Check**: Sends 30 rapid requests to detect missing rate limits + measures throttling via response time.
- **B21 — Intermittent Behavior Detection**: Detects race conditions and load balancer inconsistencies via mixed status codes (200/500, 200/403, rare 200).
- **B22 — Rule-Based Bypass Checklist**: Executes 14 bypass techniques (trailing slash, double slash, path dot, updir, uppercase, null byte, semicolon, extensions, wildcard, delete_id, url_encode_id) on blocked URLs.
- **Playwright Network Capture (`idor_playwright.py`)**: Headless browser captures all XHR/Fetch requests on SPA/Flutter/React targets. Auto-detects Firebase config, Cloud Functions, API bases, login endpoints.
- **Playwright Auto-Close**: Browser closes automatically after minimum 15s + login captured + 3 API calls + 8s quiet (or 180s hard max).
- **AI Memory (`ai_memory.py`)**: Historical context from past runs — prefers commands that succeeded before.
- **AI Planner (`ai_planner.py`)**: Strategic planning for complex targets.
- **AI Thinker (`ai_thinker.py`)**: Per-phase reflection & analysis via fast models.
- **AI Verifier (`ai_verifier.py`)**: 14 fast-check rules + AI fallback → 0 uncertain findings.
- **Telegram Integration (`telegram_io.py`)**: Interactive I/O + real-time findings alerts.
- **State Management (`state.py`)**: Centralized state handling.
- **Test Coverage (`test_coverage.py`)**: Coverage test for all 38 IDOR techniques.
- **Scope Management**: `--scope-file` supports include/exclude patterns with wildcards.
- **Hybrid Proxy Mode**: Passive tools direct, active tools via proxy, network tools auto-cleanup env.
- **Speed Guard**: Rejects AI command changes that slow down critical tools by >30%.

### ⚙️ Improved

- **IDOR Methodology Coverage**: 100% (37/37 items from OWASP IDOR testing guide).
- **AI Anti-Hallucination**: 7 validation checks per AI command (multi-line, length, tool presence, loop, prose markers, hallucinated flags, unknown flags).
- **WAF Categorization**: 3 tiers (aggressive / moderate / lenient) with speed hints per category.
- **URL Retry Wrapper**: `urllib.request.urlopen` auto-retries on 5xx with exponential backoff. Fast path for short timeouts (≤8s) to avoid log spam.
- **Custom Login JSON**: `--idor-login-json` supports `%EMAIL%` and `%PASS%` placeholders for any backend (REST, GraphQL, Firebase, Cloud Functions).

### 🐛 Fixed

- **Playwright event loop blocking**: `input()` was freezing Playwright's event loop → replaced with threaded wait + polling.
- **`import time` missing**: Fixed in `idor_testing_advanced2_fix.py`.
- **B20/B21/B22 injection**: Functions were added to wrong file (`idor_testing_advanced2.py` instead of `idor_testing_advanced2_fix.py`) — corrected.
- **Session refresh**: Auto-refreshes when A's session expires (401) mid-scan.
- **Trigger logic**: `should_bypass()` now only triggers on attacker-side blocks — not on `anon=401` (normal auth requirement).
- **Confirmed findings skip**: Bypass engine skips `type=confirmed` (already worked → no bypass needed).

---

## [v2.2] - 2026-10-07

### 🚀 Added

- **IDOR Module B11-B19**: Config IDOR, Lifecycle Mismatch, GraphQL Nested, Auth Validation Logic, Error-Based Disclosure, Clairvoyance, wpscan, Race Conditions, HPP URL+Body.
- **Extended Collection (14 functions)**: gf patterns, API versions, tokens/UUIDs, JS mining (jsluice + xnLinkFinder), GraphQL discovery, Lifecycle endpoints, Field expansion, Active params (arjun + paramspider).
- **AI Orchestrator (`ai_orchestrator.py`)**: Dynamic command review with `--help` reading, WAF-aware optimization, anti-hallucination protocol, speed guard.
- **AI Executor (`ai_executor.py`)**: Executes AI-proposed custom reconnaissance phases with validation.
- **AI Retry (`ai_retry.py`)**: Auto-fix failed commands (empty output / non-zero exit) with model fallback chain.
- **AI Loop (`ai_loop.py`)**: Multi-model orchestration loop.
- **AI Handoff (`ai_handoff.py`)**: Inter-module handoff protocol.
- **Custom Authentication**: `--idor-a-email`, `--idor-a-pass`, `--idor-b-email`, `--idor-b-pass`.
- **Custom Login Endpoint**: `--idor-login-url` + `--idor-login-json` for non-standard backends.

### ⚙️ Improved

- **Multi-Level IDOR Discovery**: 5 levels (URLs → JS → API docs → GraphQL → Extended Collection).
- **Session Persistence**: Cookies + headers maintained across all IDOR tests.
- **Smart URL Validation**: `_is_valid_candidate_url()` rejects garbage before testing.

### 🐛 Fixed

- **Command injection**: Full validation + `shlex.quote()` everywhere.
- **Resume** now stores domain + completed_phases properly.
- **Signal handler** (Ctrl+C) skips only current phase.

---

## [v2.1] - 2026-10-06

### 🚀 Added

- **IDOR Module Basic (B1-B10)**: HPP, Object Reference Testing, Numeric ID Fuzzing, State-Changing IDOR, State-Changing GET, Vertical PrivEsc, Horizontal PrivEsc, Mass Assignment, Method Tampering, Pagination Enumeration, Predictable IDs, Auth Validation Logic, JWT Manipulation, Time-Based Window, File Operations IDOR, Search IDOR, Path/Body Conflict, Cross-Location Conflict.
- **Playwright Support**: `--idor-pw`, `--idor-pw-visible`, `--idor-pw-headless`, `--idor-pw-duration`, `--idor-pw-follow-links`.
- **URL Extraction**: Extract endpoints, tokens, UUIDs from JS files.

### ⚙️ Improved

- **Response Filtering**: Extended status codes (200-308) + custom ports.
- **Content Discovery**: Added `uro` normalization + `waymore --providers`.

---

## [v2.0] - 2026-10-05

### 🚀 Added

- **Complete Rewrite**: Rewritten from scratch with modular architecture.
- **Quick Probe (Phase 0)**: Fast liveness check before full scan.
- **DNS Resolution (Phase 4)**: Pre-filter subdomains with dnsx (5x speed boost).
- **Sensitive Files Discovery (Phase 12)**: Passive filtering + active dirsearch + ffuf with 45+ extensions.
- **Scope Management**: `--scope-file` with include/exclude patterns.

### 🐛 Fixed

- **`r"..."` in shell commands**: Fixed Python raw string literals appearing in shell commands (multiple places).
- **KeyError on skipped phases**: `safe()` helper added.

---

## [v1.3] - 2026-05-09

### 🚀 Added

- **Early WAF Detection (Phase 2)**: Moved WAF detection to execute immediately after passive subdomain enumeration, enabling automatic optimization for all subsequent scanning phases.
- **Dynamic WAF-Aware Tool Configuration**: Automatic adjustment of httpx, naabu, and nmap parameters based on detected WAF type (Cloudflare, Akamai, Imperva, or default).
- **Three-Layer WAF Detection Engine**: Enhanced accuracy through intelligent fallback chain:
  - Layer 1: httpx technology fingerprinting
  - Layer 2: wafw00f with JSON batch processing
  - Layer 3: Manual HTTP header signature analysis
- **Smart Wordlist Selection by Target Type**: Automatic wordlist optimization based on target profile detection (Cloud, Enterprise, Government, E-commerce, Startup).
- **Enhanced Resume with State Preservation**: `--resume` flag now preserves detected WAF type and completion flags for seamless continuation with consistent tool optimization.
- **Interactive Phase Control via Ctrl+C**: Press Ctrl+C during any phase to skip only the current phase and automatically continue to the next.
- **Advanced Hybrid Proxy with Auto-Fallback**: Smart proxy routing with automatic recovery — passive tools run direct, active tools use proxy, with auto-retry without proxy on failure.
- **Automatic Fallback Wordlist Download**: Auto-downloads `resolvers.txt` and wordlists from trusted sources if not found locally.
- **Enhanced Verbose Output with Smart Coloring**: Color-coded terminal feedback for successful responses, access issues, and informational findings.

---

## [v1.2] - 2026-05-03

### 🐛 Fixed

- **Critical Syntax Error**: Fixed `SyntaxError: invalid syntax` in `parse_waf_simple_inner()` by completing the `for entry in data:` loop in WAF parsing module.
- **Proxy Environment Leakage**: Ensured `HTTP_PROXY`/`HTTPS_PROXY` variables are fully cleared when bypassing proxy for network tools.

### 🧹 Maintenance

- Final code cleanup and stability improvements for production use.
- **WAF Parser Scope Error**: Extracted `parse_waf_simple_inner()` outside conditional blocks to prevent `UnboundLocalError`.
- **Python 3.12+ Compatibility**: Enforced raw strings (`r"..."`) for all regex patterns to eliminate `SyntaxWarning`.

### 🚀 Added

- **Hybrid Proxy Mode (`--hybrid-proxy`)**: Smart routing that runs Passive Recon tools directly (for speed) while routing Active Scan tools through proxy (for anonymity).
- **Passive/Active Tool Classification**: Internal categorization of tools into `NO_PROXY_TOOLS`, `ACTIVE_HTTP_TOOLS`, and `NETWORK_TOOLS` for intelligent proxy handling.
- **Auto-Fallback Wordlists**: Added `ensure_essential_file()` to automatically download `resolvers.txt` and wordlist from trusted sources if not found locally.
- **Smart Command Fallback**: `run_cmd()` now retries commands without proxy if they fail/return empty with proxy enabled.
- **Proxy Health Check**: Pre-phase proxy connectivity test with auto-bypass on failure.

### ⚙️ Improved

- **Environment Cleanup**: Automatic removal of proxy env vars when executing network-level tools (nmap, naabu, dnsx) to prevent conflicts.
- **Verbose Logging**: Added `[hybrid]` prefix in verbose mode to show when proxy is bypassed for specific tools.
- **Error Resilience**: Cascading error prevention with `wlines()` creating empty files to avoid `NameError` in dependent phases.

### 🧹 Maintenance

- Removed `sublist3r` from default toolchain (legacy/unmaintained) — users can still enable manually.
- Optimized `phase_passive` execution order for faster initial results.

### 🚀 Added (2026-05-02)

- **Proxychains Integration**: New `--proxychains` flag to route ALL network tools (including nmap, naabu, dnsx) through `proxychains4`/`proxychains`.
- **Authenticated Proxy Support**: Full compatibility with `user:pass@IP:PORT` proxy format across all HTTP-based tools.
- **Dynamic Command Wrapper**: `run_cmd()` now automatically prefixes commands with proxychains binary when flag is enabled.

### 🐛 Fixed (2026-05-02)

- **Proxy Env Variable Scope**: Ensured proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) are set in both uppercase and lowercase for maximum tool compatibility.
- **JSON Parsing in WAF Module**: Improved handling of multi-object JSON responses from wafw00f.

### 🧹 Maintenance (2026-05-02)

- Standardized error handling patterns across all phase functions.
- Removed inline debug comments and legacy version markers.

### 🚀 Added (2026-05-01)

- **Smart Proxy Manager**: Introduced `ProxyManager` class for centralized proxy handling with rotation support.
- **New CLI Flags**:
  - `--proxy IP:PORT` — Single manual proxy
  - `--proxy-list FILE.txt` — Load proxies from file (one per line)
  - `--auto-proxy` — Fetch fresh proxies from public APIs automatically
  - `--rotate-proxy` — Rotate proxy per target/domain
- **Auto-Fetch Integration**: Built-in fetching from `api.proxyscrape.com` and public GitHub proxy lists.
- **Proxy Validation**: Regex-based validation to filter malformed entries before execution.

### ⚙️ Improved (2026-05-01)

- Automatically injects proxy variables into environment for tools respecting `HTTP_PROXY`.
- Graceful fallback with warning messages when no valid proxies are found.
- Enhanced terminal logging to show active proxy rotation per target.

---

## [v1.1] - 2026-04-30

### 🚀 Added

- **Resume System (`--resume`)**: Automatically saves progress to `.clicker_resume.json` after each phase completion.
- **Smart Phase Skipping**: When resuming, skips completed phases and continues from last checkpoint.
- **Automatic Checkpoint Cleanup**: Removes resume file upon successful full scan completion.

### 🐛 Fixed

- Fixed `NameError` when phases are skipped during resume mode by pre-initializing result dictionaries.
- Improved state parsing to handle corrupted/missing checkpoint files gracefully.

---

## [v1.0] - 2026-04-28

### 🚀 Added

- **Complete Architecture Rewrite**: Migrated from legacy v6.x to clean, production-ready codebase.
- **Optimized Phase Order**: Moved Subdomain Takeover and WAF Detection earlier for faster critical findings; deferred Screenshots to reduce initial load.
- **Smart File Discovery**: Added `find_file_smart()` and `ask_user_for_file()` to auto-locate wordlists/resolvers with interactive fallback.
- **Advanced Reporting**: Multi-format output (JSON, TXT, HTML, PDF) with structured target data.
- **Branding & UI**: Cleaned ASCII banner, integrated `@403_linux` handle, standardized terminal color output.

### 🐛 Fixed

- Eliminated all `SyntaxWarning` for invalid escape sequences in f-strings.
- Fixed JSON parsing errors in WAF and Port Scan output processors.
- Resolved cross-environment path handling issues.

### 🗑️ Removed

- Stripped all experimental/debug comments and legacy v6.x references.
- Removed redundant duplicate functions and unused imports.
- Replaced hardcoded paths with dynamic resolution.
```
