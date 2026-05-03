# 📜 Changelog

All notable changes to the **Clicker** project will be documented in this file.  
This project follows [Semantic Versioning](https://semver.org/).

---

## [v1.2] - 2026-05-03
### 🐛 Fixed
- **Critical Syntax Error**: Fixed `SyntaxError: invalid syntax` in `parse_waf_simple_inner()` by completing the `for entry in data:` loop in WAF parsing module.
- **Proxy Environment Leakage**: Ensured `HTTP_PROXY`/`HTTPS_PROXY` variables are fully cleared when bypassing proxy for network tools.

### 🧹 Maintenance
- Final code cleanup and stability improvements for production use.

---

## [v1.2] - 2026-05-03
### 🐛 Fixed
- **WAF Parser Scope Error**: Extracted `parse_waf_simple_inner()` outside conditional blocks to prevent `UnboundLocalError`.
- **Python 3.12+ Compatibility**: Enforced raw strings (`r"..."`) for all regex patterns to eliminate `SyntaxWarning`.

---

## [v1.2] - 2026-05-03
### 🚀 Added
- **Hybrid Proxy Mode (`--hybrid-proxy`)**: Smart routing that runs Passive Recon tools directly (for speed) while routing Active Scan tools through proxy (for anonymity).
- **Passive/Active Tool Classification**: Internal categorization of tools into `NO_PROXY_TOOLS`, `ACTIVE_HTTP_TOOLS`, and `NETWORK_TOOLS` for intelligent proxy handling.
- **Auto-Fallback Wordlists**: Added `ensure_essential_file()` to automatically download `resolvers.txt` and `wordlist` from trusted sources if not found locally.
- **Smart Command Fallback**: `run_cmd()` now retries commands without proxy if they fail/return empty with proxy enabled.
- **Proxy Health Check**: Pre-phase proxy connectivity test with auto-bypass on failure.

### ⚙️ Improved
- **Environment Cleanup**: Automatic removal of proxy env vars when executing network-level tools (`nmap`, `naabu`, `dnsx`) to prevent conflicts.
- **Verbose Logging**: Added `[hybrid]` prefix in verbose mode to show when proxy is bypassed for specific tools.
- **Error Resilience**: Cascading error prevention with `wlines()` creating empty files to avoid `NameError` in dependent phases.

### 🧹 Maintenance
- Removed `sublist3r` from default toolchain (legacy/unmaintained) — users can still enable manually.
- Optimized `phase_passive` execution order for faster initial results.

---

## [v1.3.0] - 2026-05-02
### 🚀 Added
- **Proxychains Integration**: New `--proxychains` flag to route ALL network tools (including `nmap`, `naabu`, `dnsx`) through `proxychains4`/`proxychains`.
- **Authenticated Proxy Support**: Full compatibility with `user:pass@IP:PORT` proxy format across all HTTP-based tools.
- **Dynamic Command Wrapper**: `run_cmd()` now automatically prefixes commands with proxychains binary when flag is enabled.

### 🐛 Fixed
- **Proxy Env Variable Scope**: Ensured proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`) are set in both uppercase and lowercase for maximum tool compatibility.
- **JSON Parsing in WAF Module**: Improved handling of multi-object JSON responses from `wafw00f`.

### 🧹 Maintenance
- Standardized error handling patterns across all phase functions.
- Removed inline debug comments and legacy version markers.

---

## [v1.2.0] - 2026-05-01
### 🚀 Added
- **Smart Proxy Manager**: Introduced `ProxyManager` class for centralized proxy handling with rotation support.
- **New CLI Flags**:
  - `--proxy IP:PORT` — Single manual proxy
  - `--proxy-list FILE.txt` — Load proxies from file (one per line)
  - `--auto-proxy` — Fetch fresh proxies from public APIs automatically
  - `--rotate-proxy` — Rotate proxy per target/domain
- **Auto-Fetch Integration**: Built-in fetching from `api.proxyscrape.com` and public GitHub proxy lists.
- **Proxy Validation**: Regex-based validation to filter malformed entries before execution.

### ⚙️ Improved
- Automatically injects proxy variables into environment for tools respecting `HTTP_PROXY`.
- Graceful fallback with warning messages when no valid proxies are found.
- Enhanced terminal logging to show active proxy rotation per target.

---

## [v1.1.0] - 2026-04-30
### 🚀 Added
- **Resume System (`--resume`)**: Automatically saves progress to `.clicker_resume.json` after each phase completion.
- **Smart Phase Skipping**: When resuming, skips completed phases and continues from last checkpoint.
- **Automatic Checkpoint Cleanup**: Removes resume file upon successful full scan completion.

### 🐛 Fixed
- Fixed `NameError` when phases are skipped during resume mode by pre-initializing result dictionaries.
- Improved state parsing to handle corrupted/missing checkpoint files gracefully.

---

## [v1.0.0] - 2026-04-28
### 🚀 Added
- **Complete Architecture Rewrite**: Migrated from legacy `v6.x` to clean, production-ready codebase.
- **Optimized Phase Order**: Moved `Subdomain Takeover` and `WAF Detection` earlier for faster critical findings; deferred `Screenshots` to reduce initial load.
- **Smart File Discovery**: Added `find_file_smart()` and `ask_user_for_file()` to auto-locate `wordlists`/`resolvers` with interactive fallback.
- **Advanced Reporting**: Multi-format output (`JSON`, `TXT`, `HTML`, `PDF`) with structured target data.
- **Branding & UI**: Cleaned ASCII banner, integrated `@403_linux` handle, standardized terminal color output.

### 🐛 Fixed
- Eliminated all `SyntaxWarning` for invalid escape sequences in f-strings.
- Fixed JSON parsing errors in WAF and Port Scan output processors.
- Resolved cross-environment path handling issues.

### 🗑️ Removed
- Stripped all experimental/debug comments and legacy `v6.x` references.
- Removed redundant duplicate functions and unused imports.
- Replaced hardcoded paths with dynamic resolution.
