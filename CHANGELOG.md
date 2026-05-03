# 📜 Changelog

All notable changes to the **Clicker** project will be documented in this file.  
This project follows [Semantic Versioning](https://semver.org/).

---

## [v1.2.0] - Latest
### 🚀 Added
- **Proxychains Integration**: New `--proxychains` flag to route all network tools (including `nmap`, `naabu`, `dnsx`, `ffuf`) through `proxychains4`/`proxychains`.
- **Dynamic Command Wrapper**: `run_cmd()` now automatically prefixes commands with the proxychains binary when the flag is enabled.
- **Authenticated Proxy Support**: Full compatibility with `user:pass@IP:PORT` proxy formats across all HTTP-based tools.

### 🐛 Fixed
- **Critical Syntax Error**: Fixed `SyntaxError: invalid syntax` caused by an incomplete `for entry in` loop in the WAF parsing module.
- **Scope & Refactoring**: Extracted `parse_waf_simple_inner()` outside conditional blocks to prevent `UnboundLocalError` and improve stability.
- **Python 3.12+ Compatibility**: Resolved all `SyntaxWarning: invalid escape sequence` warnings by enforcing raw strings (`r"..."`) for regex patterns.
- **Environment Cleanup**: Ensured proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, etc.) are properly unset when no proxy is active.

### 🧹 Maintenance
- Removed all inline debug comments and legacy markers.
- Standardized error handling across all phases.
- Optimized phase execution order for better resource management.

---

## [v1.2.0]
### 🚀 Added
- **Smart Proxy Manager**: Introduced `ProxyManager` class for centralized proxy handling.
- **New CLI Flags**:
  - `--proxy IP:PORT` (Single manual proxy)
  - `--proxy-list FILE.txt` (Load from file)
  - `--auto-proxy` (Fetch fresh proxies from public APIs automatically)
  - `--rotate-proxy` (Rotate proxy per target/domain)
- **Auto-Fetch Integration**: Built-in fetching from `api.proxyscrape.com` and public GitHub proxy lists.
- **Proxy Validation**: Regex-based validation to filter out malformed proxy entries before execution.

### ⚙️ Improved
- Automatically injects proxy variables into the environment for tools that respect `HTTP_PROXY`.
- Added graceful fallback and warning messages when no valid proxies are found.
- Enhanced terminal logging to show active proxy rotation per target.

---

## [v1.1.0]
### 🚀 Added
- **Resume System (`--resume`)**: Automatically saves progress to `.clicker_resume.json` after each phase.
- **Smart Phase Skipping**: When resuming, skips completed phases and continues from the last checkpoint.
- **Automatic Checkpoint Cleanup**: Removes the resume file upon successful scan completion.

### 🐛 Fixed
- Fixed `NameError` when phases are skipped during resume mode by pre-initializing result dictionaries.
- Improved state parsing to handle corrupted or missing checkpoint files gracefully without breaking the pipeline.

---

## [v1.0.0]
### 🚀 Added
- **Complete Architecture Rewrite**: Migrated from legacy `v6.x` to a clean, production-ready codebase.
- **Optimized Phase Order**: Moved `Subdomain Takeover` and `WAF Detection` earlier in the pipeline for faster critical findings. Deferred `Screenshots` to reduce initial resource load.
- **Smart File Discovery**: Added `find_file_smart()` and `ask_user_for_file()` to automatically locate `wordlists` and `resolvers`, with interactive fallback if missing.
- **Advanced Reporting**: Multi-format output generation (`JSON`, `TXT`, `HTML`, `PDF`) with structured target data.
- **Branding & UI**: Cleaned ASCII banner, integrated `@403_linux` handle, and standardized terminal color output.

### 🐛 Fixed
- Eliminated all `SyntaxWarning` warnings related to invalid escape sequences in f-strings.
- Fixed JSON parsing errors in WAF and Port Scan output processors.
- Resolved path handling issues across different Linux environments.

### 🗑️ Removed
- Stripped all experimental/debug comments and legacy `v6.x` references.
- Removed redundant duplicate functions and unused imports.
- Cleaned up hardcoded paths in favor of dynamic resolution.
