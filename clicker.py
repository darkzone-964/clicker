#!/usr/bin/env python3
"""
Clicker v2.2 - Black-box Recon & Bug Bounty Pipeline
Enhanced with fuzzing, sensitive file discovery, and URL normalization.
"""
import argparse
import datetime
import html
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from ai_orchestrator import get_ai_decision, verify_and_generate_poc_real, execute_puredns_smart, optimize_tool_command
from urllib.parse import urlparse
import telegram_io
import state
import ai_memory
import ai_thinker
import ai_executor
import ai_verifier

try:
    from idor_module import phase_idor as idor_phase_func
    IDOR_AVAILABLE = True
except ImportError:
    IDOR_AVAILABLE = False

# ============================================================================
# COLORS & BRANDING
# ============================================================================
R, G, Y, B, M, C, W = "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[95m", "\033[96m", "\033[97m"
DIM, RST, BOLD = "\033[2m", "\033[0m", "\033[1m"
AUTHOR, VERSION, INSTAGRAM = "Clicker Tool", "v2.2", "@403_linux"
ASCII_ART = r"""
.__  .__        __
____ |  | |__| ____ |  | __ ___________
_/ ___\|  | |  |/ ___\|  |/ // __ \_  __ \
\  \___|  |_|  \  \___|    <\  ___/|  | \/
 \___  >____/__|\___  >__|_ \\___  >__|
     \/             \/     \/    \/
"""
ASCII_LOGO = f"{C}{ASCII_ART}{RST}{DIM}Black-box Recon Pipeline | {BOLD}{C}{AUTHOR}{RST} {DIM}| {Y}{INSTAGRAM}{RST}"

# ============================================================================
# CONSTANTS
# ============================================================================
SENSITIVE_PREFIXES = [
    "app", "dashboard", "api", "auth", "admin", "dev", "staging", "test",
    "internal", "vpn", "mail", "ftp", "sandbox", "uat", "qa", "jenkins",
    "gitlab", "payment", "portal", "secure", "beta", "demo", "prod", "mgmt",
    "manage", "login", "sso", "id", "oauth", "backup", "old", "legacy",
    "corp", "intranet", "remote", "access", "cloud", "db", "database",
    "secret", "private", "hidden"
]
PORTS_COMMON = "21,22,23,25,53,80,110,135,139,143,389,443,445,993,995,1433,1521,2181,2375,3000,3306,3389,5000,5432,5601,5900,5984,6379,6443,7001,8000,8080,8081,8082,8083,8088,8089,8090,8443,8500,8888,8983,9000,9001,9090,9091,9100,9200,9300,9418,9999,10000,10250,11211,15672,16686,27017,50000,50070,61616"
HTTPX_PORTS = "80,443,8080,8443,8000,8888"
HTTPX_STATUS_CODES = "200,201,202,204,301,302,303,307,308"
WAF_TOOL_OPTIONS = {
    "cloudflare": {"httpx": "-timeout 10 -retries 1", "naabu": "-rate 100 -timeout 1000", "nmap": "-T3 --max-retries 1"},
    "akamai":     {"httpx": "-timeout 15 -retries 2", "naabu": "-rate 80 -timeout 1500", "nmap": "-T3 --host-timeout 15m"},
    "imperva":    {"httpx": "-timeout 20 -retries 2", "naabu": "-rate 50 -timeout 2000", "nmap": "-T2 --max-retries 2"},
    "default":    {"httpx": "-timeout 10 -retries 1", "naabu": "-rate 200 -timeout 1000", "nmap": "-T4 --max-retries 1"},
}
HTTP_PROXY_TOOLS = {
    "subfinder", "sublist3r", "chaos", "assetfinder", "github-subdomains",
    "findomain", "waybackurls", "gau", "httpx", "curl",
    "katana", "waymore", "mantra", "subzy", "subjack", "wafw00f", "ffuf",
    "nuclei", "whatweb", "uro", "dirsearch"
}
NO_PROXY_TOOLS = {
    "nmap", "naabu", "dnsx", "cdncheck", "puredns", "altdns", "shuffledns",
    "dnsrecon", "aquatone", "gowitness", "dig", "host"
}
FALLBACK_URLS = {
    "resolvers": "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
    "wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt",
    "dirsearch_wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
}
EXPOSED_FILE_PATHS = [
    "/.env", "/.env.local", "/.env.dev", "/.env.prod", "/.env.backup",
    "/.env.old", "/.env.bak", "/.env.save", "/.env.orig",
    "/.git/HEAD", "/.git/config", "/.gitignore", "/.gitconfig",
    "/.svn/entries", "/.hg/store", "/.DS_Store", "/.htaccess", "/.htpasswd",
    "/backup.zip", "/backup.tar.gz", "/backup.tar", "/backup.rar", "/backup.7z",
    "/backup.sql", "/backup.db", "/dump.sql", "/database.sql", "/db.sql",
    "/config.php.bak", "/config.old", "/config.save", "/config.orig",
    "/wp-config.php.bak", "/web.config.old", "/phpinfo.php",
    "/server-status", "/server-info", "/.well-known/security.txt",
    "/composer.json", "/package.json", "/.dockerignore", "/Dockerfile",
    "/id_rsa", "/id_rsa.pub", "/.ssh/id_rsa", "/private.key",
]
SENSITIVE_EXTENSIONS = (
    r"\.(env|ini|conf|config|cfg|yml|yaml|sql|db|sqlite|sqlite3|bak|backup|"
    r"old|log|txt|csv|xml|json|key|pem|pub|rsa|sh|bash|dump|save|orig|copy)"
    r"(\?|$)"
)
FUZZ_EXTENSIONS = "env,env.local,env.dev,env.prod,env.backup,env.old,env.bak,git,gitignore,gitconfig,svn,zip,tar,tar.gz,rar,7z,bak,old,backup,save,orig,copy,sql,sqlite,sqlite3,db,json,csv,xml,log,txt,php,js,yml,yaml,ini,cfg,config,key,pem,pub,rsa,sh,bash"
URL_FILTER_PATTERN = r"\.(jpg|jpeg|png|gif|svg|ico|webp|bmp|mp4|avi|mov|wmv|flv|webm|mkv|mp3|wav|ogg|css|woff|woff2|ttf|eot|otf|pdf|zip|tar|gz|map)(\?|$)"

# ============================================================================
# GLOBAL STATE
# ============================================================================
args_verbose = False
args_skip_screenshots = False
args_skip_js = False
args_skip_active_subs = False
args_skip_vuln = False
args_skip_fuzz = False
args_skip_idor = False
args_idor_pw = False
args_idor_pw_duration = 25
args_idor_pw_visible = False
args_idor_pw_follow_links = False
args_idor_a_email = None
args_idor_a_pass = None
args_idor_b_email = None
args_idor_b_pass = None
args_idor_login_url = None
args_idor_login_json = None
args_idor_only = False
args_keep_sources = False
args_resume = False
args_force = False
args_wordlist = ""
args_resolvers = ""
args_scope_file = None
api_keys_global = {}
workspace_global = None
GLOBAL_USE_PROXYCHAINS = False
GLOBAL_HYBRID_PROXY = False
GLOBAL_PROXY_HEALTH_OK = True
GLOBAL_WAF_TYPE = "default"
SKIP_CURRENT_PHASE = False

# Shared context passed to AI for every tool call
GLOBAL_AI_CONTEXT = {
    "domain": "",
    "phase_name": "",
    "phase_number": 0,
    "passive_subs": 0,
    "active_subs": 0,
    "resolved_hosts": 0,
    "alive_hosts": 0,
    "f403": 0,
    "f404": 0,
    "open_ports": 0,
    "urls_found": 0,
    "js_files": 0,
    "secrets": 0,
}

# AI planning loop result (set after passive phase)
AI_PLAN_GLOBAL = None

# Target-specific port (extracted from domain:port)
GLOBAL_TARGET_PORT = ""


def _extract_target_port(domain):
    """Extract port from domain:port or return ''."""
    if not domain or ":" not in domain:
        return ""
    parts = domain.rsplit(":", 1)
    if len(parts) != 2:
        return ""
    port = parts[1].strip()
    if port.isdigit() and 1 <= int(port) <= 65535:
        return port
    return ""


def _merge_port_into_list(ports_csv, extra_port):
    """Prepend extra_port to a CSV list of ports if missing."""
    if not extra_port:
        return ports_csv
    ports = [p.strip() for p in ports_csv.split(",") if p.strip()]
    if extra_port in ports:
        return ports_csv
    return extra_port + "," + ",".join(ports)


def _guess_scheme_for_port(port):
    """Return http:// or https:// based on port number."""
    try:
        pnum = int(port)
    except (ValueError, TypeError):
        return "http://"
    if pnum in (443, 8443, 9443):
        return "https://"
    return "http://"



# ============================================================================
# PROGRAM PROFILES
# ============================================================================
PROFILE_DIR = Path("programs")
GLOBAL_PROFILE = {}
GLOBAL_EXTRA_HEADERS = []
GLOBAL_RATE_LIMIT = 5.0
GLOBAL_ALLOWED_PHASES = None

def _slug(d):
    return re.sub(r"[^a-zA-Z0-9._-]", "_", d)

def profile_path(domain):
    PROFILE_DIR.mkdir(exist_ok=True)
    return PROFILE_DIR / f"{_slug(domain)}.json"

def load_profile(domain):
    p = profile_path(domain)
    if not p.exists(): return None
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None

def save_profile(domain, data):
    p = profile_path(domain)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return p

# ============================================================================
# POLICY TEXT PARSER
# ============================================================================
POLICY_PATTERNS = {
    "rate_limit": [
        r"(\d+)\s*(?:req|request)s?\s*per\s*second", r"rate\s*limit[^.]{0,60}?(\d+)",
        r"(\d+)\s*rps\b", r"(\d+)\s*requests?\s*/\s*s(?:ec)?",
    ],
    "required_headers": [
        r"(X-Bug-Bounty)[:\s]+\[?([\w.\- ]+?)\]?(?:\s|$|[,;])",
        r"(X-HackerOne-Research)[:\s]+\[?([\w.\- ]+?)\]?(?:\s|$|[,;])",
        r"(X-[\w-]+-Research)[:\s]+\[?([\w.\- ]+?)\]?(?:\s|$|[,;])",
        r"(X-[\w-]+)[:\s]+\[?([\w.\- ]+?)\]?(?:\s|$|[,;])",
    ],
    "ai_prohibited": [r"prohibit[^.]{0,80}?AI\s+agents", r"AI\s+agents[^.]{0,80}?prohibit", r"no\s+AI\s+agents"],
    "scanners_prohibited": [r"avoid\s+using\s+web\s+application\s+scanners", r"no\s+automated\s+scanners", r"automated\s+testing[^.]{0,60}?prohibit"],
    "dos_prohibited": [r"DoS[^.]{0,80}?(?:out\s+of\s+scope|prohibit)", r"no\s+DoS"],
    "in_scope_vulns": {
        "IDOR": [r"\bIDOR\b", r"broken\s+access\s+control"], "RCE": [r"\bRCE\b", r"remote\s+code\s+execution"],
        "SQLi": [r"\bSQL\s*injection", r"\bSQLi\b"], "SSRF": [r"\bSSRF\b"], "XSS": [r"\bXSS\b", r"cross[\s-]site\s+scripting"],
        "LFI/RFI": [r"\bLFI\b", r"\bRFI\b"], "Account Takeover": [r"account\s+takeover"],
        "Auth Bypass": [r"auth(?:entication|orization)?\s+bypass", r"privilege\s+escalation"], "Business Logic": [r"business[\s-]logic"],
    },
    "out_of_scope_vulns": {
        "CSRF": [r"CSRF"], "Clickjacking": [r"[Cc]lickjacking"], "Rate limit issues": [r"rate\s+limit"],
        "Missing headers": [r"missing\s+(?:HTTP\s+)?security\s+headers"], "Open redirect": [r"open\s+redirect"],
    },
}


def analyze_policy_with_ai(text):
    """Use FreeLLMAPI to intelligently parse the program policy."""
    api_key = api_keys_global.get("FREELLMAPI_API_KEY", "")
    if not api_key:
        return None

    prompt = """You are an expert Bug Bounty reconnaissance assistant. Analyze the following bug bounty program policy text and extract the rules into a STRICT JSON object with these exact keys:
    - rate_limit: (number or null, e.g., 5)
    - required_headers: (list of strings, e.g., ["X-Bug-Bounty: username"])
    - ai_prohibited: (boolean)
    - scanners_prohibited: (boolean)
    - dos_prohibited: (boolean)
    - in_scope_vulns: (list of strings, e.g., ["IDOR", "RCE"])
    - out_of_scope_vulns: (list of strings, e.g., ["CSRF", "Clickjacking"])

    Output ONLY valid JSON. Do not include markdown formatting or explanations.

    Policy Text:
    """ + text[:4000]

    try:
        url = "http://localhost:3001/v1/chat/completions"
        payload = {
            "model": "auto",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {api_key}")

        with urllib.request.urlopen(req, timeout=15) as res:
            response = json.loads(res.read().decode("utf-8"))
            content_str = response["choices"][0]["message"]["content"]
            content_str = re.sub(r'^```json\s*', '', content_str, flags=re.IGNORECASE)
            content_str = re.sub(r'\s*```$', '', content_str, flags=re.IGNORECASE)
            result = json.loads(content_str)
            result.setdefault("rate_limit", None)
            result.setdefault("required_headers", [])
            result.setdefault("ai_prohibited", False)
            result.setdefault("scanners_prohibited", False)
            result.setdefault("dos_prohibited", False)
            result.setdefault("in_scope_vulns", [])
            result.setdefault("out_of_scope_vulns", [])
            result["raw_length"] = len(text)
            return result
    except Exception as e:
        return None

def analyze_policy_text(text):
    result = {"rate_limit": None, "required_headers": [], "ai_prohibited": False, "scanners_prohibited": False, "dos_prohibited": False, "in_scope_vulns": [], "out_of_scope_vulns": [], "raw_length": len(text)}
    for pat in POLICY_PATTERNS["rate_limit"]:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            try:
                val = float(m.group(1))
                if 0 < val <= 1000: result["rate_limit"] = val; break
            except (ValueError, IndexError): continue
    for pat in POLICY_PATTERNS["required_headers"]:
        for m in re.finditer(pat, text, re.IGNORECASE):
            groups = [g for g in m.groups() if g]
            if len(groups) >= 2:
                entry = groups[0].strip() + ": " + groups[1].strip()
                if entry not in result["required_headers"]: result["required_headers"].append(entry)
    for key in ("ai_prohibited", "scanners_prohibited", "dos_prohibited"):
        for pat in POLICY_PATTERNS[key]:
            if re.search(pat, text, re.IGNORECASE): result[key] = True; break
    for vuln_name, patterns in POLICY_PATTERNS["in_scope_vulns"].items():
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE): result["in_scope_vulns"].append(vuln_name); break
    for vuln_name, patterns in POLICY_PATTERNS["out_of_scope_vulns"].items():
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE): result["out_of_scope_vulns"].append(vuln_name); break
    return result

def build_recommendations(policy):
    recs = {"headers": [], "skip_flags": [], "warnings": [], "coverage": []}
    for h in policy["required_headers"]: recs["headers"].append(h)
    if policy["rate_limit"]:
        recs["rate_limit"] = policy["rate_limit"]
        if policy["rate_limit"] < 5: recs["warnings"].append("Program rate limit is " + str(policy["rate_limit"]) + "/s")
    else: recs["rate_limit"] = 5.0
    if policy["ai_prohibited"]: recs["warnings"].append("AI agents PROHIBITED by program")
    if policy["scanners_prohibited"]: recs["skip_flags"].extend(["--skip-fuzz", "--skip-vuln"]); recs["warnings"].append("Automated scanners prohibited")
    if policy["dos_prohibited"]: recs["warnings"].append("DoS out of scope")
    coverage_map = {"IDOR": "Full (idor_module)", "RCE": "NOT COVERED", "SQLi": "Partial (nuclei)", "SSRF": "NOT COVERED", "XSS": "Partial (nuclei)", "LFI/RFI": "NOT COVERED", "Account Takeover": "Partial", "Auth Bypass": "Partial", "Business Logic": "NOT COVERED"}
    for v in policy["in_scope_vulns"]: recs["coverage"].append((v, coverage_map.get(v, "Unknown")))
    return recs

# ============================================================================
# FIXED: PASTE POLICY INTERACTIVE (Uses sys.stdin to prevent hanging)
# ============================================================================
def paste_policy_interactive():
    import signal as _signal
    
    old_handler = _signal.getsignal(_signal.SIGINT)
    _signal.signal(_signal.SIGINT, _signal.default_int_handler)
    
    try:
        print()
        print("=" * 60)
        print("  Paste Program Policy Text")
        print("=" * 60)
        print("  1. Open the program page")
        print("  2. Copy the ENTIRE text (Ctrl+A, Ctrl+C)")
        print("  3. Paste it here (Right-click or Ctrl+Shift+V)")
        print("  4. Press ENTER once, then type END and press ENTER again")
        print()
        
        lines = []
        empty_streak = 0
        
        # Using sys.stdin is much more stable for large pastes than input()
        for line in sys.stdin:
            clean_line = line.strip()
            
            if clean_line.upper() == "END":
                break
                
            if not clean_line:
                empty_streak += 1
                if empty_streak >= 3 and not lines:
                    print("   (skipped - no text detected)")
                    return None
            else:
                empty_streak = 0
                lines.append(line)
                
        text = "".join(lines)
        return text if len(text.strip()) > 20 else None
        
    except KeyboardInterrupt:
        print("\n   (skipped)")
        return None
    finally:
        _signal.signal(_signal.SIGINT, old_handler)

def show_policy_report(domain, policy, recs):
    print("\n" + "=" * 60)
    print("  Policy Analysis: " + domain)
    print("=" * 60 + "\n")
    print("Detected rules:")
    print("  Rate limit        : " + str(policy["rate_limit"] or "not specified"))
    print("  Required headers  : " + str(len(policy["required_headers"])))
    for h in policy["required_headers"]: print("      * " + h)
    print("  AI prohibited     : " + ("YES" if policy["ai_prohibited"] else "no"))
    print("  Scanners banned   : " + ("YES" if policy["scanners_prohibited"] else "no"))
    print("  DoS prohibited    : " + ("YES" if policy["dos_prohibited"] else "no") + "\n")
    if policy["in_scope_vulns"]:
        print("In-scope vulnerabilities:")
        for v in policy["in_scope_vulns"]: print("  * " + v)
        print()
    if policy["out_of_scope_vulns"]:
        print("Out-of-scope (from text):")
        for v in policy["out_of_scope_vulns"]: print("  * " + v)
        print()
    if recs["warnings"]:
        print("Warnings:")
        for w in recs["warnings"]: print("  " + w)
        print()
    if recs["coverage"]:
        print("Clicker coverage check:")
        for vuln, cov in recs["coverage"]: print("  " + vuln.ljust(22) + " " + cov)
        print()

def apply_detected_policy(domain, policy, recs):
    all_phases = ["quick", "passive", "waf", "active", "dns_resolution", "response", "tech", "takeover", "vuln", "ports", "leakix", "content", "sensitive", "js", "idor", "screenshots", "dns"]
    passive_only = ["quick", "passive", "waf", "dns_resolution", "dns"]
    passive_idor = ["quick", "passive", "waf", "active", "dns_resolution", "response", "tech", "content", "js", "idor", "dns"]
    allowed = passive_only if policy.get("scanners_prohibited") else passive_idor
    profile = {"target": domain, "headers": recs["headers"], "rate_limit": recs.get("rate_limit", 5.0), "extra_flags": recs["skip_flags"], "allowed_phases": allowed, "notes": "Auto-detected from pasted policy (" + str(len(policy["in_scope_vulns"])) + " in-scope)", "detected_policy": policy}
    p = save_profile(domain, profile)
    print("Saved profile: " + str(p))
    print("  Allowed phases: " + str(len(allowed)) + " (" + ", ".join(allowed[:5]) + "...)")
    return profile

def setup_profile_interactive(domain):
    import signal as _signal
    print("\n" + "=" * 60)
    print("  Program Policy Setup")
    print("=" * 60)
    print("  Target: " + domain + "\n")
    print("[Option A] Paste program page text (recommended)")
    print("  Just copy everything from the program page.\n")
    print("[Option B] Manual questions")
    print("  Answer 4 short questions.\n")
    try: choice = input("Choice [A/B] (default A): ").strip().lower()
    except (EOFError, KeyboardInterrupt): choice = "b"
    
    if choice in ("", "a", "paste"):
        text = paste_policy_interactive()
        if text:
            # Try AI analysis first, fallback to regex
            policy = analyze_policy_with_ai(text)
            if not policy:
                log_dim("AI analysis failed or unavailable, falling back to regex...")
                policy = analyze_policy_text(text)
            recs = build_recommendations(policy)
            show_policy_report(domain, policy, recs)
            try: apply_ans = input("Apply detected settings? [Y/n]: ").strip().lower()
            except (EOFError, KeyboardInterrupt): apply_ans = "y"
            if apply_ans in ("", "y", "yes"): return apply_detected_policy(domain, policy, recs)
        print("Falling back to manual questions...")
        
    _old_handler = _signal.getsignal(_signal.SIGINT)
    _signal.signal(_signal.SIGINT, _signal.default_int_handler)
    try:
        print("\n--- Manual Setup ---")
        print("Press Enter to skip any field (uses defaults).\n")
        profile = {"target": domain, "headers": [], "rate_limit": 5.0, "allowed_phases": None, "extra_flags": [], "notes": ""}
        print("[1/4] HTTP headers (comma-separated)")
        try: headers_in = input("      Headers: ").strip()
        except (EOFError, KeyboardInterrupt): raise
        if headers_in:
            parts = [p.strip() for p in headers_in.split(", ") if p.strip()]
            profile["headers"] = parts
            print("      OK " + str(len(parts)) + " header(s)")
        else: print("      (skipped)")
        
        print("\n[2/4] Rate limit (req/s) [default 5]")
        try: rl_in = input("      Rate: ").strip()
        except (EOFError, KeyboardInterrupt): raise
        if rl_in:
            try: profile["rate_limit"] = float(rl_in); print("      OK " + str(profile["rate_limit"]) + " req/s")
            except ValueError: profile["rate_limit"] = 5.0; print("      Invalid - using 5")
        else: print("      (default: 5)")
        
        print("\n[3/4] Extra flags (comma-separated)")
        try: flags_in = input("      Extra: ").strip()
        except (EOFError, KeyboardInterrupt): raise
        if flags_in:
            if "," in flags_in and "--" not in flags_in:
                parts = [p.strip() for p in flags_in.split(",") if p.strip()]
                profile["extra_flags"] = ["--" + p.lstrip("-") for p in parts]
            else: profile["extra_flags"] = [p for p in flags_in.split() if p]
            print("      OK " + str(len(profile["extra_flags"])) + " flag(s)")
        else: print("      (none)")
        
        print("\n[4/4] Notes (optional)")
        try: notes_in = input("      Notes: ").strip()
        except (EOFError, KeyboardInterrupt): raise
        profile["notes"] = notes_in
        
        has_data = (profile["headers"] or profile["extra_flags"] or profile["notes"] or profile["rate_limit"] != 5.0)
        if has_data:
            p = save_profile(domain, profile)
            print("\nOK Profile saved: " + str(p))
        else: print("\n-- All fields empty - no profile saved\n")
        return profile
    finally: _signal.signal(_signal.SIGINT, _old_handler)

def load_or_setup_profile(domain, force=False, skip=False):
    if skip: return {"target": domain, "headers": [], "rate_limit": 5, "allowed_phases": None, "notes": ""}
    if force: return setup_profile_interactive(domain)
    p = load_profile(domain)
    if p:
        print(f"{G}[+]{RST} Loaded profile: {C}{profile_path(domain)}{RST}")
        if p.get("headers"): print(f"    {DIM}Headers: {len(p['headers'])} applied to all requests{RST}")
        print(f"    {DIM}Rate limit: {p.get('rate_limit', 5)} req/s{RST}")
        if p.get("allowed_phases"): print(f"    {DIM}Phases: {len(p['allowed_phases'])} allowed{RST}")
        return p
    print(f"{Y}[!]{RST} No profile found for {C}{domain}{RST}")
    try: ans = input(f"{BOLD}Set up now? [Y/n]: {RST}").strip().lower()
    except (EOFError, KeyboardInterrupt): ans = "y"
    if ans in ("", "y", "yes"): return setup_profile_interactive(domain)
    return {"target": domain, "headers": [], "rate_limit": 5, "allowed_phases": None, "notes": ""}

# ============================================================================
# VALIDATION & HELPERS
# ============================================================================
DOMAIN_RE = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$')
IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

def validate_domain(d):
    if not d: raise ValueError("empty domain")
    d = d.strip().lower()
    if "://" in d:
        parsed = urlparse(d)
        d = parsed.netloc or parsed.hostname or ""
    d = d.strip(".")
    check_d = d.split(":")[0].strip(".")
    if not check_d or not DOMAIN_RE.match(check_d): raise ValueError(f"invalid domain: {d!r}")
    return d

def validate_ip(ip): return bool(IP_RE.match(ip.strip()))
def q(s): return shlex.quote(str(s))
def mkd(p): Path(p).mkdir(parents=True, exist_ok=True)
def rlines(path):
    p = Path(path)
    if not p.exists(): return []
    try: return [l.strip() for l in p.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
    except Exception: return []

def wlines(path, lines, auto_cleanup=True):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    uniq = sorted(set(l.strip() for l in lines if l and l.strip()))
    p.write_text("\n".join(uniq) + ("\n" if uniq else ""), encoding="utf-8")
    if auto_cleanup: cleanup_empty_file(p)

def is_file_empty(path):
    p = Path(path)
    if not p.exists(): return True
    try: return len(p.read_text(encoding="utf-8", errors="ignore").strip()) == 0
    except Exception: return True

def cleanup_empty_file(path, label=""):
    p = Path(path)
    if is_file_empty(p) and p.exists():
        try:
            p.unlink()
            if args_verbose:
                tag = f" ({label})" if label else ""
                print(f"  {Y}[!]{RST} {DIM}{p.name}{tag} empty -> deleted{RST}")
            return True
        except Exception: pass
    return False

def cleanup_after_merge(sources, label="source"):
    for s in sources:
        s = Path(s)
        if s.exists():
            try:
                s.unlink()
                if args_verbose: print(f"  {Y}[!]{RST} {DIM}{s.name} ({label}) merged -> deleted{RST}")
            except Exception: pass

def show_file_content(path, label, max_lines=40):
    p = Path(path)
    if not p.exists() or is_file_empty(p): return
    lines = rlines(p)
    print(f"\n{BOLD}{C}>>> {label} ({len(lines)} lines){RST}")
    print(f"{DIM}{'-' * 70}{RST}")
    for i, line in enumerate(lines[:max_lines], 1):
        if "[200]" in line or "[302]" in line: print(f"  {G}{i:3d}{RST} {line}")
        elif "[403]" in line or "[404]" in line: print(f"  {Y}{i:3d}{RST} {line}")
        elif "VULNERABLE" in line or "CVE-" in line or "EXPOSED" in line: print(f"  {R}{i:3d}{RST} {BOLD}{line}{RST}")
        else: print(f"  {DIM}{i:3d}{RST} {line}")
    if len(lines) > max_lines: print(f"  {DIM}... and {len(lines) - max_lines} more{RST}")
    print(f"{DIM}{'-' * 70}{RST}\n")

def installed(tool): return shutil.which(tool) is not None
def cleanup_sub(v, domain):
    if not v: return None
    v = v.strip().lower().replace("*.", "")
    if "://" in v: v = urlparse(v).hostname or ""
    v = v.split("/")[0].split(":")[0].split(",")[0].strip(".")
    if not v: return None
    if v == domain or v.endswith("." + domain):
        if DOMAIN_RE.match(v): return v
    return None

def extract_hosts_from_urls(lines, domain):
    out = set()
    for l in lines:
        try: h = urlparse(l.strip()).hostname
        except Exception: h = None
        c = cleanup_sub(h or "", domain)
        if c: out.add(c)
    return out

def log_info(msg):    print(f"{C}[*]{RST} {msg}")
def log_ok(msg):      print(f"{G}[+]{RST} {msg}")
def log_warn(msg):    print(f"{Y}[!]{RST} {msg}")
def log_err(msg):     print(f"{R}[x]{RST} {msg}")
def log_dim(msg):     print(f"{DIM}{msg}{RST}")


def ask_phase(phase_name, default=False, timeout=10):
    """Ask user whether to run a phase. Local 10s + Telegram 60s. First reply wins."""
    env = os.environ.get("CLICKER_PHASE_AUTO", "").strip().lower()
    if env in ("yes", "y", "all", "1", "true"):
        return True
    if env in ("no", "n", "0", "false"):
        return False

    tty = sys.stdin.isatty()
    tg = telegram_io.is_enabled()
    if not tty and not tg:
        return default

    if tty:
        label = "Y/n" if default else "y/N"
        sys.stdout.write(f"{BOLD}{C}[?]{RST} {phase_name}? [{label}] (10s local / 60s TG): ")
        sys.stdout.flush()

    try:
        ans = telegram_io.ask(
            prompt=f"Run phase: {phase_name}?",
            kind="yesno",
            default=("y" if default else "n"),
            local_timeout=timeout,
            tg_timeout=60,
        )
    except Exception as e:
        if args_verbose:
            log_warn(f"telegram_io.ask failed: {e}")
        ans = "y" if default else "n"

    if tty:
        print()

    return ans == "y"


def send_telegram_progress(domain, high_value_subs):
    """Send early progress update to Telegram when high-value subs are found."""
    token = api_keys_global.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = api_keys_global.get("TELEGRAM_CHAT_ID", "")
    
    if not token or not chat_id or not high_value_subs:
        return

    subs_to_show = high_value_subs[:15]
    subs_text = "\n".join([f"🔹 <code>{html.escape(str(s))}</code>" for s in subs_to_show])
    
    if len(high_value_subs) > 15:
        subs_text += f"\n<i>... and {len(high_value_subs) - 15} more.</i>"

    msg = f"⚡ <b>Clicker Progress Update</b>\n\n"
    msg += f"🎯 <b>Target:</b> <code>{html.escape(str(domain))}</code>\n"
    msg += f"🔥 <b>High-Value Subs Found:</b> {len(high_value_subs)}\n\n"
    msg += f"{subs_text}\n\n"
    msg += f"<i>✅ Phase 1 complete. Scan is continuing in the background...</i>"

    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": msg,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        data = urllib.parse.urlencode(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10) as res:
            if res.status == 200:
                log_ok("Telegram progress alert sent.")
    except Exception as e:
        log_warn(f"Failed to send Telegram progress alert: {e}")

# ============================================================================
# PROXY & COMMAND RUNNER
# ============================================================================
class ProxyManager:
    def __init__(self, proxy=None, proxy_file=None, auto_fetch=False, rotate=False):
        self.proxies, self.current_idx, self.rotate = [], 0, rotate
        self.load(proxy, proxy_file, auto_fetch)
    def load(self, proxy, proxy_file, auto_fetch):
        raw = []
        if auto_fetch:
            log_info("Fetching fresh proxies from public APIs...")
            for url in ["https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all", "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt"]:
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(req, timeout=10) as res: raw.extend(res.read().decode(errors="ignore").splitlines())
                except Exception as e: log_warn(f"Proxy fetch failed: {e}")
        if proxy_file and os.path.isfile(proxy_file):
            try: raw.extend(Path(proxy_file).read_text(errors="ignore").splitlines())
            except Exception: pass
        if proxy: raw.append(proxy)
        pattern = re.compile(r'^(?:[^@\s]+@)?(\d{1,3}\.){3}\d{1,3}:\d{2,5}$')
        self.proxies = sorted(set(p.strip() for p in raw if pattern.match(p.strip())))
        if not self.proxies: log_warn("No valid proxies loaded - running without proxy")
        else: log_ok(f"Loaded {len(self.proxies)} valid proxy(ies)")
    def get_current(self):
        if not self.proxies: return None
        if self.rotate:
            p = self.proxies[self.current_idx]
            self.current_idx = (self.current_idx + 1) % len(self.proxies)
            return p
        return self.proxies[0]
    def apply(self, domain=None):
        proxy = self.get_current()
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"): os.environ.pop(k, None)
        if not proxy: return
        if domain: print(f"{DIM}-> Proxy: {proxy} for {domain}{RST}")
        proxy_url = proxy if "://" in proxy else f"http://{proxy}"
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"): os.environ[k] = proxy_url

def check_proxy_health(proxy, timeout=8):
    if not proxy: return False
    try:
        proxy_url = proxy if "://" in proxy else f"http://{proxy}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
        opener.addheaders = [("User-Agent", "Mozilla/5.0")]
        with opener.open("https://httpbin.org/ip", timeout=timeout) as res: return res.status == 200
    except Exception: return False

def run_cmd(cmd, timeout=600, tool_name=None, allow_fallback=True):
    """Wrapper: run _run_cmd_core and record experience to ai_memory."""
    cmd_original = cmd
    _t0 = time.time()
    tracker = {"cmd_final": cmd}
    result = _run_cmd_core(cmd, timeout, tool_name, allow_fallback, tracker)
    if tool_name and result is not None:
        try:
            _elapsed = time.time() - _t0
            _out = result[1] or ""
            _lines = len(_out.splitlines()) if _out else 0
            _chosen = "ai" if tracker["cmd_final"] != cmd_original else "original"
            ai_memory.record_experience(
                target=GLOBAL_AI_CONTEXT.get("domain", ""),
                waf=GLOBAL_WAF_TYPE,
                phase=GLOBAL_AI_CONTEXT.get("phase_name", ""),
                tool=tool_name,
                cmd_original=cmd_original,
                cmd_ai=tracker["cmd_final"],
                chosen=_chosen,
                exit_code=int(result[0]) if isinstance(result[0], (int, float)) else 1,
                duration_sec=_elapsed,
                output_lines=_lines,
                output_sample=_out[:2000],
            )
        except Exception:
            pass
    return result


def _run_cmd_core(cmd, timeout=600, tool_name=None, allow_fallback=True, _tracker=None):
    global GLOBAL_PROXY_HEALTH_OK, SKIP_CURRENT_PHASE, GLOBAL_EXTRA_HEADERS
    if SKIP_CURRENT_PHASE: SKIP_CURRENT_PHASE = False; return (0, "", "")

    # ─── AI optimization (applies to ALL tools) ───
    if tool_name:
        api_key = api_keys_global.get("FREELLMAPI_API_KEY", "")
        if api_key:
            try:
                ctx = dict(GLOBAL_AI_CONTEXT)
                ctx["waf_type"] = GLOBAL_WAF_TYPE
                ctx["rate_limit"] = GLOBAL_RATE_LIMIT
                optimized = optimize_tool_command(tool_name, cmd, ctx, api_key)
                if optimized:
                    cmd = optimized
            except Exception as e:
                if args_verbose:
                    print(f"  \033[93m[!]\033[0m AI optimization error for {tool_name}: {e}")

    if GLOBAL_EXTRA_HEADERS and tool_name in ("httpx", "httpx-toolkit", "nuclei", "katana", "ffuf", "curl"):
        for h in GLOBAL_EXTRA_HEADERS: cmd += f" -H {q(h)}"
    has_proxy = bool(os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy"))
    use_proxy = True
    if GLOBAL_HYBRID_PROXY and tool_name:
        if tool_name in NO_PROXY_TOOLS:
            use_proxy = False
            for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"): os.environ.pop(k, None)
        elif tool_name not in HTTP_PROXY_TOOLS: use_proxy = False
    if use_proxy and GLOBAL_HYBRID_PROXY and not GLOBAL_PROXY_HEALTH_OK:
        cur = os.environ.get("HTTP_PROXY", "").replace("http://", "")
        if cur and not check_proxy_health(cur, timeout=5): use_proxy = False
        else: GLOBAL_PROXY_HEALTH_OK = True
    final_cmd = cmd
    if use_proxy and GLOBAL_USE_PROXYCHAINS:
        pc = shutil.which("proxychains4") or shutil.which("proxychains")
        if pc: final_cmd = f"{pc} -q {cmd}"
    if _tracker is not None:
        _tracker["cmd_final"] = final_cmd
    try:
        p = subprocess.run(final_cmd, shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace", timeout=timeout)
        result = (p.returncode, p.stdout.strip(), p.stderr.strip())
        if allow_fallback and use_proxy and has_proxy and (p.returncode != 0 or not p.stdout.strip()):
            if args_verbose: log_warn(f"Retrying {tool_name or 'cmd'} without proxy")
            saved = {k: os.environ.get(k) for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")}
            for k in saved: os.environ.pop(k, None)
            try:
                p2 = subprocess.run(cmd, shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace", timeout=timeout)
            finally:
                for k, v in saved.items():
                    if v: os.environ[k] = v
                    else: os.environ.pop(k, None)
            if p2.returncode == 0 and p2.stdout.strip(): return (p2.returncode, p2.stdout.strip(), p2.stderr.strip())
        return result
    except subprocess.TimeoutExpired: return (124, "", f"timeout after {timeout}s")
    except KeyboardInterrupt: SKIP_CURRENT_PHASE = False; return (0, "", "")
    except Exception as e: return (1, "", str(e))

# ============================================================================
# PROGRESS, SIGNALS, CHECKPOINT, API KEYS, SCOPE, TOOLS
# ============================================================================
class PhaseProgress:
    def __init__(self, name, total):
        self.name, self.total, self.done, self.start = name, total, 0, time.time()
        print(f"\n{BOLD}{B}{'-' * 60}{RST}")
        print(f"{BOLD}{C}  Phase: {name}{RST}")
        print(f"{BOLD}{B}{'-' * 60}{RST}")
    def step(self, label):
        global SKIP_CURRENT_PHASE
        if SKIP_CURRENT_PHASE: SKIP_CURRENT_PHASE = False; raise KeyboardInterrupt
        self.done += 1
        pct = int(self.done / self.total * 100)
        bar = int(pct / 4)
        elapsed = time.time() - self.start
        print(f"  {G}{'#' * bar}{RST}{DIM}{'.' * (25 - bar)}{RST} {BOLD}{pct:3d}%{RST} {Y}[{self.done}/{self.total}]{RST} {DIM}{elapsed:.0f}s{RST} {W}{label}{RST}")
    def done_phase(self): print(f"\n{G}=> Phase complete in {time.time() - self.start:.1f}s{RST}\n")

def signal_handler(sig, frame):
    global SKIP_CURRENT_PHASE
    print(f"\n{Y}[!] Ctrl+C -> skipping current phase, continuing...{RST}")
    SKIP_CURRENT_PHASE = True

def resume_file(workspace): return Path(workspace) / ".clicker_resume.json"
def save_checkpoint(workspace, domain, completed_phases, extra=None):
    data = {"domain": domain, "completed_phases": sorted(completed_phases), "timestamp": datetime.datetime.now().isoformat(), "extra": extra or {}}
    try: resume_file(workspace).write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception: pass
def load_checkpoint(workspace, domain):
    rf = resume_file(workspace)
    if not rf.exists(): return None
    try:
        data = json.loads(rf.read_text(encoding="utf-8"))
        if data.get("domain") != domain: return None
        return data
    except Exception: return None
def clear_checkpoint(workspace):
    rf = resume_file(workspace)
    if rf.exists():
        try: rf.unlink()
        except Exception: pass

API_KEY_FIELDS = [("CHAOS_API_KEY", "Chaos"), ("VT_API_KEY", "VirusTotal"), ("GITHUB_TOKEN", "GitHub"), ("SHODAN_API", "Shodan"), ("LEAKIX_API", "LeakIX"),
    ("FREELLMAPI_API_KEY", "FreeLLMAPI Unified Key"), ("TELEGRAM_BOT_TOKEN", "Telegram Bot Token"), ("TELEGRAM_CHAT_ID", "Telegram Chat ID")]
def read_env_file(path):
    vals = {}
    p = Path(path)
    if not p.exists(): return vals
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line: continue
        k, v = line.split("=", 1)
        vals[k.strip()] = v.strip().strip('"').strip("'")
    return vals
def save_env_file(path, vals):
    lines = ["# Clicker API keys", "# Keep this file private -> chmod 600 recommended"]
    for k, _ in API_KEY_FIELDS: lines.append(f"{k}={vals.get(k, '')}")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    try: os.chmod(path, 0o600)
    except Exception: pass
def collect_api_keys(api_file):
    existing = read_env_file(api_file)
    
    # Check if all keys are already present
    all_present = all(existing.get(key, "") for key, _ in API_KEY_FIELDS)
    
    if all_present:
        print(f"\n{G}[+]{RST} All API keys found in {api_file}")
        print(f"{DIM}    Skipping interactive setup (all keys present){RST}")
        return existing
    
    # Some keys are missing, proceed with interactive setup
    print(f"\n{BOLD}{Y}[?] API Keys Setup{RST} (file: {api_file})")
    print(f"{DIM}Press Enter to keep saved value, type 'skip' to clear.{RST}\n")
    
    updated = dict(existing)
    for key, label in API_KEY_FIELDS:
        cur = existing.get(key, "")
        tag = f"{G}[saved]{RST}" if cur else f"{R}[empty]{RST}"
        try:
            val = input(f"  {label} {tag}: ").strip()
        except (EOFError, KeyboardInterrupt):
            val = ""
        if val.lower() == "skip":
            updated[key] = ""
        elif val:
            updated[key] = val
        elif key not in updated:
            updated[key] = ""
    
    save_env_file(api_file, updated)
    log_ok(f"API keys saved to {api_file}")
    return updated

def load_scope(path):
    if not path: return None
    p = Path(path)
    if not p.exists(): log_warn(f"Scope file not found: {path}"); return None
    include, exclude = [], []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"): continue
        if line.startswith("!"): exclude.append(line[1:].strip().lower())
        else: include.append(line.lower())
    return {"include": include, "exclude": exclude}
def in_scope(domain, scope):
    if not scope: return True
    def matches(patterns):
        for pat in patterns:
            if pat.startswith("*."):
                if domain == pat[2:] or domain.endswith("." + pat[2:]): return True
            elif domain == pat: return True
        return False
    if scope["exclude"] and matches(scope["exclude"]): return False
    if not scope["include"]: return True
    return matches(scope["include"])

def check_tools(required):
    print(f"{BOLD}{Y}[*] Checking required tools...{RST}")
    available, missing = set(), []
    
    for t in required:
        # Try multiple methods to find the tool
        found = False
        
        # Method 1: shutil.which (standard PATH search)
        if shutil.which(t):
            found = True
        
        # Method 2: Try 'which' command directly
        if not found:
            try:
                result = subprocess.run(['which', t], capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    found = True
            except:
                pass
        
        # Method 3: Try 'locate' if available (faster than find)
        if not found and shutil.which('locate'):
            try:
                result = subprocess.run(['locate', '-b', t], capture_output=True, text=True, timeout=3)
                if result.returncode == 0 and result.stdout.strip():
                    found = True
            except:
                pass
        
        # Method 4: Try 'find' in common locations
        if not found:
            common_paths = ['/usr/bin', '/usr/local/bin', '/opt', '/home']
            for path in common_paths:
                if Path(path).exists():
                    try:
                        result = subprocess.run(
                            ['find', path, '-name', t, '-type', 'f', '-executable'],
                            capture_output=True, text=True, timeout=3
                        )
                        if result.returncode == 0 and result.stdout.strip():
                            found = True
                            break
                    except:
                        pass
        
        if found:
            available.add(t)
        else:
            missing.append(t)
    
    # Display results
    if missing:
        print(f"  {R}[x]{RST} {len(missing)} tool(s) missing:")
        for t in missing:
            print(f"    {R}•{RST} {DIM}{t}{RST}")
        log_warn(f"{len(missing)} tool(s) missing → affected steps will be skipped")
    else:
        log_ok("All required tools present")
    
    return available

def ensure_essential_file(file_type, path):
    p = Path(path)
    if p.exists(): return str(p)
    fallback_dir = Path.home() / ".clicker" / "wordlists"
    fallback_dir.mkdir(parents=True, exist_ok=True)
    url = FALLBACK_URLS.get(file_type)
    if not url: return None
    fp = fallback_dir / f"{file_type}.txt"
    if fp.exists(): log_ok(f"Using cached {file_type}: {fp}"); return str(fp)
    log_warn(f"{file_type} not found -> downloading fallback...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=60) as res: fp.write_bytes(res.read())
        log_ok(f"Downloaded {file_type} -> {fp}")
        return str(fp)
    except Exception as e: log_err(f"Download failed: {e}"); return None

def detect_waf_from_file(workspace, domain):
    waf_file = Path(workspace) / domain / "waf" / "waf-detected.txt"
    if waf_file.exists() and not is_file_empty(waf_file):
        content = waf_file.read_text(errors="ignore").lower()
        if "cloudflare" in content: return "cloudflare"
        if "akamai" in content or "edgekey" in content: return "akamai"
        if "imperva" in content or "incapsula" in content: return "imperva"
    return GLOBAL_WAF_TYPE
def get_tool_options(tool_name, waf_type):
    opts = WAF_TOOL_OPTIONS.get(waf_type, WAF_TOOL_OPTIONS["default"])
    return opts.get(tool_name, "")

# ============================================================================
# PHASE 0: QUICK PROBE & PHASE 1: PASSIVE
# ============================================================================
# ────────────────────────────────────────────────────────────
# AI Planning Loop integration (Task 1)
# ────────────────────────────────────────────────────────────
_PHASE_NAME_MAP = {
    "quick_probe": "quick",
    "passive_subdomain_enum": "passive",
    "waf_detection": "waf",
    "active_subdomain_enum": "active",
    "dns_resolution": "dns_resolution",
    "response_filter": "response",
    "tech_detect": "tech",
    "takeover": "takeover",
    "vuln_scan": "vuln",
    "ports": "ports",
    "leakix": "leakix",
    "content_discovery": "content",
    "sensitive_files": "sensitive",
    "js_recon": "js",
    "idor": "idor",
    "screenshots": "screenshots",
    "dns_enrichment": "dns",
}


def _run_ai_plan_loop(domain, workspace, passive_res, api_keys, _state=None):
    """Run AI planning loop after passive. Returns plan dict or None."""
    try:
        import ai_loop
    except ImportError as e:
        log_warn(f"ai_loop module not available: {e}")
        return None
    api_key = api_keys.get("FREELLMAPI_API_KEY", "")
    if not api_key:
        log_warn("No FREELLMAPI_API_KEY - AI plan skipped")
        return None

    subs = (passive_res or {}).get("all_subdomains", [])
    hv = (passive_res or {}).get("sensitive_subs", [])
    lines = [f"- {len(subs)} subdomains discovered"]
    if hv:
        lines.append(f"- {len(hv)} high-value subdomains:")
        for s in hv[:10]:
            lines.append(f"    {s}")
    else:
        lines.append("- No high-value subdomains detected")
    # Append state snapshot for AI
    try:
        if _state:
            lines.append("")
            lines.append("--- STATE SNAPSHOT ---")
            lines.append(state.summary_for_ai(_state))
    except Exception:
        pass
    summary = "\n".join(lines)

    available = [
        "quick", "passive", "waf", "active", "dns_resolution", "response",
        "tech", "takeover", "vuln", "ports", "leakix", "content",
        "sensitive", "js", "idor", "screenshots", "dns",
    ]

    try:
        # Build state summary for AI
        _state_summary = None
        try:
            if _state:
                _state_summary = state.summary_for_ai(_state)
        except Exception as _e:
            log_warn(f"state summary build failed: {_e}")

        plan = ai_loop.run_planning_loop(
            domain=domain,
            waf=GLOBAL_WAF_TYPE,
            phase_name="passive",
            phase_summary=summary,
            available_phases=available,
            api_key=api_key,
            output_dir=Path(workspace) / domain,
            max_rounds=2,
            verbose=args_verbose,
            state_summary=_state_summary,
        )
        return plan
    except Exception as e:
        log_err(f"AI planning loop failed: {e}")
        return None


# ── Technical dependency rules (not opinions — file-based facts) ──
# If X needs Y's output, Y must run before X.
PHASE_DEPS = {
    "response":     ["passive", "dns_resolution"],
    "tech":         ["response"],
    "ports":        ["dns_resolution", "response", "tech"],
    "takeover":     ["response"],
    "vuln":         ["response", "tech"],
    "content":      ["response"],
    "sensitive":    ["response", "content"],
    "js":           ["response", "content"],
    "idor":         ["content"],
    "screenshots":  ["response"],
    "dns":          ["passive"],
    "leakix":       ["response", "tech"],
}


def _reorder_phases(phases_list, ai_phases):
    """Reorder per AI preference, but respect technical dependencies."""
    # Convert AI names to clicker names
    priority = {}
    for i, ap in enumerate(ai_phases):
        clicker_name = _PHASE_NAME_MAP.get(ap, ap)
        priority[clicker_name] = i

    # Build name -> (name, fn) dict for quick lookup
    by_name = {name: (name, fn) for name, fn in phases_list}
    remaining = list(by_name.keys())
    default_order = {name: i for i, name in enumerate(remaining)}

    # Topological sort with AI priority as tiebreaker
    result = []
    placed = set()
    # Phases already completed before reorder (implicit — dependents don't need them re-added)
    # We assume phases not in `remaining` have already run (or been removed).

    def can_place(name):
        for dep in PHASE_DEPS.get(name, []):
            # If dependency is in our remaining queue, it must be placed first.
            if dep in remaining and dep not in placed:
                return False
        return True

    def priority_key(name):
        # Lower = better. AI order first, then default order.
        if name in priority:
            return (0, priority[name])
        return (1, default_order.get(name, 999))

    # Iteratively place
    max_iters = len(remaining) * len(remaining) + 10
    iters = 0
    while len(result) < len(remaining) and iters < max_iters:
        iters += 1
        candidates = [n for n in remaining if n not in placed and can_place(n)]
        if not candidates:
            # Cycle or stuck → place the highest-priority remaining anyway
            candidates = [n for n in remaining if n not in placed]
            if not candidates:
                break
        candidates.sort(key=priority_key)
        chosen = candidates[0]
        result.append(by_name[chosen])
        placed.add(chosen)

    # Any left over → append in default order
    for name in remaining:
        if name not in placed:
            result.append(by_name[name])
            placed.add(name)

    return result


def phase_quick_probe(domain, workspace):
    qdir = Path(workspace) / domain / "quick"
    mkd(qdir)
    prog = PhaseProgress("0 -> Quick Probe", 4)
    result = {"alive": False, "status": 0, "server": "", "waf_hint": "", "ip": "", "redirect": "", "skip_scan": False, "https": False}
    try:
        host = domain.split(":")[0]
        ip = socket.gethostbyname(host)
        result["ip"] = ip
        prog.step(f"DNS -> {G}{ip}{RST}")
    except Exception: prog.step(f"DNS -> {R}unresolvable{RST}")
    try:
        req = urllib.request.Request(f"https://{domain}", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as res:
            result["alive"] = True; result["https"] = True; result["status"] = res.status
            result["server"] = res.headers.get("Server", "")[:40]
            for h in ("cf-ray", "x-akamai-transformed", "akamai-grn", "x-cdn", "incap-signal", "x-sucuri-id", "x-amz-cf-id"):
                if res.headers.get(h): result["waf_hint"] = h; break
            prog.step(f"HTTPS probe -> {G}{res.status}{RST} {DIM}({result['server']}){RST}")
    except urllib.error.HTTPError as e:
        result["alive"] = True; result["https"] = True; result["status"] = e.code
        result["server"] = (e.headers.get("Server", "") if e.headers else "")[:40]
        for h in ("cf-ray", "x-akamai-transformed", "x-cdn", "incap-signal"):
            if e.headers and e.headers.get(h): result["waf_hint"] = h; break
        prog.step(f"HTTPS probe -> {Y}{e.code}{RST} {DIM}({result['server']}){RST}")
    except Exception:
        try:
            req = urllib.request.Request(f"http://{domain}", headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as res:
                result["alive"] = True; result["status"] = res.status
                result["server"] = res.headers.get("Server", "")[:40]
                if res.geturl().startswith("https://"): result["https"] = True
                prog.step(f"HTTP probe -> {G}{res.status}{RST} {DIM}({result['server']}){RST}")
        except urllib.error.HTTPError as e:
            result["alive"] = True; result["status"] = e.code
            prog.step(f"HTTP probe -> {Y}{e.code}{RST}")
        except Exception: prog.step(f"HTTPS/HTTP probe -> {R}dead{RST}")
    if not result["alive"] and not result["ip"]: result["skip_scan"] = True; prog.step(f"Decision -> {R}SKIP (unresolvable + unreachable){RST}")
    elif not result["alive"]: prog.step(f"Decision -> {Y}proceed (IP exists but no HTTP){RST}")
    else: prog.step(f"Decision -> {G}proceed{RST}")
    prog.done_phase()
    summary = [f"alive={result['alive']}", f"status={result['status']}", f"ip={result['ip']}", f"server={result['server']}", f"waf_hint={result['waf_hint']}", f"https={result['https']}", f"skip_scan={result['skip_scan']}"]
    try: (qdir / "probe.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    except Exception: pass
    if result["waf_hint"]: print(f"  {C}[*] WAF hint from headers: {result['waf_hint']}{RST}")
    if result["skip_scan"]: print(f"  {R}[!] Target seems dead -> full scan will be skipped (use --force to override){RST}")
    return result

def phase_passive(domain, workspace, api_keys, available):
    pdir = Path(workspace) / domain / "passive"
    mkd(pdir)
    collected, logs, source_files = set(), [], []
    prog = PhaseProgress("1 -> Passive Subdomain Enumeration", 4)
    try:
        # 1. Subfinder
        if "subfinder" in available:
            outf = pdir / f"{domain}_subfinder.txt"
            cmd = f"subfinder -d {q(domain)} -silent -recursive -all -rl 10 -timeout 30 -max-time 20 -o {q(outf)}"
            _, out, err = run_cmd(cmd, timeout=600, tool_name="subfinder")
            lines = rlines(outf) if outf.exists() else out.splitlines()
            parsed = {cleanup_sub(l, domain) for l in lines}
            parsed = {x for x in parsed if x}
            wlines(outf, parsed, auto_cleanup=False)
            collected.update(parsed)
            logs.append({"tool": "subfinder", "count": len(parsed), "stderr": err[:200]})
            source_files.append(outf)
            prog.step(f"subfinder -> {G}{len(parsed)}{RST} subs")
        else:
            prog.step("subfinder -> skipped")

        # 2. Chaos
        if api_keys.get("CHAOS_API_KEY") and "chaos" in available:
            outf = pdir / f"{domain}_chaos.txt"
            cmd = f"chaos -d {q(domain)} -silent -key {q(api_keys['CHAOS_API_KEY'])}"
            _, out, err = run_cmd(cmd, timeout=480, tool_name="chaos")
            parsed = {cleanup_sub(l, domain) for l in out.splitlines()}
            parsed = {x for x in parsed if x}
            wlines(outf, parsed, auto_cleanup=False)
            collected.update(parsed)
            logs.append({"tool": "chaos", "count": len(parsed), "stderr": err[:200]})
            source_files.append(outf)
            prog.step(f"chaos -> {G}{len(parsed)}{RST} subs")
        else:
            prog.step("chaos -> skipped")

                # 3. Waymore + unfurl domains (User validated command)
        if "waymore" in available and "unfurl" in available:
            wout_urls = pdir / f"{domain}_waymore_urls.txt"
            wout_subs = pdir / f"{domain}_waymore_subs.txt"
            
            # Step 1: Run waymore (without hiding errors so we can debug if needed)
            cmd1 = f"waymore -i {q(domain)} -mode U -oU {q(wout_urls)} -t 30"
            run_cmd(cmd1, timeout=600, tool_name="waymore")
            
            # Step 2: Process URLs to extract subdomains (Exact user command)
            if wout_urls.exists() and not is_file_empty(wout_urls):
                cmd2 = f"cat {q(wout_urls)} 2>/dev/null | unfurl domains | grep -Ei '(^|\\.){domain}$' | sort -u > {q(wout_subs)}"
                run_cmd(cmd2, timeout=120, tool_name="cat")
                
                if wout_subs.exists() and not is_file_empty(wout_subs):
                    parsed = {cleanup_sub(l, domain) for l in rlines(wout_subs)}
                    parsed = {x for x in parsed if x}
                    collected.update(parsed)
                    logs.append({"tool": "waymore+unfurl", "count": len(parsed)})
                    source_files.append(wout_subs)
                    prog.step(f"waymore+unfurl -> {G}{len(parsed)}{RST} subs")
                else:
                    prog.step("waymore+unfurl -> no output")
            else:
                prog.step("waymore+unfurl -> no output")
        else:
            prog.step("waymore+unfurl -> skipped")

        # Merge
        allsubs = pdir / "allsubs.txt"
        wlines(allsubs, collected, auto_cleanup=False)
        prog.step(f"merge -> {allsubs.name} ({G}{len(collected)}{RST})")
        cleanup_after_merge([f for f in source_files if f.exists()], label="passive-source")

        # High-value subs
        sensitive = [s for s in collected if s.split(".")[0] in SENSITIVE_PREFIXES]
        hv = pdir / "high_value_subs.txt"
        wlines(hv, sensitive)
        if not is_file_empty(hv):
            print(f"  {G}✓{RST} high_value_subs.txt -> {Y}{len(sensitive)}{RST} entries")
        else:
            log_warn("No high-value subdomains found")
        prog.done_phase()
        print(f"  {BOLD}Total subdomains:{RST} {G}{len(collected)}{RST}")
        print(f"  {BOLD}High-value subs :{RST} {Y}{len(sensitive)}{RST}")
        if args_verbose:
            show_file_content(allsubs, "allsubs.txt", max_lines=30)
            if not is_file_empty(hv):
                show_file_content(hv, "high_value_subs.txt", max_lines=20)
        return {
            "allsubs_file": str(allsubs),
            "all_subdomains": sorted(collected),
            "sensitive_subs": sorted(sensitive),
            "tool_logs": logs,
        }
    except KeyboardInterrupt:
        log_warn("Phase 1 skipped")
        return {"allsubs_file": str(pdir / "allsubs.txt"), "all_subdomains": [], "sensitive_subs": [], "tool_logs": []}


# ============================================================================
# PHASE 2: WAF DETECTION
# ============================================================================
def phase_waf(domain, workspace, available):
    global GLOBAL_WAF_TYPE
    pdir = Path(workspace) / domain / "passive"
    wdir = Path(workspace) / domain / "waf"
    mkd(wdir)
    high_val = pdir / "high_value_subs.txt"
    prog = PhaseProgress("2 -> WAF Detection", 3)
    detected = "default"
    waf_simple = wdir / "waf-detected.txt"
    try:
        httpx_bin = "httpx" if "httpx" in available else ("httpx-toolkit" if "httpx-toolkit" in available else None)
        if httpx_bin and high_val.exists() and not is_file_empty(high_val):
            out = wdir / "httpx-waf.txt"
            # AI Optimization for httpx
            api_key = api_keys_global.get("FREELLMAPI_API_KEY", "")
            context = {"waf_type": detected, "domain": domain}
            original_httpx_cmd = f"{httpx_bin} -l {q(high_val)} -sc -td -cl -server -title -silent -t 15 -rl 8 -timeout 10 -retries 1 -random-agent -o {q(out)}"
            opt_cmd = optimize_tool_command(httpx_bin, original_httpx_cmd, context, api_key)
            cmd = f"{opt_cmd}"
            run_cmd(cmd, timeout=600, tool_name=httpx_bin)
            for line in rlines(out):
                ll = line.lower()
                if "cloudflare" in ll: detected = "cloudflare"; break
                if "akamai" in ll or "edgekey" in ll: detected = "akamai"; break
                if "imperva" in ll or "incapsula" in ll: detected = "imperva"; break
            prog.step(f"httpx scan -> {G}{detected}{RST}")
        else: prog.step("httpx scan -> skipped")
        if detected == "default" and "wafw00f" in available and high_val.exists() and not is_file_empty(high_val):
            out = wdir / "wafw00f.txt"
            cmd = f"wafw00f -i {q(high_val)} -a -T 10 --no-colors 2>/dev/null | tee {q(out)}"
            run_cmd(cmd, timeout=900, tool_name="wafw00f")
            content = (out.read_text(errors="ignore").lower() if out.exists() else "")
            for waf_name, keys in [("cloudflare", ["cloudflare"]), ("akamai", ["akamai", "edgekey"]), ("imperva", ["imperva", "incapsula"])]:
                if any(k in content for k in keys): detected = waf_name; break
            prog.step(f"wafw00f -> {G}{detected}{RST}")
        else: prog.step("wafw00f -> skipped")
        if detected == "default" and high_val.exists():
            headers_sig = {"cloudflare": ["cf-ray", "cf-cache-status"], "akamai": ["akamai-grn", "x-akamai-transformed"], "imperva": ["x-cdn", "incap-signal"], "sucuri": ["x-sucuri-id", "x-sucuri-cache"], "aws": ["x-amz-cf-id"]}
            for host in rlines(high_val)[:10]:
                try:
                    url = host if host.startswith("http") else f"https://{host}"
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(req, timeout=5) as res:
                        hdr_str = str({k.lower(): v for k, v in res.headers.items()}).lower()
                        for waf_name, indicators in headers_sig.items():
                            if any(ind in hdr_str for ind in indicators): detected = waf_name; break
                        if detected != "default": break
                except Exception: continue
            prog.step(f"header analysis -> {G}{detected}{RST}")
        else: prog.step("header analysis -> skipped")
        if detected != "default":
            wlines(waf_simple, [f"WAF Detected: {detected.upper()}"], auto_cleanup=False)
            print(f"  {G}v{RST} Saved to {waf_simple.name}")
            GLOBAL_WAF_TYPE = detected
            try:
                ai_memory.set_target_waf(GLOBAL_AI_CONTEXT.get("domain", ""), detected)
            except Exception:
                pass
            # Also update in-memory state
            try:
                from ai_orchestrator import _categorize_waf as _cat_waf
                _state["waf"] = detected
                _state["waf_category"] = _cat_waf(detected)
                state.save_state(workspace, domain, _state)
            except Exception:
                pass
        prog.done_phase()
        print(f"{C}[*] WAF Type: {detected.upper()}{RST}")
        return {"waf_file": str(waf_simple) if waf_simple.exists() else None, "waf_type": detected}
    except KeyboardInterrupt:
        log_warn("Phase 2 skipped"); GLOBAL_WAF_TYPE = "default"
        return {"waf_file": None, "waf_type": "default"}

# ============================================================================
# PHASE 3, 4, 5, 6, 7
# ============================================================================
def phase_active_subs(domain, workspace, available):
    if not ask_phase("Run active subdomain enumeration"):
        log_warn("Active subdomain enumeration skipped by user")
        return {"active_subs_file": "", "active_count": 0, "_skipped": True}
    pdir = Path(workspace) / domain / "passive"
    adir = Path(workspace) / domain / "active_subs"
    mkd(adir)
    allsubs_in = pdir / "allsubs.txt"
    existing = set(rlines(allsubs_in)) if allsubs_in.exists() else set()
    discovered = set()
    prog = PhaseProgress("3 -> Active Subdomain Enumeration", 4)
    try:
        if "puredns" in available:
            wl = ensure_essential_file("wordlist", args_wordlist) or args_wordlist
            res = ensure_essential_file("resolvers", args_resolvers) or args_resolvers
            if wl and Path(wl).exists() and res and Path(res).exists():
                outf = adir / "puredns.txt"
                log_info(f"🤖 Executing puredns with AI (reading --help)...")
                api_key = api_keys_global.get("FREELLMAPI_API_KEY", "")
                returncode, stdout, stderr = execute_puredns_smart(
                    domain, q(wl), q(res), q(outf), GLOBAL_WAF_TYPE, api_key
                )
                parsed = {cleanup_sub(l, domain) for l in rlines(outf)}
                parsed = {x for x in parsed if x}
                discovered.update(parsed)
                prog.step(f"puredns -> {G}{len(parsed)}{RST} subs")
            else:
                prog.step("puredns -> skipped (no wordlist/resolvers)")

        if "altdns" in available and existing:
            perm_in = adir / "altdns_in.txt"
            perm_out = adir / "altdns_out.txt"
            wlines(perm_in, list(existing)[:500], auto_cleanup=False)
            # AI Optimization for altdns
            api_key = api_keys_global.get("FREELLMAPI_API_KEY", "")
            context = {"waf_type": GLOBAL_WAF_TYPE, "domain": domain}
            original_altdns_cmd = f"altdns -i {q(perm_in)} -o {q(perm_out)}"
            opt_cmd = optimize_tool_command("altdns", original_altdns_cmd, context, api_key)
            cmd = f"{opt_cmd} 2>/dev/null || true"
            run_cmd(cmd, timeout=600, tool_name="altdns")
            if perm_out.exists() and not is_file_empty(perm_out) and "dnsx" in available:
                resolved = adir / "altdns_resolved.txt"
                cmd2 = f"dnsx -l {q(perm_out)} -silent -a -resp-only -r 8.8.8.8,1.1.1.1 -o {q(resolved)}"
                run_cmd(cmd2, timeout=600, tool_name="dnsx")
                parsed = {cleanup_sub(l, domain) for l in rlines(resolved)}; parsed = {x for x in parsed if x}
                discovered.update(parsed); prog.step(f"altdns+dnsx -> {G}{len(parsed)}{RST} permutations")
            else: prog.step("altdns -> 0 permutations")
        else: prog.step("altdns -> skipped")
        if "dnsrecon" in available:
            outf = adir / "dnsrecon.txt"
            cmd = f"dnsrecon -d {q(domain)} -t axfr 2>/dev/null || true"
            _, out, _ = run_cmd(cmd, timeout=300, tool_name="dnsrecon")
            parsed = set()
            for line in out.splitlines():
                for token in re.findall(r'[a-z0-9.-]+\.' + re.escape(domain), line.lower()):
                    c = cleanup_sub(token, domain)
                    if c: parsed.add(c)
            wlines(outf, parsed, auto_cleanup=False); discovered.update(parsed)
            prog.step(f"dnsrecon AXFR -> {G}{len(parsed)}{RST} subs")
        else: prog.step("dnsrecon -> skipped")
        final = existing | discovered
        allsubs_final = pdir / "allsubs_final.txt"
        wlines(allsubs_final, final, auto_cleanup=False)
        prog.step(f"merge -> allsubs_final.txt ({G}{len(final)}{RST} total)")
        prog.done_phase()
        log_ok(f"Active subs new: {len(discovered)} | Total: {len(final)}")
        return {"active_subs_file": str(allsubs_final), "active_count": len(discovered)}
    except KeyboardInterrupt:
        log_warn("Phase 3 skipped")
        return {"active_subs_file": str(pdir / "allsubs_final.txt"), "active_count": 0}

def phase_dns_resolution(domain, workspace, available):
    pdir = Path(workspace) / domain / "passive"
    ddir = Path(workspace) / domain / "dns"
    mkd(ddir)
    allsubs = pdir / "allsubs_final.txt"
    if not allsubs.exists(): allsubs = pdir / "allsubs.txt"
    prog = PhaseProgress("4 -> DNS Resolution", 1)
    resolved = ddir / "resolved.txt"
    try:
        if "dnsx" in available and allsubs.exists() and not is_file_empty(allsubs):
            cmd = f"dnsx -l {q(allsubs)} -silent -a -r 8.8.8.8,1.1.1.1,8.8.4.4 -t 100 -rl 200 -resp-only -o {q(resolved)}"
            run_cmd(cmd, timeout=300, tool_name="dnsx")
            count = len(rlines(resolved))
            if count > 0: print(f"  {G}v{RST} resolved.txt -> {count} alive subdomains"); prog.step(f"dnsx resolution -> {G}{count}{RST} hosts")
            else:
                if allsubs.exists(): shutil.copy2(allsubs, resolved); prog.step("dnsx -> skipped (using allsubs)")
        prog.done_phase()
        return {"resolved_file": str(resolved) if resolved.exists() else ""}
    except KeyboardInterrupt: log_warn("Phase 4 skipped"); return {"resolved_file": ""}

def phase_response_filter(domain, workspace, passive, available):
    adir = Path(workspace) / domain / "active"
    mkd(adir)
    pdir = Path(workspace) / domain / "passive"
    ddir = Path(workspace) / domain / "dns"
    resolved = ddir / "resolved.txt"
    input_file = resolved if resolved.exists() and not is_file_empty(resolved) else (pdir / "allsubs_final.txt")
    if not input_file.exists() or is_file_empty(input_file): input_file = pdir / "allsubs.txt"
    if not input_file.exists() or is_file_empty(input_file):
        input_file = adir / "_seeded_target.txt"
        _scheme = _guess_scheme_for_port(GLOBAL_TARGET_PORT) if GLOBAL_TARGET_PORT else "https://"
        _seed_line = f"{_scheme}{domain}\n"
        input_file.write_text(_seed_line, encoding="utf-8")
        print(f"  {Y}[!]{RST} No subdomains found -> seeding with: {_seed_line.strip()}")
    high_val = pdir / "high_value_subs.txt"
    prog = PhaseProgress("5 -> Response Filtering", 6)
    results = {"alive": [], "f403": [], "f404": [], "details": []}
    httpx_bin = "httpx" if "httpx" in available else ("httpx-toolkit" if "httpx-toolkit" in available else None)
    waf_type = detect_waf_from_file(workspace, domain)
    httpx_opts = get_tool_options("httpx", waf_type)
    try:
        if httpx_bin and high_val.exists() and not is_file_empty(high_val):
            out = adir / "details.txt"
            cmd = f"{httpx_bin} -l {q(high_val)} -sc -td -cl -server -title -ip -silent -t 15 -rl 8 -timeout 7 -retries 1 -random-agent -follow-redirects -p {_merge_port_into_list(HTTPX_PORTS, GLOBAL_TARGET_PORT)} {httpx_opts} -o {q(out)}"
            run_cmd(cmd, timeout=600, tool_name=httpx_bin)
            results["details"] = rlines(out); prog.step(f"high-value details -> {G}{len(results['details'])}{RST}")
        else: prog.step("high-value details -> skipped")
        if httpx_bin and input_file.exists() and not is_file_empty(input_file):
            out = adir / "alive.txt"
            cmd = f"{httpx_bin} -l {q(input_file)} -mc {HTTPX_STATUS_CODES} -silent -t 20 -rl 5 -timeout 7 -retries 1 -random-agent -follow-redirects -p {_merge_port_into_list(HTTPX_PORTS, GLOBAL_TARGET_PORT)} {httpx_opts} -o {q(out)}"
            run_cmd(cmd, timeout=1200, tool_name=httpx_bin)
            results["alive"] = rlines(out); prog.step(f"alive (extended) -> {G}{len(results['alive'])}{RST}")
        else: prog.step("alive -> skipped")
        if httpx_bin and input_file.exists() and not is_file_empty(input_file):
            out = adir / "403subs.txt"
            cmd = f"{httpx_bin} -l {q(input_file)} -mc 403 -silent -t 15 -rl 8 -timeout 7 -retries 1 -random-agent -follow-redirects {httpx_opts} -o {q(out)}"
            run_cmd(cmd, timeout=600, tool_name=httpx_bin)
            results["f403"] = rlines(out); prog.step(f"403 filter -> {Y}{len(results['f403'])}{RST}")
        else: prog.step("403 filter -> skipped")
        if httpx_bin and input_file.exists() and not is_file_empty(input_file):
            out = adir / "404subs.txt"
            cmd = f"{httpx_bin} -l {q(input_file)} -mc 404 -silent -t 15 -rl 8 -timeout 7 -retries 1 -random-agent -follow-redirects {httpx_opts} -o {q(out)}"
            run_cmd(cmd, timeout=600, tool_name=httpx_bin)
            results["f404"] = rlines(out); prog.step(f"404 filter -> {R}{len(results['f404'])}{RST}")
        else: prog.step("404 filter -> skipped")
        success = adir / "success-response.txt"
        wlines(success, results["alive"], auto_cleanup=False)
        prog.step(f"success-response.txt -> {G}{len(results['alive'])}{RST}")
        prog.done_phase()
        if args_verbose: show_file_content(success, "success-response.txt", max_lines=30)
        return results
    except KeyboardInterrupt: log_warn("Phase 5 skipped"); return results

def phase_tech_detect(domain, workspace, available):
    adir = Path(workspace) / domain / "active"
    sucf = adir / "success-response.txt"
    techf = adir / "subs-Tech.txt"
    ipsf = adir / "ips.txt"
    alivef = adir / "alive-final.txt"
    prog = PhaseProgress("6 -> Technology Detection", 3)
    httpx_bin = "httpx" if "httpx" in available else ("httpx-toolkit" if "httpx-toolkit" in available else None)
    httpx_opts = get_tool_options("httpx", GLOBAL_WAF_TYPE)
    try:
        if httpx_bin and sucf.exists() and not is_file_empty(sucf):
            cmd = f"{httpx_bin} -l {q(sucf)} -sc -td -cl -server -title -ip -silent -t 15 -rl 8 -timeout 10 -retries 1 -random-agent -p {_merge_port_into_list(HTTPX_PORTS, GLOBAL_TARGET_PORT)} {httpx_opts} -o {q(techf)}"
            run_cmd(cmd, timeout=1200, tool_name=httpx_bin); prog.step(f"httpx tech detection -> {techf.name}")
        else: prog.step("httpx tech -> skipped")
        if techf.exists() and not is_file_empty(techf):
            raw = techf.read_text(errors="ignore")
            ips = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw))
            wlines(ipsf, ips); prog.step(f"IP extraction -> {G}{len(ips)}{RST}")
        else: prog.step("IP extraction -> skipped")
        if techf.exists() and not is_file_empty(techf):
            alive = []
            for line in rlines(techf):
                m = re.search(r'\[(200|201|202|204|301|302|303|307|308)\]', line)
                if m:
                    url_match = re.search(r'https?://\S+', line)
                    if url_match: alive.append(url_match.group(0))
            wlines(alivef, alive); prog.step(f"alive-final -> {G}{len(alive)}{RST}")
        else: prog.step("alive-final -> skipped")
        prog.done_phase()
        if args_verbose and techf.exists(): show_file_content(techf, "subs-Tech.txt", max_lines=30)
        return {"ips_file": str(ipsf), "alive_final": str(alivef)}
    except KeyboardInterrupt: log_warn("Phase 6 skipped"); return {"ips_file": "", "alive_final": ""}

def phase_takeover(domain, workspace, available):
    adir = Path(workspace) / domain / "active"
    tdir = Path(workspace) / domain / "takeover"
    mkd(tdir)
    f404 = adir / "404subs.txt"
    prog = PhaseProgress("7 -> Subdomain Takeover", 3)
    findings = []
    try:
        if "subzy" in available and f404.exists() and not is_file_empty(f404):
            outf = tdir / "subzy-results.txt"
            cmd = f"subzy run --targets {q(f404)} --concurrency 5 --timeout 8 --hide_fails 2>/dev/null | tee {q(outf)}"
            run_cmd(cmd, timeout=600, tool_name="subzy")
            if not is_file_empty(outf):
                # Filter out subzy progress logs, keep only actual vulnerabilities
                real_findings = [l for l in rlines(outf) if 'VULNERABLE' in l.upper()]
                findings.extend(real_findings)
                prog.step(f"subzy -> {G}{len(real_findings)}{RST} (filtered)")
            else:
                prog.step("subzy -> skipped")
        if "subjack" in available and f404.exists() and not is_file_empty(f404):
            outf = tdir / "subjack-results.json"
            cmd = f"subjack -w {q(f404)} -t 8 -timeout 10 -ssl -o {q(outf)} 2>/dev/null"
            run_cmd(cmd, timeout=600, tool_name="subjack")
            if not is_file_empty(outf): findings.extend(rlines(outf)); prog.step(f"subjack -> {G}{len(rlines(outf))}{RST}")
            else: prog.step("subjack -> skipped")
        if "nuclei" in available and f404.exists() and not is_file_empty(f404):
            outf = tdir / "nuclei-takeover.txt"
            cmd = f"nuclei -list {q(f404)} -tags takeover -silent -rl 10 -c 5 -timeout 8 -retries 1 -no-interactsh 2>/dev/null | tee {q(outf)}"
            run_cmd(cmd, timeout=1200, tool_name="nuclei")
            if not is_file_empty(outf): findings.extend(rlines(outf)); prog.step(f"nuclei takeover -> {G}{len(rlines(outf))}{RST}")
            else: prog.step("nuclei takeover -> skipped")
        prog.done_phase()
        if findings: print(f"  {R}{BOLD}x {len(findings)} potential takeover(s) found{RST}")
        return {"takeover_dir": str(tdir), "findings": findings}
    except KeyboardInterrupt: log_warn("Phase 7 skipped"); return {"takeover_dir": str(tdir), "findings": []}

# ============================================================================
# PHASE 8, 9, 10, 11, 12, 13
# ============================================================================
def _cors_one(url):
    try:
        req = urllib.request.Request(url, headers={"Origin": "https://evil-clicker-probe.com", "User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=4) as res:
            acao = res.headers.get("Access-Control-Allow-Origin", "")
            acac = res.headers.get("Access-Control-Allow-Credentials", "")
            if acao in ("https://evil-clicker-probe.com", "*"):
                severity = "HIGH" if (acac.lower() == "true" and acao != "*") else "MEDIUM"
                return f"{url} | {severity} | ACAO={acao} ACAC={acac}"
    except Exception: pass
    return None

def _exposed_one(base_url):
    out = []
    for path in EXPOSED_FILE_PATHS:
        url = base_url.rstrip("/") + path
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=3) as res:
                if res.status != 200:
                    continue

                ct = (res.headers.get("Content-Type") or "").lower()
                body = res.read(1024)
                body_lower = body.lower()
                is_html = (b"<html" in body_lower or b"<!doctype" in body_lower or b"<head" in body_lower)
                expects_html = path.endswith((".html", ".htm", "/"))

                # SPA fallback: server returns HTML for everything → false positive
                if is_html and not expects_html:
                    continue
                if "text/html" in ct and not expects_html:
                    continue

                # Path-specific content validation
                if path == "/.git/HEAD" and b"ref:" not in body_lower:
                    continue
                if path.endswith(".env") and b"=" not in body:
                    continue
                if path == "/.ssh/id_rsa" and b"private key" not in body_lower and b"-----begin" not in body_lower:
                    continue
                if path == "/.ssh/id_rsa.pub" and b"ssh-rsa" not in body_lower and b"ssh-ed25519" not in body_lower:
                    continue
                if path == "/id_rsa" and b"private key" not in body_lower and b"-----begin" not in body_lower:
                    continue
                if path == "/id_rsa.pub" and b"ssh-rsa" not in body_lower and b"ssh-ed25519" not in body_lower:
                    continue
                if path == "/.htpasswd" and b":" not in body:
                    continue
                if path == "/.gitconfig" and b"[" not in body:
                    continue
                if path == "/.gitignore" and (b"# " not in body and b"/" not in body and b"*" not in body):
                    continue
                if path == "/.dockerignore" and is_html:
                    continue
                if path == "/Dockerfile" and (b"FROM" not in body and b"#" not in body):
                    continue
                if path.endswith((".sql", "/backup.sql", "/dump.sql", "/database.sql", "/db.sql")):
                    if not any(m in body for m in (b"INSERT", b"CREATE", b"--", b"DROP", b"SELECT")):
                        continue
                if path.endswith((".db", ".sqlite", ".sqlite3")):
                    # Binary SQLite starts with "SQLite format 3"
                    if b"sqlite" not in body_lower[:50] and b"\x00" not in body[:20]:
                        continue
                if path.endswith(".bak") or path.endswith(".old") or path.endswith(".orig"):
                    # Generic backup — should not be HTML for config files
                    if is_html and not path.endswith((".html", ".htm")):
                        continue

                out.append(f"{url} [200]")
        except urllib.error.HTTPError:
            continue
        except Exception:
            continue
    return out

def phase_vuln_scan(domain, workspace, available):
    if not ask_phase("Run vulnerability scanning"):
        log_warn("Vulnerability scan skipped by user")
        return {"nuclei": [], "cors": [], "exposed": [], "_skipped": True}
    adir = Path(workspace) / domain / "active"
    vdir = Path(workspace) / domain / "vulns"
    mkd(vdir)
    alivef = adir / "alive-final.txt"
    prog = PhaseProgress("8 -> Vulnerability Scanning", 3)
    results = {"nuclei": [], "cors": [], "exposed": []}
    try:
        if "nuclei" in available and alivef.exists() and not is_file_empty(alivef):
            outf = vdir / "nuclei-results.txt"
            cmd = f"nuclei -list {q(alivef)} -severity critical,high -tags cve,exposure,misconfig -silent -rl 50 -c 25 -timeout 6 -retries 1 -no-interactsh -stats -stats-interval 15 -o {q(outf)} 2>&1 | grep -vE '^\\[INF\\]|^\\[WRN\\]' || true"
            print(f"  {DIM}Running nuclei (this may take a few minutes)...{RST}")
            run_cmd(cmd, timeout=900, tool_name="nuclei")
            if not is_file_empty(outf): results["nuclei"] = rlines(outf); prog.step(f"nuclei -> {G}{len(results['nuclei'])}{RST} findings")
            else: prog.step("nuclei -> skipped")
        hosts_to_check = []
        if alivef.exists() and not is_file_empty(alivef):
            for line in rlines(alivef):
                m = re.search(r'https?://\S+', line)
                if m: hosts_to_check.append(m.group(0))
                elif line.startswith(("http://", "https://")): hosts_to_check.append(line)
        seen = set()
        hosts_to_check = [h for h in hosts_to_check if not (h in seen or seen.add(h))]
        cors_findings = []
        if hosts_to_check:
            print(f"  {DIM}Checking CORS on {len(hosts_to_check)} host(s) (parallel)...{RST}")
            with ThreadPoolExecutor(max_workers=10) as ex:
                futures = {ex.submit(_cors_one, u): u for u in hosts_to_check[:30]}
                for fut in as_completed(futures):
                    try:
                        r = fut.result()
                        if r: cors_findings.append(r)
                    except Exception: continue
            if cors_findings:
                wlines(vdir / "cors.txt", cors_findings, auto_cleanup=False)
                results["cors"] = cors_findings; prog.step(f"CORS check -> {G}{len(cors_findings)}{RST}")
        exposed = []
        targets_exposed = hosts_to_check[:15]
        if targets_exposed:
            print(f"  {DIM}Checking exposed files on {len(targets_exposed)} host(s) (parallel)...{RST}")
            with ThreadPoolExecutor(max_workers=10) as ex:
                futures = {ex.submit(_exposed_one, u): u for u in targets_exposed}
                for fut in as_completed(futures):
                    try: exposed.extend(fut.result())
                    except Exception: continue
            if exposed:
                wlines(vdir / "exposed-files.txt", exposed, auto_cleanup=False)
                results["exposed"] = exposed; prog.step(f"Exposed files -> {G}{len(exposed)}{RST}")
        prog.done_phase()
        if args_verbose:
            if results["nuclei"]: show_file_content(vdir / "nuclei-results.txt", "nuclei-results.txt", max_lines=30)
            if results["cors"]: show_file_content(vdir / "cors.txt", "cors.txt", max_lines=20)
            if results["exposed"]: show_file_content(vdir / "exposed-files.txt", "exposed-files.txt", max_lines=20)
        return results
    except KeyboardInterrupt: log_warn("Phase 8 skipped"); return results

def phase_ports(domain, workspace, available):
    adir = Path(workspace) / domain / "active"
    pdir = Path(workspace) / domain / "passive"
    ipsf = adir / "ips.txt"
    allsubs = pdir / "allsubs_final.txt"
    if not allsubs.exists(): allsubs = pdir / "allsubs.txt"
    real_ips = adir / "real-ips.txt"
    open_ports_txt = adir / "open-ports-full.txt"
    nmap_results = adir / "nmap-scripts.txt"
    prog = PhaseProgress("9 -> Port Scanning", 5)
    naabu_opts = get_tool_options("naabu", GLOBAL_WAF_TYPE)
    nmap_opts = get_tool_options("nmap", GLOBAL_WAF_TYPE)
    try:
        resolved = adir / "resolved-ips.txt"
        if "dnsx" in available and allsubs.exists() and not is_file_empty(allsubs):
            cmd = f"dnsx -l {q(allsubs)} -resp-only -a -silent -t 100 -r 8.8.8.8,1.1.1.1 -o {q(resolved)}"
            run_cmd(cmd, timeout=300, tool_name="dnsx"); prog.step("dnsx resolve all subdomains")
        else: prog.step("dnsx -> skipped")
        all_ips = adir / "all-ips-final.txt"
        merge_src = [str(ipsf), str(resolved)]
        merge_src = [s for s in merge_src if Path(s).exists()]
        if merge_src:
            cmd = f"cat {' '.join(q(s) for s in merge_src)} 2>/dev/null | sort -u > {q(all_ips)}"
            run_cmd(cmd, timeout=60, tool_name="cat"); prog.step(f"merge all IPs -> {len(rlines(all_ips))}")
        else: all_ips.touch(); prog.step("merge all IPs -> empty")
        if not is_file_empty(all_ips) and "cdncheck" in available:
            cdn_res = adir / "cdn-results.txt"
            cmd = f"cat {q(all_ips)} | cdncheck -silent -resp -r 8.8.8.8,1.1.1.1 -o {q(cdn_res)}"
            run_cmd(cmd, timeout=180, tool_name="cdncheck")
            cmd2 = f"cat {q(all_ips)} | cdncheck -silent -resp -r 8.8.8.8,1.1.1.1 | grep -ivE 'cloudflare|akamai|fastly|cloudfront|incapsula|sucuri|aws|azure|google' | awk '{{print $1}}' | sort -u > {q(real_ips)}"
            run_cmd(cmd2, timeout=180, tool_name="cdncheck")
            if not is_file_empty(real_ips): print(f"  {G}v{RST} real-ips.txt -> {len(rlines(real_ips))} non-CDN IPs"); prog.step("CDN filtering")
            else:
                if all_ips.exists(): real_ips.write_text(all_ips.read_text())
                else: real_ips.touch()
                prog.step("CDN filtering -> skipped")
        if "naabu" in available and real_ips.exists() and not is_file_empty(real_ips):
            json_out = adir / "open-ports.json"
            cmd = f"naabu -list {q(real_ips)} -p {PORTS_COMMON} -rate 300 -c 25 -retries 1 -timeout 1000 -Pn -s s -verify -silent -json {naabu_opts} -o {q(json_out)}"
            run_cmd(cmd, timeout=1200, tool_name="naabu")
            formatted = []
            if json_out.exists():
                for line in rlines(json_out):
                    try:
                        entry = json.loads(line)
                        host = entry.get("host", entry.get("input", ""))
                        port = entry.get("port", "")
                        proto = entry.get("protocol", "tcp").upper()
                        formatted.append(f"{host}:{port}/{proto}")
                    except Exception: continue
            if formatted:
                wlines(open_ports_txt, formatted, auto_cleanup=False)
                print(f"  {G}v{RST} open-ports-full.txt -> {len(formatted)} ports")
                cleanup_empty_file(json_out, "raw-json"); prog.step(f"naabu scan -> {G}{len(formatted)}{RST} ports")
            else: prog.step("naabu -> skipped")
        if "nmap" in available and open_ports_txt.exists() and not is_file_empty(open_ports_txt):
            ips_to_scan = set()
            for line in rlines(open_ports_txt):
                m = re.match(r"([^:/]+):\d+", line)
                if m: ips_to_scan.add(m.group(1))
            if ips_to_scan:
                ip_list = adir / "nmap-targets.txt"
                wlines(ip_list, ips_to_scan, auto_cleanup=False)
                nmap_prefix = adir / "nmap-scripts"
                cmd = f"nmap -iL {q(ip_list)} -sC -sV --open -T4 -Pn -n --version-light --max-retries 1 --host-timeout 10m {nmap_opts} -p 21,22,23,25,53,80,443,3306,3389,5432,6379,8080,8443,9200,27017 -oA {q(nmap_prefix)}"
                run_cmd(cmd, timeout=1800, tool_name="nmap")
                nmap_file = adir / "nmap-scripts.nmap"
                if nmap_file.exists():
                    cmd2 = f"grep -iE 'vuln|CVE-|sqli|xss|injection|exploit|weak|anonymous|auth.*bypass|misconfig' {q(nmap_file)} | grep -vE '^#|^Nmap|^Host:|^Port:' | sort -u > {q(nmap_results)}"
                    run_cmd(cmd2, timeout=300, tool_name="grep")
                    if not is_file_empty(nmap_results): print(f"  {G}v{RST} nmap-scripts.txt -> {len(rlines(nmap_results))} findings"); prog.step("nmap -sC vuln scan")
                    else: prog.step("nmap -> skipped")
        prog.done_phase()
        if args_verbose and not is_file_empty(open_ports_txt): show_file_content(open_ports_txt, "open-ports-full.txt", max_lines=40)
        return {"open_ports_file": str(open_ports_txt) if open_ports_txt.exists() else None}
    except KeyboardInterrupt: log_warn("Phase 9 skipped"); return {"open_ports_file": None}

def phase_leakix(domain, workspace, available):
    adir = Path(workspace) / domain / "active"
    ldir = Path(workspace) / domain / "leakix"
    mkd(ldir)
    ipsf = adir / "ips.txt"
    alivef = adir / "alive-final.txt"
    prog = PhaseProgress("10 -> LeakIX Exposure Check", 2)
    key = api_keys_global.get("LEAKIX_API", "")
    out_ips = ldir / "leakix-ips.txt"
    out_doms = ldir / "leakix-domains.txt"
    try:
        if not key: prog.step("LeakIX -> skipped (no API key)"); prog.step("LeakIX -> skipped (no API key)"); prog.done_phase(); return {"leakix_ips": "", "leakix_domains": ""}
        if "curl" in available and "jq" in available and ipsf.exists() and not is_file_empty(ipsf):
            ips = [ip for ip in rlines(ipsf) if validate_ip(ip)][:30]
            findings = []
            for ip in ips:
                try:
                    url = f"https://leakix.net/host/{ip}"
                    cmd = f"curl -s --max-time 10 -H {q('api-key: ' + key)} -H 'Accept: application/json' {q(url)}"
                    _, out, _ = run_cmd(cmd, timeout=15, tool_name="curl")
                    if not out or '"error"' in out: continue
                    try: data = json.loads(out)
                    except Exception: continue
                    for svc in data.get("Services", []) or []:
                        leak = svc.get("leak") or {}
                        if leak.get("type") or leak.get("details"): findings.append(f"{ip} | port {svc.get('port')} | {svc.get('protocol','')} | leak={leak.get('type','')} | {svc.get('software', {}).get('name','')}")
                except Exception: continue
                time.sleep(0.5)
            if findings: wlines(out_ips, findings, auto_cleanup=False); print(f"  {G}v{RST} leakix-ips.txt -> {len(findings)} findings"); prog.step(f"LeakIX IP scan -> {G}{len(findings)}{RST}")
            else: prog.step("LeakIX IP scan -> skipped")
        if "curl" in available and "jq" in available and alivef.exists() and not is_file_empty(alivef):
            doms = set()
            for line in rlines(alivef)[:30]:
                try:
                    h = urlparse(line if "://" in line else "https://" + line).hostname
                    if h: doms.add(h)
                except Exception: continue
            findings = []
            for d in list(doms)[:20]:
                try:
                    url = f"https://leakix.net/domain/{d}"
                    cmd = f"curl -s --max-time 10 -H {q('api-key: ' + key)} -H 'Accept: application/json' {q(url)}"
                    _, out, _ = run_cmd(cmd, timeout=15, tool_name="curl")
                    if not out or '"error"' in out: continue
                    try: data = json.loads(out)
                    except Exception: continue
                    for svc in data.get("Services", []) or []:
                        leak = svc.get("leak") or {}
                        if leak.get("type") or leak.get("details"): findings.append(f"{d} | port {svc.get('port')} | leak={leak.get('type','')}")
                except Exception: continue
                time.sleep(0.5)
            if findings: wlines(out_doms, findings, auto_cleanup=False); print(f"  {G}v{RST} leakix-domains.txt -> {len(findings)} findings"); prog.step(f"LeakIX domain scan -> {G}{len(findings)}{RST}")
            else: prog.step("LeakIX domain scan -> skipped")
        prog.done_phase()
        return {"leakix_ips": str(out_ips) if out_ips.exists() else "", "leakix_domains": str(out_doms) if out_doms.exists() else ""}
    except KeyboardInterrupt: log_warn("Phase 10 skipped"); return {"leakix_ips": "", "leakix_domains": ""}

def phase_content_discovery(domain, workspace, available):
    adir = Path(workspace) / domain / "active"
    udir = Path(workspace) / domain / "urls"
    mkd(udir)
    alivef = adir / "alive-final.txt"
    prog = PhaseProgress("11 -> Content Discovery", 7)
    url_files = []
    try:
        if "waybackurls" in available and alivef.exists() and not is_file_empty(alivef):
            outf = udir / "waybackurls.txt"
            cmd = f"cat {q(alivef)} | waybackurls 2>/dev/null | grep -vE {q(URL_FILTER_PATTERN)} | sort -u | tee {q(outf)}"
            run_cmd(cmd, timeout=900, tool_name="waybackurls"); url_files.append(outf); prog.step(f"waybackurls -> {G}{len(rlines(outf))}{RST}")
        else: prog.step("waybackurls -> skipped")
        if "gau" in available and alivef.exists() and not is_file_empty(alivef):
            outf = udir / "gau.txt"
            cmd = f"cat {q(alivef)} | gau --threads 5 --timeout 10 --blacklist png,jpg,gif,css,js,ico,svg,woff,woff2,ttf,eot 2>/dev/null | sort -u | tee {q(outf)}"
            run_cmd(cmd, timeout=900, tool_name="gau"); url_files.append(outf); prog.step(f"gau -> {G}{len(rlines(outf))}{RST}")
        else: prog.step("gau -> skipped")
        if "katana" in available and alivef.exists() and not is_file_empty(alivef):
            outf = udir / "katana.txt"
            cmd = f"katana -list {q(alivef)} -d 3 -jc -kf all -silent -c 5 -rl 20 -timeout 10 -retry 1 -o {q(outf)}"
            run_cmd(cmd, timeout=1200, tool_name="katana"); url_files.append(outf); prog.step(f"katana -> {G}{len(rlines(outf))}{RST}")
        else: prog.step("katana -> skipped")
        if "waymore" in available and alivef.exists() and not is_file_empty(alivef):
            outf = udir / "waymore.txt"
            cmd = f"waymore -i {q(alivef)} -mode U -p 3 -oU {q(outf)} --providers wayback,commoncrawl,otx,urlscan -ow 2>/dev/null || true"
            run_cmd(cmd, timeout=1200, tool_name="waymore"); url_files.append(outf); prog.step(f"waymore -> {G}{len(rlines(outf))}{RST}")
        else: prog.step("waymore -> skipped")
        merged_urls = udir / "urls.txt"
        existing = [f for f in url_files if f.exists() and not is_file_empty(f)]
        if existing:
            cmd = f"cat {' '.join(q(str(f)) for f in existing)} 2>/dev/null | sort -u > {q(merged_urls)}"
            run_cmd(cmd, timeout=120, tool_name="cat")
        else: merged_urls.touch()
        prog.step(f"merge URLs -> {G}{len(rlines(merged_urls))}{RST}")
        clean_urls = udir / "clean_urls.txt"
        cmd = f"grep -ivE {q(URL_FILTER_PATTERN)} {q(merged_urls)} 2>/dev/null | sort -u > {q(clean_urls)} || true"
        run_cmd(cmd, timeout=60, tool_name="grep"); prog.step(f"filter media -> {G}{len(rlines(clean_urls))}{RST}")
        final_urls = udir / "final-urls.txt"
        if "uro" in available and clean_urls.exists() and not is_file_empty(clean_urls):
            cmd = f"cat {q(clean_urls)} | uro 2>/dev/null | sort -u > {q(final_urls)} || true"
            run_cmd(cmd, timeout=300, tool_name="uro")
            if is_file_empty(final_urls): shutil.copy2(clean_urls, final_urls); print(f"  {Y}[!]{RST} uro returned empty -> using clean_urls as fallback"); prog.step(f"uro normalization -> {G}{len(rlines(final_urls))}{RST} URLs")
            else: prog.step(f"uro normalization -> {G}{len(rlines(final_urls))}{RST} URLs")
        else:
            if clean_urls.exists(): shutil.copy2(clean_urls, final_urls)
            else: final_urls.touch()
            prog.step(f"final-urls -> {G}{len(rlines(final_urls))}{RST} (no uro)")
        cleanup_after_merge(existing, label="url-source")
        prog.done_phase()
        if args_verbose and not is_file_empty(final_urls): show_file_content(final_urls, "final-urls.txt", max_lines=40)
        return {"final_urls": str(final_urls), "clean_urls": str(clean_urls)}
    except KeyboardInterrupt: log_warn("Phase 11 skipped"); return {"final_urls": "", "clean_urls": ""}

def phase_sensitive_files(domain, workspace, available):
    if not ask_phase("Run fuzzing / sensitive files"):
        log_warn("Sensitive files / fuzzing skipped by user")
        return {"passive": "", "dirsearch": "", "ffuf": "", "_skipped": True}
    udir = Path(workspace) / domain / "urls"
    sdir = Path(workspace) / domain / "sensitive"
    mkd(sdir)
    clean_urls = udir / "clean_urls.txt"
    if not clean_urls.exists(): clean_urls = udir / "final-urls.txt"
    adir = Path(workspace) / domain / "active"
    alivef = adir / "alive-final.txt"
    prog = PhaseProgress("12 -> Sensitive Files", 3)
    results = {"passive": "", "dirsearch": "", "ffuf": ""}
    try:
        if clean_urls.exists() and not is_file_empty(clean_urls):
            outf = sdir / "sensitive_files_passive.txt"
            cmd = f"grep -iE {q(SENSITIVE_EXTENSIONS)} {q(clean_urls)} 2>/dev/null | grep -viE 'sitemap|robots|feed|rss|well-known|content/|news|assets/' | sort -u > {q(outf)} || true"
            run_cmd(cmd, timeout=120, tool_name="grep")
            count = len(rlines(outf))
            if count > 0: results["passive"] = str(outf); print(f"  {G}v{RST} sensitive_files_passive.txt -> {count} potential files"); prog.step(f"passive sensitive files -> {G}{count}{RST}")
            else: prog.step("passive sensitive files -> no URLs")
        if "dirsearch" in available and alivef.exists() and not is_file_empty(alivef):
            base_urls = sdir / "base_urls.txt"
            urls = []
            for line in rlines(alivef)[:10]:
                m = re.search(r'(https?://[^\s]+)', line)
                if m: urls.append(m.group(1))
            if urls:
                wlines(base_urls, urls, auto_cleanup=False)
                outf = sdir / "dirsearch.json"
                wl = ensure_essential_file("dirsearch_wordlist", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
                if not wl: wl = "/usr/share/seclists/Discovery/Web-Content/common.txt"
                cmd = f"dirsearch -l {q(base_urls)} -e {q(FUZZ_EXTENSIONS)} -w {q(wl)} -t 10 --max-rate=5 --delay=0.3 --timeout=8 --retries=1 --random-agent --full-url --exclude-sizes=0B -o {q(outf)} --format=json --log={q(sdir/'dirsearch.log')} 2>/dev/null || true"
                print(f"  {DIM}Running dirsearch on {len(urls)} host(s)...{RST}")
                run_cmd(cmd, timeout=600, tool_name="dirsearch")
                if outf.exists() and not is_file_empty(outf): results["dirsearch"] = str(outf); prog.step(f"dirsearch -> {G}{'done' if results['dirsearch'] else 'no results'}{RST}")
                else: prog.step("dirsearch -> no base URLs")
            else: prog.step("dirsearch -> skipped")
        if "ffuf" in available and alivef.exists() and not is_file_empty(alivef):
            wl = ensure_essential_file("dirsearch_wordlist", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
            if not wl: wl = "/usr/share/seclists/Discovery/Web-Content/common.txt"
            targets = []
            for line in rlines(alivef)[:5]:
                m = re.search(r'(https?://[^\s/]+)', line)
                if m and m.group(1) not in targets: targets.append(m.group(1))
            if targets and Path(wl).exists():
                all_ffuf = []
                for tgt in targets:
                    safe_name = re.sub(r'[^a-zA-Z0-9.-]', '_', tgt.replace("https://", "").replace("http://", ""))
                    outf = sdir / f"ffuf_{safe_name}.json"
                    cmd = f"ffuf -u {q(tgt)}/FUZZ -w {q(wl)} -e {q('.' + FUZZ_EXTENSIONS.replace(',', ',.'))} -D -t 15 -p 0.3-0.8 -rate 10 -timeout 8 -mc 200,204,301,302,307 -fs 0 -c -o {q(outf)} -of json 2>/dev/null || true"
                    print(f"  {DIM}Running ffuf on {tgt}...{RST}")
                    run_cmd(cmd, timeout=600, tool_name="ffuf")
                    if outf.exists() and not is_file_empty(outf): all_ffuf.append(str(outf))
                if all_ffuf: results["ffuf"] = ",".join(all_ffuf); prog.step(f"ffuf -> {G}{len(all_ffuf)}{RST} host(s)")
                else: prog.step("ffuf -> no targets")
            else: prog.step("ffuf -> skipped")
        prog.done_phase()
        return results
    except KeyboardInterrupt: log_warn("Phase 12 skipped"); return results

def phase_js_recon(domain, workspace, available):
    if not ask_phase("Run JS recon"):
        log_warn("JS recon skipped by user")
        return {"js_file": "", "secrets_file": "", "_skipped": True}
    udir = Path(workspace) / domain / "urls"
    jsdir = Path(workspace) / domain / "js"
    mkd(jsdir)
    final_urls = udir / "final-urls.txt"
    clean_urls = udir / "clean_urls.txt"
    adir = Path(workspace) / domain / "active"
    alivef = adir / "alive-final.txt"
    js_file = jsdir / "jsfiles.txt"
    prog = PhaseProgress("13 -> JS Recon & Secrets", 3)
    try:
        source_file = final_urls if final_urls.exists() else clean_urls
        if source_file.exists() and not is_file_empty(source_file):
            cmd = f"grep -iE {q(r'\.js(\?|#|$)')} {q(source_file)} 2>/dev/null | grep -E {q(r'^https?://')} | sort -u > {q(js_file)}"
            run_cmd(cmd, timeout=120, tool_name="grep")
            js_count = len(rlines(js_file)); prog.step(f"JS from URLs -> {G}{js_count}{RST}")
        else: js_count = 0; prog.step("JS from URLs -> no source")
        if "katana" in available and alivef.exists() and not is_file_empty(alivef):
            katana_js = jsdir / "katana_js.txt"
            cmd = f"katana -list {q(alivef)} -jc -d 3 -silent -c 5 -rl 20 -timeout 10 2>/dev/null | grep -iE {q(r'\.js(\?|$)')} | sort -u > {q(katana_js)} || true"
            run_cmd(cmd, timeout=900, tool_name="katana")
            if katana_js.exists() and not is_file_empty(katana_js):
                cmd2 = f"cat {q(js_file)} {q(katana_js)} 2>/dev/null | sort -u > {q(js_file)}.tmp && mv {q(js_file)}.tmp {q(js_file)}"
                run_cmd(cmd2, timeout=60, tool_name="cat")
                new_count = len(rlines(js_file)); prog.step(f"katana JS merge -> {G}{new_count}{RST} total")
            else: prog.step("katana JS -> 0 new")
        else: prog.step("katana JS -> skipped")
        secrets_file = jsdir / "secrets-found.txt"
        if "trufflehog" in available and js_file.exists() and not is_file_empty(js_file):
            outf = jsdir / "trufflehog.txt"
            cmd = f"trufflehog filesystem --no-update --json {q(jsdir)} 2>/dev/null > {q(outf)} || true"
            run_cmd(cmd, timeout=600, tool_name="trufflehog")
            if not is_file_empty(outf): shutil.copy2(outf, secrets_file); print(f"  {G}v{RST} secrets-found.txt -> {len(rlines(secrets_file))} findings")
        elif "mantra" in available and js_file.exists() and not is_file_empty(js_file):
            outf = jsdir / "mantra.txt"
            pattern = r"(api[_-]?key|secret|token|password|bearer|credential|private[_-]?key|client[_-]?secret|jwt)"
            cmd = f"mantra -s -ua 'Mozilla/5.0' -t 10 -d {q(js_file)} 2>/dev/null | grep -iE {q(pattern)} | sort -u > {q(outf)}"
            run_cmd(cmd, timeout=600, tool_name="mantra")
            if not is_file_empty(outf): shutil.copy2(outf, secrets_file)
        if js_file.exists() and not is_file_empty(js_file) and (not secrets_file.exists() or is_file_empty(secrets_file)):
            regex_file = jsdir / "regex-secrets.txt"
            pattern = r"(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24}|xox[baprs]-[0-9A-Za-z-]+|ghp_[0-9A-Za-z]{36})"
            cmd = f"grep -hoE {q(pattern)} {q(js_file)} 2>/dev/null | sort -u > {q(regex_file)} || true"
            run_cmd(cmd, timeout=60, tool_name="grep")
            if not is_file_empty(regex_file): shutil.copy2(regex_file, secrets_file); print(f"  {G}v{RST} secrets-found.txt -> {len(rlines(secrets_file))} regex hits")
        if not secrets_file.exists() or is_file_empty(secrets_file): print(f"  {Y}[!]{RST} No secrets discovered")
        prog.step(f"secret scan -> {len(rlines(secrets_file)) if secrets_file.exists() else 0}")
        prog.done_phase()
        if args_verbose and secrets_file.exists() and not is_file_empty(secrets_file): show_file_content(secrets_file, "secrets-found.txt", max_lines=30)
        return {"js_file": str(js_file), "secrets_file": str(secrets_file)}
    except KeyboardInterrupt: log_warn("Phase 13 skipped"); return {"js_file": "", "secrets_file": ""}
# ============================================================================
# PHASE 14, 15, SCORING, REPORTING
# ============================================================================
def phase_screenshots(domain, workspace, available):
    if not ask_phase("Run screenshots"):
        log_warn("Screenshots skipped by user")
        return {"_skipped": True}
    adir = Path(workspace) / domain / "active"
    alivef = adir / "alive-final.txt"
    prog = PhaseProgress("14 -> Screenshots", 2)
    try:
        if "gowitness" in available and alivef.exists() and not is_file_empty(alivef):
            gw_dir = Path(workspace) / domain / "screenshots" / "gowitness"
            mkd(gw_dir)
            cmd = f"gowitness scan file -f {q(alivef)} -q -t 10 --delay 1500 --timeout 15 --screenshot-path {q(gw_dir)} --write-db"
            run_cmd(cmd, timeout=1800, tool_name="gowitness"); prog.step(f"gowitness -> {gw_dir}")
        else: prog.step("gowitness -> skipped")
        if "aquatone" in available and alivef.exists() and not is_file_empty(alivef):
            aq_dir = Path(workspace) / domain / "screenshots" / "aquatone"
            mkd(aq_dir)
            cmd = f"cat {q(alivef)} | aquatone -out {q(aq_dir)} -silent -threads 10"
            run_cmd(cmd, timeout=1800, tool_name="aquatone"); prog.step(f"aquatone -> {aq_dir}")
        else: prog.step("aquatone -> skipped")
        prog.done_phase()
    except KeyboardInterrupt: log_warn("Phase 14 skipped")

def phase_dns_enrichment(domain, workspace, available):
    pdir = Path(workspace) / domain / "passive"
    ddir = Path(workspace) / domain / "dns"
    mkd(ddir)
    subs_file = pdir / "allsubs_final.txt"
    if not subs_file.exists(): subs_file = pdir / "allsubs.txt"
    if not subs_file.exists() or is_file_empty(subs_file): log_warn("No subdomains to enrich -> skipping DNS phase"); return {"spf": "", "dmarc": "", "dns_records": ""}
    prog = PhaseProgress("15 -> DNS Enrichment", 3)
    try:
        if "dnsx" in available:
            outf = ddir / "dns-resolved.txt"
            cmd = f"dnsx -l {q(subs_file)} -silent -a -aaaa -cname -resp -r 8.8.8.8,1.1.1.1 -o {q(outf)}"
            run_cmd(cmd, timeout=600, tool_name="dnsx")
            if not is_file_empty(outf): print(f"  {G}v{RST} dns-resolved.txt -> {len(rlines(outf))} records"); prog.step("dnsx resolution (A/AAAA/CNAME)")
            else: prog.step("dnsx -> skipped")
        spf_file = ddir / "spf.txt"
        try:
            _, out, _ = run_cmd(f"dig +short TXT {q(domain)} 2>/dev/null", timeout=30)
            spf = [l for l in out.splitlines() if "v=spf1" in l]
            wlines(spf_file, spf)
            if spf: print(f"  {G}v{RST} SPF record found")
            else: print(f"  {Y}[!]{RST} No SPF record -> potential email spoofing")
        except Exception: pass
        prog.step("SPF record check")
        dmarc_file = ddir / "dmarc.txt"
        try:
            _, out, _ = run_cmd(f"dig +short TXT _dmarc.{q(domain)} 2>/dev/null", timeout=30)
            dmarc = [l for l in out.splitlines() if "v=DMARC1" in l]
            wlines(dmarc_file, dmarc)
            if dmarc: print(f"  {G}v{RST} DMARC record found")
            else: print(f"  {Y}[!]{RST} No DMARC record -> potential email spoofing")
        except Exception: pass
        prog.step("DMARC record check")
        prog.done_phase()
        return {"spf": str(spf_file) if spf_file.exists() else "", "dmarc": str(dmarc_file) if dmarc_file.exists() else "", "dns_records": str(ddir / "dns-resolved.txt") if (ddir / "dns-resolved.txt").exists() else ""}
    except KeyboardInterrupt: log_warn("Phase 15 skipped"); return {"spf": "", "dmarc": "", "dns_records": ""}

SCORE_TABLE = {
    "takeover": 90, "env_exposed": 95, "git_exposed": 90, "backup_exposed": 85, "sensitive_passive": 80,
    "cors_high": 85, "cors_medium": 65, "secret": 85, "leakix": 80, "nuclei_critical": 95, "nuclei_high": 85,
    "nuclei_medium": 70, "dirsearch_hit": 75, "ffuf_hit": 70, "sensitive_sub": 60, "no_spf": 55, "no_dmarc": 50,
    "403_host": 45, "open_port_risky": 60,
}
def score_finding(kind, sub=None):
    base = SCORE_TABLE.get(kind, 30)
    if sub and sub.split(".")[0] in SENSITIVE_PREFIXES: base = min(100, base + 10)
    return base


def send_telegram_completion(workspace, result, findings, elapsed_sec=None):
    """Send 'Testing End' summary to Telegram when scan finishes."""
    try:
        if not telegram_io.is_enabled():
            return
    except Exception:
        return

    targets = result.get("targets", [])
    n_targets = len(targets)
    n_findings = len(findings)
    high = sum(1 for f in findings if f.get("score", 0) >= 70)
    top = findings[0] if findings else None

    lines = []
    lines.append("\u2705 <b>Testing End</b>")
    lines.append("")
    lines.append(f"<b>Version:</b> {html.escape(str(VERSION))}")
    lines.append(f"<b>Targets scanned:</b> {n_targets}")
    lines.append(f"<b>Total findings:</b> {n_findings}")
    lines.append(f"<b>High/Critical:</b> {high}")

    if top:
        lines.append("")
        lines.append("\U0001f3c6 <b>Top finding:</b>")
        lines.append(f"  Score: <b>{top.get('score')}</b>")
        lines.append(f"  Type: {html.escape(str(top.get('type', '')))}")
        lines.append(f"  Target: <code>{html.escape(str(top.get('target', ''))[:80])}</code>")

    if elapsed_sec is not None:
        m, s = divmod(int(elapsed_sec), 60)
        h, m = divmod(m, 60)
        if h:
            lines.append(f"<b>Duration:</b> {h}h {m}m {s}s")
        elif m:
            lines.append(f"<b>Duration:</b> {m}m {s}s")
        else:
            lines.append(f"<b>Duration:</b> {s}s")

    lines.append("")
    lines.append(f"<b>Workspace:</b> <code>{html.escape(str(workspace))}</code>")

    # Target list (limited)
    if targets:
        names = [t.get("domain", "?") for t in targets][:10]
        lines.append("")
        lines.append("<b>Targets:</b>")
        for nm in names:
            lines.append(f"  \u2022 <code>{html.escape(str(nm))}</code>")
        if len(targets) > 10:
            lines.append(f"  <i>... and {len(targets) - 10} more</i>")

    try:
        telegram_io.notify("\n".join(lines))
        print(f"{G}[+]{RST} Telegram completion notification sent")
    except Exception as e:
        print(f"{Y}[!]{RST} Telegram completion notify failed: {e}")


def send_telegram_report(target_domain, target_findings):
    """Send high-severity findings to Telegram."""
    token = api_keys_global.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = api_keys_global.get("TELEGRAM_CHAT_ID", "")
    
    if not token or not chat_id:
        return

    # Only send High/Critical findings (Score >= 70) to avoid spam
    important = [f for f in target_findings if f["score"] >= 70]
    if not important:
        return

    msg = f"🚨 <b>Clicker Alert: {html.escape(str(target_domain))}</b> 🚨\n\n"
    msg += f"🔥 <b>{len(important)} High/Critical Findings:</b>\n\n"

    for f in important[:15]:
        detail = html.escape(str(f["detail"])[:120])
        msg += f"📌 <b>{html.escape(str(f['type']))}</b> (Score: {f['score']})\n"
        msg += f"🎯 <code>{html.escape(str(f['target']))}</code>\n"
        msg += f"📝 <i>{detail}</i>\n\n"

    if len(important) > 15:
        msg += f"<i>... and {len(important) - 15} more. Check full report.</i>\n"

    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": msg,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        data = urllib.parse.urlencode(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10) as res:
            if res.status == 200:
                log_ok("Telegram alert sent successfully.")
    except Exception as e:
        log_warn(f"Failed to send Telegram alert: {e}")

def dedupe_findings(findings):
    """
    Remove duplicate findings while preserving the richest version.

    Key = (normalized_type, normalized_url_or_target).
    Normalization strips 'idor-', 'advanced-', 'adv-' prefixes so
    that e.g. 'idor-method-bypass' and 'method-bypass' collapse.
    Richness = len(str(detail)).
    Order preserved (first occurrence position wins).
    """
    seen = {}
    order = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        t = str(f.get("type", "")).strip().lower()
        for pfx in ("idor-", "advanced-", "adv-"):
            if t.startswith(pfx):
                t = t[len(pfx):]
                break
        u = str(f.get("url") or f.get("target") or "").strip().lower().rstrip("/")
        k = (t, u)
        if k not in seen:
            seen[k] = f
            order.append(k)
        else:
            if len(str(f.get("detail", ""))) > len(str(seen[k].get("detail", ""))):
                seen[k] = f
    return [seen[k] for k in order]


def dedupe_idor_data_inplace(result):
    """
    Patch 3: dedupe raw IDOR arrays inside result.targets[*].idor.*
    before serialization to report.json.
    Returns summary {key: (before, after)} for verbose logging.
    """
    summary = {}
    for t in result.get("targets", []):
        idor = t.get("idor")
        if not isinstance(idor, dict):
            continue
        for key in ("confirmed", "advanced_confirmed",
                    "suspicious", "advanced_suspicious"):
            arr = idor.get(key)
            if not isinstance(arr, list) or not arr:
                continue
            before = len(arr)
            try:
                after_arr = dedupe_findings(arr)
            except Exception:
                continue
            idor[key] = after_arr
            summary[key] = (before, len(after_arr))
    return summary


def build_findings_summary(result):
    findings = []
    for target in result.get("targets", []):
        dom = target.get("domain", "")
        for line in target.get("takeover", {}).get("findings", []): findings.append({"score": score_finding("takeover", dom), "type": "takeover", "target": dom, "detail": line})
        for line in target.get("vuln", {}).get("nuclei", []):
            sev = "high"
            if "[critical]" in line.lower(): sev = "critical"
            elif "[medium]" in line.lower(): sev = "medium"
            kind = "nuclei_" + sev
            findings.append({"score": score_finding(kind, dom), "type": "nuclei-" + sev, "target": dom, "detail": line})
        for line in target.get("vuln", {}).get("cors", []):
            kind = "cors_high" if "HIGH" in line else "cors_medium"
            findings.append({"score": score_finding(kind, dom), "type": "cors", "target": dom, "detail": line})
        for line in target.get("vuln", {}).get("exposed", []):
            kind = "env_exposed" if ".env" in line else ("git_exposed" if ".git" in line else "backup_exposed")
            findings.append({"score": score_finding(kind, dom), "type": "exposed-file", "target": dom, "detail": line})
        passive_sens = target.get("sensitive", {}).get("passive", "")
        if passive_sens and Path(passive_sens).exists() and not is_file_empty(passive_sens):
            for line in rlines(passive_sens): findings.append({"score": score_finding("sensitive_passive", dom), "type": "sensitive-file", "target": dom, "detail": line[:200]})
        # IDOR — read all 4 sources + preserve url/source
        idor_data = target.get("idor", {})
        for _source_key in ("confirmed", "advanced_confirmed",
                           "suspicious", "advanced_suspicious"):
            for finding in idor_data.get(_source_key, []) or []:
                _url = finding.get("url", "") or finding.get("endpoint", "")
                _reason = finding.get("reason", "") or finding.get("description", "")
                _ftype = finding.get("type", "unknown")
                if "missing-auth" in _ftype or "anon" in _ftype:
                    _kind = "nuclei_critical"
                elif "cross-account" in _ftype or "horizontal" in _ftype:
                    _kind = "takeover"
                elif "method-bypass" in _ftype:
                    _kind = "nuclei_high"
                else:
                    _kind = "takeover"
                findings.append({
                    "score": score_finding(_kind, dom),
                    "type": "idor-" + _ftype,
                    "target": dom,
                    "url": _url,
                    "detail": (_url + " -> " + _reason)[:300],
                    "source": _source_key,
                    "suspicious": _source_key in ("suspicious", "advanced_suspicious"),
                })
        secrets = target.get("js", {}).get("secrets_file", "")
        if secrets and Path(secrets).exists() and not is_file_empty(secrets):
            for line in rlines(secrets): findings.append({"score": score_finding("secret", dom), "type": "secret", "target": dom, "detail": line[:200]})
        for s in target.get("passive", {}).get("sensitive_subs", []): findings.append({"score": score_finding("sensitive_sub", s), "type": "sensitive-subdomain", "target": s, "detail": s})
        spf_path = target.get("dns", {}).get("spf", "")
        dmarc_path = target.get("dns", {}).get("dmarc", "")
        if spf_path and not Path(spf_path).exists(): findings.append({"score": score_finding("no_spf", dom), "type": "no-spf", "target": dom, "detail": "No SPF record"})
        if dmarc_path and not Path(dmarc_path).exists(): findings.append({"score": score_finding("no_dmarc", dom), "type": "no-dmarc", "target": dom, "detail": "No DMARC record"})
    findings.sort(key=lambda f: f["score"], reverse=True)
    return dedupe_findings(findings)

def safe(d, *keys, default=0):
    for k in keys:
        if isinstance(d, dict): d = d.get(k, None)
        else: return default
        if d is None: return default
    return d

def write_txt(path, result, findings):
    lines = ["CLICKER v2.2 -> BUG BOUNTY RECON REPORT", "=" * 72, f"Generated : {result['generated_at']}", f"Findings  : {len(findings)}", "", "TOP FINDINGS (by score)", "-" * 72]
    for f in findings[:30]: lines.append(f"  [{f['score']:3d}] {f['type']:<22} {f['target']:<40} {f['detail'][:80]}")
    lines.append("")
    for t in result["targets"]:
        lines += [f"Target : {t['domain']}", "-" * 40, f"  Passive subdomains : {len(safe(t, 'passive', 'all_subdomains', default=[]))}", f"  High-value subs    : {len(safe(t, 'passive', 'sensitive_subs', default=[]))}", f"  Alive hosts        : {len(safe(t, 'response', 'alive', default=[]))}", f"  403 hosts          : {len(safe(t, 'response', 'f403', default=[]))}", f"  404 hosts          : {len(safe(t, 'response', 'f404', default=[]))}", f"  WAF                : {safe(t, 'waf', 'waf_type', default='default')}", ""]
    Path(path).write_text("\n".join(lines), encoding="utf-8")

def write_html(path, result, findings):
    rows = []
    for f in findings[:100]:
        sev_cls = "critical" if f["score"] >= 85 else ("high" if f["score"] >= 70 else "medium")
        rows.append(f'<tr class="{sev_cls}"><td>{f["score"]}</td><td>{html.escape(f["type"])}</td><td>{html.escape(f["target"])}</td><td>{html.escape(f["detail"][:200])}</td></tr>')
    blocks = []
    for t in result["targets"]:
        blocks.append(f"""<section><h2>Target: {html.escape(t['domain'])}</h2><table>
<tr><td>Passive subdomains</td><td>{len(safe(t, 'passive', 'all_subdomains', default=[]))}</td></tr>
<tr><td>High-value subs</td><td>{len(safe(t, 'passive', 'sensitive_subs', default=[]))}</td></tr>
<tr><td>Alive hosts</td><td>{len(safe(t, 'response', 'alive', default=[]))}</td></tr>
<tr><td>WAF</td><td>{html.escape(str(safe(t, 'waf', 'waf_type', default='default')))}</td></tr></table></section>""")
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Clicker Report</title>
<style>body {{font-family: -apple-system, monospace; background: #060d1f; color: #d0d8f0; padding: 24px;}} h1 {{color: #7dd3fc;}} h2 {{color: #38bdf8; border-bottom: 1px solid #1e3a5f; padding-bottom: 6px;}} table {{border-collapse: collapse; width: 100%; margin: 10px 0;}} td, th {{border: 1px solid #1e3a5f; padding: 6px 12px; font-size: 13px;}} tr.critical {{background: #4a0d0d;}} tr.high {{background: #3a2409;}} tr.medium {{background: #102a3d;}}</style></head><body>
<h1>Clicker v2.2 Report</h1><p>Generated: {html.escape(result['generated_at'])} | Findings: {len(findings)}</p>
<h2>Top Findings</h2><table><thead><tr><th>Score</th><th>Type</th><th>Target</th><th>Detail</th></tr></thead><tbody>{''.join(rows)}</tbody></table>{''.join(blocks)}</body></html>"""
    Path(path).write_text(doc, encoding="utf-8")

# ============================================================================
# TARGETS PARSING & MAIN
# ============================================================================
def parse_targets(single, tfile):
    targets = []
    if single:
        try: targets.append(validate_domain(single))
        except ValueError as e: sys.exit(f"{R}[!] {e}{RST}")
    if tfile:
        p = Path(tfile)
        if not p.exists(): sys.exit(f"{R}[!] targets file not found: {tfile}{RST}")
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"): continue
            try: targets.append(validate_domain(line))
            except ValueError as e: log_warn(f"Skipping invalid target: {e}")
    targets = sorted(set(targets))
    if not targets: sys.exit(f"{R}[!] No valid targets. Use -t or --targets-file{RST}")
    return targets

def _run_idor(domain, workspace, available, scope):
    # Import idor_module at top (fixes 'local variable' error)
    import idor_module

    """Wrapper that sets IDOR module globals + optional Playwright capture."""
    if not IDOR_AVAILABLE:
        return {}
    if args_skip_idor:
        return {}

    target_host = domain.split(":")[0]
    scheme = "https"
    target_url = f"{scheme}://{target_host}"
    if ":" in domain and ":443" not in domain and ":80" not in domain:
        target_url = f"https://{domain}"
    elif ":80" in domain:
        target_url = f"http://{domain}"

    # ═══════════════════════════════════════════════════════════
    # STEP 1: Playwright capture (if --idor-pw)
    # ═══════════════════════════════════════════════════════════
    pw_captured_urls = []
    pw_login_shapes = []
    if args_idor_pw:
        try:
            import idor_playwright
            if not idor_playwright.is_available():
                log_warn("Playwright not installed — install with: pip install playwright && playwright install chromium")
            else:
                print(f"\n{BOLD}{C}{'═' * 60}{RST}")
                print(f"{BOLD}{C}  Playwright Network Capture{RST}")
                print(f"{BOLD}{C}{'═' * 60}{RST}")

                # Optional auto-login to get token (if creds provided)
                auth_token = None
                if args_idor_a_email and args_idor_a_pass and args_idor_login_url and args_idor_login_json:
                    try:
                        login_result = idor_playwright.auto_login_via_api(
                            args_idor_login_url,
                            args_idor_login_json,
                            args_idor_a_email,
                            args_idor_a_pass,
                        )
                        if login_result:
                            auth_token = login_result["token"]
                            print(f"{G}[PW] Auto-login OK (token captured){RST}")
                        else:
                            log_warn("Auto-login failed — capturing without auth")
                    except Exception as _le:
                        log_warn(f"Auto-login error: {_le}")

                pw_result = idor_playwright.capture_network(
                    target_url,
                    duration=args_idor_pw_duration,
                    headless=not args_idor_pw_visible,
                    scroll=True,
                    follow_links=args_idor_pw_follow_links,
                    auth_token=auth_token,
                    wait_for_enter=args_idor_pw_visible,
                )

                if pw_result:
                    idor_playwright.display_summary(pw_result)
                    pw_dir = Path(workspace) / domain / "idor"
                    idor_playwright.write_findings(pw_result, pw_dir)

                    pw_captured_urls = sorted(pw_result["api_calls"])
                    pw_login_shapes = pw_result.get("post_jsons", [])

                    # Persist to workspace for phase_idor to pick up
                    (pw_dir / "pw_captured_urls.txt").write_text(
                        "\n".join(pw_captured_urls), encoding="utf-8"
                    )
                    if pw_result.get("login_endpoints"):
                        (pw_dir / "pw_login_endpoints.txt").write_text(
                            "\n".join(sorted(pw_result["login_endpoints"])),
                            encoding="utf-8"
                        )

                    # Auto-set login URL if not provided
                    # Prioritize actual login endpoints over token-refresh ones
                    if not args_idor_login_url and pw_result.get("login_endpoints"):
                        _logins = list(pw_result["login_endpoints"])
                        # Priority: cloudfunctions > login/signin > identitytoolkit
                        def _login_priority(url):
                            u = url.lower()
                            if "cloudfunctions" in u and "login" in u:
                                return 0
                            if "/login" in u or "signin" in u:
                                return 1
                            if "auth" in u:
                                return 2
                            # identitytoolkit token endpoints — lowest priority
                            return 9
                        _logins.sort(key=_login_priority)
                        best_login = _logins[0]
                        print(f"{G}[PW] Picked login URL (priority 0-1): {best_login}{RST}")
                        idor_module.GLOBAL_LOGIN_URL = best_login
                        print(f"{G}[PW] Auto-set login URL: {best_login}{RST}")

                        # Auto-set login JSON if we captured the shape
                        if pw_login_shapes:
                            shape_data = pw_login_shapes[0].get("raw", {})
                            # Replace values with placeholders
                            def _placeholderize(obj):
                                if isinstance(obj, dict):
                                    out = {}
                                    for k, v in obj.items():
                                        if k in ("email",):
                                            out[k] = "%EMAIL%"
                                        elif k in ("password",):
                                            out[k] = "%PASS%"
                                        else:
                                            out[k] = _placeholderize(v) if isinstance(v, (dict, list)) else v
                                    return out
                                if isinstance(obj, list):
                                    return [_placeholderize(x) for x in obj]
                                return obj

                            placeholder_json = json.dumps(_placeholderize(shape_data))
                            idor_module.GLOBAL_LOGIN_JSON = placeholder_json
                            print(f"{G}[PW] Auto-set login JSON: {placeholder_json[:80]}...{RST}")
                    else:
                        idor_module.GLOBAL_LOGIN_URL = args_idor_login_url
                        idor_module.GLOBAL_LOGIN_JSON = args_idor_login_json

                    # Merge Playwright-generated probes (Firestore + Cloud Functions)
                    probe_urls = []
                    for probe_file in ("pw_firestore_probes.txt", "pw_cloudfunc_probes.txt"):
                        pf = pw_dir / probe_file
                        if pf.exists():
                            for line in pf.read_text(errors="ignore").splitlines():
                                line = line.strip()
                                if line and line.startswith(("http://", "https://")):
                                    probe_urls.append(line)
                    if probe_urls:
                        print(f"{G}[PW] Loaded {len(probe_urls)} probe URLs{RST}")

                    # Merge captured URLs into final-urls.txt
                    all_pw_urls = list(set(pw_captured_urls + probe_urls))
                    if all_pw_urls:
                        final_urls = Path(workspace) / domain / "urls" / "final-urls.txt"
                        final_urls.parent.mkdir(parents=True, exist_ok=True)
                        existing = set()
                        if final_urls.exists():
                            existing = set(rlines(final_urls))
                        merged = sorted(existing | set(all_pw_urls))
                        final_urls.write_text("\n".join(merged), encoding="utf-8")
                        # Also update clean_urls.txt
                        clean_urls = final_urls.parent / "clean_urls.txt"
                        clean_urls.write_text("\n".join(merged), encoding="utf-8")
                        print(f"{G}[PW] Merged {len(all_pw_urls)} URLs (captured + probes) into final-urls.txt{RST}")
        except Exception as _pw_e:
            log_warn(f"Playwright capture failed: {_pw_e}")

    # ═══════════════════════════════════════════════════════════
    # STEP 2: Set IDOR module globals
    # ═══════════════════════════════════════════════════════════
    try:
        idor_module.GLOBAL_SCOPE = scope
        idor_module.GLOBAL_LOGIN_URL = args_idor_login_url or getattr(idor_module, "GLOBAL_LOGIN_URL", None)
        idor_module.GLOBAL_LOGIN_JSON = args_idor_login_json or getattr(idor_module, "GLOBAL_LOGIN_JSON", None)

        # Pass credentials if provided (for auto-login without prompts)
        if args_idor_a_email:
            idor_module.GLOBAL_A_EMAIL = args_idor_a_email
            idor_module.GLOBAL_A_PASS = args_idor_a_pass
        if args_idor_b_email:
            idor_module.GLOBAL_B_EMAIL = args_idor_b_email
            idor_module.GLOBAL_B_PASS = args_idor_b_pass
    except Exception:
        pass

    return idor_phase_func(domain, workspace, PhaseProgress, log_info, log_ok, log_warn)



def main():
    global args_verbose, args_skip_screenshots, args_skip_js, args_skip_active_subs
    global args_skip_vuln, args_skip_fuzz, args_keep_sources, args_idor_only, args_resume, args_wordlist, args_resolvers
    global GLOBAL_PROFILE, GLOBAL_EXTRA_HEADERS, GLOBAL_RATE_LIMIT, GLOBAL_ALLOWED_PHASES
    global args_idor_login_url, args_idor_login_json, args_idor_pw, args_idor_pw_duration, args_idor_pw_visible, args_idor_pw_follow_links, args_idor_a_email, args_idor_a_pass, args_idor_b_email, args_idor_b_pass
    global api_keys_global, workspace_global, GLOBAL_USE_PROXYCHAINS, GLOBAL_HYBRID_PROXY
    global GLOBAL_PROXY_HEALTH_OK, GLOBAL_WAF_TYPE, args_scope_file, args_force
    global AI_PLAN_GLOBAL, GLOBAL_TARGET_PORT
    signal.signal(signal.SIGINT, signal_handler)
    if sys.platform != "linux": log_warn("Clicker is designed for Linux -> some features may not work")
    parser = argparse.ArgumentParser(description=f"Clicker {VERSION} -> Bug Bounty Recon Pipeline | {INSTAGRAM}", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-t", "--target", help="Single target domain")
    parser.add_argument("--targets-file", help="File with one domain per line")
    parser.add_argument("--scope-file", help="Scope file (one pattern per line, prefix '!' to exclude)")
    parser.add_argument("--workspace", default="clicker_output", help="Output directory")
    parser.add_argument("--api-file", default="clicker_api.env", help="API keys file")
    parser.add_argument("--report-format", choices=["txt", "html", "both"], default="both")
    parser.add_argument("--program-setup", action="store_true", help="Force re-run program policy setup wizard")
    parser.add_argument("--idor-login-url", default=None, help="Custom IDOR login URL (external hosts supported)")
    parser.add_argument("--idor-login-json", default=None, help="Custom IDOR login JSON body (use %%EMAIL%% and %%PASS%% placeholders)")
    parser.add_argument("--idor-pw", action="store_true", help="Auto-capture network via Playwright headless browser")
    parser.add_argument("--idor-pw-duration", type=int, default=25, help="Playwright capture duration (seconds)")
    parser.add_argument("--idor-pw-headless", action="store_true", default=True, help="Run Playwright headless (default)")
    parser.add_argument("--idor-pw-visible", action="store_true", help="Run Playwright in visible browser mode")
    parser.add_argument("--idor-pw-follow-links", action="store_true", help="Follow internal links during capture")
    parser.add_argument("--idor-a-email", default=None, help="IDOR Account A (attacker) email")
    parser.add_argument("--idor-a-pass", default=None, help="IDOR Account A password")
    parser.add_argument("--idor-b-email", default=None, help="IDOR Account B (victim) email")
    parser.add_argument("--idor-b-pass", default=None, help="IDOR Account B password")
    parser.add_argument("--no-profile", action="store_true", help="Skip program profile (use defaults)")
    parser.add_argument("--idor-only", action="store_true", help="Run ONLY IDOR phase (skip all others)")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    parser.add_argument("--force", action="store_true", help="Force scan even if quick probe says target is dead")
    parser.add_argument("--proxy", help="Single proxy (user:pass@IP:PORT or IP:PORT)")
    parser.add_argument("--proxy-list", help="Path to proxy list file")
    parser.add_argument("--auto-proxy", action="store_true", help="Fetch fresh proxies from public APIs")
    parser.add_argument("--rotate-proxy", action="store_true", help="Rotate proxies per target")
    parser.add_argument("--proxychains", action="store_true", help="Route all tools via proxychains4")
    parser.add_argument("--hybrid-proxy", action="store_true", help="Smart: proxy only for HTTP tools")
    parser.add_argument("--wordlist", default="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt")
    parser.add_argument("--resolvers", default="/usr/share/seclists/Discovery/DNS/resolvers.txt")
    parser.add_argument("--keep-sources", action="store_true", help="Keep intermediate files")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show detailed output")
    args = parser.parse_args()
    print(ASCII_LOGO)
    _scan_start_ts = time.time()
    args_verbose = args.verbose
    args_skip_screenshots = False; args_skip_js = False
    args_skip_active_subs = False; args_skip_vuln = False; args_skip_fuzz = False
    args_skip_idor = False
    _program_setup = getattr(args, "program_setup", False); _no_profile = getattr(args, "no_profile", False)
    args_idor_login_url = None; args_idor_login_json = None
    args_idor_only = args.idor_only
    args_idor_login_url = args.idor_login_url
    args_idor_login_json = args.idor_login_json
    # --idor-pw-visible implies --idor-pw
    args_idor_pw = args.idor_pw or args.idor_pw_visible
    args_idor_pw_duration = args.idor_pw_duration
    args_idor_pw_visible = args.idor_pw_visible
    args_idor_pw_follow_links = args.idor_pw_follow_links
    args_idor_a_email = args.idor_a_email
    args_idor_a_pass = args.idor_a_pass
    args_idor_b_email = args.idor_b_email
    args_idor_b_pass = args.idor_b_pass; args_keep_sources = args.keep_sources; args_resume = args.resume
    args_force = args.force; args_wordlist = args.wordlist; args_resolvers = args.resolvers; args_scope_file = args.scope_file
    GLOBAL_USE_PROXYCHAINS = args.proxychains; GLOBAL_HYBRID_PROXY = args.hybrid_proxy
    pm = ProxyManager(proxy=args.proxy, proxy_file=args.proxy_list, auto_fetch=args.auto_proxy, rotate=args.rotate_proxy)
    if GLOBAL_HYBRID_PROXY and pm.proxies:
        test_proxy = pm.get_current()
        if test_proxy and not check_proxy_health(test_proxy, timeout=8):
            log_warn("Initial proxy health check failed -> will auto-bypass when needed"); GLOBAL_PROXY_HEALTH_OK = False
        else: GLOBAL_PROXY_HEALTH_OK = True
    pm.apply()
    api_keys_global = collect_api_keys(Path(args.api_file))
    # ── Configure Telegram bidirectional I/O ──
    try:
        telegram_io.configure(
            api_keys_global.get("TELEGRAM_BOT_TOKEN", ""),
            api_keys_global.get("TELEGRAM_CHAT_ID", ""),
        )
        if telegram_io.is_enabled():
            log_ok("Telegram interactive I/O enabled")
        else:
            log_dim("Telegram interactive I/O disabled (no token/chat_id)")
    except Exception as e:
        log_warn(f"Telegram config failed: {e}")
    scope = load_scope(args.scope_file)
    targets = parse_targets(args.target, args.targets_file)
    workspace = Path(args.workspace); mkd(workspace); workspace_global = workspace
    if targets:
        primary_target = targets[0]
        GLOBAL_PROFILE = load_or_setup_profile(primary_target, force=_program_setup, skip=_no_profile)
        GLOBAL_EXTRA_HEADERS = GLOBAL_PROFILE.get("headers", [])
        GLOBAL_RATE_LIMIT = float(GLOBAL_PROFILE.get("rate_limit", 5))
        allowed = GLOBAL_PROFILE.get("allowed_phases")
        GLOBAL_ALLOWED_PHASES = set(allowed) if allowed else None
        if GLOBAL_EXTRA_HEADERS:
            try:
                curlrc = Path.home() / ".curlrc"
                existing = curlrc.read_text().splitlines() if curlrc.exists() else []
                existing = [l for l in existing if not l.startswith('header = "X-Bug-Bounty:')]
                for h in GLOBAL_EXTRA_HEADERS: existing.append(f'header = "{h}"')
                curlrc.write_text("\n".join(existing) + "\n")
                print(f"{G}[+]{RST} Headers synced to ~/.curlrc ({len(GLOBAL_EXTRA_HEADERS)})")
            except Exception as e: log_warn(f"Could not write ~/.curlrc: {e}")
    required_tools = ["subfinder", "sublist3r", "chaos", "assetfinder", "github-subdomains", "findomain", "waybackurls", "gau", "httpx", "naabu", "dnsx", "cdncheck", "nmap", "aquatone", "gowitness", "katana", "waymore", "mantra", "subzy", "subjack", "wafw00f", "puredns", "altdns", "shuffledns", "dnsrecon", "ffuf", "nuclei", "trufflehog", "gitleaks", "curl", "jq", "grep", "sed", "awk", "sort", "cat", "dig", "unfurl", "uro", "dirsearch"]
    available = check_tools(required_tools)
    result = {"generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"), "version": VERSION, "targets": []}
    print(f"\n{BOLD}{M}[>] Starting scan on {len(targets)} target(s){RST}\n")
    for domain in targets:
        if not in_scope(domain, scope): log_warn(f"OUT OF SCOPE: {domain} -> skipping"); continue
        pm.apply(domain=domain)
        print(f"\n{BOLD}{W}{'=' * 60}{RST}")
        print(f"{BOLD}{M}  Target : {domain}{RST}")
        print(f"{BOLD}{W}{'=' * 60}{RST}")
        AI_PLAN_GLOBAL = None
        GLOBAL_TARGET_PORT = _extract_target_port(domain)
        if GLOBAL_TARGET_PORT:
            print(f"  {DIM}[+] Target port detected: {GLOBAL_TARGET_PORT}{RST}")
        # Fresh state per scan (unless resuming)
        try:
            if args_resume:
                _state = state.load_state(workspace, domain)
                log_ok(f"Resumed state from {state.state_path(workspace, domain)}")
            else:
                _state = state.default_state(domain)
                state.save_state(workspace, domain, _state)
        except Exception as _e:
            log_warn(f"state init failed: {_e}")
            _state = state.default_state(domain)
        completed = set()
        if args_resume:
            cp = load_checkpoint(workspace, domain)
            if cp: completed = set(cp.get("completed_phases", [])); log_ok(f"Resuming -> completed phases: {sorted(completed)}")
        quick, passive, waf, dns_resolution, response, tech, takeover, vuln, ports, leakix, urls, sensitive, js, idor_res, dns_res = {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}
        def make_phases():
            return [
                ("quick", lambda: phase_quick_probe(domain, workspace)),
                ("passive", lambda: phase_passive(domain, workspace, api_keys_global, available)),
                ("waf", lambda: phase_waf(domain, workspace, available)),
                ("active", lambda: phase_active_subs(domain, workspace, available)),
                ("dns_resolution", lambda: phase_dns_resolution(domain, workspace, available)),
                ("response", lambda: phase_response_filter(domain, workspace, passive, available)),
                ("tech", lambda: phase_tech_detect(domain, workspace, available)),
                ("takeover", lambda: phase_takeover(domain, workspace, available)),
                ("vuln", lambda: phase_vuln_scan(domain, workspace, available)),
                ("ports", lambda: phase_ports(domain, workspace, available)),
                ("leakix", lambda: phase_leakix(domain, workspace, available)),
                ("content", lambda: phase_content_discovery(domain, workspace, available)),
                ("sensitive", lambda: phase_sensitive_files(domain, workspace, available)),
                ("js", lambda: phase_js_recon(domain, workspace, available)),
                ("idor", lambda: _run_idor(domain, workspace, available, scope)),
                ("screenshots", lambda: phase_screenshots(domain, workspace, available)),
                ("dns", lambda: phase_dns_enrichment(domain, workspace, available)),
            ]
        _phase_counter = 0
        _phases_seq = list(make_phases())
        _idx = 0
        while _idx < len(_phases_seq):
            phase_name, phase_fn = _phases_seq[_idx]
            _idx += 1
            _phase_counter += 1
            GLOBAL_AI_CONTEXT["domain"] = domain
            GLOBAL_AI_CONTEXT["phase_name"] = phase_name
            GLOBAL_AI_CONTEXT["phase_number"] = _phase_counter
            if phase_name in completed: log_warn(f"Skipping {phase_name} (already completed)"); continue
            if args_idor_only and phase_name != "idor": continue
            if GLOBAL_ALLOWED_PHASES is not None and phase_name not in GLOBAL_ALLOWED_PHASES: log_warn(f"Skipping {phase_name} (not in program profile)"); continue
            if quick.get("passive_only") and phase_name in ("response", "tech", "takeover", "vuln", "ports", "leakix", "content", "sensitive", "js", "idor", "screenshots"):
                log_warn(f"Skipping {phase_name} (passive-only mode: target dead)"); continue
            if phase_name == "quick":
                try:
                    res = phase_fn()
                    quick = res if res else {}
                    completed.add(phase_name)
                    save_checkpoint(workspace, domain, completed, extra={"waf_type": GLOBAL_WAF_TYPE})
                    _passive_ok = (GLOBAL_ALLOWED_PHASES is None or "passive" in GLOBAL_ALLOWED_PHASES)
                    if quick.get("skip_scan") and not args_force:
                        if _passive_ok:
                            log_warn(f"Target {domain} root unresolvable -> continuing in PASSIVE-ONLY mode")
                            log_dim("  Passive tools (subfinder, crt.sh, etc.) work without root DNS")
                            quick["skip_scan"] = False
                            quick["passive_only"] = True
                        else:
                            log_err(f"Target {domain} appears dead -> skipping remaining phases")
                            log_dim("  Use --force to override")
                            break
                except KeyboardInterrupt:
                    log_warn("Quick probe interrupted -> continuing anyway")
                    completed.add(phase_name)
                    save_checkpoint(workspace, domain, completed, extra={"waf_type": GLOBAL_WAF_TYPE})
                    continue
                # منع التكرار: تخطي كتلة التنفيذ العامة لهذه المرحلة
                continue

            try:
                res = phase_fn()
                if res is None: res = {}

                # ── User rejected this phase: remove from sequence ──
                if isinstance(res, dict) and res.get("_skipped"):
                    try:
                        _phases_seq[:] = [p for p in _phases_seq if p[0] != phase_name]
                        if args_verbose:
                            log_ok(f"Removed '{phase_name}' from queue (user rejected)")
                    except Exception as _e:
                        log_warn(f"remove-skipped failed: {_e}")
                if phase_name == "passive":
                    passive = res
                    subs_count = len(res.get("all_subdomains", [])) if res else 0
                    if subs_count > 0 and quick.get("passive_only"):
                        log_ok(f"Passive enum found {subs_count} subs -> clearing passive-only mode"); quick["passive_only"] = False

                    # ── AI Planning Loop (Task 1) ──
                    try:
                        print()
                        print(f"{BOLD}{M}[AI LOOP]{RST} Team planning next phases...")
                        _plan = _run_ai_plan_loop(domain, workspace, res, api_keys_global, _state=_state)
                        if _plan and _plan.get("next_phases"):
                            AI_PLAN_GLOBAL = _plan
                            _np = _plan.get("next_phases", [])
                            _cp = _plan.get("custom_phases_added", [])
                            log_ok(f"AI planned {len(_np)} phases" + (f" + {len(_cp)} custom" if _cp else ""))
                            print(f"{M}[AI LOOP]{RST} Suggested order:")
                            for _p in _np[:10]:
                                print(f"    -> {_p}")
                            if _cp:
                                print(f"{M}[AI LOOP]{RST} Custom phases added:")
                                for _c in _cp[:5]:
                                    _targets = _c.get("target_subs", [])
                                    _reason = _c.get("reason", "")
                                    print(f"    {BOLD}* {_c.get('name')}{RST}")
                                    if _targets:
                                        _tlist = ", ".join(_targets[:5])
                                        _extra = f" (+{len(_targets)-5} more)" if len(_targets) > 5 else ""
                                        print(f"      {DIM}Targets:{RST} {_tlist}{_extra}")
                                    if _reason:
                                        print(f"      {DIM}Reason:{RST} {_reason[:250]}")

                                # ── Execute custom phases ──
                                _api_key_exec = api_keys_global.get("FREELLMAPI_API_KEY", "")
                                if _api_key_exec and _cp:
                                    print()
                                    print(f"{BOLD}{M}[EXECUTOR]{RST} Executing {len(_cp)} custom phase(s)...")
                                    _custom_results = []
                                    try:
                                        _state_summary_for_exec = state.summary_for_ai(_state)
                                    except Exception:
                                        _state_summary_for_exec = None
                                    for _cph in _cp[:5]:  # max 5
                                        try:
                                            _cres = ai_executor.execute_custom_phase(
                                                domain, _cph, _api_key_exec,
                                                workspace,
                                                state_summary=_state_summary_for_exec,
                                                verbose=True,
                                            )
                                            _custom_results.append(_cres)
                                            # Save to state
                                            try:
                                                _state["custom_phases"] = _state.get("custom_phases", [])
                                                _state["custom_phases"].append({
                                                    "name": _cres.get("name"),
                                                    "command": _cres.get("command"),
                                                    "exit_code": _cres.get("exit_code"),
                                                    "duration": _cres.get("duration"),
                                                    "output_file": _cres.get("output_file"),
                                                })
                                                state.save_state(workspace, domain, _state)
                                            except Exception:
                                                pass
                                        except Exception as _ce:
                                            log_warn(f"Custom phase '{_cph.get('name')}' failed: {_ce}")
                                    if _custom_results:
                                        _summary = ai_executor.save_custom_summary(
                                            domain, _custom_results, workspace
                                        )
                                        if _summary:
                                            log_ok(f"Custom summary: {_summary}")
                                        # Save in result
                                        AI_PLAN_GLOBAL = AI_PLAN_GLOBAL or {}
                                        AI_PLAN_GLOBAL["custom_results"] = _custom_results
                            # Reorder remaining phases per AI suggestion
                            try:
                                _rest = _reorder_phases(list(_phases_seq[_idx:]), _np)
                                _new_seq = list(_phases_seq[:_idx]) + _rest
                                _phases_seq[:] = _new_seq   # in-place mutation, no rebinding
                                if args_verbose:
                                    log_ok("Reordered remaining phases per AI plan")
                            except Exception as _re:
                                log_warn(f"Reorder failed (continuing): {_re}")
                        else:
                            log_warn("AI plan empty - using default order")
                    except Exception as _e:
                        log_warn(f"AI loop error (continuing): {_e}")
                elif phase_name == "waf": waf = res
                elif phase_name == "dns_resolution":
                    dns_resolution = res
                    resolved_file = res.get("resolved_file", "") if res else ""
                    if resolved_file and Path(resolved_file).exists():
                        try: alive_count = len([l for l in Path(resolved_file).read_text().splitlines() if l.strip()])
                        except Exception: alive_count = 0
                        if alive_count > 0 and quick.get("passive_only"):
                            log_ok(f"DNS found {alive_count} alive hosts -> clearing passive-only mode"); quick["passive_only"] = False
                elif phase_name == "response": response = res
                elif phase_name == "tech": tech = res
                elif phase_name == "takeover": takeover = res
                elif phase_name == "vuln": vuln = res
                elif phase_name == "ports": ports = res
                elif phase_name == "leakix": leakix = res
                elif phase_name == "content": urls = res
                elif phase_name == "sensitive": sensitive = res
                elif phase_name == "js": js = res
                elif phase_name == "idor": idor_res = res
                elif phase_name == "dns": dns_res = res
                completed.add(phase_name)
                try:
                    _state = state.update_after_phase(workspace, domain, _state, phase_name, res)
                except Exception as _e:
                    log_warn(f"state update failed for {phase_name}: {_e}")

                # ── AI Thinking (Task 2) ──
                try:
                    if not (isinstance(res, dict) and res.get("_skipped")):
                        _api_key_think = api_keys_global.get("FREELLMAPI_API_KEY", "")
                        if _api_key_think:
                            print()
                            print(f"{DIM}[THINK]{RST} {phase_name}: analyzing output...")
                            _think = ai_thinker.think_about_phase(
                                domain, phase_name, res, GLOBAL_WAF_TYPE,
                                _api_key_think, verbose=args_verbose,
                            )
                            if _think:
                                print(f"{BOLD}{M}[THINK]{RST} {phase_name} "
                                      f"{DIM}({_think['model']}, {_think['elapsed']}s){RST}")
                                for line in _think["analysis"].split(". "):
                                    line = line.strip()
                                    if line:
                                        if not line.endswith("."):
                                            line += "."
                                        print(f"  {line}")
                                _saved = ai_thinker.save_thinking(
                                    domain, phase_name, _think,
                                    Path(workspace) / domain
                                )
                                if _saved and args_verbose:
                                    log_dim(f"Saved: {_saved}")
                            else:
                                print(f"{DIM}[THINK]{RST} {phase_name}: (no analysis)")
                except Exception as _te:
                    if args_verbose:
                        log_warn(f"AI thinking failed for {phase_name}: {_te}")

                save_checkpoint(workspace, domain, completed, extra={"waf_type": GLOBAL_WAF_TYPE})
            except KeyboardInterrupt:
                log_warn(f"Phase {phase_name} interrupted"); completed.add(phase_name)
                save_checkpoint(workspace, domain, completed, extra={"waf_type": GLOBAL_WAF_TYPE}); continue
            except Exception as e: log_err(f"Phase {phase_name} failed: {e}"); continue
        # ── Update AI context with this target's results ──
        try:
            GLOBAL_AI_CONTEXT["passive_subs"]   = len((passive or {}).get("all_subdomains", []))
            GLOBAL_AI_CONTEXT["alive_hosts"]    = len((response or {}).get("alive", []))
            GLOBAL_AI_CONTEXT["f403"]           = len((response or {}).get("f403", []))
            GLOBAL_AI_CONTEXT["f404"]           = len((response or {}).get("f404", []))
            GLOBAL_AI_CONTEXT["open_ports"]     = sum(1 for _ in rlines((ports or {}).get("open_ports_file", "")))
            GLOBAL_AI_CONTEXT["urls_found"]     = sum(1 for _ in rlines((urls or {}).get("final_urls", "")))
            GLOBAL_AI_CONTEXT["js_files"]       = sum(1 for _ in rlines((js or {}).get("js_file", "")))
            GLOBAL_AI_CONTEXT["secrets"]        = sum(1 for _ in rlines((js or {}).get("secrets_file", "")))
        except Exception:
            pass

        result["targets"].append({"domain": domain, "quick": quick, "passive": passive, "waf": waf, "dns_resolution": dns_resolution, "response": response, "tech": tech, "takeover": takeover, "vuln": vuln, "ports": ports, "leakix": leakix, "urls": urls, "sensitive": sensitive, "js": js, "idor": idor_res, "dns": dns_res, "ai_plan": AI_PLAN_GLOBAL})

        # --- VERIFY FINDINGS (Patch C) ---
        current_target_data = {"targets": [result["targets"][-1]]}
        current_findings = build_findings_summary(current_target_data)

        try:
            _api_key_verify = api_keys_global.get("FREELLMAPI_API_KEY", "")
            if current_findings and _api_key_verify:
                _verified, _stats = ai_verifier.verify_all(
                    current_findings, domain, _api_key_verify,
                    verbose=args_verbose,
                )
                current_findings = _verified
                # Save verification stats to result
                result["targets"][-1]["verification_stats"] = _stats
                # Filter for telegram: only confirmed + uncertain
                _telegram_findings = [
                    f for f in current_findings
                    if f.get("verification_status") in ("confirmed", "uncertain")
                ]
                print(f"{G}[+]{RST} Verification: "
                      f"{_stats.get('confirmed', 0)} confirmed, "
                      f"{_stats.get('false-positive', 0)} false-positive, "
                      f"{_stats.get('uncertain', 0)} uncertain")
            else:
                _telegram_findings = current_findings
        except Exception as _ve:
            log_warn(f"Verification failed: {_ve}")
            _telegram_findings = current_findings

        # --- TELEGRAM NOTIFICATION ---
        send_telegram_report(domain, _telegram_findings)

        clear_checkpoint(workspace)
    findings = build_findings_summary(result)
    # Keep the verified versions (if any)
    try:
        if "verification_stats" in (result["targets"][-1] if result["targets"] else {}):
            # build_findings_summary rebuilds; re-verify would double-call.
            # Instead, keep as-is — verification data is already in the finding details.
            pass
    except Exception:
        pass
    result["findings"] = findings
    print(f"\n{BOLD}{B}{'=' * 60}{RST}")
    print(f"{BOLD}{C}  Writing Reports{RST}")
    print(f"{BOLD}{B}{'=' * 60}{RST}")
    # ── Patch 3: dedupe raw IDOR arrays before JSON write ──
    try:
        _dedup_summary = dedupe_idor_data_inplace(result)
        if _dedup_summary and globals().get("args_verbose", False):
            for k, (b, a) in _dedup_summary.items():
                print(f"  {G}[dedup]{RST} idor.{k}: {b} → {a}")
    except Exception as _de:
        print(f"  {Y}[dedup warn]{RST} {_de}")

    json_path = workspace / "report.json"
    json_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    print(f"  {G}v{RST} JSON  -> {json_path}")
    if args.report_format in ("txt", "both"):
        tp = workspace / "report.txt"; write_txt(tp, result, findings); print(f"  {G}v{RST} TXT   -> {tp}")
    if args.report_format in ("html", "both"):
        hp = workspace / "report.html"; write_html(hp, result, findings); print(f"  {G}v{RST} HTML  -> {hp}")
    print(f"\n{BOLD}{G}[+] Clicker {VERSION} complete -> {workspace}/{RST}")
    if findings: print(f"{BOLD}{Y}Top finding score: {findings[0]['score']} -> {findings[0]['type']}{RST}")
    print(f"{DIM}Follow updates: {Y}{INSTAGRAM}{RST}\n")

    # ── Send 'Testing End' notification to Telegram ──
    try:
        _elapsed = None
        try:
            _elapsed = time.time() - _scan_start_ts
        except NameError:
            pass
        send_telegram_completion(workspace, result, findings, elapsed_sec=_elapsed)
    except Exception as _e:
        log_warn(f"completion notify failed: {_e}")

if __name__ == "__main__":
    main()
