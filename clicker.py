#!/usr/bin/env python3
"""
Clicker v2.0 - Black-box Recon & Bug Bounty Pipeline
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
from urllib.parse import urlparse

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

# Ports for httpx probing (matches recon file)
HTTPX_PORTS = "80,443,8080,8443,8000,8888"

# Extended HTTP status codes for alive detection (matches recon file)
HTTPX_STATUS_CODES = "200,201,202,204,301,302,303,307,308"

WAF_TOOL_OPTIONS = {
    "cloudflare": {"httpx": "-timeout 10 -retries 1", "naabu": "-rate 100 -timeout 1000", "nmap": "-T3 --max-retries 1"},
    "akamai":     {"httpx": "-timeout 15 -retries 2", "naabu": "-rate 80 -timeout 1500", "nmap": "-T3 --host-timeout 15m"},
    "imperva":    {"httpx": "-timeout 20 -retries 2", "naabu": "-rate 50 -timeout 2000", "nmap": "-T2 --max-retries 2"},
    "default":    {"httpx": "-timeout 10 -retries 1", "naabu": "-rate 200 -timeout 1000", "nmap": "-T4 --max-retries 1"},
}

HTTP_PROXY_TOOLS = {
    "subfinder", "sublist3r", "chaos", "assetfinder", "github-subdomains",
    "findomain", "waybackurls", "gau", "httpx", "httpx-toolkit", "curl",
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
    "dirsearch_wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt",
}

# Active probing paths
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

# Passive sensitive file extensions (from recon file)
SENSITIVE_EXTENSIONS = (
    r"\.(env|ini|conf|config|cfg|yml|yaml|sql|db|sqlite|sqlite3|bak|backup|"
    r"old|log|txt|csv|xml|json|key|pem|pub|rsa|sh|bash|dump|save|orig|copy)"
    r"(\?|$)"
)

# File extensions for dirsearch / ffuf fuzzing (from recon file)
FUZZ_EXTENSIONS = "env,env.local,env.dev,env.prod,env.backup,env.old,env.bak,git,gitignore,gitconfig,svn,zip,tar,tar.gz,rar,7z,bak,old,backup,save,orig,copy,sql,sqlite,sqlite3,db,json,csv,xml,log,txt,php,js,yml,yaml,ini,cfg,config,key,pem,pub,rsa,sh,bash"

# Filter pattern for URL discovery (media files)
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

# ============================================================================
# VALIDATION
# ============================================================================
DOMAIN_RE = re.compile(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$')
IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

def validate_domain(d):
    if not d:
        raise ValueError("empty domain")
    d = d.strip().lower()
    if "://" in d:
        d = urlparse(d).hostname or ""
    d = d.strip(".")
    if not d or not DOMAIN_RE.match(d):
        raise ValueError(f"invalid domain: {d!r}")
    return d

def validate_ip(ip):
    return bool(IP_RE.match(ip.strip()))

# ============================================================================
# SHELL & IO HELPERS
# ============================================================================
def q(s):
    return shlex.quote(str(s))

def mkd(p):
    Path(p).mkdir(parents=True, exist_ok=True)

def rlines(path):
    p = Path(path)
    if not p.exists():
        return []
    try:
        return [l.strip() for l in p.read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
    except Exception:
        return []

def wlines(path, lines, auto_cleanup=True):
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    uniq = sorted(set(l.strip() for l in lines if l and l.strip()))
    p.write_text("\n".join(uniq) + ("\n" if uniq else ""), encoding="utf-8")
    if auto_cleanup:
        cleanup_empty_file(p)

def is_file_empty(path):
    p = Path(path)
    if not p.exists():
        return True
    try:
        return len(p.read_text(encoding="utf-8", errors="ignore").strip()) == 0
    except Exception:
        return True

def cleanup_empty_file(path, label=""):
    p = Path(path)
    if is_file_empty(p) and p.exists():
        try:
            p.unlink()
            if args_verbose:
                tag = f" ({label})" if label else ""
                print(f"  {Y}[!]{RST} {DIM}{p.name}{tag} empty → deleted{RST}")
            return True
        except Exception:
            pass
    return False

def cleanup_after_merge(sources, label="source"):
    for s in sources:
        s = Path(s)
        if s.exists():
            try:
                s.unlink()
                if args_verbose:
                    print(f"  {Y}[!]{RST} {DIM}{s.name} ({label}) merged → deleted{RST}")
            except Exception:
                pass

def show_file_content(path, label, max_lines=40):
    p = Path(path)
    if not p.exists() or is_file_empty(p):
        return
    lines = rlines(p)
    print(f"\n{BOLD}{C}📄 {label} ({len(lines)} lines){RST}")
    print(f"{DIM}{'─' * 70}{RST}")
    for i, line in enumerate(lines[:max_lines], 1):
        if "[200]" in line or "[302]" in line:
            print(f"  {G}{i:3d}{RST} {line}")
        elif "[403]" in line or "[404]" in line:
            print(f"  {Y}{i:3d}{RST} {line}")
        elif "VULNERABLE" in line or "CVE-" in line or "EXPOSED" in line:
            print(f"  {R}{i:3d}{RST} {BOLD}{line}{RST}")
        else:
            print(f"  {DIM}{i:3d}{RST} {line}")
    if len(lines) > max_lines:
        print(f"  {DIM}... and {len(lines) - max_lines} more{RST}")
    print(f"{DIM}{'─' * 70}{RST}\n")

def installed(tool):
    return shutil.which(tool) is not None

def cleanup_sub(v, domain):
    if not v:
        return None
    v = v.strip().lower().replace("*.", "")
    if "://" in v:
        v = urlparse(v).hostname or ""
    v = v.split("/")[0].split(":")[0].split(",")[0].strip(".")
    if not v:
        return None
    if v == domain or v.endswith("." + domain):
        if DOMAIN_RE.match(v):
            return v
    return None

def extract_hosts_from_urls(lines, domain):
    out = set()
    for l in lines:
        try:
            h = urlparse(l.strip()).hostname
        except Exception:
            h = None
        c = cleanup_sub(h or "", domain)
        if c:
            out.add(c)
    return out

# ============================================================================
# LOGGER
# ============================================================================
def log_info(msg):    print(f"{C}[*]{RST} {msg}")
def log_ok(msg):      print(f"{G}[+]{RST} {msg}")
def log_warn(msg):    print(f"{Y}[!]{RST} {msg}")
def log_err(msg):     print(f"{R}[✘]{RST} {msg}")
def log_dim(msg):     print(f"{DIM}{msg}{RST}")
# ============================================================================
# PROXY MANAGER
# ============================================================================
class ProxyManager:
    def __init__(self, proxy=None, proxy_file=None, auto_fetch=False, rotate=False):
        self.proxies = []
        self.current_idx = 0
        self.rotate = rotate
        self.load(proxy, proxy_file, auto_fetch)

    def load(self, proxy, proxy_file, auto_fetch):
        raw = []
        if auto_fetch:
            log_info("Fetching fresh proxies from public APIs...")
            for url in [
                "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all",
                "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
            ]:
                try:
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(req, timeout=10) as res:
                        raw.extend(res.read().decode(errors="ignore").splitlines())
                except Exception as e:
                    log_warn(f"Proxy fetch failed: {e}")
        if proxy_file and os.path.isfile(proxy_file):
            try:
                raw.extend(Path(proxy_file).read_text(errors="ignore").splitlines())
            except Exception:
                pass
        if proxy:
            raw.append(proxy)

        pattern = re.compile(r'^(?:[^@\s]+@)?(\d{1,3}\.){3}\d{1,3}:\d{2,5}$')
        self.proxies = sorted(set(p.strip() for p in raw if pattern.match(p.strip())))
        if not self.proxies:
            log_warn("No valid proxies loaded - running without proxy")
        else:
            log_ok(f"Loaded {len(self.proxies)} valid proxy(ies)")

    def get_current(self):
        if not self.proxies:
            return None
        if self.rotate:
            p = self.proxies[self.current_idx]
            self.current_idx = (self.current_idx + 1) % len(self.proxies)
            return p
        return self.proxies[0]

    def apply(self, domain=None):
        proxy = self.get_current()
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            os.environ.pop(k, None)
        if not proxy:
            return
        if domain:
            print(f"{DIM}↻ Proxy: {proxy} for {domain}{RST}")
        proxy_url = proxy if "://" in proxy else f"http://{proxy}"
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            os.environ[k] = proxy_url

def check_proxy_health(proxy, timeout=8):
    if not proxy:
        return False
    try:
        proxy_url = proxy if "://" in proxy else f"http://{proxy}"
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url})
        )
        opener.addheaders = [("User-Agent", "Mozilla/5.0")]
        with opener.open("https://httpbin.org/ip", timeout=timeout) as res:
            return res.status == 200
    except Exception:
        return False

# ============================================================================
# COMMAND RUNNER
# ============================================================================
def run_cmd(cmd, timeout=600, tool_name=None, allow_fallback=True):
    global GLOBAL_PROXY_HEALTH_OK, SKIP_CURRENT_PHASE
    if SKIP_CURRENT_PHASE:
        SKIP_CURRENT_PHASE = False
        return (0, "", "")

    has_proxy = bool(os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy"))

    use_proxy = True
    if GLOBAL_HYBRID_PROXY and tool_name:
        if tool_name in NO_PROXY_TOOLS:
            use_proxy = False
            for k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
                os.environ.pop(k, None)
        elif tool_name not in HTTP_PROXY_TOOLS:
            use_proxy = False

    if use_proxy and GLOBAL_HYBRID_PROXY and not GLOBAL_PROXY_HEALTH_OK:
        cur = os.environ.get("HTTP_PROXY", "").replace("http://", "")
        if cur and not check_proxy_health(cur, timeout=5):
            use_proxy = False
        else:
            GLOBAL_PROXY_HEALTH_OK = True

    final_cmd = cmd
    if use_proxy and GLOBAL_USE_PROXYCHAINS:
        pc = shutil.which("proxychains4") or shutil.which("proxychains")
        if pc:
            final_cmd = f"{pc} -q {cmd}"

    try:
        p = subprocess.run(
            final_cmd, shell=True, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=timeout
        )
        result = (p.returncode, p.stdout.strip(), p.stderr.strip())

        if allow_fallback and use_proxy and has_proxy and (p.returncode != 0 or not p.stdout.strip()):
            if args_verbose:
                log_warn(f"Retrying {tool_name or 'cmd'} without proxy")
            saved = {k: os.environ.get(k) for k in
                     ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")}
            for k in saved:
                os.environ.pop(k, None)
            try:
                p2 = subprocess.run(
                    cmd, shell=True, check=False,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    text=True, timeout=timeout
                )
            finally:
                for k, v in saved.items():
                    if v:
                        os.environ[k] = v
                    else:
                        os.environ.pop(k, None)
            if p2.returncode == 0 and p2.stdout.strip():
                return (p2.returncode, p2.stdout.strip(), p2.stderr.strip())
        return result
    except subprocess.TimeoutExpired:
        return (124, "", f"timeout after {timeout}s")
    except KeyboardInterrupt:
        SKIP_CURRENT_PHASE = False
        return (0, "", "")
    except Exception as e:
        return (1, "", str(e))

# ============================================================================
# PHASE PROGRESS
# ============================================================================
class PhaseProgress:
    def __init__(self, name, total):
        self.name, self.total, self.done, self.start = name, total, 0, time.time()
        print(f"\n{BOLD}{B}{'═' * 60}{RST}")
        print(f"{BOLD}{C}  Phase: {name}{RST}")
        print(f"{BOLD}{B}{'═' * 60}{RST}")

    def step(self, label):
        global SKIP_CURRENT_PHASE
        if SKIP_CURRENT_PHASE:
            SKIP_CURRENT_PHASE = False
            raise KeyboardInterrupt
        self.done += 1
        pct = int(self.done / self.total * 100)
        bar = int(pct / 4)
        elapsed = time.time() - self.start
        print(f"  {G}{'█' * bar}{RST}{DIM}{'░' * (25 - bar)}{RST} "
              f"{BOLD}{pct:3d}%{RST} {Y}[{self.done}/{self.total}]{RST} "
              f"{DIM}{elapsed:.0f}s{RST} {W}{label}{RST}")

    def done_phase(self):
        print(f"\n  {G}✔ Phase complete in {time.time() - self.start:.1f}s{RST}\n")

# ============================================================================
# SIGNAL HANDLER
# ============================================================================
def signal_handler(sig, frame):
    global SKIP_CURRENT_PHASE
    print(f"\n{Y}[!] Ctrl+C — skipping current phase, continuing...{RST}")
    SKIP_CURRENT_PHASE = True

# ============================================================================
# CHECKPOINT (RESUME)
# ============================================================================
def resume_file(workspace):
    return Path(workspace) / ".clicker_resume.json"

def save_checkpoint(workspace, domain, completed_phases, extra=None):
    data = {
        "domain": domain,
        "completed_phases": sorted(completed_phases),
        "timestamp": datetime.datetime.now().isoformat(),
        "extra": extra or {},
    }
    try:
        resume_file(workspace).write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass

def load_checkpoint(workspace, domain):
    rf = resume_file(workspace)
    if not rf.exists():
        return None
    try:
        data = json.loads(rf.read_text(encoding="utf-8"))
        if data.get("domain") != domain:
            return None
        return data
    except Exception:
        return None

def clear_checkpoint(workspace):
    rf = resume_file(workspace)
    if rf.exists():
        try:
            rf.unlink()
        except Exception:
            pass

# ============================================================================
# API KEYS
# ============================================================================
API_KEY_FIELDS = [
    ("CHAOS_API_KEY", "Chaos"),
    ("VT_API_KEY", "VirusTotal"),
    ("GITHUB_TOKEN", "GitHub"),
    ("SHODAN_API", "Shodan"),
    ("LEAKIX_API", "LeakIX"),
]

def read_env_file(path):
    vals = {}
    p = Path(path)
    if not p.exists():
        return vals
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        vals[k.strip()] = v.strip().strip('"').strip("'")
    return vals

def save_env_file(path, vals):
    lines = ["# Clicker API keys", "# Keep this file private — chmod 600 recommended"]
    for k, _ in API_KEY_FIELDS:
        lines.append(f"{k}={vals.get(k, '')}")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def collect_api_keys(api_file):
    existing = read_env_file(api_file)
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

# ============================================================================
# SCOPE MANAGEMENT
# ============================================================================
def load_scope(path):
    if not path:
        return None
    p = Path(path)
    if not p.exists():
        log_warn(f"Scope file not found: {path}")
        return None
    include, exclude = [], []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!"):
            exclude.append(line[1:].strip().lower())
        else:
            include.append(line.lower())
    return {"include": include, "exclude": exclude}

def in_scope(domain, scope):
    if not scope:
        return True
    def matches(patterns):
        for pat in patterns:
            if pat.startswith("*."):
                if domain == pat[2:] or domain.endswith("." + pat[2:]):
                    return True
            elif domain == pat:
                return True
        return False
    if scope["exclude"] and matches(scope["exclude"]):
        return False
    if not scope["include"]:
        return True
    return matches(scope["include"])

# ============================================================================
# TOOL CHECK
# ============================================================================
def check_tools(required):
    print(f"{BOLD}{Y}[*] Checking required tools...{RST}")
    available, missing = set(), []
    for t in required:
        if installed(t):
            available.add(t)
            print(f"  {G}✔{RST} {t}")
        else:
            missing.append(t)
            print(f"  {R}✘{RST} {DIM}{t}{RST}")
    if missing:
        log_warn(f"{len(missing)} tool(s) missing — affected steps will be skipped")
    else:
        log_ok("All required tools present")
    return available

# ============================================================================
# FALLBACK FILE DOWNLOAD
# ============================================================================
def ensure_essential_file(file_type, path):
    p = Path(path)
    if p.exists():
        return str(p)
    fallback_dir = Path.home() / ".clicker" / "wordlists"
    fallback_dir.mkdir(parents=True, exist_ok=True)
    url = FALLBACK_URLS.get(file_type)
    if not url:
        return None
    fp = fallback_dir / f"{file_type}.txt"
    if fp.exists():
        log_ok(f"Using cached {file_type}: {fp}")
        return str(fp)
    log_warn(f"{file_type} not found — downloading fallback...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=60) as res:
            fp.write_bytes(res.read())
        log_ok(f"Downloaded {file_type} → {fp}")
        return str(fp)
    except Exception as e:
        log_err(f"Download failed: {e}")
        return None

# ============================================================================
# WAF DETECTION HELPERS
# ============================================================================
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
# PHASE 0 — QUICK PROBE
# ============================================================================
def phase_quick_probe(domain, workspace):
    qdir = Path(workspace) / domain / "quick"
    mkd(qdir)
    prog = PhaseProgress("0 — Quick Probe", 4)
    result = {
        "alive": False, "status": 0, "server": "", "waf_hint": "",
        "ip": "", "redirect": "", "skip_scan": False, "https": False,
    }

    try:
        ip = socket.gethostbyname(domain)
        result["ip"] = ip
        prog.step(f"DNS → {G}{ip}{RST}")
    except Exception:
        prog.step(f"DNS → {R}unresolvable{RST}")

    try:
        req = urllib.request.Request(f"https://{domain}", headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as res:
            result["alive"] = True
            result["https"] = True
            result["status"] = res.status
            result["server"] = res.headers.get("Server", "")[:40]
            for h in ("cf-ray", "x-akamai-transformed", "akamai-grn", "x-cdn", "incap-signal", "x-sucuri-id", "x-amz-cf-id"):
                if res.headers.get(h):
                    result["waf_hint"] = h
                    break
            prog.step(f"HTTPS probe → {G}{res.status}{RST} {DIM}({result['server']}){RST}")
    except urllib.error.HTTPError as e:
        result["alive"] = True
        result["https"] = True
        result["status"] = e.code
        result["server"] = (e.headers.get("Server", "") if e.headers else "")[:40]
        for h in ("cf-ray", "x-akamai-transformed", "x-cdn", "incap-signal"):
            if e.headers and e.headers.get(h):
                result["waf_hint"] = h
                break
        prog.step(f"HTTPS probe → {Y}{e.code}{RST} {DIM}({result['server']}){RST}")
    except Exception:
        try:
            req = urllib.request.Request(f"http://{domain}", headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=10) as res:
                result["alive"] = True
                result["status"] = res.status
                result["server"] = res.headers.get("Server", "")[:40]
                if res.geturl().startswith("https://"):
                    result["https"] = True
                prog.step(f"HTTP probe → {G}{res.status}{RST} {DIM}({result['server']}){RST}")
        except urllib.error.HTTPError as e:
            result["alive"] = True
            result["status"] = e.code
            prog.step(f"HTTP probe → {Y}{e.code}{RST}")
        except Exception:
            prog.step(f"HTTPS/HTTP probe → {R}dead{RST}")

    if not result["alive"] and not result["ip"]:
        result["skip_scan"] = True
        prog.step(f"Decision → {R}SKIP (unresolvable + unreachable){RST}")
    elif not result["alive"]:
        prog.step(f"Decision → {Y}proceed (IP exists but no HTTP){RST}")
    else:
        prog.step(f"Decision → {G}proceed{RST}")

    prog.done_phase()

    summary = [
        f"alive={result['alive']}",
        f"status={result['status']}",
        f"ip={result['ip']}",
        f"server={result['server']}",
        f"waf_hint={result['waf_hint']}",
        f"https={result['https']}",
        f"skip_scan={result['skip_scan']}",
    ]
    try:
        (qdir / "probe.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    except Exception:
        pass

    if result["waf_hint"]:
        print(f"  {C}[*] WAF hint from headers: {result['waf_hint']}{RST}")
    if result["skip_scan"]:
        print(f"  {R}[!] Target seems dead — full scan will be skipped (use --force to override){RST}")

    return result

# ============================================================================
# PHASE 1 — PASSIVE SUBDOMAIN ENUMERATION (enhanced: -recursive + waymore+unfurl)
# ============================================================================
def phase_passive(domain, workspace, api_keys, available):
    pdir = Path(workspace) / domain / "passive"
    mkd(pdir)
    collected = set()
    logs = []
    source_files = []
    prog = PhaseProgress("1 — Passive Subdomain Enumeration", 12)

    try:
        # Subfinder (with -recursive)
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
            prog.step(f"subfinder → {G}{len(parsed)}{RST} subs")
        else:
            prog.step("subfinder — skipped")

        # Sublist3r
        if "sublist3r" in available:
            outf = pdir / f"{domain}_sublist3r.txt"
            cmd = f"sublist3r -d {q(domain)} -e 'Google,Bing,Virustotal,Netcraft' -v -o {q(outf)}"
            _, out, err = run_cmd(cmd, timeout=480, tool_name="sublist3r")
            lines = rlines(outf) if outf.exists() else out.splitlines()
            parsed = {cleanup_sub(l, domain) for l in lines}
            parsed = {x for x in parsed if x}
            wlines(outf, parsed, auto_cleanup=False)
            collected.update(parsed)
            logs.append({"tool": "sublist3r", "count": len(parsed), "stderr": err[:200]})
            source_files.append(outf)
            prog.step(f"sublist3r → {G}{len(parsed)}{RST} subs")
        else:
            prog.step("sublist3r — skipped")

        # Chaos
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
            prog.step(f"chaos → {G}{len(parsed)}{RST} subs")
        else:
            prog.step("chaos — skipped")

        # Assetfinder
        if "assetfinder" in available:
            outf = pdir / f"{domain}_assetfinder.txt"
            cmd = f"assetfinder --subs-only {q(domain)}"
            _, out, err = run_cmd(cmd, timeout=480, tool_name="assetfinder")
            parsed = {cleanup_sub(l, domain) for l in out.splitlines()}
            parsed = {x for x in parsed if x}
            wlines(outf, parsed, auto_cleanup=False)
            collected.update(parsed)
            logs.append({"tool": "assetfinder", "count": len(parsed), "stderr": err[:200]})
            source_files.append(outf)
            prog.step(f"assetfinder → {G}{len(parsed)}{RST} subs")
        else:
            prog.step("assetfinder — skipped")

        # GitHub-subdomains
        if api_keys.get("GITHUB_TOKEN") and "github-subdomains" in available:
            outf = pdir / f"{domain}_github.txt"
            cmd = f"github-subdomains -d {q(domain)} -t {q(api_keys['GITHUB_TOKEN'])} -q -raw -o {q(outf)}"
            _, out, err = run_cmd(cmd, timeout=480, tool_name="github-subdomains")
            lines = rlines(outf) if outf.exists() else out.splitlines()
            parsed = {cleanup_sub(l, domain) for l in lines}
            parsed = {x for x in parsed if x}
            wlines(outf, parsed, auto_cleanup=False)
            collected.update(parsed)
            logs.append({"tool": "github-subdomains", "count": len(parsed), "stderr": err[:200]})
            source_files.append(outf)
            prog.step(f"github-subdomains → {G}{len(parsed)}{RST} subs")
        else:
            prog.step("github-subdomains — skipped")

        # Findomain
        if "findomain" in available:
            outf = pdir / f"{domain}_findomain.txt"
            cmd = f"findomain -t {q(domain)} -q --rate-limit 1"
            _, out, err = run_cmd(cmd, timeout=480, tool_name="findomain")
            parsed = {cleanup_sub(l, domain) for l in out.splitlines()}
            parsed = {x for x in parsed if x}
            wlines(outf, parsed, auto_cleanup=False)
            collected.update(parsed)
            logs.append({"tool": "findomain", "count": len(parsed), "stderr": err[:200]})
            source_files.append(outf)
            prog.step(f"findomain → {G}{len(parsed)}{RST} subs")
        else:
            prog.step("findomain — skipped")

        # crt.sh
        if "curl" in available and "jq" in available:
            outf = pdir / f"{domain}_crtsh.txt"
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            cmd = (f"curl -s --max-time 30 --retry 2 -A 'Mozilla/5.0' {q(url)} "
                   f"| jq -r '.[].name_value' 2>/dev/null "
                   f"| sort -u")
            _, out, err = run_cmd(cmd, timeout=120, tool_name="curl")
            parsed = {cleanup_sub(l, domain) for l in out.splitlines()}
            parsed = {x for x in parsed if x}
            wlines(outf, parsed, auto_cleanup=False)
            collected.update(parsed)
            logs.append({"tool": "crt.sh", "count": len(parsed), "stderr": err[:200]})
            source_files.append(outf)
            prog.step(f"crt.sh → {G}{len(parsed)}{RST} subs")
        else:
            prog.step("crt.sh — skipped")

        # Waybackurls
        if "waybackurls" in available:
            outf = pdir / f"{domain}_waybackurls.txt"
            cmd = f"echo {q(domain)} | waybackurls | sort -u"
            _, out, err = run_cmd(cmd, timeout=480, tool_name="waybackurls")
            parsed = extract_hosts_from_urls(out.splitlines(), domain)
            wlines(outf, parsed, auto_cleanup=False)
            collected.update(parsed)
            logs.append({"tool": "waybackurls", "count": len(parsed), "stderr": err[:200]})
            source_files.append(outf)
            prog.step(f"waybackurls → {G}{len(parsed)}{RST} subs")
        else:
            prog.step("waybackurls — skipped")

        # GAU
        if "gau" in available:
            outf = pdir / f"{domain}_gau.txt"
            cmd = f"echo {q(domain)} | gau --subs --timeout 10 --threads 2 | sort -u"
            _, out, err = run_cmd(cmd, timeout=480, tool_name="gau")
            parsed = extract_hosts_from_urls(out.splitlines(), domain)
            wlines(outf, parsed, auto_cleanup=False)
            collected.update(parsed)
            logs.append({"tool": "gau", "count": len(parsed), "stderr": err[:200]})
            source_files.append(outf)
            prog.step(f"gau → {G}{len(parsed)}{RST} subs")
        else:
            prog.step("gau — skipped")

        # VirusTotal
        if api_keys.get("VT_API_KEY") and "curl" in available:
            outf = pdir / f"{domain}_virustotal.txt"
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
            cmd = f"curl -s --max-time 30 -H {q('x-apikey: ' + api_keys['VT_API_KEY'])} {q(url)} | jq -r '.data[].id' 2>/dev/null"
            _, out, err = run_cmd(cmd, timeout=60, tool_name="curl")
            parsed = {cleanup_sub(l, domain) for l in out.splitlines()}
            parsed = {x for x in parsed if x}
            wlines(outf, parsed, auto_cleanup=False)
            collected.update(parsed)
            logs.append({"tool": "virustotal", "count": len(parsed), "stderr": err[:200]})
            source_files.append(outf)
            prog.step(f"virustotal → {G}{len(parsed)}{RST} subs")
        else:
            prog.step("virustotal — skipped")

        # NEW: waymore + unfurl domains
        if "waymore" in available and "unfurl" in available:
            wout = pdir / f"{domain}_waymore_urls.txt"
            cmd = f"waymore -i {q(domain)} -mode U -oU {q(wout)} -t 30 2>/dev/null || true"
            run_cmd(cmd, timeout=600, tool_name="waymore")
            if wout.exists() and not is_file_empty(wout):
                outf = pdir / f"{domain}_waymore_subs.txt"
                cmd2 = (f"cat {q(wout)} | unfurl domains 2>/dev/null "
                        f"| grep -Ei '(^|\\.){re.escape(domain)}$' | sort -u")
                _, out, _ = run_cmd(cmd2, timeout=120, tool_name="cat")
                parsed = {cleanup_sub(l, domain) for l in out.splitlines()}
                parsed = {x for x in parsed if x}
                wlines(outf, parsed, auto_cleanup=False)
                collected.update(parsed)
                logs.append({"tool": "waymore+unfurl", "count": len(parsed)})
                source_files.append(outf)
                prog.step(f"waymore+unfurl → {G}{len(parsed)}{RST} subs")
            else:
                prog.step("waymore+unfurl — no output")
        elif "waymore" in available:
            # Fallback: extract subs without unfurl using Python urlparse
            wout = pdir / f"{domain}_waymore_urls.txt"
            cmd = f"waymore -i {q(domain)} -mode U -oU {q(wout)} -t 30 2>/dev/null || true"
            run_cmd(cmd, timeout=600, tool_name="waymore")
            if wout.exists() and not is_file_empty(wout):
                parsed = extract_hosts_from_urls(rlines(wout), domain)
                outf = pdir / f"{domain}_waymore_subs.txt"
                wlines(outf, parsed, auto_cleanup=False)
                collected.update(parsed)
                logs.append({"tool": "waymore", "count": len(parsed)})
                source_files.append(outf)
                prog.step(f"waymore → {G}{len(parsed)}{RST} subs")
            else:
                prog.step("waymore — no output")
        else:
            prog.step("waymore+unfurl — skipped")

        # Merge
        allsubs = pdir / "allsubs.txt"
        wlines(allsubs, collected, auto_cleanup=False)
        prog.step(f"merge → {allsubs.name} ({G}{len(collected)}{RST})")

        cleanup_after_merge([f for f in source_files if f.exists()], label="passive-source")

        # High-value subs
        sensitive = [s for s in collected if s.split(".")[0] in SENSITIVE_PREFIXES]
        hv = pdir / "high_value_subs.txt"
        wlines(hv, sensitive)
        if not is_file_empty(hv):
            print(f"  {G}✔{RST} high_value_subs.txt — {Y}{len(sensitive)}{RST} entries")
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
# PHASE 2 — WAF DETECTION
# ============================================================================
def phase_waf(domain, workspace, available):
    global GLOBAL_WAF_TYPE
    pdir = Path(workspace) / domain / "passive"
    wdir = Path(workspace) / domain / "waf"
    mkd(wdir)
    high_val = pdir / "high_value_subs.txt"
    prog = PhaseProgress("2 — WAF Detection", 3)
    detected = "default"
    waf_simple = wdir / "waf-detected.txt"

    try:
        httpx_bin = "httpx-toolkit" if "httpx-toolkit" in available else ("httpx" if "httpx" in available else None)

        if httpx_bin and high_val.exists() and not is_file_empty(high_val):
            out = wdir / "httpx-waf.txt"
            cmd = (f"{httpx_bin} -l {q(high_val)} -sc -td -cl -server -title -silent "
                   f"-t 15 -rl 8 -timeout 10 -retries 1 -random-agent -o {q(out)}")
            run_cmd(cmd, timeout=600, tool_name=httpx_bin)
            for line in rlines(out):
                ll = line.lower()
                if "cloudflare" in ll:
                    detected = "cloudflare"
                    break
                if "akamai" in ll or "edgekey" in ll:
                    detected = "akamai"
                    break
                if "imperva" in ll or "incapsula" in ll:
                    detected = "imperva"
                    break
            prog.step(f"httpx scan → {G}{detected}{RST}")
        else:
            prog.step("httpx scan — skipped")

        if detected == "default" and "wafw00f" in available and high_val.exists() and not is_file_empty(high_val):
            out = wdir / "wafw00f.txt"
            cmd = f"wafw00f -i {q(high_val)} -a -T 10 --no-colors 2>/dev/null | tee {q(out)}"
            run_cmd(cmd, timeout=900, tool_name="wafw00f")
            content = (out.read_text(errors="ignore").lower() if out.exists() else "")
            for waf_name, keys in [
                ("cloudflare", ["cloudflare"]),
                ("akamai", ["akamai", "edgekey"]),
                ("imperva", ["imperva", "incapsula"]),
            ]:
                if any(k in content for k in keys):
                    detected = waf_name
                    break
            prog.step(f"wafw00f → {G}{detected}{RST}")
        else:
            prog.step("wafw00f — skipped")

        if detected == "default" and high_val.exists():
            headers_sig = {
                "cloudflare": ["cf-ray", "cf-cache-status"],
                "akamai": ["akamai-grn", "x-akamai-transformed"],
                "imperva": ["x-cdn", "incap-signal"],
                "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
                "aws": ["x-amz-cf-id"],
            }
            for host in rlines(high_val)[:10]:
                try:
                    url = host if host.startswith("http") else f"https://{host}"
                    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                    with urllib.request.urlopen(req, timeout=5) as res:
                        hdr_str = str({k.lower(): v for k, v in res.headers.items()}).lower()
                        for waf_name, indicators in headers_sig.items():
                            if any(ind in hdr_str for ind in indicators):
                                detected = waf_name
                                break
                    if detected != "default":
                        break
                except Exception:
                    continue
            prog.step(f"header analysis → {G}{detected}{RST}")
        else:
            prog.step("header analysis — skipped")

        if detected != "default":
            wlines(waf_simple, [f"WAF Detected: {detected.upper()}"], auto_cleanup=False)
            print(f"  {G}✔{RST} Saved to {waf_simple.name}")

        GLOBAL_WAF_TYPE = detected
        prog.done_phase()
        print(f"{C}[*] WAF Type: {detected.upper()}{RST}")
        return {"waf_file": str(waf_simple) if waf_simple.exists() else None, "waf_type": detected}
    except KeyboardInterrupt:
        log_warn("Phase 2 skipped")
        GLOBAL_WAF_TYPE = "default"
        return {"waf_file": None, "waf_type": "default"}

# ============================================================================
# PHASE 3 — ACTIVE SUBDOMAIN ENUMERATION
# ============================================================================
def phase_active_subs(domain, workspace, available):
    if args_skip_active_subs:
        log_warn("Active subdomain enumeration skipped via flag")
        return {"active_subs_file": "", "active_count": 0}

    pdir = Path(workspace) / domain / "passive"
    adir = Path(workspace) / domain / "active_subs"
    mkd(adir)
    allsubs_in = pdir / "allsubs.txt"
    existing = set(rlines(allsubs_in)) if allsubs_in.exists() else set()
    discovered = set()
    prog = PhaseProgress("3 — Active Subdomain Enumeration", 4)

    try:
        if "puredns" in available:
            wl = ensure_essential_file("wordlist", args_wordlist) or args_wordlist
            res = ensure_essential_file("resolvers", args_resolvers) or args_resolvers
            if wl and Path(wl).exists() and res and Path(res).exists():
                outf = adir / "puredns.txt"
                cmd = (f"puredns bruteforce {q(wl)} {q(domain)} "
                       f"-r {q(res)} -w {q(outf)} --quiet")
                run_cmd(cmd, timeout=1800, tool_name="puredns")
                parsed = {cleanup_sub(l, domain) for l in rlines(outf)}
                parsed = {x for x in parsed if x}
                discovered.update(parsed)
                prog.step(f"puredns → {G}{len(parsed)}{RST} subs")
            else:
                prog.step("puredns — skipped (missing wordlist/resolvers)")
        else:
            prog.step("puredns — skipped (not installed)")

        if "altdns" in available and existing:
            perm_in = adir / "altdns_in.txt"
            perm_out = adir / "altdns_out.txt"
            wlines(perm_in, list(existing)[:500], auto_cleanup=False)
            cmd = f"altdns -i {q(perm_in)} -o {q(perm_out)} 2>/dev/null || true"
            run_cmd(cmd, timeout=600, tool_name="altdns")
            if perm_out.exists() and not is_file_empty(perm_out) and "dnsx" in available:
                resolved = adir / "altdns_resolved.txt"
                cmd2 = f"dnsx -l {q(perm_out)} -silent -a -resp-only -r 8.8.8.8,1.1.1.1 -o {q(resolved)}"
                run_cmd(cmd2, timeout=600, tool_name="dnsx")
                parsed = {cleanup_sub(l, domain) for l in rlines(resolved)}
                parsed = {x for x in parsed if x}
                discovered.update(parsed)
                prog.step(f"altdns+dnsx → {G}{len(parsed)}{RST} permutations")
            else:
                prog.step("altdns — 0 permutations")
        else:
            prog.step("altdns — skipped")

        if "dnsrecon" in available:
            outf = adir / "dnsrecon.txt"
            cmd = f"dnsrecon -d {q(domain)} -t axfr 2>/dev/null || true"
            _, out, _ = run_cmd(cmd, timeout=300, tool_name="dnsrecon")
            parsed = set()
            for line in out.splitlines():
                for token in re.findall(r'[a-z0-9.-]+\.' + re.escape(domain), line.lower()):
                    c = cleanup_sub(token, domain)
                    if c:
                        parsed.add(c)
            wlines(outf, parsed, auto_cleanup=False)
            discovered.update(parsed)
            prog.step(f"dnsrecon AXFR → {G}{len(parsed)}{RST} subs")
        else:
            prog.step("dnsrecon — skipped")

        final = existing | discovered
        allsubs_final = pdir / "allsubs_final.txt"
        wlines(allsubs_final, final, auto_cleanup=False)
        prog.step(f"merge → allsubs_final.txt ({G}{len(final)}{RST} total)")

        prog.done_phase()
        log_ok(f"Active subs new: {len(discovered)} | Total: {len(final)}")

        return {
            "active_subs_file": str(allsubs_final),
            "active_count": len(discovered),
        }
    except KeyboardInterrupt:
        log_warn("Phase 3 skipped")
        return {"active_subs_file": str(pdir / "allsubs_final.txt"), "active_count": 0}

# ============================================================================
# PHASE 4 — DNS RESOLUTION (NEW: dnsx pre-filter for httpx)
# ============================================================================
def phase_dns_resolution(domain, workspace, available):
    pdir = Path(workspace) / domain / "passive"
    ddir = Path(workspace) / domain / "dns"
    mkd(ddir)
    allsubs = pdir / "allsubs_final.txt"
    if not allsubs.exists():
        allsubs = pdir / "allsubs.txt"
    prog = PhaseProgress("4 — DNS Resolution", 1)
    resolved = ddir / "resolved.txt"

    try:
        if "dnsx" in available and allsubs.exists() and not is_file_empty(allsubs):
            cmd = (f"dnsx -l {q(allsubs)} -silent -a "
                   f"-r 8.8.8.8,1.1.1.1,8.8.4.4 -t 100 -rl 200 -resp-only -o {q(resolved)}")
            run_cmd(cmd, timeout=300, tool_name="dnsx")
            count = len(rlines(resolved))
            if count > 0:
                print(f"  {G}✔{RST} resolved.txt — {count} alive subdomains")
            prog.step(f"dnsx resolution → {G}{count}{RST} hosts")
        else:
            # Fallback: use allsubs directly
            if allsubs.exists():
                shutil.copy2(allsubs, resolved)
            prog.step("dnsx — skipped (using allsubs)")
        prog.done_phase()
        return {"resolved_file": str(resolved) if resolved.exists() else ""}
    except KeyboardInterrupt:
        log_warn("Phase 4 skipped")
        return {"resolved_file": ""}

# ============================================================================
# PHASE 5 — RESPONSE FILTERING (enhanced: ports + status codes)
# ============================================================================
def phase_response_filter(domain, workspace, passive, available):
    adir = Path(workspace) / domain / "active"
    mkd(adir)
    pdir = Path(workspace) / domain / "passive"
    ddir = Path(workspace) / domain / "dns"

    # Use resolved.txt if exists, fallback to allsubs
    resolved = ddir / "resolved.txt"
    if resolved.exists() and not is_file_empty(resolved):
        input_file = resolved
    else:
        input_file = pdir / "allsubs_final.txt"
        if not input_file.exists():
            input_file = pdir / "allsubs.txt"

    high_val = pdir / "high_value_subs.txt"

    prog = PhaseProgress("5 — Response Filtering", 6)
    results = {"alive": [], "f403": [], "f404": [], "details": []}
    httpx_bin = "httpx-toolkit" if "httpx-toolkit" in available else ("httpx" if "httpx" in available else None)
    waf_type = detect_waf_from_file(workspace, domain)
    httpx_opts = get_tool_options("httpx", waf_type)

    try:
        if httpx_bin and high_val.exists() and not is_file_empty(high_val):
            out = adir / "details.txt"
            cmd = (f"{httpx_bin} -l {q(high_val)} -sc -td -cl -server -title -ip -silent "
                   f"-t 15 -rl 8 -timeout 7 -retries 1 -random-agent -follow-redirects "
                   f"-p {HTTPX_PORTS} {httpx_opts} -o {q(out)}")
            run_cmd(cmd, timeout=600, tool_name=httpx_bin)
            results["details"] = rlines(out)
            prog.step(f"high-value details → {G}{len(results['details'])}{RST}")
        else:
            prog.step("high-value details — skipped")

        # Alive check with extended ports + status codes
        if httpx_bin and input_file.exists() and not is_file_empty(input_file):
            out = adir / "alive.txt"
            cmd = (f"{httpx_bin} -l {q(input_file)} "
                   f"-mc {HTTPX_STATUS_CODES} -silent -t 20 -rl 5 "
                   f"-timeout 7 -retries 1 -random-agent -follow-redirects "
                   f"-p {HTTPX_PORTS} {httpx_opts} -o {q(out)}")
            run_cmd(cmd, timeout=1200, tool_name=httpx_bin)
            results["alive"] = rlines(out)
            prog.step(f"alive (extended) → {G}{len(results['alive'])}{RST}")
        else:
            prog.step("alive — skipped")

        # 403
        if httpx_bin and input_file.exists() and not is_file_empty(input_file):
            out = adir / "403subs.txt"
            cmd = (f"{httpx_bin} -l {q(input_file)} -mc 403 -silent -t 15 -rl 8 "
                   f"-timeout 7 -retries 1 -random-agent -follow-redirects "
                   f"{httpx_opts} -o {q(out)}")
            run_cmd(cmd, timeout=600, tool_name=httpx_bin)
            results["f403"] = rlines(out)
            prog.step(f"403 filter → {Y}{len(results['f403'])}{RST}")
        else:
            prog.step("403 filter — skipped")

        # 404
        if httpx_bin and input_file.exists() and not is_file_empty(input_file):
            out = adir / "404subs.txt"
            cmd = (f"{httpx_bin} -l {q(input_file)} -mc 404 -silent -t 15 -rl 8 "
                   f"-timeout 7 -retries 1 -random-agent -follow-redirects "
                   f"{httpx_opts} -o {q(out)}")
            run_cmd(cmd, timeout=600, tool_name=httpx_bin)
            results["f404"] = rlines(out)
            prog.step(f"404 filter → {R}{len(results['f404'])}{RST}")
        else:
            prog.step("404 filter — skipped")

        success = adir / "success-response.txt"
        wlines(success, results["alive"], auto_cleanup=False)
        prog.step(f"success-response.txt → {G}{len(results['alive'])}{RST}")

        prog.done_phase()
        if args_verbose:
            show_file_content(success, "success-response.txt", max_lines=30)
        return results
    except KeyboardInterrupt:
        log_warn("Phase 5 skipped")
        return results

# ============================================================================
# PHASE 6 — TECHNOLOGY DETECTION
# ============================================================================
def phase_tech_detect(domain, workspace, available):
    adir = Path(workspace) / domain / "active"
    sucf = adir / "success-response.txt"
    techf = adir / "subs-Tech.txt"
    ipsf = adir / "ips.txt"
    alivef = adir / "alive-final.txt"
    prog = PhaseProgress("6 — Technology Detection", 3)
    httpx_bin = "httpx-toolkit" if "httpx-toolkit" in available else ("httpx" if "httpx" in available else None)
    httpx_opts = get_tool_options("httpx", GLOBAL_WAF_TYPE)

    try:
        if httpx_bin and sucf.exists() and not is_file_empty(sucf):
            cmd = (f"{httpx_bin} -l {q(sucf)} -sc -td -cl -server -title -ip -silent "
                   f"-t 15 -rl 8 -timeout 10 -retries 1 -random-agent {httpx_opts} -o {q(techf)}")
            run_cmd(cmd, timeout=1200, tool_name=httpx_bin)
            prog.step(f"httpx tech detection → {techf.name}")
        else:
            prog.step("httpx tech — skipped")

        if techf.exists() and not is_file_empty(techf):
            raw = techf.read_text(errors="ignore")
            ips = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', raw))
            wlines(ipsf, ips)
            prog.step(f"IP extraction → {G}{len(ips)}{RST}")
        else:
            prog.step("IP extraction — skipped")

        if techf.exists() and not is_file_empty(techf):
            alive = []
            for line in rlines(techf):
                m = re.search(r'\[(200|201|202|204|301|302|303|307|308)\]', line)
                if m:
                    url_match = re.search(r'https?://\S+', line)
                    if url_match:
                        alive.append(url_match.group(0))
            wlines(alivef, alive)
            prog.step(f"alive-final → {G}{len(alive)}{RST}")
        else:
            prog.step("alive-final — skipped")

        prog.done_phase()
        if args_verbose:
            if techf.exists():
                show_file_content(techf, "subs-Tech.txt", max_lines=30)
        return {"ips_file": str(ipsf), "alive_final": str(alivef)}
    except KeyboardInterrupt:
        log_warn("Phase 6 skipped")
        return {"ips_file": "", "alive_final": ""}

# ============================================================================
# PHASE 7 — SUBDOMAIN TAKEOVER
# ============================================================================
def phase_takeover(domain, workspace, available):
    adir = Path(workspace) / domain / "active"
    tdir = Path(workspace) / domain / "takeover"
    mkd(tdir)
    f404 = adir / "404subs.txt"
    prog = PhaseProgress("7 — Subdomain Takeover", 3)
    findings = []

    try:
        if "subzy" in available and f404.exists() and not is_file_empty(f404):
            outf = tdir / "subzy-results.txt"
            cmd = f"subzy run --targets {q(f404)} --concurrency 5 --timeout 8 --hide_fails 2>/dev/null | tee {q(outf)}"
            run_cmd(cmd, timeout=600, tool_name="subzy")
            if not is_file_empty(outf):
                findings.extend(rlines(outf))
            prog.step(f"subzy → {G}{len(rlines(outf))}{RST}")
        else:
            prog.step("subzy — skipped")

        if "subjack" in available and f404.exists() and not is_file_empty(f404):
            outf = tdir / "subjack-results.json"
            cmd = f"subjack -w {q(f404)} -t 8 -timeout 10 -ssl -o {q(outf)} 2>/dev/null"
            run_cmd(cmd, timeout=600, tool_name="subjack")
            if not is_file_empty(outf):
                findings.extend(rlines(outf))
            prog.step(f"subjack → {G}{len(rlines(outf))}{RST}")
        else:
            prog.step("subjack — skipped")

        if "nuclei" in available and f404.exists() and not is_file_empty(f404):
            outf = tdir / "nuclei-takeover.txt"
            cmd = (f"nuclei -list {q(f404)} -tags takeover -silent -rl 10 -c 5 "
                   f"-timeout 8 -retries 1 -no-interactsh 2>/dev/null | tee {q(outf)}")
            run_cmd(cmd, timeout=1200, tool_name="nuclei")
            if not is_file_empty(outf):
                findings.extend(rlines(outf))
            prog.step(f"nuclei takeover → {G}{len(rlines(outf))}{RST}")
        else:
            prog.step("nuclei takeover — skipped")

        prog.done_phase()
        if findings:
            print(f"  {R}{BOLD}⚠ {len(findings)} potential takeover(s) found{RST}")
        return {"takeover_dir": str(tdir), "findings": findings}
    except KeyboardInterrupt:
        log_warn("Phase 7 skipped")
        return {"takeover_dir": str(tdir), "findings": []}

# ============================================================================
# PHASE 8 — VULNERABILITY SCANNING
# ============================================================================
def _cors_one(url):
    try:
        req = urllib.request.Request(url, headers={
            "Origin": "https://evil-clicker-probe.com",
            "User-Agent": "Mozilla/5.0",
        })
        with urllib.request.urlopen(req, timeout=4) as res:
            acao = res.headers.get("Access-Control-Allow-Origin", "")
            acac = res.headers.get("Access-Control-Allow-Credentials", "")
            if acao in ("https://evil-clicker-probe.com", "*"):
                severity = "HIGH" if (acac.lower() == "true" and acao != "*") else "MEDIUM"
                return f"{url} | {severity} | ACAO={acao} ACAC={acac}"
    except Exception:
        pass
    return None

def _exposed_one(base_url):
    out = []
    for path in EXPOSED_FILE_PATHS:
        url = base_url.rstrip("/") + path
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=3) as res:
                if res.status == 200:
                    body = res.read(512)
                    if path == "/.git/HEAD" and b"ref:" not in body.lower():
                        continue
                    if path.endswith(".env") and b"=" not in body:
                        continue
                    out.append(f"{url} [200]")
        except urllib.error.HTTPError:
            continue
        except Exception:
            continue
    return out

def phase_vuln_scan(domain, workspace, available):
    if args_skip_vuln:
        log_warn("Vulnerability scan skipped via flag")
        return {"nuclei": [], "cors": [], "exposed": []}

    adir = Path(workspace) / domain / "active"
    vdir = Path(workspace) / domain / "vulns"
    mkd(vdir)
    alivef = adir / "alive-final.txt"
    prog = PhaseProgress("8 — Vulnerability Scanning", 3)
    results = {"nuclei": [], "cors": [], "exposed": []}

    try:
        if "nuclei" in available and alivef.exists() and not is_file_empty(alivef):
            outf = vdir / "nuclei-results.txt"
            cmd = (f"nuclei -list {q(alivef)} "
                   f"-severity critical,high "
                   f"-tags cve,exposure,misconfig "
                   f"-silent -rl 50 -c 25 -timeout 6 -retries 1 "
                   f"-no-interactsh -stats -stats-interval 15 "
                   f"-o {q(outf)} 2>&1 | grep -vE '^\\[INF\\]|^\\[WRN\\]' || true")
            print(f"  {DIM}Running nuclei (this may take a few minutes)...{RST}")
            run_cmd(cmd, timeout=900, tool_name="nuclei")
            if not is_file_empty(outf):
                results["nuclei"] = rlines(outf)
            prog.step(f"nuclei → {G}{len(results['nuclei'])}{RST} findings")
        else:
            prog.step("nuclei — skipped")

        hosts_to_check = []
        if alivef.exists() and not is_file_empty(alivef):
            for line in rlines(alivef):
                m = re.search(r'https?://\S+', line)
                if m:
                    hosts_to_check.append(m.group(0))
                elif line.startswith(("http://", "https://")):
                    hosts_to_check.append(line)
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
                        if r:
                            cors_findings.append(r)
                    except Exception:
                        continue
            if cors_findings:
                wlines(vdir / "cors.txt", cors_findings, auto_cleanup=False)
                results["cors"] = cors_findings
        prog.step(f"CORS check → {G}{len(cors_findings)}{RST}")

        exposed = []
        targets_exposed = hosts_to_check[:15]
        if targets_exposed:
            print(f"  {DIM}Checking exposed files on {len(targets_exposed)} host(s) (parallel)...{RST}")
            with ThreadPoolExecutor(max_workers=10) as ex:
                futures = {ex.submit(_exposed_one, u): u for u in targets_exposed}
                for fut in as_completed(futures):
                    try:
                        exposed.extend(fut.result())
                    except Exception:
                        continue
            if exposed:
                wlines(vdir / "exposed-files.txt", exposed, auto_cleanup=False)
                results["exposed"] = exposed
        prog.step(f"Exposed files → {G}{len(exposed)}{RST}")

        prog.done_phase()
        if args_verbose:
            if results["nuclei"]:
                show_file_content(vdir / "nuclei-results.txt", "nuclei-results.txt", max_lines=30)
            if results["cors"]:
                show_file_content(vdir / "cors.txt", "cors.txt", max_lines=20)
            if results["exposed"]:
                show_file_content(vdir / "exposed-files.txt", "exposed-files.txt", max_lines=20)
        return results
    except KeyboardInterrupt:
        log_warn("Phase 8 skipped")
        return results

# ============================================================================
# PHASE 9 — PORT SCANNING
# ============================================================================
def phase_ports(domain, workspace, available):
    adir = Path(workspace) / domain / "active"
    pdir = Path(workspace) / domain / "passive"
    ipsf = adir / "ips.txt"
    allsubs = pdir / "allsubs_final.txt"
    if not allsubs.exists():
        allsubs = pdir / "allsubs.txt"
    real_ips = adir / "real-ips.txt"
    open_ports_txt = adir / "open-ports-full.txt"
    nmap_results = adir / "nmap-scripts.txt"
    prog = PhaseProgress("9 — Port Scanning", 5)
    naabu_opts = get_tool_options("naabu", GLOBAL_WAF_TYPE)
    nmap_opts = get_tool_options("nmap", GLOBAL_WAF_TYPE)

    try:
        resolved = adir / "resolved-ips.txt"
        if "dnsx" in available and allsubs.exists() and not is_file_empty(allsubs):
            cmd = f"dnsx -l {q(allsubs)} -resp-only -a -silent -t 100 -r 8.8.8.8,1.1.1.1 -o {q(resolved)}"
            run_cmd(cmd, timeout=300, tool_name="dnsx")
            prog.step("dnsx resolve all subdomains")
        else:
            prog.step("dnsx — skipped")

        all_ips = adir / "all-ips-final.txt"
        merge_src = [str(ipsf), str(resolved)]
        merge_src = [s for s in merge_src if Path(s).exists()]
        if merge_src:
            cmd = f"cat {' '.join(q(s) for s in merge_src)} 2>/dev/null | sort -u > {q(all_ips)}"
            run_cmd(cmd, timeout=60, tool_name="cat")
            prog.step(f"merge all IPs → {len(rlines(all_ips))}")
        else:
            all_ips.touch()
            prog.step("merge all IPs — empty")

        if not is_file_empty(all_ips) and "cdncheck" in available:
            cdn_res = adir / "cdn-results.txt"
            cmd = f"cat {q(all_ips)} | cdncheck -silent -resp -r 8.8.8.8,1.1.1.1 -o {q(cdn_res)}"
            run_cmd(cmd, timeout=180, tool_name="cdncheck")
            cmd2 = (f"cat {q(all_ips)} | cdncheck -silent -resp -r 8.8.8.8,1.1.1.1 "
                    f"| grep -ivE 'cloudflare|akamai|fastly|cloudfront|incapsula|sucuri|aws|azure|google' "
                    f"| awk '{{print $1}}' | sort -u > {q(real_ips)}")
            run_cmd(cmd2, timeout=180, tool_name="cdncheck")
            if not is_file_empty(real_ips):
                print(f"  {G}✔{RST} real-ips.txt — {len(rlines(real_ips))} non-CDN IPs")
            prog.step("CDN filtering")
        else:
            if all_ips.exists():
                real_ips.write_text(all_ips.read_text())
            else:
                real_ips.touch()
            prog.step("CDN filtering — skipped")

        if "naabu" in available and real_ips.exists() and not is_file_empty(real_ips):
            json_out = adir / "open-ports.json"
            cmd = (f"naabu -list {q(real_ips)} -p {PORTS_COMMON} -rate 300 -c 25 -retries 1 "
                   f"-timeout 1000 -Pn -s s -verify -silent -json {naabu_opts} -o {q(json_out)}")
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
                    except Exception:
                        continue
            if formatted:
                wlines(open_ports_txt, formatted, auto_cleanup=False)
                print(f"  {G}✔{RST} open-ports-full.txt — {len(formatted)} ports")
            cleanup_empty_file(json_out, "raw-json")
            prog.step(f"naabu scan → {G}{len(formatted)}{RST} ports")
        else:
            prog.step("naabu — skipped")

        if "nmap" in available and open_ports_txt.exists() and not is_file_empty(open_ports_txt):
            ips_to_scan = set()
            for line in rlines(open_ports_txt):
                m = re.match(r"([^:/]+):\d+", line)
                if m:
                    ips_to_scan.add(m.group(1))
            if ips_to_scan:
                ip_list = adir / "nmap-targets.txt"
                wlines(ip_list, ips_to_scan, auto_cleanup=False)
                nmap_prefix = adir / "nmap-scripts"
                cmd = (f"nmap -iL {q(ip_list)} -sC -sV --open -T4 -Pn -n --version-light "
                       f"--max-retries 1 --host-timeout 10m {nmap_opts} "
                       f"-p 21,22,23,25,53,80,443,3306,3389,5432,6379,8080,8443,9200,27017 "
                       f"-oA {q(nmap_prefix)}")
                run_cmd(cmd, timeout=1800, tool_name="nmap")
                nmap_file = adir / "nmap-scripts.nmap"
                if nmap_file.exists():
                    cmd2 = (f"grep -iE 'vuln|CVE-|sqli|xss|injection|exploit|weak|anonymous|"
                            f"auth.*bypass|misconfig' {q(nmap_file)} | grep -vE '^#|^Nmap|^Host:|^Port:' "
                            f"| sort -u > {q(nmap_results)}")
                    run_cmd(cmd2, timeout=300, tool_name="grep")
                    if not is_file_empty(nmap_results):
                        print(f"  {G}✔{RST} nmap-scripts.txt — {len(rlines(nmap_results))} findings")
            prog.step("nmap -sC vuln scan")
        else:
            prog.step("nmap — skipped")

        prog.done_phase()
        if args_verbose and not is_file_empty(open_ports_txt):
            show_file_content(open_ports_txt, "open-ports-full.txt", max_lines=40)
        return {"open_ports_file": str(open_ports_txt) if open_ports_txt.exists() else None}
    except KeyboardInterrupt:
        log_warn("Phase 9 skipped")
        return {"open_ports_file": None}

# ============================================================================
# PHASE 10 — LEAKIX
# ============================================================================
def phase_leakix(domain, workspace, available):
    adir = Path(workspace) / domain / "active"
    ldir = Path(workspace) / domain / "leakix"
    mkd(ldir)
    ipsf = adir / "ips.txt"
    alivef = adir / "alive-final.txt"
    prog = PhaseProgress("10 — LeakIX Exposure Check", 2)
    key = api_keys_global.get("LEAKIX_API", "")
    out_ips = ldir / "leakix-ips.txt"
    out_doms = ldir / "leakix-domains.txt"

    try:
        if not key:
            prog.step("LeakIX — skipped (no API key)")
            prog.step("LeakIX — skipped (no API key)")
            prog.done_phase()
            return {"leakix_ips": "", "leakix_domains": ""}

        if "curl" in available and "jq" in available and ipsf.exists() and not is_file_empty(ipsf):
            ips = [ip for ip in rlines(ipsf) if validate_ip(ip)][:30]
            findings = []
            for ip in ips:
                try:
                    url = f"https://leakix.net/host/{ip}"
                    cmd = f"curl -s --max-time 10 -H {q('api-key: ' + key)} -H 'Accept: application/json' {q(url)}"
                    _, out, _ = run_cmd(cmd, timeout=15, tool_name="curl")
                    if not out or '"error"' in out:
                        continue
                    try:
                        data = json.loads(out)
                    except Exception:
                        continue
                    for svc in data.get("Services", []) or []:
                        leak = svc.get("leak") or {}
                        if leak.get("type") or leak.get("details"):
                            findings.append(
                                f"{ip} | port {svc.get('port')} | {svc.get('protocol','')} | "
                                f"leak={leak.get('type','')} | {svc.get('software', {}).get('name','')}"
                            )
                except Exception:
                    continue
                time.sleep(0.5)
            if findings:
                wlines(out_ips, findings, auto_cleanup=False)
                print(f"  {G}✔{RST} leakix-ips.txt — {len(findings)} findings")
            prog.step(f"LeakIX IP scan → {G}{len(findings)}{RST}")
        else:
            prog.step("LeakIX IP scan — skipped")

        if "curl" in available and "jq" in available and alivef.exists() and not is_file_empty(alivef):
            doms = set()
            for line in rlines(alivef)[:30]:
                try:
                    h = urlparse(line if "://" in line else "https://" + line).hostname
                    if h:
                        doms.add(h)
                except Exception:
                    continue
            findings = []
            for d in list(doms)[:20]:
                try:
                    url = f"https://leakix.net/domain/{d}"
                    cmd = f"curl -s --max-time 10 -H {q('api-key: ' + key)} -H 'Accept: application/json' {q(url)}"
                    _, out, _ = run_cmd(cmd, timeout=15, tool_name="curl")
                    if not out or '"error"' in out:
                        continue
                    try:
                        data = json.loads(out)
                    except Exception:
                        continue
                    for svc in data.get("Services", []) or []:
                        leak = svc.get("leak") or {}
                        if leak.get("type") or leak.get("details"):
                            findings.append(
                                f"{d} | port {svc.get('port')} | leak={leak.get('type','')}"
                            )
                except Exception:
                    continue
                time.sleep(0.5)
            if findings:
                wlines(out_doms, findings, auto_cleanup=False)
                print(f"  {G}✔{RST} leakix-domains.txt — {len(findings)} findings")
            prog.step(f"LeakIX domain scan → {G}{len(findings)}{RST}")
        else:
            prog.step("LeakIX domain scan — skipped")

        prog.done_phase()
        return {
            "leakix_ips": str(out_ips) if out_ips.exists() else "",
            "leakix_domains": str(out_doms) if out_doms.exists() else "",
        }
    except KeyboardInterrupt:
        log_warn("Phase 10 skipped")
        return {"leakix_ips": "", "leakix_domains": ""}

# ============================================================================
# PHASE 11 — CONTENT DISCOVERY (enhanced: uro + waymore providers + gau blacklist)
# ============================================================================
def phase_content_discovery(domain, workspace, available):
    adir = Path(workspace) / domain / "active"
    udir = Path(workspace) / domain / "urls"
    mkd(udir)
    alivef = adir / "alive-final.txt"
    prog = PhaseProgress("11 — Content Discovery", 7)
    url_files = []

    try:
        # waybackurls
        if "waybackurls" in available and alivef.exists() and not is_file_empty(alivef):
            outf = udir / "waybackurls.txt"
            cmd = (f"cat {q(alivef)} | waybackurls 2>/dev/null | grep -vE {q(URL_FILTER_PATTERN)} "
                   f"| sort -u | tee {q(outf)}")
            run_cmd(cmd, timeout=900, tool_name="waybackurls")
            url_files.append(outf)
            prog.step(f"waybackurls → {G}{len(rlines(outf))}{RST}")
        else:
            prog.step("waybackurls — skipped")

        # gau with --blacklist (faster than grep)
        if "gau" in available and alivef.exists() and not is_file_empty(alivef):
            outf = udir / "gau.txt"
            cmd = (f"cat {q(alivef)} | gau --threads 5 --timeout 10 "
                   f"--blacklist png,jpg,gif,css,js,ico,svg,woff,woff2,ttf,eot 2>/dev/null "
                   f"| sort -u | tee {q(outf)}")
            run_cmd(cmd, timeout=900, tool_name="gau")
            url_files.append(outf)
            prog.step(f"gau → {G}{len(rlines(outf))}{RST}")
        else:
            prog.step("gau — skipped")

        # katana
        if "katana" in available and alivef.exists() and not is_file_empty(alivef):
            outf = udir / "katana.txt"
            cmd = (f"katana -list {q(alivef)} -d 3 -jc -kf all -silent -c 5 -rl 20 "
                   f"-timeout 10 -retry 1 -o {q(outf)}")
            run_cmd(cmd, timeout=1200, tool_name="katana")
            url_files.append(outf)
            prog.step(f"katana → {G}{len(rlines(outf))}{RST}")
        else:
            prog.step("katana — skipped")

        # waymore with --providers
        if "waymore" in available and alivef.exists() and not is_file_empty(alivef):
            outf = udir / "waymore.txt"
            cmd = (f"waymore -i {q(alivef)} -mode U -p 3 -oU {q(outf)} "
                   f"--providers wayback,commoncrawl,otx,urlscan -ow 2>/dev/null || true")
            run_cmd(cmd, timeout=1200, tool_name="waymore")
            url_files.append(outf)
            prog.step(f"waymore → {G}{len(rlines(outf))}{RST}")
        else:
            prog.step("waymore — skipped")

        # Merge all URLs
        merged_urls = udir / "urls.txt"
        existing = [f for f in url_files if f.exists() and not is_file_empty(f)]
        if existing:
            cmd = f"cat {' '.join(q(str(f)) for f in existing)} 2>/dev/null | sort -u > {q(merged_urls)}"
            run_cmd(cmd, timeout=120, tool_name="cat")
        else:
            merged_urls.touch()
        prog.step(f"merge URLs → {G}{len(rlines(merged_urls))}{RST}")

        # Apply URL filter (in case gau/katana missed some)
        clean_urls = udir / "clean_urls.txt"
        cmd = (f"grep -ivE {q(URL_FILTER_PATTERN)} {q(merged_urls)} 2>/dev/null "
               f"| sort -u > {q(clean_urls)} || true")
        run_cmd(cmd, timeout=60, tool_name="grep")
        prog.step(f"filter media → {G}{len(rlines(clean_urls))}{RST}")

        # NEW: uro normalization
        final_urls = udir / "final-urls.txt"
        if "uro" in available and clean_urls.exists() and not is_file_empty(clean_urls):
            cmd = f"cat {q(clean_urls)} | uro | sort -u > {q(final_urls)} || cp {q(clean_urls)} {q(final_urls)}"
            run_cmd(cmd, timeout=300, tool_name="uro")
            prog.step(f"uro normalization → {G}{len(rlines(final_urls))}{RST} URLs")
        else:
            # Fallback: copy clean_urls to final
            if clean_urls.exists():
                shutil.copy2(clean_urls, final_urls)
            else:
                final_urls.touch()
            prog.step(f"final-urls → {G}{len(rlines(final_urls))}{RST} (no uro)")

        cleanup_after_merge(existing, label="url-source")
        prog.done_phase()
        if args_verbose and not is_file_empty(final_urls):
            show_file_content(final_urls, "final-urls.txt", max_lines=40)
        return {"final_urls": str(final_urls), "clean_urls": str(clean_urls)}
    except KeyboardInterrupt:
        log_warn("Phase 11 skipped")
        return {"final_urls": "", "clean_urls": ""}

# ============================================================================
# PHASE 12 — SENSITIVE FILES (NEW: passive + active dirsearch + ffuf)
# ============================================================================
def phase_sensitive_files(domain, workspace, available):
    if args_skip_fuzz:
        log_warn("Sensitive files / fuzzing skipped via flag")
        return {"passive": "", "dirsearch": "", "ffuf": ""}

    udir = Path(workspace) / domain / "urls"
    sdir = Path(workspace) / domain / "sensitive"
    mkd(sdir)
    clean_urls = udir / "clean_urls.txt"
    if not clean_urls.exists():
        clean_urls = udir / "final-urls.txt"
    adir = Path(workspace) / domain / "active"
    alivef = adir / "alive-final.txt"

    prog = PhaseProgress("12 — Sensitive Files", 3)
    results = {"passive": "", "dirsearch": "", "ffuf": ""}

    try:
        # --- Step 1: Passive filtering from URLs ---
        if clean_urls.exists() and not is_file_empty(clean_urls):
            outf = sdir / "sensitive_files_passive.txt"
            # Filter out noise (sitemap, robots, feed, well-known, news, content/)
            cmd = (f"grep -iE {q(SENSITIVE_EXTENSIONS)} {q(clean_urls)} 2>/dev/null "
                   f"| grep -viE 'sitemap|robots|feed|rss|well-known|content/|news|assets/' "
                   f"| sort -u > {q(outf)} || true")
            run_cmd(cmd, timeout=120, tool_name="grep")
            count = len(rlines(outf))
            if count > 0:
                results["passive"] = str(outf)
                print(f"  {G}✔{RST} sensitive_files_passive.txt — {count} potential files")
            prog.step(f"passive sensitive files → {G}{count}{RST}")
        else:
            prog.step("passive sensitive files — no URLs")

        # --- Step 2: Active dirsearch on alive hosts ---
        if "dirsearch" in available and alivef.exists() and not is_file_empty(alivef):
            # Extract base URLs
            base_urls = sdir / "base_urls.txt"
            urls = []
            for line in rlines(alivef)[:10]:  # limit to 10 to avoid very long runs
                m = re.search(r'(https?://[^\s]+)', line)
                if m:
                    urls.append(m.group(1))
            if urls:
                wlines(base_urls, urls, auto_cleanup=False)
                outf = sdir / "dirsearch.json"
                # Use downloaded wordlist
                wl = ensure_essential_file("dirsearch_wordlist", 
                    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
                if not wl:
                    wl = "/usr/share/seclists/Discovery/Web-Content/common.txt"
                
                cmd = (f"dirsearch -l {q(base_urls)} "
                       f"-e {q(FUZZ_EXTENSIONS)} "
                       f"-w {q(wl)} "
                       f"-t 5 --max-rate=3 --delay=0.7 --timeout=10 --retries=2 "
                       f"--random-agent -r --max-recursion-depth=2 --full-url "
                       f"--exclude-sizes=0B "
                       f"-o {q(outf)} --format=json --log={q(sdir/'dirsearch.log')} 2>/dev/null || true")
                print(f"  {DIM}Running dirsearch on {len(urls)} host(s)...{RST}")
                run_cmd(cmd, timeout=1800, tool_name="dirsearch")
                if outf.exists() and not is_file_empty(outf):
                    results["dirsearch"] = str(outf)
                prog.step(f"dirsearch → {G}{'done' if results['dirsearch'] else 'no results'}{RST}")
            else:
                prog.step("dirsearch — no base URLs")
        else:
            prog.step("dirsearch — skipped")

        # --- Step 3: ffuf on top alive hosts ---
        if "ffuf" in available and alivef.exists() and not is_file_empty(alivef):
            wl = ensure_essential_file("dirsearch_wordlist",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
            if not wl:
                wl = "/usr/share/seclists/Discovery/Web-Content/common.txt"

            # Extract first 5 URLs
            targets = []
            for line in rlines(alivef)[:5]:
                m = re.search(r'(https?://[^\s/]+)', line)
                if m and m.group(1) not in targets:
                    targets.append(m.group(1))

            if targets and Path(wl).exists():
                all_ffuf = []
                for tgt in targets:
                    safe_name = re.sub(r'[^a-zA-Z0-9.-]', '_', tgt.replace("https://", "").replace("http://", ""))
                    outf = sdir / f"ffuf_{safe_name}.json"
                    cmd = (f"ffuf -u {q(tgt)}/FUZZ -w {q(wl)} "
                           f"-e {q('.' + FUZZ_EXTENSIONS.replace(',', ',.'))} "
                           f"-D -t 5 -p 0.7-1.2 -rate 3 -timeout 10 "
                           f"-recursion -recursion-depth 2 -recursion-strategy greedy "
                           f"-mc 200,204,301,302,307 -fs 0 -c "
                           f"-o {q(outf)} -of json 2>/dev/null || true")
                    print(f"  {DIM}Running ffuf on {tgt}...{RST}")
                    run_cmd(cmd, timeout=1200, tool_name="ffuf")
                    if outf.exists() and not is_file_empty(outf):
                        all_ffuf.append(str(outf))
                if all_ffuf:
                    results["ffuf"] = ",".join(all_ffuf)
                prog.step(f"ffuf → {G}{len(all_ffuf)}{RST} host(s)")
            else:
                prog.step("ffuf — no targets")
        else:
            prog.step("ffuf — skipped")

        prog.done_phase()
        return results
    except KeyboardInterrupt:
        log_warn("Phase 12 skipped")
        return results

# ============================================================================
# PHASE 13 — JS RECON (enhanced: katana JS extraction)
# ============================================================================
def phase_js_recon(domain, workspace, available):
    if args_skip_js:
        log_warn("JS recon skipped via flag")
        return {"js_file": "", "secrets_file": ""}

    udir = Path(workspace) / domain / "urls"
    jsdir = Path(workspace) / domain / "js"
    mkd(jsdir)
    final_urls = udir / "final-urls.txt"
    clean_urls = udir / "clean_urls.txt"
    adir = Path(workspace) / domain / "active"
    alivef = adir / "alive-final.txt"

    js_file = jsdir / "jsfiles.txt"
    prog = PhaseProgress("13 — JS Recon & Secrets", 3)

    try:
        # Source 1: from final URLs
        source_file = final_urls if final_urls.exists() else clean_urls
        if source_file.exists() and not is_file_empty(source_file):
            cmd = (f"grep -iE {q(r'\.js(\?|#|$)')} {q(source_file)} 2>/dev/null "
                   f"| grep -E {q(r'^https?://')} | sort -u > {q(js_file)}")
            run_cmd(cmd, timeout=120, tool_name="grep")
            js_count = len(rlines(js_file))
            prog.step(f"JS from URLs → {G}{js_count}{RST}")
        else:
            js_count = 0
            prog.step("JS from URLs — no source")

        # Source 2: katana JS extraction (NEW)
        if "katana" in available and alivef.exists() and not is_file_empty(alivef):
            katana_js = jsdir / "katana_js.txt"
            cmd = (f"katana -list {q(alivef)} -jc -d 3 -silent -c 5 -rl 20 -timeout 10 2>/dev/null "
                   f"| grep -iE {q(r'\.js(\?|$)')} | sort -u > {q(katana_js)} || true")
            run_cmd(cmd, timeout=900, tool_name="katana")
            if katana_js.exists() and not is_file_empty(katana_js):
                # Merge with existing
                cmd2 = f"cat {q(js_file)} {q(katana_js)} 2>/dev/null | sort -u > {q(js_file)}.tmp && mv {q(js_file)}.tmp {q(js_file)}"
                run_cmd(cmd2, timeout=60, tool_name="cat")
                new_count = len(rlines(js_file))
                prog.step(f"katana JS merge → {G}{new_count}{RST} total")
            else:
                prog.step("katana JS — 0 new")
        else:
            prog.step("katana JS — skipped")

        secrets_file = jsdir / "secrets-found.txt"

        if "trufflehog" in available and js_file.exists() and not is_file_empty(js_file):
            outf = jsdir / "trufflehog.txt"
            cmd = f"trufflehog filesystem --no-update --json {q(jsdir)} 2>/dev/null > {q(outf)} || true"
            run_cmd(cmd, timeout=600, tool_name="trufflehog")
            if not is_file_empty(outf):
                shutil.copy2(outf, secrets_file)
                print(f"  {G}✔{RST} secrets-found.txt — {len(rlines(secrets_file))} findings")
        elif "mantra" in available and js_file.exists() and not is_file_empty(js_file):
            outf = jsdir / "mantra.txt"
            pattern = r"(api[_-]?key|secret|token|password|bearer|credential|private[_-]?key|client[_-]?secret|jwt)"
            cmd = (f"mantra -s -ua 'Mozilla/5.0' -t 10 -d {q(js_file)} 2>/dev/null "
                   f"| grep -iE {q(pattern)} | sort -u > {q(outf)}")
            run_cmd(cmd, timeout=600, tool_name="mantra")
            if not is_file_empty(outf):
                shutil.copy2(outf, secrets_file)

        # Regex fallback
        if js_file.exists() and not is_file_empty(js_file) and (not secrets_file.exists() or is_file_empty(secrets_file)):
            regex_file = jsdir / "regex-secrets.txt"
            pattern = r"(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24}|xox[baprs]-[0-9A-Za-z-]+|ghp_[0-9A-Za-z]{36})"
            cmd = f"grep -hoE {q(pattern)} {q(js_file)} 2>/dev/null | sort -u > {q(regex_file)} || true"
            run_cmd(cmd, timeout=60, tool_name="grep")
            if not is_file_empty(regex_file):
                shutil.copy2(regex_file, secrets_file)
                print(f"  {G}✔{RST} secrets-found.txt — {len(rlines(secrets_file))} regex hits")

        if not secrets_file.exists() or is_file_empty(secrets_file):
            print(f"  {Y}[!]{RST} No secrets discovered")

        prog.step(f"secret scan → {len(rlines(secrets_file)) if secrets_file.exists() else 0}")

        prog.done_phase()
        if args_verbose and secrets_file.exists() and not is_file_empty(secrets_file):
            show_file_content(secrets_file, "secrets-found.txt", max_lines=30)
        return {"js_file": str(js_file), "secrets_file": str(secrets_file)}
    except KeyboardInterrupt:
        log_warn("Phase 13 skipped")
        return {"js_file": "", "secrets_file": ""}

# ============================================================================
# PHASE 14 — SCREENSHOTS
# ============================================================================
def phase_screenshots(domain, workspace, available):
    if args_skip_screenshots:
        log_warn("Screenshots skipped via flag")
        return

    adir = Path(workspace) / domain / "active"
    alivef = adir / "alive-final.txt"
    prog = PhaseProgress("14 — Screenshots", 2)

    try:
        if "gowitness" in available and alivef.exists() and not is_file_empty(alivef):
            gw_dir = Path(workspace) / domain / "screenshots" / "gowitness"
            mkd(gw_dir)
            cmd = (f"gowitness scan file -f {q(alivef)} -q -t 10 --delay 1500 --timeout 15 "
                   f"--screenshot-path {q(gw_dir)} --write-db")
            run_cmd(cmd, timeout=1800, tool_name="gowitness")
            prog.step(f"gowitness → {gw_dir}")
        else:
            prog.step("gowitness — skipped")

        if "aquatone" in available and alivef.exists() and not is_file_empty(alivef):
            aq_dir = Path(workspace) / domain / "screenshots" / "aquatone"
            mkd(aq_dir)
            cmd = f"cat {q(alivef)} | aquatone -out {q(aq_dir)} -silent -threads 10"
            run_cmd(cmd, timeout=1800, tool_name="aquatone")
            prog.step(f"aquatone → {aq_dir}")
        else:
            prog.step("aquatone — skipped")

        prog.done_phase()
    except KeyboardInterrupt:
        log_warn("Phase 14 skipped")

# ============================================================================
# PHASE 15 — DNS ENRICHMENT
# ============================================================================
def phase_dns_enrichment(domain, workspace, available):
    pdir = Path(workspace) / domain / "passive"
    ddir = Path(workspace) / domain / "dns"
    mkd(ddir)
    subs_file = pdir / "allsubs_final.txt"
    if not subs_file.exists():
        subs_file = pdir / "allsubs.txt"
    if not subs_file.exists() or is_file_empty(subs_file):
        log_warn("No subdomains to enrich — skipping DNS phase")
        return {"spf": "", "dmarc": "", "dns_records": ""}

    prog = PhaseProgress("15 — DNS Enrichment", 3)
    try:
        if "dnsx" in available:
            outf = ddir / "dns-resolved.txt"
            cmd = f"dnsx -l {q(subs_file)} -silent -a -aaaa -cname -resp -r 8.8.8.8,1.1.1.1 -o {q(outf)}"
            run_cmd(cmd, timeout=600, tool_name="dnsx")
            if not is_file_empty(outf):
                print(f"  {G}✔{RST} dns-resolved.txt — {len(rlines(outf))} records")
            prog.step("dnsx resolution (A/AAAA/CNAME)")
        else:
            prog.step("dnsx — skipped")

        spf_file = ddir / "spf.txt"
        try:
            _, out, _ = run_cmd(f"dig +short TXT {q(domain)} 2>/dev/null", timeout=30)
            spf = [l for l in out.splitlines() if "v=spf1" in l]
            wlines(spf_file, spf)
            if spf:
                print(f"  {G}✔{RST} SPF record found")
            else:
                print(f"  {Y}[!]{RST} No SPF record — potential email spoofing")
        except Exception:
            pass
        prog.step("SPF record check")

        dmarc_file = ddir / "dmarc.txt"
        try:
            _, out, _ = run_cmd(f"dig +short TXT _dmarc.{q(domain)} 2>/dev/null", timeout=30)
            dmarc = [l for l in out.splitlines() if "v=DMARC1" in l]
            wlines(dmarc_file, dmarc)
            if dmarc:
                print(f"  {G}✔{RST} DMARC record found")
            else:
                print(f"  {Y}[!]{RST} No DMARC record — potential email spoofing")
        except Exception:
            pass
        prog.step("DMARC record check")

        prog.done_phase()
        return {
            "spf": str(spf_file) if spf_file.exists() else "",
            "dmarc": str(dmarc_file) if dmarc_file.exists() else "",
            "dns_records": str(ddir / "dns-resolved.txt") if (ddir / "dns-resolved.txt").exists() else "",
        }
    except KeyboardInterrupt:
        log_warn("Phase 15 skipped")
        return {"spf": "", "dmarc": "", "dns_records": ""}

# ============================================================================
# SCORING
# ============================================================================
SCORE_TABLE = {
    "takeover": 90,
    "env_exposed": 95,
    "git_exposed": 90,
    "backup_exposed": 85,
    "sensitive_passive": 80,
    "cors_high": 85,
    "cors_medium": 65,
    "secret": 85,
    "leakix": 80,
    "nuclei_critical": 95,
    "nuclei_high": 85,
    "nuclei_medium": 70,
    "dirsearch_hit": 75,
    "ffuf_hit": 70,
    "sensitive_sub": 60,
    "no_spf": 55,
    "no_dmarc": 50,
    "403_host": 45,
    "open_port_risky": 60,
}

def score_finding(kind, sub=None):
    base = SCORE_TABLE.get(kind, 30)
    if sub and sub.split(".")[0] in SENSITIVE_PREFIXES:
        base = min(100, base + 10)
    return base

def build_findings_summary(result):
    findings = []
    for target in result.get("targets", []):
        dom = target.get("domain", "")
        for line in target.get("takeover", {}).get("findings", []):
            findings.append({"score": score_finding("takeover", dom), "type": "takeover", "target": dom, "detail": line})
        for line in target.get("vuln", {}).get("nuclei", []):
            sev = "high"
            if "[critical]" in line.lower():
                sev = "critical"
            elif "[medium]" in line.lower():
                sev = "medium"
            kind = "nuclei_" + sev
            findings.append({"score": score_finding(kind, dom), "type": "nuclei-" + sev, "target": dom, "detail": line})
        for line in target.get("vuln", {}).get("cors", []):
            kind = "cors_high" if "HIGH" in line else "cors_medium"
            findings.append({"score": score_finding(kind, dom), "type": "cors", "target": dom, "detail": line})
        for line in target.get("vuln", {}).get("exposed", []):
            kind = "env_exposed" if ".env" in line else ("git_exposed" if ".git" in line else "backup_exposed")
            findings.append({"score": score_finding(kind, dom), "type": "exposed-file", "target": dom, "detail": line})

        # Passive sensitive files
        passive_sens = target.get("sensitive", {}).get("passive", "")
        if passive_sens and Path(passive_sens).exists() and not is_file_empty(passive_sens):
            for line in rlines(passive_sens):
                findings.append({"score": score_finding("sensitive_passive", dom), "type": "sensitive-file", "target": dom, "detail": line[:200]})

        # Secrets
        secrets = target.get("js", {}).get("secrets_file", "")
        if secrets and Path(secrets).exists() and not is_file_empty(secrets):
            for line in rlines(secrets):
                findings.append({"score": score_finding("secret", dom), "type": "secret", "target": dom, "detail": line[:200]})

        # Sensitive subs
        for s in target.get("passive", {}).get("sensitive_subs", []):
            findings.append({"score": score_finding("sensitive_sub", s), "type": "sensitive-subdomain", "target": s, "detail": s})

        # SPF/DMARC
        spf_path = target.get("dns", {}).get("spf", "")
        dmarc_path = target.get("dns", {}).get("dmarc", "")
        if spf_path and not Path(spf_path).exists():
            findings.append({"score": score_finding("no_spf", dom), "type": "no-spf", "target": dom, "detail": "No SPF record"})
        if dmarc_path and not Path(dmarc_path).exists():
            findings.append({"score": score_finding("no_dmarc", dom), "type": "no-dmarc", "target": dom, "detail": "No DMARC record"})

    findings.sort(key=lambda f: f["score"], reverse=True)
    return findings

# ============================================================================
# REPORTING
# ============================================================================
def safe(d, *keys, default=0):
    for k in keys:
        if isinstance(d, dict):
            d = d.get(k, None)
        else:
            return default
        if d is None:
            return default
    return d

def write_txt(path, result, findings):
    lines = [
        "CLICKER v2.2 — BUG BOUNTY RECON REPORT",
        "=" * 72,
        f"Generated : {result['generated_at']}",
        f"Findings  : {len(findings)}",
        "",
    ]
    lines.append("TOP FINDINGS (by score)")
    lines.append("-" * 72)
    for f in findings[:30]:
        lines.append(f"  [{f['score']:3d}] {f['type']:<22} {f['target']:<40} {f['detail'][:80]}")
    lines.append("")

    for t in result["targets"]:
        lines += [
            f"Target : {t['domain']}",
            "-" * 40,
            f"  Passive subdomains : {len(safe(t, 'passive', 'all_subdomains', default=[]))}",
            f"  High-value subs    : {len(safe(t, 'passive', 'sensitive_subs', default=[]))}",
            f"  Alive hosts        : {len(safe(t, 'response', 'alive', default=[]))}",
            f"  403 hosts          : {len(safe(t, 'response', 'f403', default=[]))}",
            f"  404 hosts          : {len(safe(t, 'response', 'f404', default=[]))}",
            f"  WAF                : {safe(t, 'waf', 'waf_type', default='default')}",
            "",
        ]
    Path(path).write_text("\n".join(lines), encoding="utf-8")

def write_html(path, result, findings):
    rows = []
    for f in findings[:100]:
        sev_cls = "critical" if f["score"] >= 85 else ("high" if f["score"] >= 70 else "medium")
        rows.append(
            f'<tr class="{sev_cls}"><td>{f["score"]}</td><td>{html.escape(f["type"])}</td>'
            f'<td>{html.escape(f["target"])}</td><td>{html.escape(f["detail"][:200])}</td></tr>'
        )

    blocks = []
    for t in result["targets"]:
        blocks.append(f"""
        <section>
          <h2>🎯 {html.escape(t['domain'])}</h2>
          <table>
            <tr><td>Passive subdomains</td><td>{len(safe(t, 'passive', 'all_subdomains', default=[]))}</td></tr>
            <tr><td>High-value subs</td><td>{len(safe(t, 'passive', 'sensitive_subs', default=[]))}</td></tr>
            <tr><td>Alive hosts</td><td>{len(safe(t, 'response', 'alive', default=[]))}</td></tr>
            <tr><td>WAF</td><td>{html.escape(str(safe(t, 'waf', 'waf_type', default='default')))}</td></tr>
          </table>
        </section>""")

    doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Clicker Report</title>
<style>
body {{font-family: -apple-system, monospace; background: #060d1f; color: #d0d8f0; padding: 24px;}}
h1 {{color: #7dd3fc;}}
h2 {{color: #38bdf8; border-bottom: 1px solid #1e3a5f; padding-bottom: 6px;}}
table {{border-collapse: collapse; width: 100%; margin: 10px 0;}}
td, th {{border: 1px solid #1e3a5f; padding: 6px 12px; font-size: 13px;}}
tr.critical {{background: #4a0d0d;}}
tr.high {{background: #3a2409;}}
tr.medium {{background: #102a3d;}}
</style></head><body>
<h1>⚡ Clicker v2.2 Report</h1>
<p>Generated: {html.escape(result['generated_at'])} | Findings: {len(findings)}</p>
<h2>Top Findings</h2>
<table><thead><tr><th>Score</th><th>Type</th><th>Target</th><th>Detail</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
{''.join(blocks)}
</body></html>"""
    Path(path).write_text(doc, encoding="utf-8")

# ============================================================================
# TARGETS PARSING
# ============================================================================
def parse_targets(single, tfile):
    targets = []
    if single:
        try:
            targets.append(validate_domain(single))
        except ValueError as e:
            sys.exit(f"{R}[!] {e}{RST}")
    if tfile:
        p = Path(tfile)
        if not p.exists():
            sys.exit(f"{R}[!] targets file not found: {tfile}{RST}")
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                targets.append(validate_domain(line))
            except ValueError as e:
                log_warn(f"Skipping invalid target: {e}")
    targets = sorted(set(targets))
    if not targets:
        sys.exit(f"{R}[!] No valid targets. Use -t or --targets-file{RST}")
    return targets

# ============================================================================
# MAIN
# ============================================================================
def main():
    global args_verbose, args_skip_screenshots, args_skip_js, args_skip_active_subs
    global args_skip_vuln, args_skip_fuzz, args_keep_sources, args_resume, args_wordlist, args_resolvers
    global api_keys_global, workspace_global, GLOBAL_USE_PROXYCHAINS, GLOBAL_HYBRID_PROXY
    global GLOBAL_PROXY_HEALTH_OK, GLOBAL_WAF_TYPE, args_scope_file, args_force

    signal.signal(signal.SIGINT, signal_handler)

    if sys.platform != "linux":
        log_warn("Clicker is designed for Linux — some features may not work")

    parser = argparse.ArgumentParser(
        description=f"Clicker {VERSION} — Bug Bounty Recon Pipeline | {INSTAGRAM}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-t", "--target", help="Single target domain")
    parser.add_argument("--targets-file", help="File with one domain per line")
    parser.add_argument("--scope-file", help="Scope file (one pattern per line, prefix '!' to exclude)")
    parser.add_argument("--workspace", default="clicker_output", help="Output directory")
    parser.add_argument("--api-file", default="clicker_api.env", help="API keys file")
    parser.add_argument("--report-format", choices=["txt", "html", "both"], default="both")
    parser.add_argument("--skip-screenshots", action="store_true")
    parser.add_argument("--skip-js", action="store_true")
    parser.add_argument("--skip-active-subs", action="store_true")
    parser.add_argument("--skip-vuln", action="store_true", help="Skip vulnerability scanning phase")
    parser.add_argument("--skip-fuzz", action="store_true", help="Skip sensitive files / dirsearch / ffuf phase")
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

    args_verbose = args.verbose
    args_skip_screenshots = args.skip_screenshots
    args_skip_js = args.skip_js
    args_skip_active_subs = args.skip_active_subs
    args_skip_vuln = args.skip_vuln
    args_skip_fuzz = args.skip_fuzz
    args_keep_sources = args.keep_sources
    args_resume = args.resume
    args_force = args.force
    args_wordlist = args.wordlist
    args_resolvers = args.resolvers
    args_scope_file = args.scope_file
    GLOBAL_USE_PROXYCHAINS = args.proxychains
    GLOBAL_HYBRID_PROXY = args.hybrid_proxy

    pm = ProxyManager(
        proxy=args.proxy,
        proxy_file=args.proxy_list,
        auto_fetch=args.auto_proxy,
        rotate=args.rotate_proxy,
    )
    if GLOBAL_HYBRID_PROXY and pm.proxies:
        test_proxy = pm.get_current()
        if test_proxy and not check_proxy_health(test_proxy, timeout=8):
            log_warn("Initial proxy health check failed — will auto-bypass when needed")
            GLOBAL_PROXY_HEALTH_OK = False
        else:
            GLOBAL_PROXY_HEALTH_OK = True
    pm.apply()

    api_keys_global = collect_api_keys(Path(args.api_file))
    scope = load_scope(args.scope_file)
    targets = parse_targets(args.target, args.targets_file)

    workspace = Path(args.workspace)
    mkd(workspace)
    workspace_global = workspace

    required_tools = [
        "subfinder", "sublist3r", "chaos", "assetfinder", "github-subdomains",
        "findomain", "waybackurls", "gau", "httpx", "httpx-toolkit", "naabu",
        "dnsx", "cdncheck", "nmap", "aquatone", "gowitness", "katana",
        "waymore", "mantra", "subzy", "subjack", "wafw00f", "puredns",
        "altdns", "shuffledns", "dnsrecon", "ffuf", "nuclei", "trufflehog",
        "gitleaks", "curl", "jq", "grep", "sed", "awk", "sort", "cat", "dig",
        "unfurl", "uro", "dirsearch",
    ]
    available = check_tools(required_tools)

    result = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "version": VERSION,
        "targets": [],
    }

    print(f"\n{BOLD}{M}[►] Starting scan on {len(targets)} target(s){RST}\n")

    for domain in targets:
        if not in_scope(domain, scope):
            log_warn(f"OUT OF SCOPE: {domain} — skipping")
            continue

        pm.apply(domain=domain)
        print(f"\n{BOLD}{W}{'━' * 60}{RST}")
        print(f"{BOLD}{M}  Target : {domain}{RST}")
        print(f"{BOLD}{W}{'━' * 60}{RST}")

        completed = set()
        if args_resume:
            cp = load_checkpoint(workspace, domain)
            if cp:
                completed = set(cp.get("completed_phases", []))
                log_ok(f"Resuming — completed phases: {sorted(completed)}")

        # Storage
        quick = {}
        passive = {}
        waf = {}
        dns_resolution = {}
        response = {}
        tech = {}
        takeover = {}
        vuln = {}
        ports = {}
        leakix = {}
        urls = {}
        sensitive = {}
        js = {}
        dns_res = {}

        def make_phases():
            return [
                ("quick",           lambda: phase_quick_probe(domain, workspace)),
                ("passive",         lambda: phase_passive(domain, workspace, api_keys_global, available)),
                ("waf",             lambda: phase_waf(domain, workspace, available)),
                ("active",          lambda: phase_active_subs(domain, workspace, available)),
                ("dns_resolution",  lambda: phase_dns_resolution(domain, workspace, available)),
                ("response",        lambda: phase_response_filter(domain, workspace, passive, available)),
                ("tech",            lambda: phase_tech_detect(domain, workspace, available)),
                ("takeover",        lambda: phase_takeover(domain, workspace, available)),
                ("vuln",            lambda: phase_vuln_scan(domain, workspace, available)),
                ("ports",           lambda: phase_ports(domain, workspace, available)),
                ("leakix",          lambda: phase_leakix(domain, workspace, available)),
                ("content",         lambda: phase_content_discovery(domain, workspace, available)),
                ("sensitive",       lambda: phase_sensitive_files(domain, workspace, available)),
                ("js",              lambda: phase_js_recon(domain, workspace, available)),
                ("screenshots",     lambda: phase_screenshots(domain, workspace, available)),
                ("dns",             lambda: phase_dns_enrichment(domain, workspace, available)),
            ]

        for phase_name, phase_fn in make_phases():
            if phase_name in completed:
                log_warn(f"Skipping {phase_name} (already completed)")
                continue

            if phase_name == "quick":
                try:
                    res = phase_fn()
                    quick = res if res else {}
                    completed.add(phase_name)
                    save_checkpoint(workspace, domain, completed, extra={"waf_type": GLOBAL_WAF_TYPE})
                    if quick.get("skip_scan") and not args_force:
                        log_err(f"Target {domain} appears dead — skipping remaining phases")
                        log_dim("  Use --force to override")
                        break
                except KeyboardInterrupt:
                    log_warn("Quick probe interrupted — continuing anyway")
                    completed.add(phase_name)
                    save_checkpoint(workspace, domain, completed, extra={"waf_type": GLOBAL_WAF_TYPE})
                continue

            try:
                res = phase_fn()
                if res is None:
                    res = {}
                if phase_name == "passive":
                    passive = res
                elif phase_name == "waf":
                    waf = res
                elif phase_name == "dns_resolution":
                    dns_resolution = res
                elif phase_name == "response":
                    response = res
                elif phase_name == "tech":
                    tech = res
                elif phase_name == "takeover":
                    takeover = res
                elif phase_name == "vuln":
                    vuln = res
                elif phase_name == "ports":
                    ports = res
                elif phase_name == "leakix":
                    leakix = res
                elif phase_name == "content":
                    urls = res
                elif phase_name == "sensitive":
                    sensitive = res
                elif phase_name == "js":
                    js = res
                elif phase_name == "dns":
                    dns_res = res
                completed.add(phase_name)
                save_checkpoint(workspace, domain, completed, extra={"waf_type": GLOBAL_WAF_TYPE})
            except KeyboardInterrupt:
                log_warn(f"Phase {phase_name} interrupted")
                completed.add(phase_name)
                save_checkpoint(workspace, domain, completed, extra={"waf_type": GLOBAL_WAF_TYPE})
                continue
            except Exception as e:
                log_err(f"Phase {phase_name} failed: {e}")
                continue

        result["targets"].append({
            "domain": domain,
            "quick": quick,
            "passive": passive,
            "waf": waf,
            "dns_resolution": dns_resolution,
            "response": response,
            "tech": tech,
            "takeover": takeover,
            "vuln": vuln,
            "ports": ports,
            "leakix": leakix,
            "urls": urls,
            "sensitive": sensitive,
            "js": js,
            "dns": dns_res,
        })

        clear_checkpoint(workspace)

    findings = build_findings_summary(result)
    result["findings"] = findings

    print(f"\n{BOLD}{B}{'═' * 60}{RST}")
    print(f"{BOLD}{C}  Writing Reports{RST}")
    print(f"{BOLD}{B}{'═' * 60}{RST}")

    json_path = workspace / "report.json"
    json_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    print(f"  {G}✔{RST} JSON  → {json_path}")

    if args.report_format in ("txt", "both"):
        tp = workspace / "report.txt"
        write_txt(tp, result, findings)
        print(f"  {G}✔{RST} TXT   → {tp}")

    if args.report_format in ("html", "both"):
        hp = workspace / "report.html"
        write_html(hp, result, findings)
        print(f"  {G}✔{RST} HTML  → {hp}")

    print(f"\n{BOLD}{G}[✔] Clicker {VERSION} complete → {workspace}/{RST}")
    if findings:
        print(f"{BOLD}{Y}Top finding score: {findings[0]['score']} — {findings[0]['type']}{RST}")
    print(f"{DIM}Follow updates: {Y}{INSTAGRAM}{RST}\n")

if __name__ == "__main__":
    main()
