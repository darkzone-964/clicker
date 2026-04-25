#!/usr/bin/env python3
"""
clicker.py — Full Black-box Recon & Vulnerability Assessment Pipeline
Author : Clicker Tool
OS : Linux
Usage :
python3 clicker.py -t example.com --report-format both --pdf
python3 clicker.py --targets-file targets.txt --nt /path/to/templates --verbose

[MODIFIED v6 - VERBOSE]
- Show FULL file content in terminal after each phase (--verbose/-v)
- Still saves all results to files
- REMOVED: jsfinder, wappalyzer
- Formatted port scan output, nmap -sC, LeakIX fixes, etc.
"""

import argparse
import datetime as dt
import html as html_lib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

# ─── ANSI colours ────────────────────────────────────────────────────────────
R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
M = "\033[95m"
C = "\033[96m"
W = "\033[97m"
DIM= "\033[2m"
RST= "\033[0m"
BOLD="\033[1m"

ASCII_LOGO = f"""{C}
██████╗██╗ ██╗ ██████╗██╗ ██╗███████╗██████╗
██╔════╝██║ ██║██╔════╝██║ ██╔╝██╔════╝██╔══██╗
██║     ██║ ██║██║     ██║ ██║ ██████╗ ██████╔╝
██║     ██║ ██║██║     ██║ ██║ ██╔══██╗██╔══██╗
╚██████╗███████╗╚██████╗██║ ██║███████║██║ ██║
╚═════╝╚══════╝ ╚═════╝╚═╝ ╚═╝╚══════╝╚═╝ ╚═╝
{RST}{DIM} Black-box Recon & Vulnerability Assessment Pipeline {RST}
"""

SENSITIVE_PREFIXES = [
"app","dashboard","api","auth","admin","dev","staging","test",
"internal","vpn","mail","ftp","sandbox","uat","qa","jenkins",
"gitlab","payment","portal","secure","beta","demo","prod",
"mgmt","manage","login","sso","id","oauth","backup","old",
"legacy","corp","intranet","remote","access","cloud","db",
"database","secret","private","hidden",
]

PORTS_FULL = (
"21,22,23,25,53,80,110,111,135,139,143,389,443,445,993,995,"
"1433,1521,2181,2375,2376,3000,3001,3306,3389,4848,4999,5000,"
"5432,5601,5900,5984,6379,6443,7001,7077,7474,8000,8080,8081,"
"8082,8083,8085,8088,8089,8090,8091,8092,8095,8096,8097,8098,"
"8099,8161,8443,8444,8500,8600,8686,8765,8800,8848,8880,8888,"
"8983,9000,9001,9002,9090,9091,9092,9093,9094,9095,9096,9100,"
"9200,9300,9418,9999,10000,10250,10255,11211,15672,16686,27017,"
"28017,50000,50070,50090,61616"
)

TOOL_HINTS = {
"subfinder" : "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
"sublist3r" : "pip install sublist3r",
"chaos" : "go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
"assetfinder" : "go install github.com/tomnomnom/assetfinder@latest",
"github-subdomains": "go install github.com/gwen001/github-subdomains@latest",
"findomain" : "https://github.com/Findomain/Findomain/releases",
"waybackurls" : "go install github.com/tomnomnom/waybackurls@latest",
"unfurl" : "go install github.com/tomnomnom/unfurl@latest",
"anew" : "go install github.com/tomnomnom/anew@latest",
"gau" : "go install github.com/lc/gau/v2/cmd/gau@latest",
"httpx" : "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
"httpx-toolkit" : "sudo apt install httpx-toolkit (Kali) or use httpx",
"naabu" : "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
"dnsx" : "go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
"cdncheck" : "go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest",
"nuclei" : "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
"nmap" : "sudo apt install nmap",
"aquatone" : "go install github.com/michenriksen/aquatone@latest",
"gowitness" : "go install github.com/sensepost/gowitness@latest",
"katana" : "go install github.com/projectdiscovery/katana/cmd/katana@latest",
"waymore" : "pip install waymore",
"mantra" : "go install github.com/brosck/mantra@latest",
"subzy" : "go install github.com/PentestPad/subzy@latest",
"subjack" : "go install github.com/haccer/subjack@latest",
"wafw00f" : "pip install wafw00f",
"curl" : "sudo apt install curl",
"jq" : "sudo apt install jq",
}

# ─── Global flags ────────────────────────────────────────────────────────────
args_show_results = False
args_verbose_output = False  # [NEW] Show full content in terminal
nuclei_templates_global = ""

# ─── helpers ─────────────────────────────────────────────────────────────────
def run_cmd(cmd: str, timeout: int = 600):
    try:
        p = subprocess.run(
            cmd, shell=True, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=timeout,
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"

def installed(tool: str) -> bool:
    return shutil.which(tool) is not None

def mkd(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def wlines(path: Path, lines, auto_cleanup: bool = True):
    """Write unique sorted lines to file, optionally cleanup if empty"""
    with path.open("w", encoding="utf-8") as f:
        for l in sorted(set(lines)):
            if l.strip():
                f.write(l.strip() + "\n")
    if auto_cleanup:
        cleanup_empty_file(path)

def rlines(path: Path):
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]

def clean_sub(val: str, domain: str):
    if not val:
        return None
    v = val.strip().lower().replace("*.", "")
    v = v.split(",")[0].strip().split(":")[0]
    if v.startswith("http://") or v.startswith("https://"):
        v = urlparse(v).hostname or ""
    v = v.strip(".")
    if not v:
        return None
    if (v == domain or v.endswith("." + domain)) and re.match(r"^[a-z0-9.-]+$", v):
        return v
    return None

def extract_hosts_from_urls(lines, domain):
    out = set()
    for l in lines:
        h = urlparse(l.strip()).hostname
        c = clean_sub(h or "", domain)
        if c:
            out.add(c)
    return out

# ─── [NEW] Cleanup Helpers ───────────────────────────────────────────────────
def is_file_empty(path: Path) -> bool:
    """Check if file is empty or contains only whitespace"""
    if not path.exists():
        return True
    try:
        content = path.read_text(encoding="utf-8").strip()
        return len(content) == 0
    except:
        return True

def cleanup_empty_file(path: Path, label: str = "") -> bool:
    """Delete file if empty and notify user. Returns True if deleted."""
    if is_file_empty(path):
        try:
            label_str = f" ({label})" if label else ""
            print(f"  {Y}[!] Cleaned:{RST} {DIM}{path.name}{label_str} {R}[empty — deleted]{RST}")
            path.unlink(missing_ok=True)
            return True
        except Exception as e:
            print(f"  {R}[!] Failed to delete {path.name}: {e}{RST}")
    return False

def cleanup_merged_files(source_files: list, final_file: Path, phase_name: str = "", keep_sources_if_empty: bool = False):
    """Delete source files after successful merge to final_file"""
    if keep_sources_if_empty and (not final_file.exists() or is_file_empty(final_file)):
        print(f"  {Y}[!] Merge skipped: {final_file.name} is empty, keeping sources{RST}")
        return False
    deleted_count = 0
    print(f"  {DIM}🧹 Cleaning up {len(source_files)} source file(s) after merge...{RST}")
    for src in source_files:
        if src.exists() and src.resolve() != final_file.resolve():
            try:
                src.unlink()
                print(f"    {G}✔{RST} {DIM}deleted: {src.name}{RST}")
                deleted_count += 1
            except Exception as e:
                print(f"    {R}✘{RST} {DIM}failed: {src.name} — {e}{RST}")
    if deleted_count > 0:
        print(f"  {G}✔{RST} {DIM}Cleanup complete: {deleted_count} file(s) removed{RST}")
    return deleted_count > 0

def cleanup_source_files_after_merge(source_files: list, label: str = "source"):
    """Force delete source files after merge (regardless of content)"""
    deleted_count = 0
    for src in source_files:
        if src.exists():
            try:
                src.unlink()
                print(f"  {Y}[!] Cleaned:{RST} {DIM}{src.name}{RST} {R}[{label} — merged → deleted]{RST}")
                deleted_count += 1
            except Exception as e:
                print(f"  {R}[!] Failed to delete {src.name}: {e}{RST}")
    if deleted_count > 0:
        print(f"  {G}✔{RST} {DIM}{label} files cleaned: {deleted_count} removed{RST}")
    return deleted_count

# ─── [NEW] Phase Results Display ─────────────────────────────────────────────
def show_phase_results(phase_num: int, phase_name: str, results: dict):
    """Display a summary of results after each phase completes"""
    print(f"\n{BOLD}{B}{'─'*60}{RST}")
    print(f"{BOLD}{C}📊 Phase {phase_num} Results: {phase_name}{RST}")
    print(f"{BOLD}{B}{'─'*60}{RST}")
    
    if not results:
        print(f"  {DIM}No results to display{RST}")
        return
    
    for key, value in results.items():
        if isinstance(value, (list, set)):
            count = len(value)
            if count > 0:
                print(f"  {G}✔{RST} {key}: {C}{count}{RST} items")
                items = list(value)[:3] if isinstance(value, set) else value[:3]
                for item in items:
                    preview = str(item)[:60] + "..." if len(str(item)) > 60 else str(item)
                    print(f"     {DIM}• {preview}{RST}")
                if len(value) > 3:
                    print(f"     {DIM}... and {len(value)-3} more{RST}")
        elif isinstance(value, int):
            symbol = G if value > 0 else Y
            print(f"  {symbol}✔{RST} {key}: {C}{value}{RST}")
        elif isinstance(value, str) and value:
            print(f"  {G}✔{RST} {key}: {DIM}{value[:70]}{'...' if len(value)>70 else ''}{RST}")
    
    print(f"{BOLD}{B}{'─'*60}{RST}\n")

# ─── [NEW] Display full file content in terminal ─────────────────────────────
def show_file_content(file_path: Path, label: str, max_lines: int = 50):
    """Display file content in terminal with formatting"""
    if not file_path.exists() or is_file_empty(file_path):
        print(f"  {Y}[!] {label}: No content to display{RST}")
        return
    
    lines = rlines(file_path)
    count = len(lines)
    print(f"\n{BOLD}{C}📄 {label} ({count} lines){RST}")
    print(f"{DIM}{'─'*70}{RST}")
    
    # Show content with line numbers
    display_lines = lines[:max_lines] if max_lines > 0 else lines
    for i, line in enumerate(display_lines, 1):
        # Color-code based on content
        if '[200]' in line or '✓' in line or '→ http' in line:
            print(f"  {G}{i:3d}{RST} {line}")
        elif '[403]' in line or '[404]' in line:
            print(f"  {Y}{i:3d}{RST} {line}")
        elif 'VULNERABLE' in line or 'CVE-' in line or 'sqli' in line.lower() or 'xss' in line.lower():
            print(f"  {R}{i:3d}{RST} {BOLD}{line}{RST}")
        elif 'ModSecurity' in line or 'WAF' in line:
            print(f"  {M}{i:3d}{RST} {line}")
        else:
            print(f"  {DIM}{i:3d}{RST} {line}")
    
    if max_lines > 0 and count > max_lines:
        print(f"  {DIM}... and {count - max_lines} more lines (see file: {file_path.name}){RST}")
    print(f"{DIM}{'─'*70}{RST}\n")

# ─── [NEW] Nuclei Templates Path Handler ─────────────────────────────────────
def find_nuclei_templates(custom_path: str = None) -> str:
    """Find nuclei templates path: use custom if provided, else search common locations."""
    if custom_path and Path(custom_path).exists():
        print(f"  {G}✔{RST} Using custom nuclei templates: {DIM}{custom_path}{RST}")
        return custom_path
    
    search_paths = [
        Path.home() / ".config" / "nuclei" / "templates",
        Path("/usr/share/nuclei-templates"),
        Path("/opt/nuclei-templates"),
        Path("./nuclei-templates"),
        Path(os.environ.get("HOME", "")) / "nuclei-templates",
    ]
    
    if installed("nuclei"):
        try:
            _, out, _ = run_cmd("nuclei -silent -td 2>/dev/null | head -1", timeout=30)
            if out and Path(out.strip()).exists():
                search_paths.insert(0, Path(out.strip()))
        except:
            pass
    
    print(f"  {DIM}🔍 Searching for nuclei templates...{RST}")
    for p in search_paths:
        if p.exists() and ((p / "cves").exists() or (p / "http").exists() or list(p.glob("*.yaml"))):
            print(f"  {G}✔{RST} Found templates at: {DIM}{p}{RST}")
            return str(p)
    
    print(f"  {Y}[!]{RST} No custom templates found — using nuclei default templates")
    return ""

def build_nuclei_cmd(base_cmd: str, templates_path: str, extra_args: str = "") -> str:
    """Build nuclei command with template path if available"""
    cmd = base_cmd
    if templates_path:
        cmd += f" -t {templates_path}"
    if extra_args:
        cmd += f" {extra_args}"
    return cmd

# ─── [FIXED] Format naabu JSON output to readable table ──────────────────────
def format_naabu_output(json_file: Path, output_file: Path):
    """Convert naabu JSON output to readable format: domain:port → service/version"""
    if not json_file.exists() or is_file_empty(json_file):
        return False
    
    formatted = []
    try:
        with open(json_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    host = entry.get('host', entry.get('input', ''))
                    port = entry.get('port', '')
                    protocol = entry.get('protocol', 'tcp').upper()
                    service = entry.get('service', {}).get('name', '')
                    version = entry.get('service', {}).get('version', '')
                    
                    line_out = f"{host}:{port}/{protocol}"
                    if service:
                        line_out += f" → {service}"
                        if version:
                            line_out += f" ({version})"
                    formatted.append(line_out)
                except json.JSONDecodeError:
                    continue
        
        if formatted:
            wlines(output_file, formatted, auto_cleanup=False)
            return True
    except Exception as e:
        print(f"  {R}[!] Error formatting naabu output: {e}{RST}")
    
    return False

# ─── [FIXED] Parse LeakIX output for real findings only ──────────────────────
def has_real_leakix_findings(file_path: Path) -> bool:
    """Check if LeakIX output contains actual findings (not just headers)"""
    if not file_path.exists() or is_file_empty(file_path):
        return False
    
    content = file_path.read_text(encoding="utf-8")
    if re.search(r'"leak"\s*:\s*\{', content) or re.search(r'"Services"\s*:\s*\[', content):
        return True
    if re.search(r'"port"\s*:\s*\d+', content) and re.search(r'"software"', content):
        return True
    return False

# ─── [FIXED] Parse WAF output for simple display ─────────────────────────────
def parse_waf_simple(json_file: Path, output_file: Path):
    """Parse wafw00f JSON and create simple table: URL | WAF Name"""
    if not json_file.exists() or is_file_empty(json_file):
        return False
    
    results = []
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
            if isinstance(data, list):
                seen = set()
                for entry in data:
                    url = entry.get('url', '')
                    detected = entry.get('detected', False)
                    waf_name = entry.get('firewall', 'None') if detected else 'None'
                    
                    if url and url not in seen:
                        seen.add(url)
                        status = f"{G}✓{RST} {waf_name}" if detected else f"{DIM}—{RST} None"
                        results.append(f"{url:50} | {status}")
        
        if results:
            header = f"{'URL':50} | WAF Detected\n{'-'*70}"
            wlines(output_file, [header] + results, auto_cleanup=False)
            return True
    except Exception as e:
        print(f"  {R}[!] Error parsing WAF output: {e}{RST}")
    
    return False

# ─── progress bar ─────────────────────────────────────────────────────────────
class PhaseProgress:
    def __init__(self, phase_name: str, total_steps: int):
        self.name = phase_name
        self.total = total_steps
        self.done = 0
        self.start = time.time()
        self._print_header()

    def _print_header(self):
        print(f"\n{BOLD}{B}{'═'*60}{RST}")
        print(f"{BOLD}{C}  Phase: {self.name}{RST}")
        print(f"{BOLD}{B}{'═'*60}{RST}")

    def step(self, label: str):
        self.done += 1
        pct = int(self.done / self.total * 100)
        bar = int(pct / 4)
        elapsed = time.time() - self.start
        eta = (elapsed / self.done) * (self.total - self.done) if self.done > 0 else 0
        filled = f"{G}{'█' * bar}{RST}"
        empty = f"{DIM}{'░' * (25 - bar)}{RST}"
        print(
            f"  {filled}{empty} {BOLD}{pct:3d}%{RST}"
            f"  {Y}[{self.done}/{self.total}]{RST}"
            f"  {DIM}elapsed {elapsed:.0f}s  ETA ~{eta:.0f}s{RST}"
            f"  {W}{label}{RST}"
        )

    def done_phase(self):
        elapsed = time.time() - self.start
        print(f"\n  {G}✔ Phase complete in {elapsed:.1f}s{RST}\n")

# ─── API keys ─────────────────────────────────────────────────────────────────
def read_env_file(path: Path):
    vals = {}
    if not path.exists():
        return vals
    for line in path.read_text(encoding="utf-8").splitlines():
        row = line.strip()
        if not row or row.startswith("#") or "=" not in row:
            continue
        k, v = row.split("=", 1)
        vals[k.strip()] = v.strip().strip('"').strip("'")
    return vals

def save_env_file(path: Path, vals: dict):
    keys = ["CHAOS_API_KEY","VT_API_KEY","GITHUB_TOKEN","SHODAN_API","LEAKIX_API"]
    lines = ["# Clicker API keys — do not share this file"]
    for k in keys:
        lines.append(f"{k}={vals.get(k,'')}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

def collect_api_keys(api_file: Path):
    existing = read_env_file(api_file)
    print(f"\n{BOLD}{Y}[?] API Keys Setup{RST} (file: {api_file})")
    print(f"{DIM} Press Enter to keep saved value, type 'skip' to leave empty.{RST}\n")
    prompts = [
        ("CHAOS_API_KEY", "Chaos ProjectDiscovery API Key"),
        ("VT_API_KEY", "VirusTotal API Key"),
        ("GITHUB_TOKEN", "GitHub Personal Token"),
        ("SHODAN_API", "Shodan API Key"),
        ("LEAKIX_API", "LeakIX API Key"),
    ]
    updated = dict(existing)
    for key, label in prompts:
        cur = existing.get(key, "")
        tag = f"{G}[saved]{RST}" if cur else f"{R}[empty]{RST}"
        val = input(f" {label} {tag}: ").strip()
        if val.lower() == "skip":
            updated[key] = ""
        elif val:
            updated[key] = val
        elif key not in updated:
            updated[key] = ""
    save_env_file(api_file, updated)
    print(f"\n{G}[+] API keys saved to {api_file}{RST}\n")
    return updated

# ─── tool check ───────────────────────────────────────────────────────────────
def check_tools(required: list):
    print(f"{BOLD}{Y}[*] Checking required tools...{RST}")
    available, missing = set(), []
    for t in required:
        if installed(t):
            available.add(t)
            print(f" {G}✔{RST} {t}")
        else:
            missing.append(t)
            hint = TOOL_HINTS.get(t, "install manually")
            print(f" {R}✘{RST} {t} {DIM}→ {hint}{RST}")
    if missing:
        print(f"\n{Y}[!] {len(missing)} tool(s) missing — affected steps will be skipped.{RST}\n")
    else:
        print(f"\n{G}[+] All tools present.{RST}\n")
    return available

# ─── parse targets ────────────────────────────────────────────────────────────
def parse_targets(single, tfile):
    targets = []
    if single:
        targets.append(single.strip().lower())
    if tfile:
        p = Path(tfile)
        if not p.exists():
            sys.exit(f"{R}[!] targets file not found: {tfile}{RST}")
        for line in p.read_text(encoding="utf-8").splitlines():
            c = line.strip().lower()
            if c and not c.startswith("#"):
                targets.append(c)
    targets = sorted(set(targets))
    if not targets:
        sys.exit(f"{R}[!] No targets. Use -t or --targets-file{RST}")
    return targets

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — Passive Subdomain Enumeration
# ══════════════════════════════════════════════════════════════════════════════
def phase_passive(domain, workspace, api_keys, av):
    pdir = workspace / domain / "passive"
    mkd(pdir)
    collected = set()
    logs = []

    total_steps = 12
    prog = PhaseProgress("1 — Passive Subdomain Enumeration", total_steps)

    def rc(tool, cmd, fname, parser="lines", timeout=480):
        ofile = pdir / fname
        if tool not in av:
            logs.append({"tool": tool, "status": "skipped", "reason": "not installed"})
            prog.step(f"{tool} — skipped")
            return
        _, out, err = run_cmd(cmd, timeout)
        parsed = set()
        if parser == "lines":
            parsed = {clean_sub(l, domain) for l in out.splitlines()}
        elif parser == "plain":
            for l in out.splitlines():
                c = clean_sub(l, domain)
                if c:
                    parsed.add(c)
        elif parser == "urls":
            parsed = extract_hosts_from_urls(out.splitlines(), domain)
        parsed = {x for x in parsed if x}
        wlines(ofile, parsed, auto_cleanup=False)
        collected.update(parsed)
        logs.append({"tool": tool, "count": len(parsed), "stderr": err[:300]})
        prog.step(f"{tool} — {G}{len(parsed)} subs{RST}")

    source_files = []
    
    rc("subfinder", f"subfinder -d {domain} -silent -all -recursive", "subs1.txt")
    source_files.append(pdir / "subs1.txt")
    rc("sublist3r", f"sublist3r -d {domain}", "subs2.txt")
    source_files.append(pdir / "subs2.txt")

    if api_keys.get("CHAOS_API_KEY"):
        rc("chaos", f"chaos -d {domain} -silent -key {api_keys['CHAOS_API_KEY']}", "subs3.txt")
        source_files.append(pdir / "subs3.txt")
    else:
        logs.append({"tool":"chaos","status":"skipped","reason":"no CHAOS_API_KEY"})
        prog.step("chaos — skipped (no key)")

    rc("assetfinder", f"assetfinder --subs-only {domain}", "subs4.txt")
    source_files.append(pdir / "subs4.txt")

    if api_keys.get("GITHUB_TOKEN"):
        rc("github-subdomains", f"github-subdomains -d {domain} -t {api_keys['GITHUB_TOKEN']}", "subs5.txt")
        source_files.append(pdir / "subs5.txt")
    else:
        logs.append({"tool":"github-subdomains","status":"skipped","reason":"no GITHUB_TOKEN"})
        prog.step("github-subdomains — skipped (no token)")

    rc("findomain", f"findomain -t {domain}", "subs6.txt")
    source_files.append(pdir / "subs6.txt")

    if "curl" in av and "jq" in av:
        rc("curl", f"curl -s 'https://crt.sh/?q=%25.{domain}&output=json' | jq -r '.[].name_value'", "subs7.txt", "plain")
        source_files.append(pdir / "subs7.txt")
    else:
        logs.append({"tool":"crtsh","status":"skipped","reason":"curl/jq missing"})
        prog.step("crt.sh — skipped")

    rc("waybackurls", f"echo {domain} | waybackurls", "subs8.txt", "urls")
    source_files.append(pdir / "subs8.txt")

    if "curl" in av and "jq" in av:
        rc("curl",
           f"curl -s 'https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names' | jq -r '.[].dns_names[]'",
           "subs9.txt", "plain")
        source_files.append(pdir / "subs9.txt")
    else:
        prog.step("certspotter — skipped")

    if api_keys.get("VT_API_KEY") and "curl" in av and "jq" in av:
        rc("curl",
           f"curl -s 'https://www.virustotal.com/vtapi/v2/domain/report?apikey={api_keys['VT_API_KEY']}&domain={domain}' | jq -r '.subdomains[]?'",
           "subs10.txt", "plain")
        source_files.append(pdir / "subs10.txt")
    else:
        logs.append({"tool":"virustotal","status":"skipped","reason":"no VT_API_KEY"})
        prog.step("virustotal — skipped")

    rc("gau", f"echo {domain} | gau --subs", "subs11.txt", "urls")
    source_files.append(pdir / "subs11.txt")

    allsubs = pdir / "allsubs.txt"
    wlines(allsubs, collected, auto_cleanup=False)
    prog.step(f"merge → {allsubs.name}")

    existing_sources = [f for f in source_files if f.exists()]
    if existing_sources:
        cleanup_source_files_after_merge(existing_sources, label="subdomain-tool-output")

    sensitive = [s for s in collected if s.split(".")[0] in SENSITIVE_PREFIXES]
    wlines(pdir / "high_value_subs.txt", sensitive)
    if not cleanup_empty_file(pdir / "high_value_subs.txt", "high-value"):
        print(f"  {G}✔{RST} high_value_subs.txt — {Y}{len(sensitive)} entries{RST}")

    prog.done_phase()
    print(f"  {BOLD}Total subdomains : {G}{len(collected)}{RST}")
    print(f"  {BOLD}High-value subs  : {Y}{len(sensitive)}{RST}")

    # [VERBOSE] Show full content of main output files
    if args_verbose_output:
        show_file_content(allsubs, "allsubs.txt - All Discovered Subdomains", max_lines=30)
        if (pdir / "high_value_subs.txt").exists():
            show_file_content(pdir / "high_value_subs.txt", "high_value_subs.txt - High-Value Subdomains", max_lines=20)

    if args_show_results:
        phase_results = {
            "total_subdomains": len(collected),
            "high_value_subs": len(sensitive),
            "tools_used": [log["tool"] for log in logs if log.get("count",0) > 0],
        }
        show_phase_results(1, "Passive Subdomain Enumeration", phase_results)

    return {
        "domain": domain,
        "allsubs_file": str(allsubs),
        "all_subdomains": sorted(collected),
        "sensitive_subs": sorted(sensitive),
        "tool_logs": logs,
    }

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — Response Filtering (200/302 / 403 / 404)
# ══════════════════════════════════════════════════════════════════════════════
def phase_response_filter(domain, workspace, passive, av):
    adir = workspace / domain / "active"
    mkd(adir)
    allsubs_file = passive["allsubs_file"]
    high_val = str(workspace / domain / "passive" / "high_value_subs.txt")

    prog = PhaseProgress("2 — Response Filtering", 7)
    results = {"alive": [], "ports_alive": [], "f403": [], "f404": [], "details": []}

    httpx_bin = "httpx-toolkit" if "httpx-toolkit" in av else ("httpx" if "httpx" in av else None)

    if httpx_bin:
        _, out, _ = run_cmd(
            f"{httpx_bin} -l {high_val} -sc -td -cl -server -title -ip -o {adir/'details.txt'}", 600)
        results["details"] = rlines(adir / "details.txt")
    prog.step("high-value details scan")
    cleanup_empty_file(adir / "details.txt", "details")

    alive_file = adir / "alive.txt"
    if httpx_bin:
        run_cmd(f"{httpx_bin} -l {allsubs_file} -mc 200,302 -o {alive_file}", 900)
        results["alive"] = rlines(alive_file)
    prog.step(f"alive 200/302 — {G}{len(results['alive'])} hosts{RST}")

    alive2_file = adir / "2alive.txt"
    if httpx_bin:
        run_cmd(f"{httpx_bin} -l {allsubs_file} -ports 80,8443,8080,8000 -o {alive2_file}", 600)
    prog.step("alive extra ports (80,8443,8080,8000)")

    alive3_file = adir / "3alive.txt"
    if "naabu" in av:
        run_cmd(f"naabu -list {allsubs_file} -port 80,443,8000,8080 -o {alive3_file}", 900)
    prog.step("naabu fallback liveness")

    f403_file = adir / "403subs.txt"
    if httpx_bin:
        run_cmd(f"{httpx_bin} -l {allsubs_file} -mc 403 -o {f403_file}", 600)
        results["f403"] = rlines(f403_file)
    prog.step(f"403 filter — {Y}{len(results['f403'])} hosts{RST}")
    cleanup_empty_file(f403_file, "403")

    f404_file = adir / "404subs.txt"
    if httpx_bin:
        run_cmd(f"{httpx_bin} -l {allsubs_file} -mc 404 -o {f404_file}", 600)
        results["f404"] = rlines(f404_file)
    prog.step(f"404 filter — {R}{len(results['f404'])} hosts{RST}")
    cleanup_empty_file(f404_file, "404")

    source_files = [alive_file, alive2_file, alive3_file]
    success_file = adir / "success-response.txt"
    run_cmd(f"cat {alive_file} {alive2_file} {alive3_file} 2>/dev/null | sort -u > {success_file}")
    prog.step("merge → success-response.txt")
    
    cleanup_source_files_after_merge([f for f in source_files if f.exists()], label="response-filter")

    prog.done_phase()
    
    # [VERBOSE] Show full content of main output files
    if args_verbose_output:
        show_file_content(success_file, "success-response.txt - Alive Hosts (200/302)", max_lines=40)
        if (adir / "details.txt").exists() and not is_file_empty(adir / "details.txt"):
            show_file_content(adir / "details.txt", "details.txt - High-Value Host Details", max_lines=20)
    
    if args_show_results:
        phase_results = {
            "alive_hosts": len(results["alive"]),
            "hosts_403": len(results["f403"]),
            "hosts_404": len(results["f404"]),
            "success_response_file": str(success_file),
        }
        show_phase_results(2, "Response Filtering", phase_results)
    
    return results

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — Technology Detection & IP Extraction
# ══════════════════════════════════════════════════════════════════════════════
def phase_tech_detect(domain, workspace, av):
    adir = workspace / domain / "active"
    sucf = adir / "success-response.txt"
    techf = adir / "subs-Tech.txt"
    ipsf = adir / "ips.txt"
    alivef = adir / "alive-final.txt"

    prog = PhaseProgress("3 — Technology Detection & IP Extraction", 3)

    httpx_bin = "httpx-toolkit" if "httpx-toolkit" in av else ("httpx" if "httpx" in av else None)

    if httpx_bin and sucf.exists():
        run_cmd(
            f"{httpx_bin} -l {sucf} -r 8.8.8.8,1.1.1.1 -sc -td -cl -server -title -ip -fr -t 30 -timeout 10 -retries 2 -o {techf}",
            1200)
    prog.step(f"httpx tech detection → {techf.name}")

    if techf.exists():
        _, out, _ = run_cmd(
            f"grep -oE '\\b([0-9]{{1,3}}\\.)'{{3}}'[0-9]{{1,3}}\\b' {techf} | sort -u")
        wlines(ipsf, out.splitlines(), auto_cleanup=False)
    prog.step(f"IP extraction → {ipsf.name}")
    
    if not cleanup_empty_file(ipsf, "ips"):
        print(f"  {G}✔{RST} ips.txt — {len(rlines(ipsf))} unique IPs{RST}")

    if techf.exists():
        run_cmd(
            f"cat {techf} | sed 's/\\x1b\\[[0-9;]*m//g' | "
            f"grep -E '\\[200\\]|\\[302\\]|\\[301,200\\]|\\[302,200\\]' | "
            f"awk '{{print $1}}' > {alivef}")
    prog.step(f"alive-final re-filter → {alivef.name}")
    
    if not cleanup_empty_file(alivef, "alive-final"):
        print(f"  {G}✔{RST} alive-final.txt — {len(rlines(alivef))} hosts{RST}")

    prog.done_phase()
    
    # [VERBOSE] Show full content of main output files
    if args_verbose_output:
        show_file_content(techf, "subs-Tech.txt - Technology Detection + IPs", max_lines=30)
        show_file_content(alivef, "alive-final.txt - Final Alive Hosts", max_lines=30)
    
    if args_show_results:
        ip_count = len(rlines(ipsf)) if ipsf.exists() else 0
        alive_count = len(rlines(alivef)) if alivef.exists() else 0
        phase_results = {
            "unique_ips": ip_count,
            "alive_hosts": alive_count,
            "tech_file": str(techf),
        }
        show_phase_results(3, "Technology Detection & IP Extraction", phase_results)
    
    return {"ips_file": str(ipsf), "alive_final": str(alivef)}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 4 — Port Scanning [FIXED]
# ══════════════════════════════════════════════════════════════════════════════
def phase_ports(domain, workspace, av):
    adir = workspace / domain / "active"
    pdir = workspace / domain / "passive"
    ipsf = adir / "ips.txt"
    allsubs = pdir / "allsubs.txt"
    highval = pdir / "high_value_subs.txt"

    prog = PhaseProgress("4 — Port Scanning", 9)

    resolved = adir / "resolved-ips-full.txt"
    if "dnsx" in av:
        run_cmd(
            f"dnsx -l {allsubs} -resp-only -a -silent -t 100 -retry 3 -o {resolved}",
            900)
    prog.step("dnsx resolve all subdomains")

    all_ips = adir / "all-ips-final.txt"
    merge_sources = [ipsf, resolved] if resolved.exists() else [ipsf]
    run_cmd(f"cat {ipsf} {resolved} 2>/dev/null | sort -u > {all_ips}")
    prog.step("merge all IPs → all-ips-final.txt")
    cleanup_source_files_after_merge([f for f in merge_sources if f.exists()], label="ip-source")

    cdn_res = adir / "cdn-results.txt"
    real_ips = adir / "real-ips.txt"
    if "cdncheck" in av:
        run_cmd(f"cat {all_ips} | cdncheck -silent -o {cdn_res}", 300)
        run_cmd(
            f"cat {all_ips} | cdncheck -silent -resp | "
            f"grep -iv 'cloudflare\\|akamai\\|fastly\\|cloudfront\\|incapsula\\|sucuri' | "
            f"awk '{{print $1}}' > {real_ips}")
    prog.step("CDN detection & real-IP extraction")
    
    if real_ips.exists():
        if not cleanup_empty_file(real_ips, "real-ips"):
            print(f"  {G}✔{RST} real-ips.txt — {len(rlines(real_ips))} non-CDN IPs{RST}")

    open_ports_json = adir / "open-ports-full.json"
    open_ports_txt = adir / "open-ports-full.txt"
    if "naabu" in av and real_ips.exists():
        run_cmd(
            f"naabu -list {real_ips} -p {PORTS_FULL} "
            f"-rate 500 -c 25 -retries 3 -timeout 1500 -Pn -sV -verify "
            f"-scan-all-ips -ip-version 4 "
            f"-o {open_ports_json} -j -stats",
            2400)
        if format_naabu_output(open_ports_json, open_ports_txt):
            print(f"  {G}✔{RST} Formatted port scan → {open_ports_txt.name}")
        cleanup_empty_file(open_ports_json, "raw-json")
    prog.step("naabu full port scan + format output")

    nmap_results = adir / "nmap-scripts.txt"
    if "nmap" in av and open_ports_txt.exists() and not is_file_empty(open_ports_txt):
        ips_to_scan = set()
        for line in rlines(open_ports_txt):
            match = re.match(r'([^:/]+):\d+', line)
            if match:
                ips_to_scan.add(match.group(1))
        
        if ips_to_scan:
            ip_list = adir / "nmap-targets.txt"
            wlines(ip_list, ips_to_scan, auto_cleanup=False)
            run_cmd(
                f"nmap -iL {ip_list} -sC -sV --open -T4 -Pn "
                f"-p 21,22,23,25,53,80,110,139,143,389,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017 "
                f"-oA {adir/'nmap-scripts'} --reason",
                1800)
            if (adir / "nmap-scripts.nmap").exists():
                run_cmd(
                    f"grep -E 'VULNERABLE| vuln |CVE-|sqli|xss|injection' {adir/'nmap-scripts.nmap'} | sort -u > {nmap_results}",
                    300)
                if not cleanup_empty_file(nmap_results, "nmap-vulns"):
                    count = len(rlines(nmap_results))
                    print(f"  {G}✔{RST} nmap-scripts.txt — {C}{count} potential findings{RST}")
    prog.step("nmap -sC vulnerability scripts scan")

    open_subs_json = adir / "open-ports-subs.json"
    open_subs_txt = adir / "open-ports-subs.txt"
    if "naabu" in av:
        run_cmd(
            f"naabu -list {allsubs} -p {PORTS_FULL} "
            f"-rate 300 -c 25 -retries 3 -timeout 2000 -Pn -verify "
            f"-scan-all-ips -ip-version 4 "
            f"-o {open_subs_json} -j -stats",
            2400)
        if format_naabu_output(open_subs_json, open_subs_txt):
            print(f"  {G}✔{RST} Formatted fallback scan → {open_subs_txt.name}")
        cleanup_empty_file(open_subs_json, "raw-json")
    prog.step("naabu fallback scan + format")
    cleanup_empty_file(open_subs_txt, "fallback-ports")

    hv_ips = adir / "high-value-ips.txt"
    if "dnsx" in av and highval.exists():
        run_cmd(
            f"dnsx -l {highval} -resp-only -a -silent -retry 3 -o {hv_ips}",
            300)
    prog.step("dnsx resolve high-value subs")

    if "nmap" in av and hv_ips.exists():
        run_cmd(
            f"nmap -iL {hv_ips} -sV -sC -Pn -T4 --open "
            f"-p 21,22,23,25,53,80,443,3306,3389,5432,5900,6379,8080,8443,9200,27017 "
            f"--script=banner,http-title,ssl-cert,vuln "
            f"-oA {adir/'nmap-highvalue'} --reason",
            1800)
    prog.step("nmap deep scan on high-value IPs")

    shodan_out = adir / "shodan-results.txt"
    if api_keys_global.get("SHODAN_API") and "curl" in av and "jq" in av and ipsf.exists():
        key = api_keys_global["SHODAN_API"]
        script = (
            f"while IFS= read -r ip; do "
            f"echo \"=== $ip ===\"; "
            f"curl -s 'https://api.shodan.io/shodan/host/$ip?key={key}' | jq '.ports, .vulns, .org'; "
            f"done < {ipsf} > {shodan_out}"
        )
        run_cmd(script, 600)
    prog.step("Shodan IP lookup")
    cleanup_empty_file(shodan_out, "shodan")

    prog.done_phase()
    
    # [VERBOSE] Show full content of main output files
    if args_verbose_output:
        if open_ports_txt.exists() and not is_file_empty(open_ports_txt):
            show_file_content(open_ports_txt, "open-ports-full.txt - Discovered Open Ports", max_lines=40)
        if nmap_results.exists() and not is_file_empty(nmap_results):
            show_file_content(nmap_results, "nmap-scripts.txt - Potential Vulnerabilities", max_lines=30)
    
    if args_show_results:
        ports_count = len(rlines(open_ports_txt)) if open_ports_txt.exists() else 0
        vuln_count = len(rlines(nmap_results)) if nmap_results.exists() else 0
        phase_results = {
            "open_ports_found": ports_count,
            "nmap_script_findings": vuln_count,
            "real_ips": len(rlines(real_ips)) if real_ips.exists() else 0,
        }
        show_phase_results(4, "Port Scanning", phase_results)
    
    return {"open_ports_file": str(open_ports_txt) if open_ports_txt.exists() else None}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 5 — Screenshots
# ══════════════════════════════════════════════════════════════════════════════
def phase_screenshots(domain, workspace, av):
    adir = workspace / domain / "active"
    alivef = adir / "alive-final.txt"

    prog = PhaseProgress("5 — Screenshots", 2)

    if "aquatone" in av and alivef.exists():
        aq_dir = workspace / domain / "screenshots" / "aquatone"
        mkd(aq_dir)
        run_cmd(f"cat {alivef} | aquatone -out {aq_dir}", 900)
        prog.step(f"aquatone → {aq_dir}")
    else:
        prog.step("aquatone — skipped")

    if "gowitness" in av and alivef.exists():
        gw_dir = workspace / domain / "screenshots" / "gowitness"
        mkd(gw_dir)
        run_cmd(
            f"gowitness scan file -f {alivef} --write-db --screenshot-path {gw_dir}",
            900)
        prog.step(f"gowitness → {gw_dir}")
    else:
        prog.step("gowitness — skipped")

    prog.done_phase()
    
    # [VERBOSE] Show screenshot summary
    if args_verbose_output:
        aq_html = workspace / domain / "screenshots" / "aquatone" / "aquatone.html"
        gw_db = workspace / domain / "screenshots" / "gowitness" / "gowitness.db"
        if aq_html.exists():
            print(f"\n{BOLD}{C}📸 Aquatone screenshots:{RST} {DIM}{aq_html}{RST}")
        if gw_db.exists():
            print(f"{BOLD}{C}📸 Gowitness database:{RST} {DIM}{gw_db}{RST}")
    
    if args_show_results:
        aq_dir = workspace / domain / "screenshots" / "aquatone"
        gw_dir = workspace / domain / "screenshots" / "gowitness"
        phase_results = {
            "aquatone_output": str(aq_dir) if (aq_dir / "aquatone.html").exists() else "skipped",
            "gowitness_output": str(gw_dir) if (gw_dir / "gowitness.db").exists() else "skipped",
        }
        show_phase_results(5, "Screenshots", phase_results)

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 6 — Content Discovery
# ══════════════════════════════════════════════════════════════════════════════
def phase_content_discovery(domain, workspace, av):
    adir = workspace / domain / "active"
    alivef = adir / "alive-final.txt"
    udir = workspace / domain / "urls"
    mkd(udir)

    prog = PhaseProgress("6 — Content Discovery", 5)

    url_files = []
    
    if "waybackurls" in av and alivef.exists():
        uf = udir / "urls.txt"
        run_cmd(f"cat {alivef} | waybackurls | tee {uf}", 900)
        url_files.append(uf)
    prog.step("waybackurls")

    if "gau" in av and alivef.exists():
        uf = udir / "2urls.txt"
        run_cmd(f"cat {alivef} | gau | tee {uf}", 900)
        url_files.append(uf)
    prog.step("gau")

    if "katana" in av and alivef.exists():
        uf = udir / "3urls.txt"
        run_cmd(f"katana -list {alivef} -d 3 -jc -kf all -o {uf}", 1200)
        url_files.append(uf)
    prog.step("katana")

    if "waymore" in av and alivef.exists():
        uf = udir / "4urls.txt"
        run_cmd(f"waymore -i {alivef} -mode U -oU {uf}", 1200)
        url_files.append(uf)
    prog.step("waymore")

    final_urls = udir / "final-urls.txt"
    run_cmd(
        f"cat {' '.join(str(f) for f in url_files)} 2>/dev/null | sort -u > {final_urls}")
    prog.step("merge → final-urls.txt")
    
    cleanup_source_files_after_merge([f for f in url_files if f.exists()], label="url-source")
    
    if not is_file_empty(final_urls):
        count = len(rlines(final_urls))
        print(f"  {G}✔{RST} final-urls.txt — {C}{count} unique URLs{RST}")
    else:
        print(f"  {R}[!] final-urls.txt is empty — no URLs discovered{RST}")

    prog.done_phase()
    
    # [VERBOSE] Show full content of final URLs
    if args_verbose_output:
        show_file_content(final_urls, "final-urls.txt - All Discovered URLs", max_lines=50)
    
    if args_show_results:
        url_count = len(rlines(final_urls)) if final_urls.exists() else 0
        phase_results = {
            "total_urls": url_count,
            "output_file": str(final_urls),
        }
        show_phase_results(6, "Content Discovery", phase_results)
    
    return {"final_urls": str(final_urls)}

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 7 — LeakIX [FIXED: only save if real findings]
# ══════════════════════════════════════════════════════════════════════════════
def phase_leakix(domain, workspace, av):
    adir = workspace / domain / "active"
    ldir = workspace / domain / "leakix"
    mkd(ldir)
    ipsf = adir / "ips.txt"
    alivef = adir / "alive-final.txt"

    prog = PhaseProgress("7 — LeakIX Exposure Check", 2)

    key = api_keys_global.get("LEAKIX_API", "")

    leakix_ips_file = ldir / 'leakix-ips.txt'
    if key and "curl" in av and "jq" in av and ipsf.exists():
        script = (
            f"while IFS= read -r ip; do "
            f"echo \"=== $ip ===\"; "
            f"data=$(curl -s \"https://leakix.net/host/$ip\" "
            f"-H \"api-key: {key}\" -H \"Accept: application/json\"); "
            f"echo \"$data\" | jq '.Services[]? | select("
            f"(.leak.type != null and .leak.type != \"\") or "
            f"(.port == 21 or .port == 22 or .port == 3306 or .port == 5432 or "
            f".port == 6379 or .port == 27017 or .port == 9200)) | "
            f"{{port,protocol,software:.software.name,version:.software.version,"
            f"leak_type:.leak.type}}' 2>/dev/null; "
            f"done < {ipsf} > {leakix_ips_file}"
        )
        run_cmd(script, 900)
        if not has_real_leakix_findings(leakix_ips_file):
            cleanup_empty_file(leakix_ips_file, 'leakix-ips')
            print(f"  {Y}[!] leakix-ips.txt — no real findings, deleted{RST}")
    prog.step("LeakIX IP scan")

    leakix_doms_file = ldir / 'leakix-domains.txt'
    if key and "curl" in av and "jq" in av and alivef.exists():
        script = (
            f"cat {alivef} | sed \"s|https\\?://||\" | while IFS= read -r dom; do "
            f"echo \"=== $dom ===\"; "
            f"data=$(curl -s \"https://leakix.net/domain/$dom\" "
            f"-H \"api-key: {key}\" -H \"Accept: application/json\"); "
            f"echo \"$data\" | jq '.Services[]? | select("
            f"(.leak.type != null and .leak.type != \"\") or "
            f"(.port == 21 or .port == 22 or .port == 3306 or .port == 5432)) | "
            f"{{port,protocol,software:.software.name,leak_type:.leak.type}}' 2>/dev/null; "
            f"sleep 0.5; "
            f"done > {leakix_doms_file}"
        )
        run_cmd(script, 1800)
        if not has_real_leakix_findings(leakix_doms_file):
            cleanup_empty_file(leakix_doms_file, 'leakix-domains')
            print(f"  {Y}[!] leakix-domains.txt — no real findings, deleted{RST}")
    prog.step("LeakIX domain scan")

    if not key:
        print(f"  {Y}[!] LEAKIX_API not set — phase skipped{RST}")

    prog.done_phase()
    
    # [VERBOSE] Show LeakIX findings if any
    if args_verbose_output:
        if leakix_ips_file.exists() and not is_file_empty(leakix_ips_file):
            show_file_content(leakix_ips_file, "leakix-ips.txt - IP Exposure Findings", max_lines=30)
        if leakix_doms_file.exists() and not is_file_empty(leakix_doms_file):
            show_file_content(leakix_doms_file, "leakix-domains.txt - Domain Exposure Findings", max_lines=30)
    
    if args_show_results:
        leak_ips = len(rlines(leakix_ips_file)) if leakix_ips_file.exists() and not is_file_empty(leakix_ips_file) else 0
        leak_doms = len(rlines(leakix_doms_file)) if leakix_doms_file.exists() and not is_file_empty(leakix_doms_file) else 0
        phase_results = {
            "leakix_ip_findings": leak_ips,
            "leakix_domain_findings": leak_doms,
            "api_key_set": bool(key),
        }
        show_phase_results(7, "LeakIX Exposure Check", phase_results)

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 8 — JS Recon [mantra + SecretFinder only]
# ══════════════════════════════════════════════════════════════════════════════
def phase_js_recon(domain, workspace, av):
    udir = workspace / domain / "urls"
    jsdir = workspace / domain / "js"
    mkd(jsdir)

    prog = PhaseProgress("8 — JS Recon & Secret Discovery", 3)

    final_urls = udir / "final-urls.txt"

    js_file = jsdir / 'jsfiles.txt'
    if final_urls.exists():
        run_cmd(
            f"cat {final_urls} | grep -iE '\\.js(\\?|$|#)' | "
            f"grep -viE '\\.(png|jpg|jpeg|gif|svg|css|ico|woff|ttf|eot)' | "
            f"sort -u > {js_file}")
    
    js_count = len(rlines(js_file)) if js_file.exists() else 0
    if js_count > 0:
        print(f"  {G}✔{RST} jsfiles.txt — {C}{js_count} JS files{RST}")
    else:
        print(f"  {Y}[!] No JS files found — skipping secret scans{RST}")
        cleanup_empty_file(js_file, "js-list")
    prog.step(f"JS file collection — {G}{js_count} files{RST}")

    secrets_file = jsdir / 'secrets-found.txt'
    found_any = False
    
    # mantra with better filtering
    if "mantra" in av and js_file.exists() and js_count > 0:
        mantra_out = jsdir / 'mantra-raw.txt'
        run_cmd(
            f"cat {js_file} | mantra -ua 'Mozilla/5.0' -d 2>/dev/null | "
            f"grep -viE 'processing|fetching|scanning|url:' | "
            f"grep -E 'api[_-]?key|secret|token|password|auth|credential|private[_-]?key' > {mantra_out}",
            900)
        if not is_file_empty(mantra_out):
            with open(mantra_out) as f, open(secrets_file, 'a') as out:
                for line in f:
                    if line.strip() and 'processing' not in line.lower():
                        out.write(line)
            found_any = True
        cleanup_empty_file(mantra_out, 'mantra-raw')
    prog.step("mantra secret scan")

    # SecretFinder fallback
    sf = Path("SecretFinder.py")
    if sf.exists() and js_file.exists() and js_count > 0:
        sf_out = jsdir / 'sf-raw.txt'
        run_cmd(
            f"cat {js_file} | head -20 | while IFS= read -r url; do "
            f"python3 {sf} -i \"$url\" -o cli 2>/dev/null | "
            f"grep -E 'api[_-]?key|secret|token|password' >> {sf_out}; "
            f"done",
            600)
        if not is_file_empty(sf_out):
            with open(sf_out) as f, open(secrets_file, 'a') as out:
                for line in f:
                    if line.strip():
                        out.write(f"[SecretFinder] {line}")
            found_any = True
        cleanup_empty_file(sf_out, 'sf-raw')
    prog.step("SecretFinder fallback")

    if secrets_file.exists():
        if not is_file_empty(secrets_file):
            unique_secrets = set()
            with open(secrets_file) as f:
                for line in f:
                    line = line.strip()
                    if line and len(line) > 20:
                        unique_secrets.add(line)
            wlines(secrets_file, unique_secrets, auto_cleanup=False)
            print(f"  {G}✔{RST} secrets-found.txt — {C}{len(unique_secrets)} potential secrets{RST}")
        else:
            cleanup_empty_file(secrets_file, 'secrets')
            print(f"  {Y}[!] No secrets discovered{RST}")
    
    prog.done_phase()
    
    # [VERBOSE] Show discovered secrets
    if args_verbose_output and secrets_file.exists() and not is_file_empty(secrets_file):
        show_file_content(secrets_file, "secrets-found.txt - Potential API Keys/Secrets", max_lines=30)
    
    if args_show_results:
        secret_count = len(rlines(secrets_file)) if secrets_file.exists() else 0
        phase_results = {
            "js_files_found": js_count,
            "potential_secrets": secret_count,
            "output_dir": str(jsdir),
        }
        show_phase_results(8, "JS Recon & Secret Discovery", phase_results)

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 9 — Subdomain Takeover
# ══════════════════════════════════════════════════════════════════════════════
def phase_takeover(domain, workspace, av):
    adir = workspace / domain / "active"
    tdir = workspace / domain / "takeover"
    mkd(tdir)
    f404 = adir / "404subs.txt"

    prog = PhaseProgress("9 — Subdomain Takeover Detection", 3)

    if "subzy" in av and f404.exists() and not is_file_empty(f404):
        run_cmd(f"subzy run --targets {f404} --hide_fails | tee {tdir/'subzy-results.txt'}", 600)
    prog.step("subzy takeover check")
    cleanup_empty_file(tdir / 'subzy-results.txt', 'subzy')

    if "subjack" in av and f404.exists() and not is_file_empty(f404):
        run_cmd(
            f"subjack -w {f404} -t 100 -timeout 30 -ssl -v -a -o {tdir/'subjack-results.json'}",
            600)
    prog.step("subjack takeover check")
    cleanup_empty_file(tdir / 'subjack-results.json', 'subjack')

    if "nuclei" in av and f404.exists() and not is_file_empty(f404):
        tpl = Path("takeover.yaml")
        if tpl.exists():
            run_cmd(f"nuclei -list {f404} -t {tpl} | tee {tdir/'nuclei-takeover.txt'}", 600)
        else:
            run_cmd(
                f"nuclei -list {f404} -tags takeover -silent | tee {tdir/'nuclei-takeover.txt'}",
                600)
    prog.step("nuclei takeover template")
    cleanup_empty_file(tdir / 'nuclei-takeover.txt', 'nuclei-takeover')

    prog.done_phase()
    
    # [VERBOSE] Show takeover findings if any
    if args_verbose_output:
        for fname in ['subzy-results.txt', 'subjack-results.json', 'nuclei-takeover.txt']:
            fpath = tdir / fname
            if fpath.exists() and not is_file_empty(fpath):
                show_file_content(fpath, f"{fname} - Takeover Findings", max_lines=20)
    
    if args_show_results:
        subzy_res = len(rlines(tdir/'subzy-results.txt')) if (tdir/'subzy-results.txt').exists() and not is_file_empty(tdir/'subzy-results.txt') else 0
        subjack_res = len(rlines(tdir/'subjack-results.json')) if (tdir/'subjack-results.json').exists() and not is_file_empty(tdir/'subjack-results.json') else 0
        phase_results = {
            "subzy_findings": subzy_res,
            "subjack_findings": subjack_res,
            "vulnerable_subs": subzy_res + subjack_res,
        }
        show_phase_results(9, "Subdomain Takeover Detection", phase_results)

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 10 — WAF Detection [FIXED: simple output]
# ══════════════════════════════════════════════════════════════════════════════
def phase_waf(domain, workspace, av):
    adir = workspace / domain / "active"
    alivef = adir / "alive-final.txt"
    wdir = workspace / domain / "waf"
    mkd(wdir)

    prog = PhaseProgress("10 — WAF Detection", 1)

    waf_json = wdir / 'waf-report.json'
    waf_simple = wdir / 'waf-detected.txt'
    
    if "wafw00f" in av and alivef.exists() and not is_file_empty(alivef):
        run_cmd(
            f"wafw00f -i {alivef} -a -v -T 15 -o {waf_json} --format json",
            900)
        if parse_waf_simple(waf_json, waf_simple):
            print(f"  {G}✔{RST} WAF results → {waf_simple.name}")
            detected = sum(1 for l in rlines(waf_simple) if '✓' in l)
            print(f"  {G}✔{RST} WAFs detected: {C}{detected}{RST} hosts")
        prog.step(f"wafw00f → {waf_simple.name}")
    else:
        prog.step("wafw00f — skipped")
    
    cleanup_empty_file(waf_json, 'waf-raw-json')
    cleanup_empty_file(waf_simple, 'waf-simple')
    prog.done_phase()
    
    # [VERBOSE] Show WAF detection results
    if args_verbose_output and waf_simple.exists() and not is_file_empty(waf_simple):
        show_file_content(waf_simple, "waf-detected.txt - WAF Detection Results", max_lines=30)
    
    if args_show_results:
        waf_detected = 0
        if waf_simple.exists() and not is_file_empty(waf_simple):
            waf_detected = sum(1 for l in rlines(waf_simple) if '✓' in l)
        phase_results = {
            "waf_detected_count": waf_detected,
            "report_file": str(waf_simple),
        }
        show_phase_results(10, "WAF Detection", phase_results)

# ══════════════════════════════════════════════════════════════════════════════
# PHASE 11 — Nuclei Vuln Scan
# ══════════════════════════════════════════════════════════════════════════════
def phase_nuclei(domain, workspace, av, nuclei_templates_path: str = ""):
    adir = workspace / domain / "active"
    alivef = adir / "alive-final.txt"
    ndir = workspace / domain / "nuclei"
    mkd(ndir)

    prog = PhaseProgress("11 — Nuclei Vulnerability Scan", 1)

    findings = []
    if "nuclei" in av and alivef.exists() and not is_file_empty(alivef):
        out_file = ndir / "nuclei.jsonl"
        
        base_cmd = f"nuclei -l {alivef} -jsonl -severity critical,high,medium,low -silent -o {out_file}"
        final_cmd = build_nuclei_cmd(base_cmd, nuclei_templates_path)
        
        _, out, _ = run_cmd(final_cmd, 3600)
        for line in rlines(out_file):
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        
        results = {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f.get("info",{}).get("severity","").lower()=="critical"),
            "high": sum(1 for f in findings if f.get("info",{}).get("severity","").lower()=="high"),
            "medium": sum(1 for f in findings if f.get("info",{}).get("severity","").lower()=="medium"),
            "low": sum(1 for f in findings if f.get("info",{}).get("severity","").lower()=="low"),
        }
        prog.step(f"nuclei — {R}{results['total_findings']} findings{RST}")
        cleanup_empty_file(out_file, 'nuclei-raw')
        
        # [VERBOSE] Show nuclei findings in terminal
        if args_verbose_output and findings:
            print(f"\n{BOLD}{C}🔴 Nuclei Vulnerability Findings ({len(findings)} total){RST}")
            print(f"{DIM}{'─'*70}{RST}")
            for i, f in enumerate(findings[:20], 1):  # Show first 20
                info = f.get('info', {})
                name = info.get('name', 'Unknown')
                severity = info.get('severity', 'info').upper()
                url = f.get('host', '') + f.get('matched-at', '')
                color = R if severity == 'CRITICAL' else (Y if severity == 'HIGH' else (M if severity == 'MEDIUM' else C))
                print(f"  {color}{i:2d}. [{severity}] {name}{RST}")
                print(f"      {DIM}→ {url}{RST}")
            if len(findings) > 20:
                print(f"  {DIM}... and {len(findings) - 20} more (see nuclei.jsonl){RST}")
            print(f"{DIM}{'─'*70}{RST}\n")
        
        if args_show_results:
            show_phase_results(11, "Nuclei Vulnerability Scan", results)
            
    else:
        prog.step("nuclei — skipped")
        if args_show_results:
            show_phase_results(11, "Nuclei Vulnerability Scan", {"status": "skipped"})

    prog.done_phase()
    return findings

# ══════════════════════════════════════════════════════════════════════════════
# REPORTS
# ══════════════════════════════════════════════════════════════════════════════
def sev_summary(findings):
    s = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for f in findings:
        sv = (f.get("info",{}).get("severity") or "info").lower()
        s[sv] = s.get(sv,0)+1
    return s

def write_txt(path: Path, result: dict):
    lines = [
        "CLICKER — BLACK-BOX VULNERABILITY ASSESSMENT REPORT",
        "="*72,
        f"Generated : {result['generated_at']}",
        "",
    ]
    for t in result["targets"]:
        lines += [
            f"Target : {t['domain']}",
            "-"*40,
            f" Passive subdomains : {len(t['passive']['all_subdomains'])}",
            f" High-value subs : {len(t['passive']['sensitive_subs'])}",
            f" Alive hosts (200/302): {len(t['response']['alive'])}",
            f" 403 hosts : {len(t['response']['f403'])}",
            f" 404 hosts : {len(t['response']['f404'])}",
            f" Nuclei findings : {sev_summary(t['nuclei'])}",
            "",
        ]
    path.write_text("\n".join(lines), encoding="utf-8")

def write_html(path: Path, result: dict):
    blocks = []
    for t in result["targets"]:
        sv = sev_summary(t["nuclei"])
        blocks.append(f"""
<section>
<h2>🎯 {html_lib.escape(t['domain'])}</h2>
<table>
<tr><td>Passive subdomains</td><td>{len(t['passive']['all_subdomains'])}</td></tr>
<tr><td>High-value subs</td><td>{len(t['passive']['sensitive_subs'])}</td></tr>
<tr><td>Alive (200/302)</td><td>{len(t['response']['alive'])}</td></tr>
<tr><td>403 hosts</td><td>{len(t['response']['f403'])}</td></tr>
<tr><td>404 hosts</td><td>{len(t['response']['f404'])}</td></tr>
<tr><td>Nuclei findings</td><td>{html_lib.escape(str(sv))}</td></tr>
</table>
<details><summary>Passive tool logs</summary>
<pre>{html_lib.escape(json.dumps(t['passive']['tool_logs'],indent=2))}</pre>
</details>
<details><summary>High-value subdomains</summary>
<pre>{html_lib.escape(chr(10).join(t['passive']['sensitive_subs']))}</pre>
</details>
</section>""")

    doc = f"""<!doctype html><html lang="en"><head>
<meta charset="utf-8"><title>Clicker Report</title>
<style> body{{font-family:monospace;background:#060d1f;color:#d0d8f0;padding:24px;margin:0}} h1{{color:#7dd3fc}} h2{{color:#38bdf8;border-bottom:1px solid #1e3a5f;padding-bottom:6px}} table{{border-collapse:collapse;width:100%;margin:10px 0}} td{{border:1px solid #1e3a5f;padding:6px 12px}} tr:first-child td{{background:#0f1e3d}} pre{{background:#0a1128;padding:12px;border-radius:6px;overflow:auto;white-space:pre-wrap}} details{{margin:8px 0}} summary{{cursor:pointer;color:#7dd3fc}} </style></head><body> <h1>⚡ Clicker Report</h1> <p>Generated: {html_lib.escape(result['generated_at'])}</p> {''.join(blocks)} </body></html>"""
    path.write_text(doc, encoding="utf-8")

def write_pdf(path: Path, result: dict):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas as pdfcanvas
    except ImportError:
        print(f"{Y}[!] reportlab not installed — skipping PDF (pip install reportlab){RST}")
        return False
    c = pdfcanvas.Canvas(str(path), pagesize=A4)
    W_p, H = A4
    y = H - 40
    c.setFont("Helvetica-Bold", 15)
    c.drawString(40, y, "Clicker — Black-box Assessment Report")
    y -= 20
    c.setFont("Helvetica", 9)
    c.drawString(40, y, f"Generated: {result['generated_at']}")
    y -= 22
    for t in result["targets"]:
        if y < 140:
            c.showPage(); y = H-40
        sv = sev_summary(t["nuclei"])
        c.setFont("Helvetica-Bold", 12)
        c.drawString(40, y, f"Target: {t['domain']}"); y -= 16
        c.setFont("Helvetica", 10)
        rows = [
            f"Passive subdomains : {len(t['passive']['all_subdomains'])}",
            f"High-value subs : {len(t['passive']['sensitive_subs'])}",
            f"Alive (200/302) : {len(t['response']['alive'])}",
            f"403 hosts : {len(t['response']['f403'])}",
            f"404 hosts : {len(t['response']['f404'])}",
            f"Nuclei findings : {sv}",
        ]
        for row in rows:
            c.drawString(52, y, row); y -= 14
        y -= 8
    c.save()
    return True

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
api_keys_global = {}

def main():
    global api_keys_global, args_show_results, args_verbose_output, nuclei_templates_global

    if sys.platform != "linux":
        print(f"{Y}[!] Clicker is designed for Linux.{RST}")

    parser = argparse.ArgumentParser(
        description="Clicker — Black-box Recon & Vulnerability Assessment [VERBOSE v6]")
    parser.add_argument("-t","--target", help="Single target domain")
    parser.add_argument("--targets-file", help="File with one domain per line")
    parser.add_argument("--workspace", default="clicker_output")
    parser.add_argument("--api-file", default="clicker_api.env")
    parser.add_argument("--report-format", choices=["txt","html","both"], default="both")
    parser.add_argument("--pdf", action="store_true")
    parser.add_argument("--skip-screenshots", action="store_true")
    parser.add_argument("--skip-js", action="store_true")
    parser.add_argument("--keep-sources", action="store_true", help="Keep source files after merge (debug mode)")
    
    parser.add_argument("--nt", "--nuclei-templates", dest="nuclei_templates", 
                        help="Custom path for nuclei templates (auto-search if not provided)")
    
    parser.add_argument("--show-phase-results", action="store_true", 
                        help="Show detailed results summary after each phase")
    
    # [NEW] Verbose output option
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show FULL output content in terminal after each phase (in addition to saving)")
    
    args = parser.parse_args()

    print(ASCII_LOGO)

    # ── Set global flags
    args_show_results = args.show_phase_results
    args_verbose_output = args.verbose  # [NEW]
    nuclei_templates_global = find_nuclei_templates(args.nuclei_templates)

    # ── API keys
    api_keys_global = collect_api_keys(Path(args.api_file))

    # ── targets
    targets = parse_targets(args.target, args.targets_file)
    workspace = Path(args.workspace)
    mkd(workspace)

    # [REMOVED jsfinder, wappalyzer from required tools]
    required_tools = [
        "subfinder","sublist3r","chaos","assetfinder","github-subdomains",
        "findomain","waybackurls","gau","httpx","httpx-toolkit",
        "naabu","dnsx","cdncheck","nuclei","nmap",
        "aquatone","gowitness","katana","waymore",
        "mantra","subzy","subjack","wafw00f",
        "curl","jq","grep","sed","awk","sort","cat",
    ]
    available = check_tools(required_tools)

    result = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat().replace('+00:00', 'Z'),  # [FIXED] Deprecation warning
        "targets": [],
    }

    total_phases = 11
    print(f"\n{BOLD}{M}[►] Starting scan on {len(targets)} target(s) — {total_phases} phases each{RST}\n")

    for domain in targets:
        print(f"\n{BOLD}{W}{'━'*60}{RST}")
        print(f"{BOLD}{M}  Target : {domain}{RST}")
        print(f"{BOLD}{W}{'━'*60}{RST}")

        passive = phase_passive(domain, workspace, api_keys_global, available)
        response = phase_response_filter(domain, workspace, passive, available)
        tech = phase_tech_detect(domain, workspace, available)
        ports = phase_ports(domain, workspace, available)

        if not args.skip_screenshots:
            phase_screenshots(domain, workspace, available)

        urls = phase_content_discovery(domain, workspace, available)
        phase_leakix(domain, workspace, available)

        if not args.skip_js:
            phase_js_recon(domain, workspace, available)

        phase_takeover(domain, workspace, available)
        phase_waf(domain, workspace, available)
        nuclei_findings = phase_nuclei(domain, workspace, available, nuclei_templates_global)

        result["targets"].append({
            "domain": domain,
            "passive": passive,
            "response": response,
            "tech": tech,
            "ports": ports,
            "urls": urls,
            "nuclei": nuclei_findings,
        })

        if not args.keep_sources:
            print(f"\n{DIM}🧹 Final cleanup for {domain}...{RST}")
            target_dir = workspace / domain

            for root, dirs, files in os.walk(target_dir, topdown=False):
                for d in dirs:
                    dp = Path(root) / d
                    try:
                        if not any(dp.iterdir()):
                            dp.rmdir()
                            print(f"  {Y}[!] Removed empty directory: {dp.relative_to(workspace)}{RST}")
                    except:
                        pass

            total_size = sum(f.stat().st_size for f in target_dir.rglob('*') if f.is_file())
            print(f"  {G}✔{RST} Target workspace: {C}{total_size/1024:.1f} KB{RST} in {DIM}{target_dir.relative_to(workspace)}{RST}")

    print(f"\n{BOLD}{B}{'═'*60}{RST}")
    print(f"{BOLD}{C}  Writing Reports{RST}")
    print(f"{BOLD}{B}{'═'*60}{RST}")

    json_path = workspace / "report.json"
    json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"  {G}✔{RST} JSON  → {json_path}")

    if args.report_format in {"txt","both"}:
        tp = workspace / "report.txt"
        write_txt(tp, result)
        print(f"  {G}✔{RST} TXT   → {tp}")

    if args.report_format in {"html","both"}:
        hp = workspace / "report.html"
        write_html(hp, result)
        print(f"  {G}✔{RST} HTML  → {hp}")

    if args.pdf:
        pp = workspace / "report.pdf"
        if write_pdf(pp, result):
            print(f"  {G}✔{RST} PDF   → {pp}")

    print(f"\n{BOLD}{G}[✔] Clicker completed. Output → {workspace}/{RST}\n")

if __name__ == "__main__":
    main()
