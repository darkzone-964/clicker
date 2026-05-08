#!/usr/bin/env python3
import argparse, datetime, html, json, os, re, shutil, subprocess, sys, time, random, urllib.request, socket, signal
from pathlib import Path
from urllib.parse import urlparse

R,G,Y,B,M,C,W,DIM,RST,BOLD = "\033[91m","\033[92m","\033[93m","\033[94m","\033[95m","\033[96m","\033[97m","\033[2m","\033[0m","\033[1m"
AUTHOR,VERSION,INSTAGRAM = "Clicker Tool","v1.3","@403_linux"

ASCII_ART = r"""
.__  .__        __                 
  ____ |  | |__| ____ |  | __ ___________ 
_/ ___\|  | |  |/ ___\|  |/ // __ \_  __ \
\  \___|  |_|  \  \___|    <\  ___/|  | \/
 \___  >____/__|\___  >__|_ \\___  >__|   
     \/             \/     \/    \/       
"""
ASCII_LOGO = f"{C}{ASCII_ART}{RST}{DIM}Black-box Recon Pipeline | {BOLD}{C}{AUTHOR}{RST} {DIM}| {Y}{INSTAGRAM}{RST}"

SENSITIVE_PREFIXES = ["app","dashboard","api","auth","admin","dev","staging","test","internal","vpn","mail","ftp","sandbox","uat","qa","jenkins","gitlab","payment","portal","secure","beta","demo","prod","mgmt","manage","login","sso","id","oauth","backup","old","legacy","corp","intranet","remote","access","cloud","db","database","secret","private","hidden"]
PORTS_FULL = ",".join(["21","22","23","25","53","80","110","111","135","139","143","389","443","445","993","995","1433","1521","2181","2375","2376","3000","3001","3306","3389","4848","4999","5000","5432","5601","5900","5984","6379","6443","7001","7077","7474","8000","8080","8081","8082","8083","8085","8088","8089","8090","8091","8092","8095","8096","8097","8098","8099","8161","8443","8444","8500","8600","8686","8765","8800","8848","8880","8888","8983","9000","9001","9002","9090","9091","9092","9093","9094","9095","9096","9100","9200","9300","9418","9999","10000","10250","10255","11211","15672","16686","27017","28017","50000","50070","50090","61616"])

args_show_results,args_verbose_output,args_skip_active_subs,args_resume = False,False,False,False
args_wordlist = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
args_resolvers = "/usr/share/seclists/Discovery/DNS/resolvers.txt"
api_keys_global = {}
RESUME_FILE = None
GLOBAL_USE_PROXYCHAINS = False
GLOBAL_HYBRID_PROXY = False
GLOBAL_PROXY_HEALTH_OK = True
SKIP_CURRENT_PHASE = False
GLOBAL_WAF_TYPE = "default"

SMART_WORDLISTS = {
    "default": ["/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"],
    "cloud": ["/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt", "/usr/share/seclists/Discovery/DNS/names_from_dnsdb.txt"],
    "enterprise": ["/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt", "/usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top50000.txt"],
    "startup": ["/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"],
    "gov": ["/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt", "/usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top100000.txt"],
    "ecommerce": ["/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt", "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"]
}

WAF_TOOL_OPTIONS = {
    "cloudflare": {"httpx": "-timeout 10 -retries 1", "naabu": "-rate 100 -timeout 1000", "nmap": "-T3 --max-retries 1"},
    "akamai": {"httpx": "-timeout 15 -retries 2", "naabu": "-rate 80 -timeout 1500", "nmap": "-T3 --host-timeout 15m"},
    "imperva": {"httpx": "-timeout 20 -retries 2", "naabu": "-rate 50 -timeout 2000", "nmap": "-T2 --max-retries 2"},
    "default": {"httpx": "-timeout 10 -retries 1", "naabu": "-rate 200 -timeout 1000", "nmap": "-T4 --max-retries 1"}
}

HTTP_PROXY_TOOLS = {
    "subfinder", "sublist3r", "chaos", "assetfinder", "github-subdomains", "findomain",
    "waybackurls", "gau", "httpx", "httpx-toolkit", "curl", "katana", "waymore",
    "mantra", "subzy", "subjack", "wafw00f", "ffuf", "nuclei", "locate", "whatweb"
}
NO_PROXY_TOOLS = {
    "nmap", "naabu", "dnsx", "cdncheck", "puredns", "altdns", "shuffledns", "dnsrecon",
    "aquatone", "gowitness"
}
FALLBACK_URLS = {
    "resolvers": "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
    "wordlist": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt"
}

class ProxyManager:
    def __init__(self, proxy=None, proxy_file=None, auto_fetch=False, rotate=False):
        self.proxies, self.current_idx, self.rotate = [], 0, rotate
        self.load(proxy, proxy_file, auto_fetch)
    def load(self, proxy, proxy_file, auto_fetch):
        raw = []
        if auto_fetch:
            print(f"{C}[*] Fetching fresh proxies from public API...{RST}")
            try:
                for url in ["https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=5000&country=all&ssl=all&anonymity=all", "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt"]:
                    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=10) as res: raw.extend(res.read().decode().splitlines())
                print(f"{G}[+] Fetched {len(raw)} raw proxies. Validating...{RST}")
            except Exception as e: print(f"{Y}[!] Proxy fetch failed: {e}{RST}")
        if proxy_file and os.path.isfile(proxy_file):
            with open(proxy_file) as f: raw.extend(f.read().splitlines())
        if proxy: raw.append(proxy)
        pattern = re.compile(r'^(?:[^@]+@)?(\d{1,3}\.){3}\d{1,3}:\d{2,5}$')
        self.proxies = list(set([p.strip() for p in raw if pattern.match(p.strip())]))
        if not self.proxies: print(f"{Y}[!] No valid proxies loaded. Running without proxy.{RST}")
        else: print(f"{G}[+] Loaded {len(self.proxies)} valid proxy(ies).{RST}")
    def get_current(self):
        if not self.proxies: return None
        if self.rotate:
            proxy = self.proxies[self.current_idx]
            self.current_idx = (self.current_idx + 1) % len(self.proxies)
            return proxy
        return self.proxies[0]
    def apply(self, domain=None):
        proxy = self.get_current()
        if not proxy:
            for k in ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy']: os.environ.pop(k, None)
            return
        if domain: print(f"{DIM}↻ Rotating proxy: {proxy} for {domain}{RST}")
        proxy_url = proxy if any(proxy.startswith(p) for p in ["http://", "https://", "socks4://", "socks5://"]) else f"http://{proxy}"
        for k in ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy']: os.environ[k] = proxy_url

def signal_handler(sig, frame):
    global SKIP_CURRENT_PHASE
    print(f"\n{Y}[!] Ctrl+C detected — skipping current phase...{RST}")
    SKIP_CURRENT_PHASE = True
    raise KeyboardInterrupt

def check_proxy_health(proxy, timeout=8):
    if not proxy: return False
    try:
        proxy_url = proxy if any(proxy.startswith(p) for p in ["http://", "https://", "socks4://", "socks5://"]) else f"http://{proxy}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy_url, 'https': proxy_url}))
        opener.addheaders = [('User-Agent', 'Mozilla/5.0')]
        with opener.open("https://httpbin.org/ip", timeout=timeout) as res: return res.status == 200
    except: return False

def detect_target_type(domain):
    domain_lower = domain.lower()
    if any(kw in domain_lower for kw in ["cloud", "aws", "azure", "gcp", "digitalocean", "heroku"]): return "cloud"
    elif any(kw in domain_lower for kw in ["corp", "enterprise", "company", "inc", "ltd", "group"]): return "enterprise"
    elif any(kw in domain_lower for kw in ["gov", "government", "state", "municipal", "public"]): return "gov"
    elif any(kw in domain_lower for kw in ["shop", "store", "ecommerce", "market", "buy", "cart"]): return "ecommerce"
    elif any(kw in domain_lower for kw in ["startup", "app", "tech", "io", "ai", "labs"]): return "startup"
    return "default"

def get_smart_wordlist(domain, preferred=None):
    target_type = detect_target_type(domain)
    candidates = SMART_WORDLISTS.get(target_type, SMART_WORDLISTS["default"])
    if preferred and preferred in candidates: candidates = [preferred] + [c for c in candidates if c != preferred]
    for wl in candidates:
        if Path(wl).exists(): return Path(wl)
    return ensure_essential_file("wordlist", Path(candidates[0]))

def detect_waf(domain, workspace):
    waf_file = workspace/domain/"passive"/"waf-detected.txt"
    if waf_file.exists() and not is_file_empty(waf_file):
        content = waf_file.read_text().lower()
        if "cloudflare" in content: return "cloudflare"
        elif "akamai" in content: return "akamai"
        elif "imperva" in content or "incapsula" in content: return "imperva"
    return GLOBAL_WAF_TYPE

def get_tool_options(tool_name, waf_type):
    waf_opts = WAF_TOOL_OPTIONS.get(waf_type, WAF_TOOL_OPTIONS["default"])
    return waf_opts.get(tool_name, "")

def ensure_essential_file(file_type, path):
    if Path(path).exists(): return path
    fallback_dir = Path.home() / ".clicker" / "wordlists"; fallback_dir.mkdir(parents=True, exist_ok=True)
    url = FALLBACK_URLS.get(file_type)
    if not url: return None
    fallback_path = fallback_dir / f"{file_type}.txt"
    if fallback_path.exists(): print(f"{G}[+] Using cached {file_type}: {fallback_path}{RST}"); return fallback_path
    print(f"{Y}[!] {file_type} not found — downloading fallback...{RST}")
    try:
        with urllib.request.urlopen(url, timeout=60) as res: content = res.read().decode(); fallback_path.write_text(content, encoding="utf-8")
        print(f"{G}[+] Downloaded {file_type} to {fallback_path}{RST}"); return fallback_path
    except Exception as e: print(f"{R}[!] Failed to download {file_type}: {e}{RST}"); return None

def run_cmd(cmd, timeout=600, tool_name=None, allow_fallback=True):
    global GLOBAL_HYBRID_PROXY, GLOBAL_USE_PROXYCHAINS, GLOBAL_PROXY_HEALTH_OK, SKIP_CURRENT_PHASE
    if SKIP_CURRENT_PHASE: SKIP_CURRENT_PHASE = False; return (0, "", "")
    use_proxy = True
    if GLOBAL_HYBRID_PROXY and tool_name:
        if tool_name in NO_PROXY_TOOLS:
            use_proxy = False
            for k in ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy']: os.environ.pop(k, None)
            if args_verbose_output: print(f"{DIM}[hybrid] Cleaned env + bypassed proxy for {tool_name}{RST}")
        elif tool_name not in HTTP_PROXY_TOOLS: use_proxy = False
    if use_proxy and GLOBAL_HYBRID_PROXY:
        current_proxy = os.environ.get('HTTP_PROXY', '').replace('http://', '')
        if current_proxy and not GLOBAL_PROXY_HEALTH_OK:
            if not check_proxy_health(current_proxy, timeout=5):
                if args_verbose_output: print(f"{Y}[!] Proxy health check failed — temporarily bypassing{RST}"); use_proxy = False
            else: GLOBAL_PROXY_HEALTH_OK = True
    final_cmd = cmd
    if use_proxy and GLOBAL_USE_PROXYCHAINS:
        pc_bin = shutil.which("proxychains4") or shutil.which("proxychains")
        if pc_bin: final_cmd = f"{pc_bin} -q {cmd}"
    try:
        p = subprocess.run(final_cmd, shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        result = (p.returncode, p.stdout.strip(), p.stderr.strip())
        if allow_fallback and use_proxy and (p.returncode != 0 or not p.stdout.strip()):
            if args_verbose_output: print(f"{Y}[!] Command failed/empty with proxy — retrying without proxy{RST}")
            saved_env = {k: os.environ.get(k) for k in ['HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy']}
            for k in saved_env: os.environ.pop(k, None)
            p_retry = subprocess.run(cmd, shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
            for k, v in saved_env.items():
                if v: os.environ[k] = v
                else: os.environ.pop(k, None)
            if p_retry.returncode == 0 and p_retry.stdout.strip():
                if args_verbose_output: print(f"{G}[+] Fallback succeeded without proxy{RST}"); return (p_retry.returncode, p_retry.stdout.strip(), p_retry.stderr.strip())
        return result
    except subprocess.TimeoutExpired: return (124, "", f"timeout after {timeout}s")
    except KeyboardInterrupt: SKIP_CURRENT_PHASE = False; return (0, "", "")

def installed(tool): return shutil.which(tool) is not None
def mkd(p): p.mkdir(parents=True,exist_ok=True)
def wlines(path,lines,auto_cleanup=True):
    with path.open("w",encoding="utf-8") as f:
        for l in sorted(set(lines)):
            if l.strip(): f.write(l.strip()+"\n")
    if not path.exists(): path.touch()
    if auto_cleanup: cleanup_empty_file(path)
def rlines(path):
    if not path.exists(): return []
    return [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
def clean_sub(val,domain):
    if not val: return None
    v = val.strip().lower().replace("*.","").split(",")[0].strip().split(":")[0]
    if v.startswith("http://") or v.startswith("https://"): v = urlparse(v).hostname or ""
    v = v.strip(".")
    if not v: return None
    if (v==domain or v.endswith("."+domain)) and re.match(r"^[a-z0-9.-]+$",v): return v
    return None
def extract_hosts_from_urls(lines,domain):
    out=set()
    for l in lines:
        h=urlparse(l.strip()).hostname; c=clean_sub(h or "",domain)
        if c: out.add(c)
    return out
def is_file_empty(path):
    if not path.exists(): return True
    try: return len(path.read_text(encoding="utf-8").strip())==0
    except: return True
def cleanup_empty_file(path,label=""):
    if is_file_empty(path):
        try:
            label_str=f" ({label})" if label else ""
            print(f"  {Y}[!]{RST} {DIM}{path.name}{label_str} {R}[empty — deleted]{RST}")
            path.unlink(missing_ok=True); return True
        except: pass
    return False
def cleanup_source_files_after_merge(source_files,label="source"):
    for src in source_files:
        if src.exists():
            try: src.unlink(); print(f"  {Y}[!]{RST} {DIM}{src.name}{RST} {R}[{label} — merged → deleted]{RST}")
            except: pass
def show_file_content(file_path,label,max_lines=50):
    if not file_path.exists() or is_file_empty(file_path): return
    lines=rlines(file_path)
    print(f"\n{BOLD}{C}📄 {label} ({len(lines)} lines){RST}\n{DIM}{'─'*70}{RST}")
    for i,line in enumerate(lines[:max_lines],1):
        if '[200]' in line or '✓' in line or '→ http' in line: print(f"  {G}{i:3d}{RST} {line}")
        elif '[403]' in line or '[404]' in line: print(f"  {Y}{i:3d}{RST} {line}")
        elif 'VULNERABLE' in line or 'CVE-' in line: print(f"  {R}{i:3d}{RST} {BOLD}{line}{RST}")
        else: print(f"  {DIM}{i:3d}{RST} {line}")
    if len(lines)>max_lines: print(f"  {DIM}... and {len(lines)-max_lines} more{RST}")
    print(f"{DIM}{'─'*70}{RST}\n")

class PhaseProgress:
    def __init__(self,name,total): self.name,self.total,self.done,self.start=name,total,0,time.time(); self._print_header()
    def _print_header(self): print(f"\n{BOLD}{B}{'═'*60}{RST}\n{BOLD}{C}  Phase: {self.name}{RST}\n{BOLD}{B}{'═'*60}{RST}")
    def step(self,label):
        global SKIP_CURRENT_PHASE
        if SKIP_CURRENT_PHASE: SKIP_CURRENT_PHASE = False; raise KeyboardInterrupt
        self.done+=1; pct=int(self.done/self.total*100); bar=int(pct/4)
        elapsed=time.time()-self.start; eta=(elapsed/self.done)*(self.total-self.done) if self.done>0 else 0
        print(f"  {G}{'█'*bar}{RST}{DIM}{'░'*(25-bar)}{RST} {BOLD}{pct:3d}%{RST} {Y}[{self.done}/{self.total}]{RST} {DIM}elapsed {elapsed:.0f}s{RST} {W}{label}{RST}")
    def done_phase(self): print(f"\n  {G}✔ Phase complete in {time.time()-self.start:.1f}s{RST}\n")

def save_checkpoint(phase_name):
    global RESUME_FILE
    if RESUME_FILE: RESUME_FILE.write_text(json.dumps({"last_phase": phase_name, "timestamp": datetime.datetime.now().isoformat(), "completed": True}), encoding="utf-8")
def load_checkpoint():
    global RESUME_FILE
    if RESUME_FILE and RESUME_FILE.exists():
        try: return json.loads(RESUME_FILE.read_text())
        except: pass
    return {}
def read_env_file(path):
    vals={}
    if not path.exists(): return vals
    for line in path.read_text(encoding="utf-8").splitlines():
        row=line.strip()
        if not row or row.startswith("#") or "=" not in row: continue
        k,v=row.split("=",1); vals[k.strip()]=v.strip().strip('"').strip("'")
    return vals
def save_env_file(path,vals):
    keys=["CHAOS_API_KEY","VT_API_KEY","GITHUB_TOKEN","SHODAN_API","LEAKIX_API"]; lines=["# Clicker API keys"]
    for k in keys: lines.append(f"{k}={vals.get(k,'')}")
    path.write_text("\n".join(lines)+"\n",encoding="utf-8")
def collect_api_keys(api_file):
    existing=read_env_file(api_file)
    print(f"\n{BOLD}{Y}[?] API Keys Setup{RST} (file: {api_file})\n{DIM}Press Enter to keep saved, type 'skip' to leave empty.{RST}\n")
    prompts=[("CHAOS_API_KEY","Chaos"),("VT_API_KEY","VirusTotal"),("GITHUB_TOKEN","GitHub"),("SHODAN_API","Shodan"),("LEAKIX_API","LeakIX")]; updated=dict(existing)
    for key,label in prompts:
        cur=existing.get(key,""); tag=f"{G}[saved]{RST}" if cur else f"{R}[empty]{RST}"
        val=input(f" {label} {tag}: ").strip()
        if val.lower()=="skip": updated[key]=""
        elif val: updated[key]=val
        elif key not in updated: updated[key]=""
    save_env_file(api_file,updated); print(f"\n{G}[+] API keys saved to {api_file}{RST}\n"); return updated

def check_tools(required):
    print(f"{BOLD}{Y}[*] Checking required tools...{RST}")
    available,missing=set(),[]
    for t in required:
        if installed(t): available.add(t); print(f" {G}✔{RST} {t}")
        else: missing.append(t); print(f" {R}✘{RST} {t}")
    if missing: print(f"\n{Y}[!] {len(missing)} tool(s) missing — affected steps will be skipped.{RST}\n")
    else: print(f"\n{G}[+] All tools present.{RST}\n")
    return available

def parse_targets(single,tfile):
    targets=[]
    if single: targets.append(single.strip().lower())
    if tfile:
        p=Path(tfile)
        if not p.exists(): sys.exit(f"{R}[!] targets file not found: {tfile}{RST}")
        for line in p.read_text(encoding="utf-8").splitlines():
            c=line.strip().lower()
            if c and not c.startswith("#"): targets.append(c)
    targets=sorted(set(targets))
    if not targets: sys.exit(f"{R}[!] No targets. Use -t or --targets-file{RST}")
    return targets

def find_file_smart(filename, search_names=None):
    if search_names is None: search_names = [filename]
    found_files = []
    for name in search_names:
        _, out, _ = run_cmd(f"locate -i '{name}' 2>/dev/null | head -20", timeout=30, tool_name="locate")
        if out:
            for line in out.splitlines():
                path = line.strip()
                if path and os.path.isfile(path) and path.endswith('.txt'): found_files.append(path)
    common_paths = ["/usr/share/seclists/Discovery/DNS/","/usr/share/wordlists/","/opt/wordlists/",os.path.expanduser("~/wordlists/"),"./wordlists/","/root/wordlists/"]
    for cp in common_paths:
        if os.path.isdir(cp):
            for name in search_names:
                candidate = os.path.join(cp, name)
                if os.path.isfile(candidate) and candidate not in found_files: found_files.append(candidate)
    return list(set(found_files))

def ask_user_for_file(filename, found_files):
    if not found_files:
        print(f"  {Y}[!] {filename} not found in system{RST}")
        user_path = input(f"  {DIM}Enter custom path for {filename} (or press Enter to skip): {RST}").strip()
        if user_path and os.path.isfile(user_path): print(f"  {G}✔{RST} Using: {user_path}"); return user_path
        return None
    print(f"\n  {Y}[?] Found {len(found_files)} possible {filename} file(s):{RST}")
    for i, f in enumerate(found_files[:5], 1): print(f"    {i}. {DIM}{f}{RST}")
    if len(found_files) > 5: print(f"    {DIM}... and {len(found_files)-5} more{RST}")
    while True:
        choice = input(f"  {DIM}Use one of these? Enter number (1-{min(5,len(found_files))}), 'n' for custom path, or Enter to skip: {RST}").strip()
        if choice == "" or choice.lower() == "skip": return None
        elif choice.lower() == "n":
            user_path = input(f"  {DIM}Enter custom path for {filename}: {RST}").strip()
            if user_path and os.path.isfile(user_path): print(f"  {G}✔{RST} Using: {user_path}"); return user_path
            print(f"  {R}[!] Invalid path{RST}")
        elif choice.isdigit() and 1 <= int(choice) <= min(5, len(found_files)):
            selected = found_files[int(choice)-1]
            confirm = input(f"  {DIM}Use {selected}? (Y/n): {RST}").strip().lower()
            if confirm == "" or confirm == "y": print(f"  {G}✔{RST} Using: {selected}"); return selected
        else: print(f"  {R}[!] Invalid choice{RST}")

def phase_passive(domain,workspace,api_keys,av):
    global SKIP_CURRENT_PHASE
    pdir=workspace/domain/"passive"; mkd(pdir); collected=set(); logs=[]
    prog=PhaseProgress("1 — Passive Subdomain Enumeration",12); source_files=[]
    try:
        if "subfinder" in av:
            outfile=pdir/f"{domain}_subfinder.txt"; cmd=f'subfinder -d {domain} -silent -all -rl 10 -timeout 30 -max-time 15 -o "{outfile}"'
            _,out,err=run_cmd(cmd,timeout=480,tool_name="subfinder"); lines=rlines(outfile) if outfile.exists() else out.splitlines()
            parsed={clean_sub(l,domain) for l in lines}; parsed={x for x in parsed if x}
            wlines(outfile,parsed,auto_cleanup=False); collected.update(parsed); logs.append({"tool":"subfinder","count":len(parsed),"stderr":err[:300]}); prog.step(f"subfinder — {G}{len(parsed)} subs{RST}"); source_files.append(outfile)
        else: logs.append({"tool":"subfinder","status":"skipped","reason":"not installed"}); prog.step("subfinder — skipped")
        if "sublist3r" in av:
            outfile=pdir/f"{domain}_sublist3r.txt"; cmd=f'sublist3r -d {domain} -e "Google,Bing,Virustotal,Netcraft" -v -o "{outfile}"'
            _,out,err=run_cmd(cmd,timeout=480,tool_name="sublist3r"); lines=rlines(outfile) if outfile.exists() else out.splitlines()
            parsed={clean_sub(l,domain) for l in lines}; parsed={x for x in parsed if x}
            wlines(outfile,parsed,auto_cleanup=False); collected.update(parsed); logs.append({"tool":"sublist3r","count":len(parsed),"stderr":err[:300]}); prog.step(f"sublist3r — {G}{len(parsed)} subs{RST}"); source_files.append(outfile)
        else: logs.append({"tool":"sublist3r","status":"skipped","reason":"not installed"}); prog.step("sublist3r — skipped")
        if api_keys.get("CHAOS_API_KEY") and "chaos" in av:
            outfile=pdir/f"{domain}_chaos.txt"; cmd=f'chaos -d {domain} -silent -key {api_keys["CHAOS_API_KEY"]}'
            _,out,err=run_cmd(cmd,timeout=480,tool_name="chaos"); parsed={clean_sub(l,domain) for l in out.splitlines()}; parsed={x for x in parsed if x}
            wlines(outfile,parsed,auto_cleanup=False); collected.update(parsed); logs.append({"tool":"chaos","count":len(parsed),"stderr":err[:300]}); prog.step(f"chaos — {G}{len(parsed)} subs{RST}"); source_files.append(outfile)
        if "assetfinder" in av:
            outfile=pdir/f"{domain}_assetfinder.txt"; cmd=f'assetfinder --subs-only {domain}'; _,out,err=run_cmd(cmd,timeout=480,tool_name="assetfinder")
            parsed={clean_sub(l,domain) for l in out.splitlines()}; parsed={x for x in parsed if x}
            wlines(outfile,parsed,auto_cleanup=False); collected.update(parsed); logs.append({"tool":"assetfinder","count":len(parsed),"stderr":err[:300]}); prog.step(f"assetfinder — {G}{len(parsed)} subs{RST}"); source_files.append(outfile)
        if api_keys.get("GITHUB_TOKEN") and "github-subdomains" in av:
            outfile=pdir/f"{domain}_github.txt"; cmd=f'github-subdomains -d {domain} -t {api_keys["GITHUB_TOKEN"]} -q -raw -o "{outfile}"'
            _,out,err=run_cmd(cmd,timeout=480,tool_name="github-subdomains"); lines=rlines(outfile) if outfile.exists() else out.splitlines()
            parsed={clean_sub(l,domain) for l in lines}; parsed={x for x in parsed if x}
            wlines(outfile,parsed,auto_cleanup=False); collected.update(parsed); logs.append({"tool":"github-subdomains","count":len(parsed),"stderr":err[:300]}); prog.step(f"github-subdomains — {G}{len(parsed)} subs{RST}"); source_files.append(outfile)
        if "findomain" in av:
            outfile=pdir/f"{domain}_findomain.txt"; cmd=f'findomain -t {domain} -q --rate-limit 1'; _,out,err=run_cmd(cmd,timeout=480,tool_name="findomain")
            wlines(outfile,out.splitlines(),auto_cleanup=False); parsed={clean_sub(l,domain) for l in out.splitlines()}; parsed={x for x in parsed if x}
            collected.update(parsed); logs.append({"tool":"findomain","count":len(parsed),"stderr":err[:300]}); prog.step(f"findomain — {G}{len(parsed)} subs{RST}"); source_files.append(outfile)
        if "curl" in av and "jq" in av:
            outfile=pdir/f"{domain}_crtsh.txt"; cmd=f'curl -s --max-time 30 --retry 2 --user-agent "Mozilla/5.0" "https://crt.sh/?q=%25.{domain}&output=json" | jq -r \'.[].name_value\' 2>/dev/null | grep -F "{domain}" | grep -v r"\\*\\." | sort -u'
            _,out,err=run_cmd(cmd,timeout=480,tool_name="curl"); parsed={clean_sub(l,domain) for l in out.splitlines()}; parsed={x for x in parsed if x}
            wlines(outfile,parsed,auto_cleanup=False); collected.update(parsed); logs.append({"tool":"crt.sh","count":len(parsed),"stderr":err[:300]}); prog.step(f"crt.sh — {G}{len(parsed)} subs{RST}"); source_files.append(outfile)
        if "waybackurls" in av:
            outfile=pdir/f"{domain}_waybackurls.txt"; cmd=f'echo "{domain}" | waybackurls | sort -u | grep -vE r"\\.(jpg|png|gif|css|js|svg|ico)$" | grep -F "{domain}"'
            _,out,err=run_cmd(cmd,timeout=480,tool_name="waybackurls"); parsed=extract_hosts_from_urls(out.splitlines(),domain); parsed={x for x in parsed if x}
            wlines(outfile,parsed,auto_cleanup=False); collected.update(parsed); logs.append({"tool":"waybackurls","count":len(parsed),"stderr":err[:300]}); prog.step(f"waybackurls — {G}{len(parsed)} subs{RST}"); source_files.append(outfile)
        if "gau" in av:
            outfile=pdir/f"{domain}_gau.txt"; cmd=f'echo "{domain}" | gau --subs --timeout 10 --threads 2 | grep -F "{domain}" | grep -v r"\\*\\." | grep -vE r"\\.(jpg|png|gif|css|js|svg|ico|woff|woff2|pdf)$" | sort -u'
            _,out,err=run_cmd(cmd,timeout=480,tool_name="gau"); parsed=extract_hosts_from_urls(out.splitlines(),domain); parsed={x for x in parsed if x}
            wlines(outfile,parsed,auto_cleanup=False); collected.update(parsed); logs.append({"tool":"gau","count":len(parsed),"stderr":err[:300]}); prog.step(f"gau — {G}{len(parsed)} subs{RST}"); source_files.append(outfile)
        allsubs=pdir/"allsubs.txt"; wlines(allsubs,collected,auto_cleanup=False); prog.step(f"merge → {allsubs.name}")
        existing_sources=[f for f in source_files if f.exists()]
        if existing_sources: cleanup_source_files_after_merge(existing_sources,label="subdomain-tool-output")
        sensitive=[s for s in collected if s.split(".")[0] in SENSITIVE_PREFIXES]; wlines(pdir/"high_value_subs.txt",sensitive)
        if not cleanup_empty_file(pdir/"high_value_subs.txt","high-value"): print(f"  {G}✔{RST} high_value_subs.txt — {Y}{len(sensitive)} entries{RST}")
        prog.done_phase(); print(f"  {BOLD}Total subdomains : {G}{len(collected)}{RST}\n  {BOLD}High-value subs  : {Y}{len(sensitive)}{RST}")
        if args_verbose_output:
            show_file_content(allsubs,"allsubs.txt - All Discovered Subdomains",max_lines=30)
            if (pdir/"high_value_subs.txt").exists(): show_file_content(pdir/"high_value_subs.txt","high_value_subs.txt - High-Value Subdomains",max_lines=20)
        return {"domain":domain,"allsubs_file":str(allsubs),"all_subdomains":sorted(collected),"sensitive_subs":sorted(sensitive),"tool_logs":logs}
    except KeyboardInterrupt: print(f"{Y}[!] Phase 1 skipped by user{RST}"); return {"domain":domain,"allsubs_file":"","all_subdomains":[],"sensitive_subs":[],"tool_logs":[]}

def phase_waf(domain,workspace,av):
    global SKIP_CURRENT_PHASE, GLOBAL_WAF_TYPE
    pdir=workspace/domain/"passive"; wdir=workspace/domain/"waf"; mkd(wdir)
    high_val=pdir/"high_value_subs.txt"; allsubs=pdir/"allsubs.txt"
    
    prog=PhaseProgress("2 — WAF Detection",3)
    waf_json=wdir/'waf-report.json'; waf_simple=wdir/'waf-detected.txt'
    detected_waf = "default"
    
    try:
        httpx_bin="httpx-toolkit" if "httpx-toolkit" in av else ("httpx" if "httpx" in av else None)
        if httpx_bin and high_val.exists() and not is_file_empty(high_val):
            httpx_out=wdir/"httpx-waf-check.txt"
            cmd=f"{httpx_bin} -l {high_val} -sc -td -cl -server -title -ip -silent -t 15 -rl 8 -timeout 10 -retries 1 -random-agent -follow-redirects -o {httpx_out}"
            run_cmd(cmd,timeout=600,tool_name=httpx_bin)
            if httpx_out.exists():
                for line in rlines(httpx_out):
                    line_lower=line.lower()
                    if 'cloudflare' in line_lower: detected_waf="cloudflare"; break
                    elif 'akamai' in line_lower or 'edgekey' in line_lower: detected_waf="akamai"; break
                    elif 'imperva' in line_lower or 'incapsula' in line_lower: detected_waf="imperva"; break
            prog.step(f"httpx WAF scan → {G}{detected_waf}{RST}" if detected_waf!="default" else "httpx WAF scan → no WAF detected")
        
        
        if detected_waf=="default" and "wafw00f" in av and high_val.exists() and not is_file_empty(high_val):
            batch_prefix=str(wdir/"batch_")
            cmd=f'split -l 50 {high_val} "{batch_prefix}" && for f in "{batch_prefix}"*; do wafw00f -i "$f" -a -T 10 --format json --no-colors; sleep 30; done >> "{waf_json}" && rm -f "{batch_prefix}"*'
            run_cmd(cmd,timeout=1800,tool_name="wafw00f")
            if waf_json.exists() and not is_file_empty(waf_json):
                try:
                    content=waf_json.read_text(encoding="utf-8")
                    all_results=[]
                    decoder=json.JSONDecoder()
                    idx=0
                    while idx<len(content):
                        while idx<len(content) and content[idx] in ' \t\n\r': idx+=1
                        if idx>=len(content): break
                        try: 
                            obj,idx=decoder.raw_decode(content,idx=idx)
                            if isinstance(obj,list): all_results.extend(obj)
                            elif isinstance(obj,dict): all_results.append(obj)
                        except: break
                    for entry in all_results:
                        fw = entry.get('firewall', entry.get('waf', '')).lower()
                        if 'cloudflare' in fw: detected_waf = "cloudflare"; break
                        elif 'akamai' in fw or 'edgekey' in fw: detected_waf = "akamai"; break
                        elif 'imperva' in fw or 'incapsula' in fw: detected_waf = "imperva"; break
                except: pass
            prog.step(f"wafw00f scan → {G}{detected_waf}{RST}" if detected_waf!="default" else "wafw00f scan → no WAF detected")
        
        
        if detected_waf=="default" and high_val.exists():
            waf_headers = {
                "cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare"],
                "akamai": ["akamai-grn", "x-akamai-transformed", "server: akamai"],
                "imperva": ["x-cdn", "incap-signal", "server: imperva"],
                "sucuri": ["x-sucuri-id", "x-sucuri-cache"],
                "aws": ["x-amz-cf-id", "x-amz-request-id"]
            }
            for url in rlines(high_val)[:10]:
                try:
                    req = urllib.request.Request(url if url.startswith("http") else f"https://{url}", headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=5) as res:
                        headers = {k.lower():v for k,v in res.headers.items()}
                        for waf_name, indicators in waf_headers.items():
                            if any(ind in headers.get('server','').lower() or ind in str(headers) for ind in indicators):
                                detected_waf = waf_name
                                break
                    if detected_waf != "default": break
                except: continue
            prog.step(f"Header analysis → {G}{detected_waf}{RST}" if detected_waf!="default" else "Header analysis → no WAF detected")
        
        
        if detected_waf != "default":
            results = []
            for url in rlines(high_val)[:20]:
                results.append(f"{url:50} | {G}✓{RST} {detected_waf.upper()}")
            if results:
                header=f"{'URL':50} | WAF Detected\n{'-'*70}"
                wlines(waf_simple, [header]+results, auto_cleanup=False)
                print(f"  {G}✔{RST} WAF results → {waf_simple.name}")
                print(f"  {G}✔{RST} WAFs detected: {C}{len(results)}{RST} hosts")
        
        cleanup_empty_file(waf_json,'waf-raw-json')
        if not cleanup_empty_file(waf_simple,'waf-simple'):
            print(f"  {Y}[!] No WAF detected or results empty{RST}")
        
        prog.done_phase()
        GLOBAL_WAF_TYPE = detected_waf
        print(f"{C}[*] Detected WAF Type: {detected_waf.upper()}{RST}")
        
        if args_verbose_output and waf_simple.exists() and not is_file_empty(waf_simple): 
            show_file_content(waf_simple,"waf-detected.txt - WAF Detection Results",max_lines=30)
        
        return {"waf_file":str(waf_simple) if waf_simple.exists() else None, "waf_type": detected_waf}
    
    except KeyboardInterrupt: 
        print(f"{Y}[!] Phase 2 skipped by user{RST}")
        return {"waf_file":None, "waf_type":"default"}

def phase_response_filter(domain,workspace,passive,av,active_result=None):
    global SKIP_CURRENT_PHASE
    adir=workspace/domain/"active"; mkd(adir)
    
    if active_result and isinstance(active_result, dict) and active_result.get("merged_file"):
        allsubs_file = active_result["merged_file"]
    elif isinstance(passive, dict) and passive.get("allsubs_file"):
        allsubs_file = passive["allsubs_file"]
    else:
        allsubs_file = str(workspace/domain/"passive"/"allsubs.txt")
    
    high_val=str(workspace/domain/"passive"/"high_value_subs.txt")
    prog=PhaseProgress("3 — Response Filtering",7)
    results={"alive":[],"ports_alive":[],"f403":[],"f404":[],"details":[]}
    httpx_bin="httpx-toolkit" if "httpx-toolkit" in av else ("httpx" if "httpx" in av else None)
    waf_type = detect_waf(domain, workspace); httpx_opts = get_tool_options("httpx", waf_type)
    
    try:
        if httpx_bin: cmd=f"{httpx_bin} -l {high_val} -sc -td -cl -server -title -ip -silent -t 15 -rl 8 -timeout 5 -retries 1 -random-agent -follow-redirects {httpx_opts} -o {adir/'details.txt'}"; run_cmd(cmd,timeout=600,tool_name=httpx_bin); results["details"]=rlines(adir/"details.txt")
        prog.step("high-value details scan"); cleanup_empty_file(adir/"details.txt","details")
        alive_file=adir/"alive.txt"
        if httpx_bin: cmd=f"{httpx_bin} -l {allsubs_file} -mc 200,302 -silent -t 15 -rl 8 -timeout 5 -retries 1 -random-agent -follow-redirects {httpx_opts} -o {alive_file}"; run_cmd(cmd,timeout=900,tool_name=httpx_bin); results["alive"]=rlines(alive_file)
        prog.step(f"alive 200/302 — {G}{len(results['alive'])} hosts{RST}")
        alive2_file=adir/"2alive.txt"
        if httpx_bin: cmd=f"{httpx_bin} -l {allsubs_file} -ports 80,8443,8080,8000 -silent -t 15 -rl 8 -timeout 5 -retries 1 -random-agent -follow-redirects {httpx_opts} -o {alive2_file}"; run_cmd(cmd,timeout=600,tool_name=httpx_bin)
        prog.step("alive extra ports (80,8443,8080,8000)")
        alive3_file=adir/"3alive.txt"
        if "naabu" in av: naabu_opts = get_tool_options("naabu", waf_type); cmd=f"naabu -list {allsubs_file} -port 80,443,8000,8080 -silent -s s -rate 200 -c 10 -timeout 1500 -retries 1 {naabu_opts} -o {alive3_file}"; run_cmd(cmd,timeout=900,tool_name="naabu")
        prog.step("naabu fallback liveness")
        f403_file=adir/"403subs.txt"
        if httpx_bin: cmd=f"{httpx_bin} -l {allsubs_file} -mc 403 -silent -t 15 -rl 8 -timeout 5 -retries 1 -random-agent -follow-redirects {httpx_opts} -o {f403_file}"; run_cmd(cmd,timeout=600,tool_name=httpx_bin); results["f403"]=rlines(f403_file)
        prog.step(f"403 filter — {Y}{len(results['f403'])} hosts{RST}"); cleanup_empty_file(f403_file,"403")
        f404_file=adir/"404subs.txt"
        if httpx_bin: cmd=f"{httpx_bin} -l {allsubs_file} -mc 404 -silent -t 15 -rl 8 -timeout 5 -retries 1 -random-agent -follow-redirects {httpx_opts} -o {f404_file}"; run_cmd(cmd,timeout=600,tool_name=httpx_bin); results["f404"]=rlines(f404_file)
        prog.step(f"404 filter — {R}{len(results['f404'])} hosts{RST}"); cleanup_empty_file(f404_file,"404")
        source_files=[alive_file,alive2_file,alive3_file]; success_file=adir/"success-response.txt"
        run_cmd(f"cat {alive_file} {alive2_file} {alive3_file} 2>/dev/null | sort -u > {success_file}", tool_name="cat"); prog.step("merge → success-response.txt")
        cleanup_source_files_after_merge([f for f in source_files if f.exists()],label="response-filter"); prog.done_phase()
        if args_verbose_output:
            show_file_content(success_file,"success-response.txt - Alive Hosts (200/302)",max_lines=40)
            if (adir/"details.txt").exists() and not is_file_empty(adir/"details.txt"): show_file_content(adir/"details.txt","details.txt - High-Value Host Details",max_lines=20)
        return results
    except KeyboardInterrupt: print(f"{Y}[!] Phase 3 skipped by user{RST}"); return {"alive":[],"ports_alive":[],"f403":[],"f404":[],"details":[]}

def phase_tech_detect(domain,workspace,av,waf_type="default"):
    global SKIP_CURRENT_PHASE
    adir=workspace/domain/"active"; sucf=adir/"success-response.txt"; techf=adir/"subs-Tech.txt"; ipsf=adir/"ips.txt"; alivef=adir/"alive-final.txt"
    prog=PhaseProgress("4 — Technology Detection & IP Extraction",3)
    httpx_bin="httpx-toolkit" if "httpx-toolkit" in av else ("httpx" if "httpx" in av else None)
    httpx_opts = get_tool_options("httpx", waf_type)
    try:
        if httpx_bin and sucf.exists(): cmd=f"{httpx_bin} -l {sucf} -r 8.8.8.8,1.1.1.1 -sc -td -cl -server -title -ip -fr -silent -t 15 -rl 8 -timeout 10 -retries 1 -random-agent {httpx_opts} -o {techf}"; run_cmd(cmd,timeout=1200,tool_name=httpx_bin)
        prog.step(f"httpx tech detection → {techf.name}")
        
        
        if techf.exists():
            
            cmd_ipv4 = f"grep -oE r'\\b(?:[0-9]{{1,3}}\\.){3}[0-9]{{1,3}}\\b' {techf} | sort -u > {ipsf}"
            run_cmd(cmd_ipv4, timeout=300, tool_name="grep")
            
            cmd_ipv6 = f"grep -oE r'([0-9a-fA-F]{{1,4}}:){7}[0-9a-fA-F]{{1,4}}|::1' {techf} | sort -u >> {ipsf} 2>/dev/null || true"
            run_cmd(cmd_ipv6, timeout=300, tool_name="grep")
        prog.step(f"IP extraction → {ipsf.name}")
        
        if not cleanup_empty_file(ipsf,"ips"): print(f"  {G}✔{RST} ips.txt — {len(rlines(ipsf))} unique IPs{RST}")
        
        
        if techf.exists():
            
            cmd=f"grep -E r'\\[(200|301|302)' {techf} | sed 's/\\x1b\\[[0-9;]*m//g' | awk '{{print $1}}' | sort -u > {alivef}"; run_cmd(cmd,timeout=300,tool_name="sed")
        prog.step(f"alive-final re-filter → {alivef.name}")
        
        if not cleanup_empty_file(alivef,"alive-final"): print(f"  {G}✔{RST} alive-final.txt — {len(rlines(alivef))} hosts{RST}")
        prog.done_phase()
        if args_verbose_output: show_file_content(techf,"subs-Tech.txt - Technology Detection + IPs",max_lines=30); show_file_content(alivef,"alive-final.txt - Final Alive Hosts",max_lines=30)
        return {"ips_file":str(ipsf),"alive_final":str(alivef)}
    except KeyboardInterrupt: print(f"{Y}[!] Phase 4 skipped by user{RST}"); return {"ips_file":"","alive_final":""}

def phase_ports(domain,workspace,av,waf_type="default"):
    global SKIP_CURRENT_PHASE
    adir=workspace/domain/"active"; pdir=workspace/domain/"passive"; ipsf=adir/"ips.txt"; allsubs=pdir/"allsubs_final.txt" if (pdir/"allsubs_final.txt").exists() else pdir/"allsubs.txt"; highval=pdir/"high_value_subs.txt"; prog=PhaseProgress("5 — Port Scanning",11)
    naabu_opts = get_tool_options("naabu", waf_type)
    nmap_opts = get_tool_options("nmap", waf_type)
    try:
        resolved=adir/"resolved-ips-full.txt"
        if "dnsx" in av: cmd=f"dnsx -l {allsubs} -resp-only -a -silent -t 100 -retry 1 -timeout 200 -r 8.8.8.8,1.1.1.1 -o {resolved}"; run_cmd(cmd,timeout=300,tool_name="dnsx")
        prog.step("dnsx resolve all subdomains"); all_ips=adir/"all-ips-final.txt"; merge_sources=[ipsf,resolved] if resolved.exists() else [ipsf]
        cmd=f'{{ cat {ipsf} {resolved} 2>/dev/null || true; }} | grep -v \'\' | sort -u > {all_ips}'; run_cmd(cmd,timeout=300,tool_name="cat"); prog.step("merge all IPs → all-ips-final.txt"); cleanup_source_files_after_merge([f for f in merge_sources if f.exists()],label="ip-source")
        if not is_file_empty(all_ips):
            cdn_res,real_ips=adir/"cdn-results.txt",adir/"real-ips.txt"
            if "cdncheck" in av: cmd=f"cat {all_ips} | cdncheck -silent -resp -r 8.8.8.8,1.1.1.1 -retry 1 -o {cdn_res}"; run_cmd(cmd,timeout=120,tool_name="cdncheck")
            prog.step("CDN detection")
            if "cdncheck" in av: cmd=f"cat {all_ips} | cdncheck -silent -resp -r 8.8.8.8,1.1.1.1 -retry 1 | grep -ivE 'cloudflare|akamai|fastly|cloudfront|incapsula|sucuri|aws|azure|google' | awk '{{print $1}}' | sort -u > {real_ips}"; run_cmd(cmd,timeout=120,tool_name="cdncheck")
            prog.step("real-IP extraction")
            if real_ips.exists() and not cleanup_empty_file(real_ips,"real-ips"): print(f"  {G}✔{RST} real-ips.txt — {len(rlines(real_ips))} non-CDN IPs{RST}")
        else: print(f"{Y}[!] No IPs to scan — skipping CDN/port scans{RST}"); real_ips=adir/"real-ips.txt"; real_ips.touch()
        open_ports_json,open_ports_txt=adir/"open-ports-full.json",adir/"open-ports-full.txt"
        if "naabu" in av and real_ips.exists() and not is_file_empty(real_ips):
            cmd=f"naabu -list {real_ips} -p {PORTS_FULL} -rate 300 -c 25 -retries 1 -timeout 1000 -Pn -s s -verify -scan-all-ips -ip-version 4 -silent -json {naabu_opts} -o {open_ports_json}"; run_cmd(cmd,timeout=600,tool_name="naabu")
            if open_ports_json.exists():
                formatted=[]
                try:
                    with open(open_ports_json,'r') as f:
                        for line in f:
                            line=line.strip()
                            if not line: continue
                            try:
                                entry=json.loads(line)
                                host=entry.get('host',entry.get('input',''))
                                port=entry.get('port','')
                                protocol=entry.get('protocol','tcp').upper()
                                service=entry.get('service',{}).get('name','')
                                version=entry.get('service',{}).get('version','')
                                line_out=f"{host}:{port}/{protocol}"
                                if service: line_out+=f" → {service}"
                                if version: line_out+=f" ({version})"
                                formatted.append(line_out)
                            except: continue
                    if formatted: wlines(open_ports_txt,formatted,auto_cleanup=False); print(f"  {G}✔{RST} Formatted port scan → {open_ports_txt.name}")
                except: pass
            cleanup_empty_file(open_ports_json,"raw-json")
        prog.step("naabu full port scan + format output")
        nmap_results=adir/"nmap-scripts.txt"
        if "nmap" in av and open_ports_txt.exists() and not is_file_empty(open_ports_txt):
            ips_to_scan=set()
            for line in rlines(open_ports_txt): 
                match=re.match(r'([^:/]+):\d+',line)
                if match: ips_to_scan.add(match.group(1))
            if ips_to_scan:
                ip_list=adir/"nmap-targets.txt"; wlines(ip_list,ips_to_scan,auto_cleanup=False)
                cmd=f"nmap -iL {ip_list} -sC -sV --open -T4 -Pn -n --version-light --max-retries 1 --host-timeout 10m --max-rate 200 -p 21,22,23,25,53,80,443,3306,3389,5432,6379,8080,8443,9200,27017 {nmap_opts} -oA {adir/'nmap-scripts'} --reason --open"; run_cmd(cmd,timeout=1800,tool_name="nmap")
                if (adir/"nmap-scripts.nmap").exists(): cmd=f"grep -iE r'vuln(erability|erable)?|CVE-[0-9]{{4}}-[0-9]{{4,}}|sqli|xss|injection|exploit|weak|default.*cred|anonymous|auth.*bypass|priv.*escalat|misconfig' {adir/'nmap-scripts.nmap'} | grep -vE r'^#|^\\s*$|^Nmap scan report|^Host:|^Port:' | sort -u > {nmap_results}"; run_cmd(cmd,timeout=300,tool_name="grep")
                if not cleanup_empty_file(nmap_results,"nmap-vulns"): print(f"  {G}✔{RST} nmap-scripts.txt — {C}{len(rlines(nmap_results))} potential findings{RST}")
        prog.step("nmap -sC vulnerability scripts scan")
        if not open_ports_txt.exists() or is_file_empty(open_ports_txt):
            open_subs_json,open_subs_txt=adir/"open-ports-subs.json",adir/"open-ports-subs.txt"
            if "naabu" in av: cmd=f"naabu -list {allsubs} -p {PORTS_FULL} -rate 200 -c 20 -retries 1 -timeout 1000 -Pn -s s -verify -scan-all-ips -ip-version 4 -silent -json {naabu_opts} -exclude-cdn -o {open_subs_json}"; run_cmd(cmd,timeout=600,tool_name="naabu")
            if open_subs_json.exists():
                formatted=[]
                try:
                    with open(open_subs_json,'r') as f:
                        for line in f:
                            line=line.strip()
                            if not line: continue
                            try: 
                                entry=json.loads(line)
                                host=entry.get('host',entry.get('input',''))
                                port=entry.get('port','')
                                protocol=entry.get('protocol','tcp').upper()
                                service=entry.get('service',{}).get('name','')
                                version=entry.get('service',{}).get('version','')
                                line_out=f"{host}:{port}/{protocol}"
                                if service: line_out+=f" → {service}"
                                if version: line_out+=f" ({version})"
                                formatted.append(line_out)
                            except: continue
                    if formatted: wlines(open_subs_txt,formatted,auto_cleanup=False); print(f"  {G}✔{RST} Formatted fallback scan → {open_ports_txt.name}")
                except: pass
            cleanup_empty_file(open_subs_json,"raw-json"); prog.step("naabu fallback scan + format"); cleanup_empty_file(open_subs_txt,"fallback-ports")
        hv_ips=adir/"high-value-ips.txt"
        if "dnsx" in av and highval.exists() and not is_file_empty(highval): cmd=f"dnsx -l {highval} -a -resp-only -silent -r 8.8.8.8,1.1.1.1,9.9.9.9 -t 50 -retry 1 -timeout 200 -o {hv_ips}"; run_cmd(cmd,timeout=120,tool_name="dnsx")
        prog.step("dnsx resolve high-value subs")
        if "nmap" in av and hv_ips.exists() and not is_file_empty(hv_ips): cmd=f"nmap -iL {hv_ips} -sC -sV --open -Pn -n -T4 --version-light --max-rate 150 --scan-delay 100ms --max-retries 1 --host-timeout 10m -p 21,22,23,25,53,80,443,3306,3389,5432,5900,6379,8080,8443,9200,27017 {nmap_opts} --script=banner,http-title,ssl-cert,vuln -oA {adir/'nmap-highvalue'} --reason"; run_cmd(cmd,timeout=1800,tool_name="nmap")
        prog.step("nmap deep scan on high-value IPs")
        shodan_out,shodan_err=adir/"shodan-results.txt",adir/"shodan-errors.log"
        if api_keys_global.get("SHODAN_API") and "curl" in av and "jq" in av and ipsf.exists() and not is_file_empty(ipsf):
            key=api_keys_global["SHODAN_API"]; script=f'while IFS= read -r ip; do [[ -z "$ip" || "$ip" =~ ^# ]] && continue; result=$(curl -s --max-time 15 --retry 1 --user-agent "Mozilla/5.0" "https://api.shodan.io/shodan/host/${{ip}}?key={key}" -H "Accept: application/json" 2>/dev/null); if echo "$result" | jq -e \'.error\' >/dev/null 2>&1; then error_msg=$(echo "$result" | jq -r \'.error // "Unknown error"\'); echo "[$(date +%H:%M:%S)] ⚠️ $ip: $error_msg" >&2; [[ "$error_msg" =~ [Rr]ate.*limit|[Ll]imit|429 ]] && sleep 10 || sleep 2; continue; else echo "$result" | jq -r --arg ip "$ip" r"\"\\($ip) | Ports: \\(.ports // [] | join(\", \")) | Vulns: \\(.vulns // [] | join(\", \")) | Org: \\(.org // \"N/A\") | Country: \\(.country_name // \"N/A\")\"" ; fi; sleep 1; done < <(grep -oE r\'^([0-9]{{1,3}}\\\\.){{3}}[0-9]{{1,3}}$\' {ipsf} | sort -u) > {shodan_out} 2> {shodan_err}'
            run_cmd(script,timeout=300,tool_name="curl")
        prog.step("Shodan IP lookup"); cleanup_empty_file(shodan_out,"shodan"); prog.done_phase()
        if args_verbose_output:
            if open_ports_txt.exists() and not is_file_empty(open_ports_txt): show_file_content(open_ports_txt,"open-ports-full.txt - Discovered Open Ports",max_lines=40)
            if nmap_results.exists() and not is_file_empty(nmap_results): show_file_content(nmap_results,"nmap-scripts.txt - Potential Vulnerabilities",max_lines=30)
        return {"open_ports_file":str(open_ports_txt) if open_ports_txt.exists() else None}
    except KeyboardInterrupt: print(f"{Y}[!] Phase 5 skipped by user{RST}"); return {"open_ports_file":None}

def phase_takeover(domain,workspace,av):
    global SKIP_CURRENT_PHASE
    adir=workspace/domain/"active"; tdir=workspace/domain/"takeover"; mkd(tdir); f404=adir/"404subs.txt"; prog=PhaseProgress("6 — Subdomain Takeover Detection",3)
    try:
        if "subzy" in av and f404.exists() and not is_file_empty(f404): subzy_out=tdir/'subzy-results.txt'; cmd=f'subzy run --targets {f404} --concurrency 5 --timeout 8 --hide_fails --vuln | tee {subzy_out}'; run_cmd(cmd,timeout=600,tool_name="subzy"); cleanup_empty_file(subzy_out,'subzy')
        prog.step("subzy takeover check")
        if "subjack" in av and f404.exists() and not is_file_empty(f404): subjack_out=tdir/'subjack-results.json'; cmd=f'subjack -w {f404} -t 8 -timeout 10 -ssl -o {subjack_out}'; run_cmd(cmd,timeout=600,tool_name="subjack"); cleanup_empty_file(subjack_out,'subjack')
        prog.step("subjack takeover check")
        if "nuclei" in av and f404.exists() and not is_file_empty(f404):
            nuclei_out=tdir/'nuclei-takeover.txt'; tpl=Path("takeover.yaml"); base_cmd=f"nuclei -list {f404} -t {tpl} -silent" if tpl.exists() else f"nuclei -list {f404} -tags takeover -silent"
            cmd=f'{base_cmd} -rl 10 -c 5 -timeout 8 -retries 1 -fr -no-interactsh -nmhe -headless-concurrency 1 -headless-bulk-size 1 | tee {nuclei_out}'; run_cmd(cmd,timeout=1200,tool_name="nuclei"); cleanup_empty_file(nuclei_out,'nuclei-takeover')
        prog.step("nuclei takeover template"); prog.done_phase()
        if args_verbose_output:
            for fname in ['subzy-results.txt','subjack-results.json','nuclei-takeover.txt']:
                fpath=tdir/fname
                if fpath.exists() and not is_file_empty(fpath): show_file_content(fpath,f"{fname} - Takeover Findings",max_lines=20)
        return {"takeover_dir":str(tdir)}
    except KeyboardInterrupt: print(f"{Y}[!] Phase 6 skipped by user{RST}"); return {"takeover_dir":str(tdir)}

def phase_screenshots(domain,workspace,av):
    global SKIP_CURRENT_PHASE
    adir=workspace/domain/"active"; alivef=adir/"alive-final.txt"; prog=PhaseProgress("7 — Screenshots",2)
    try:
        if "aquatone" in av and alivef.exists(): aq_dir=workspace/domain/"screenshots"/"aquatone"; mkd(aq_dir); cmd=f"cat {alivef} | aquatone -out {aq_dir} -silent -threads 10 -http-timeout 5000 -screenshot-timeout 20000"; run_cmd(cmd,timeout=1800,tool_name="aquatone"); prog.step(f"aquatone → {aq_dir}")
        else: prog.step("aquatone — skipped")
        if "gowitness" in av and alivef.exists(): gw_dir=workspace/domain/"screenshots"/"gowitness"; mkd(gw_dir); cmd=f"gowitness scan file -f {alivef} -q -t 10 --delay 1500 --timeout 15 --screenshot-path {gw_dir} --write-db"; run_cmd(cmd,timeout=1800,tool_name="gowitness"); prog.step(f"gowitness → {gw_dir}")
        else: prog.step("gowitness — skipped")
        prog.done_phase()
        if args_verbose_output:
            aq_html=workspace/domain/"screenshots"/"aquatone"/"aquatone.html"; gw_db=workspace/domain/"screenshots"/"gowitness"/"gowitness.db"
            if aq_html.exists(): print(f"\n{BOLD}{C}📸 Aquatone screenshots:{RST} {DIM}{aq_html}{RST}")
            if gw_db.exists(): print(f"{BOLD}{C}📸 Gowitness database:{RST} {DIM}{gw_db}{RST}")
    except KeyboardInterrupt: print(f"{Y}[!] Phase 7 skipped by user{RST}")

def phase_content_discovery(domain,workspace,av):
    global SKIP_CURRENT_PHASE
    adir=workspace/domain/"active"; alivef=adir/"alive-final.txt"; udir=workspace/domain/"urls"; mkd(udir); prog=PhaseProgress("8 — Content Discovery",5); url_files=[]
    filter_pattern = r"\.(jpg|png|gif|css|js|svg|ico|woff|pdf|zip|tar|gz|map|woff2|ttf|eot|otf|webp|avif|mp[34]|webm|ogg|exe|dll|so)$"
    try:
        if "waybackurls" in av and alivef.exists(): uf=udir/"urls.txt"; cmd=f'cat {alivef} | waybackurls | grep -vE r"{filter_pattern}" | sort -u | tee {uf}'; run_cmd(cmd,timeout=900,tool_name="waybackurls"); url_files.append(uf)
        prog.step("waybackurls")
        if "gau" in av and alivef.exists(): uf=udir/"2urls.txt"; cmd=f'cat {alivef} | gau --threads 2 --timeout 10 | grep -vE r"{filter_pattern}" | sort -u | tee {uf}'; run_cmd(cmd,timeout=900,tool_name="gau"); url_files.append(uf)
        prog.step("gau")
        if "katana" in av and alivef.exists(): uf=udir/"3urls.txt"; cmd=f'katana -list {alivef} -d 3 -jc -kf all -o {uf} -silent -c 5 -rl 20 -hrl 3 -rd 1 -timeout 10 -retry 1 -fs rdn -ef png,jpg,gif,css,svg,ico,woff,woff2,pdf,map -iqp'; run_cmd(cmd,timeout=1200,tool_name="katana"); url_files.append(uf)
        prog.step("katana")
        if "waymore" in av and alivef.exists(): uf=udir/"4urls.txt"; cmd=f'waymore -i {alivef} -mode U -oU {uf} -p 2 -lr 300 -t 20 -r 1 -wrlr 5 -urlr 3 -fc "200,301,302" -ft "text/html,application/json,text/javascript" -ci d'; run_cmd(cmd,timeout=1200,tool_name="waymore"); url_files.append(uf)
        prog.step("waymore"); final_urls=udir/"final-urls.txt"; run_cmd(f"cat {' '.join(str(f) for f in url_files)} 2>/dev/null | sort -u > {final_urls}", tool_name="cat"); prog.step("merge → final-urls.txt")
        cleanup_source_files_after_merge([f for f in url_files if f.exists()],label="url-source")
        if not final_urls.exists(): final_urls.touch()
        if not is_file_empty(final_urls): print(f"  {G}✔{RST} final-urls.txt — {C}{len(rlines(final_urls))} unique URLs{RST}")
        else: print(f"  {Y}[!] final-urls.txt is empty — no URLs discovered{RST}")
        prog.done_phase()
        if args_verbose_output: show_file_content(final_urls,"final-urls.txt - All Discovered URLs",max_lines=50)
        return {"final_urls":str(final_urls)}
    except KeyboardInterrupt: print(f"{Y}[!] Phase 8 skipped by user{RST}"); return {"final_urls":""}

def phase_js_recon(domain,workspace,av):
    global SKIP_CURRENT_PHASE
    udir=workspace/domain/"urls"; jsdir=workspace/domain/"js"; mkd(jsdir); prog=PhaseProgress("9 — JS Recon & Secret Discovery",2); final_urls=udir/"final-urls.txt"
    js_file=jsdir/'jsfiles.txt'
    try:
        if final_urls.exists() and not is_file_empty(final_urls): cmd=f'grep -iE r"\\\\.js([?&#]|$)" {final_urls} | grep -viE r"\\.(png|jpe?g|gif|svg|css|ico|woff2?|ttf|eot|otf|webp|avif|mp[34]|webm|ogg|pdf|zip|tar|gz|map)$" | grep -E r"^https?://[^[:space:]]+\\\\.js" | sed \'s/[?#].*$//\' | sort -u > {js_file}'; run_cmd(cmd,timeout=300,tool_name="grep")
        js_count=len(rlines(js_file)) if js_file.exists() else 0
        if js_count>0: print(f"  {G}✔{RST} jsfiles.txt — {C}{js_count} JS files{RST}")
        else: print(f"  {Y}[!] No JS files found — skipping secret scans{RST}"); cleanup_empty_file(js_file,"js-list")
        prog.step(f"JS file collection — {G}{js_count} files{RST}")
        secrets_file=jsdir/'secrets-found.txt'
        if "mantra" in av and js_file.exists() and js_count>0:
            mantra_out=jsdir/'mantra-raw.txt'; cmd=f'mantra -s -ua \'Mozilla/5.0\' -t 10 -d {js_file} 2>/dev/null | grep -iE r"(api[_-]?key|secret|token|password|passwd|pwd|auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer|credential|private[_-]?key|client[_-]?secret|jwt|session[_-]?id|csrf)" | grep -vE r"^[[:space:]]*$" | sort -u > {mantra_out}'; run_cmd(cmd,timeout=900,tool_name="mantra")
            if not is_file_empty(mantra_out): shutil.copy2(mantra_out,secrets_file); print(f"  {G}✔{RST} secrets-found.txt — {C}{len(rlines(secrets_file))} potential secrets{RST}")
            else: cleanup_empty_file(secrets_file,'secrets'); print(f"  {Y}[!] No secrets discovered{RST}")
            cleanup_empty_file(mantra_out,'mantra-raw')
        prog.step("mantra secret scan"); prog.done_phase()
        if args_verbose_output and secrets_file.exists() and not is_file_empty(secrets_file): show_file_content(secrets_file,"secrets-found.txt - Potential API Keys/Secrets",max_lines=30)
        return {"js_file":str(js_file),"secrets_file":str(secrets_file)}
    except KeyboardInterrupt: print(f"{Y}[!] Phase 9 skipped by user{RST}"); return {"js_file":"","secrets_file":""}

def phase_leakix(domain,workspace,av):
    global SKIP_CURRENT_PHASE
    adir=workspace/domain/"active"; ldir=workspace/domain/"leakix"; mkd(ldir); ipsf=adir/"ips.txt"; alivef=adir/"alive-final.txt"; prog=PhaseProgress("10 — LeakIX Exposure Check",2); key=api_keys_global.get("LEAKIX_API","")
    leakix_ips_file,leakix_ips_err=ldir/'leakix-ips.txt',ldir/'leakix-errors.log'
    try:
        if key and "curl" in av and "jq" in av and ipsf.exists():
            script=f'while IFS= read -r ip; do [[ -z "$ip" || ! "$ip" =~ ^([0-9]{{1,3}}\\\\.){{3}}[0-9]{{1,3}}$ ]] && continue; response=$(curl -s --max-time 15 --retry 1 --user-agent "Mozilla/5.0" "https://leakix.net/host/$ip" -H "api-key: {key}" -H "Accept: application/json" 2>/dev/null); if echo "$response" | jq -e \'.error\' >/dev/null 2>&1; then error_msg=$(echo "$response" | jq -r \'.error // "Unknown error"\'); echo "[$(date +%H:%M:%S)] ⚠️ $ip: $error_msg" >&2; [[ "$error_msg" =~ [Rr]ate.*limit|[Ll]imit|429 ]] && sleep 10 || sleep 2; continue; else echo "$response" | jq -r --arg ip "$ip" r\'".Services[]? | select((.leak.type != null and .leak.type != "") or (.port | IN(21,22,3306,5432,6379,27017,9200,1433,1521,3389,5900))) | "\\($ip) | Port: \\(.port) | Proto: \\(.protocol) | Software: \\(.software.name // "N/A") | Leak: \\(.leak.type // "None") | Version: \\(.software.version // "N/A")"\' 2>/dev/null; fi; sleep 1; done < <(grep -oE r\'^([0-9]{{1,3}}\\\\.){{3}}[0-9]{{1,3}}$\' {ipsf} 2>/dev/null | sort -u) | sort -u > {leakix_ips_file} 2> {leakix_ips_err}'
            run_cmd(script,timeout=1800,tool_name="curl")
            if not is_file_empty(leakix_ips_file): print(f"  {G}✔{RST} leakix-ips.txt — {C}{len(rlines(leakix_ips_file))} findings{RST}")
        prog.step("LeakIX IP scan")
        leakix_doms_file,leakix_doms_err=ldir/'leakix-domains.txt',ldir/'leakix-domains-errors.log'
        if key and "curl" in av and "jq" in av and alivef.exists():
            script=f'cat "{alivef}" | sed "s|https\\?://||; s|/.*||" | grep -E r\'^[a-zA-Z0-9.-]+\\.[a-zA-Z]{{2,}}$\' | sort -u | while IFS= read -r dom; do [[ -z "$dom" || "$dom" =~ ^# ]] && continue; response=$(curl -s --max-time 15 --retry 1 --user-agent "Mozilla/5.0" "https://leakix.net/domain/$dom" -H "api-key: {key}" -H "Accept: application/json" 2>/dev/null); if echo "$response" | jq -e \'.error\' >/dev/null 2>&1; then error_msg=$(echo "$response" | jq -r \'.error // "Unknown error"\'); echo "[$(date +%H:%M:%S)] ⚠️ $dom: $error_msg" >&2; [[ "$error_msg" =~ [Rr]ate.*limit|[Ll]imit|429 ]] && sleep 15 || sleep 3; continue; else echo "$response" | jq -r --arg dom "$dom" r\'.Services[]? | select((.leak.type != null and .leak.type != "") or (.port | IN(21,22,23,25,53,80,110,139,143,389,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017))) | "\\($dom) | Port: \\(.port) | Proto: \\(.protocol) | Software: \\(.software.name // "N/A") | Version: \\(.software.version // "N/A") | Leak: \\(.leak.type // "None") | Details: \\(.leak.details // "N/A")"\' 2>/dev/null; fi; sleep 1; done | sort -u > {leakix_doms_file} 2> {leakix_doms_err}'
            run_cmd(script,timeout=2400,tool_name="curl")
            if not is_file_empty(leakix_doms_file): print(f"  {G}✔{RST} leakix-domains.txt — {C}{len(rlines(leakix_doms_file))} findings{RST}")
        prog.step("LeakIX domain scan")
        if not key: print(f"  {Y}[!] LEAKIX_API not set — phase skipped{RST}")
        prog.done_phase()
        if args_verbose_output:
            if leakix_ips_file.exists() and not is_file_empty(leakix_ips_file): show_file_content(leakix_ips_file,"leakix-ips.txt - IP Exposure Findings",max_lines=30)
            if leakix_doms_file.exists() and not is_file_empty(leakix_doms_file): show_file_content(leakix_doms_file,"leakix-domains.txt - Domain Exposure Findings",max_lines=30)
        return {"leakix_ips":str(leakix_ips_file),"leakix_domains":str(leakix_doms_file)}
    except KeyboardInterrupt: print(f"{Y}[!] Phase 10 skipped by user{RST}"); return {"leakix_ips":"","leakix_domains":""}

def write_txt(path,result):
    lines=["CLICKER — BLACK-BOX RECON & ASSESSMENT REPORT","="*72,f"Generated : {result['generated_at']}",""]
    for t in result["targets"]: 
        lines+=[f"Target : {t['domain']}","-"*40,
                f" Passive subdomains : {len(t['passive']['all_subdomains'])}",
                f" Active subdomains  : {len(t.get('active',{}).get('active_subs',[]))}",
                f" High-value subs : {len(t['passive']['sensitive_subs'])}",
                f" Alive hosts (200/302): {len(t['response']['alive'])}",
                f" 403 hosts : {len(t['response']['f403'])}",
                f" 404 hosts : {len(t['response']['f404'])}",""]
    path.write_text("\n".join(lines),encoding="utf-8")

def write_html(path,result):
    blocks=[]
    for t in result["targets"]:
        active_count=len(t.get('active',{}).get('active_subs',[]))
        blocks.append(f"""<section><h2>🎯 {html.escape(t['domain'])}</h2><table>
<tr><td>Passive subdomains</td><td>{len(t['passive']['all_subdomains'])}</td></tr>
<tr><td>Active subdomains</td><td>{active_count}</td></tr>
<tr><td>High-value subs</td><td>{len(t['passive']['sensitive_subs'])}</td></tr>
<tr><td>Alive (200/302)</td><td>{len(t['response']['alive'])}</td></tr>
<tr><td>403 hosts</td><td>{len(t['response']['f403'])}</td></tr>
<tr><td>404 hosts</td><td>{len(t['response']['f404'])}</td></tr></table>
<details><summary>Passive tool logs</summary><pre>{html.escape(json.dumps(t['passive']['tool_logs'],indent=2))}</pre></details>
<details><summary>High-value subdomains</summary><pre>{html.escape(chr(10).join(t['passive']['sensitive_subs']))}</pre></details></section>""")
    doc=f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Clicker Report</title>
<style> body{{font-family:monospace;background:#060d1f;color:#d0d8f0;padding:24px;margin:0}} 
h1{{color:#7dd3fc}} h2{{color:#38bdf8;border-bottom:1px solid #1e3a5f;padding-bottom:6px}} 
table{{border-collapse:collapse;width:100%;margin:10px 0}} td{{border:1px solid #1e3a5f;padding:6px 12px}} 
tr:first-child td{{background:#0f1e3d}} pre{{background:#0a1128;padding:12px;border-radius:6px;overflow:auto;white-space:pre-wrap}} 
details{{margin:8px 0}} summary{{cursor:pointer;color:#7dd3fc}} </style></head><body> 
<h1>⚡ Clicker Report</h1> <p>Generated: {html.escape(result['generated_at'])} | Follow: {INSTAGRAM}</p> 
{''.join(blocks)} </body></html>"""
    path.write_text(doc,encoding="utf-8")

def write_pdf(path,result):
    try: 
        from reportlab.lib.pagesizes import A4
        from reportlab.pdfgen import canvas as pdfcanvas
    except ImportError: 
        print(f"{Y}[!] reportlab not installed — skipping PDF (pip install reportlab){RST}")
        return False
    c=pdfcanvas.Canvas(str(path),pagesize=A4)
    W_p,H=A4
    y=H-40
    c.setFont("Helvetica-Bold",15)
    c.drawString(40,y,"Clicker — Black-box Assessment Report")
    y-=20
    c.setFont("Helvetica",9)
    c.drawString(40,y,f"Generated: {result['generated_at']} | {INSTAGRAM}")
    y-=22
    for t in result["targets"]:
        if y<140: 
            c.showPage()
            y=H-40
        c.setFont("Helvetica-Bold",12)
        c.drawString(40,y,f"Target: {t['domain']}")
        y-=16
        c.setFont("Helvetica",10)
        active_count=len(t.get('active',{}).get('active_subs',[]))
        rows=[f"Passive subdomains : {len(t['passive']['all_subdomains'])}",
              f"Active subdomains  : {active_count}",
              f"High-value subs : {len(t['passive']['sensitive_subs'])}",
              f"Alive (200/302) : {len(t['response']['alive'])}",
              f"403 hosts : {len(t['response']['f403'])}",
              f"404 hosts : {len(t['response']['f404'])}"]
        for row in rows: 
            c.drawString(52,y,row)
            y-=14
        y-=8
    c.save()
    return True

def main():
    global api_keys_global,args_show_results,args_verbose_output,args_skip_active_subs,args_resume
    global args_wordlist,args_resolvers,RESUME_FILE,GLOBAL_USE_PROXYCHAINS,GLOBAL_HYBRID_PROXY,SKIP_CURRENT_PHASE, GLOBAL_WAF_TYPE
    
    signal.signal(signal.SIGINT, signal_handler)
    
    if sys.platform!="linux": 
        print(f"{Y}[!] Clicker is designed for Linux.{RST}")
    
    parser=argparse.ArgumentParser(description=f"Clicker {VERSION} — Black-box Recon Pipeline | {INSTAGRAM}")
    parser.add_argument("-t","--target",help="Single target domain")
    parser.add_argument("--targets-file",help="File with one domain per line")
    parser.add_argument("--workspace",default="clicker_output")
    parser.add_argument("--api-file",default="clicker_api.env")
    parser.add_argument("--report-format",choices=["txt","html","both"],default="both")
    parser.add_argument("--pdf",action="store_true")
    parser.add_argument("--skip-screenshots",action="store_true")
    parser.add_argument("--skip-js",action="store_true")
    parser.add_argument("--skip-active-subs",action="store_true",help="Skip active subdomain enumeration")
    parser.add_argument("--resume",action="store_true",help="Resume scan from last checkpoint")
    parser.add_argument("--proxy", help="Single proxy (user:pass@IP:PORT or IP:PORT)")
    parser.add_argument("--proxy-list", help="Path to proxy list file")
    parser.add_argument("--auto-proxy", action="store_true", help="Fetch fresh proxies from public APIs automatically")
    parser.add_argument("--rotate-proxy", action="store_true", help="Rotate proxies per target")
    parser.add_argument("--proxychains", action="store_true", help="Route all tools via proxychains (requires proxychains4)")
    parser.add_argument("--hybrid-proxy", action="store_true", help="Smart mode: use proxy only for HTTP tools, bypass for TCP/UDP tools + auto fallback")
    parser.add_argument("--wordlist",default="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt",help="Wordlist for active subdomain brute-force")
    parser.add_argument("--resolvers",default="/usr/share/seclists/Discovery/DNS/resolvers.txt",help="Resolvers file for DNS queries")
    parser.add_argument("--keep-sources",action="store_true",help="Keep source files after merge (debug mode)")
    parser.add_argument("--show-phase-results",action="store_true",help="Show detailed results summary after each phase")
    parser.add_argument("--verbose","-v",action="store_true",help="Show FULL output content in terminal after each phase")
    
    args=parser.parse_args()
    print(ASCII_LOGO)
    
    GLOBAL_USE_PROXYCHAINS = args.proxychains
    GLOBAL_HYBRID_PROXY = args.hybrid_proxy
    
    pm = ProxyManager(proxy=args.proxy, proxy_file=args.proxy_list, auto_fetch=args.auto_proxy, rotate=args.rotate_proxy)
    
    if GLOBAL_HYBRID_PROXY and pm.proxies:
        test_proxy = pm.get_current()
        if test_proxy and not check_proxy_health(test_proxy, timeout=8): 
            print(f"{Y}[!] Initial proxy health check failed — will auto-bypass when needed{RST}")
            GLOBAL_PROXY_HEALTH_OK = False
        else: 
            GLOBAL_PROXY_HEALTH_OK = True
    
    pm.apply()
    
    args_show_results=args.show_phase_results
    args_verbose_output=args.verbose
    args_skip_active_subs=args.skip_active_subs
    args_resume=args.resume
    args_wordlist=args.wordlist
    args_resolvers=args.resolvers
    
    api_keys_global=collect_api_keys(Path(args.api_file))
    
    targets = parse_targets(args.target, args.targets_file)
    if not targets:
        sys.exit(f"{R}[!] No targets to scan{RST}")
    
    workspace=Path(args.workspace)
    mkd(workspace)
    RESUME_FILE = workspace / ".clicker_resume.json"
    
    required_tools=["subfinder","sublist3r","chaos","assetfinder","github-subdomains","findomain",
                   "waybackurls","gau","httpx","httpx-toolkit","naabu","dnsx","cdncheck","nmap",
                   "aquatone","gowitness","katana","waymore","mantra","subzy","subjack","wafw00f",
                   "puredns","altdns","shuffledns","dnsrecon","ffuf","curl","jq","grep","sed","awk","sort","cat"]
    
    available = check_tools(required_tools)
    
    result={"generated_at":datetime.datetime.now(datetime.timezone.utc).isoformat().replace('+00:00','Z'),"targets":[]}
    total_phases=10
    
    print(f"\n{BOLD}{M}[►] Starting scan on {len(targets)} target(s) — {total_phases} phases each{RST}\n")
    
    resume_state = load_checkpoint() if args_resume else {}
    
    for domain in targets:
        pm.apply(domain=domain)
        print(f"\n{BOLD}{W}{'━'*60}{RST}\n{BOLD}{M}  Target : {domain}{RST}\n{BOLD}{W}{'━'*60}{RST}")
        
        passive=active=response=tech=ports=takeover=waf=urls=js=leakix={}
        skip_until = ""
        
        if args_resume and resume_state.get("domain") == domain and resume_state.get("completed"):
            skip_until = resume_state.get("last_phase", "")
            if skip_until: 
                print(f"{G}[+] Resuming scan from phase: {skip_until}{RST}")
            else: 
                print(f"{Y}[!] No valid checkpoint found, starting from beginning.{RST}")
        
        GLOBAL_WAF_TYPE = "default"
        
        # ✅ Updated phase order: WAF is now Phase 2 (after passive)
        phases = [
            ("passive", lambda: phase_passive(domain,workspace,api_keys_global,available)),
            ("waf", lambda: phase_waf(domain,workspace,available)),
            ("response", lambda: phase_response_filter(domain,workspace,passive,available,active)),
            ("tech", lambda: phase_tech_detect(domain,workspace,available,GLOBAL_WAF_TYPE)),
            ("ports", lambda: phase_ports(domain,workspace,available,GLOBAL_WAF_TYPE)),
            ("takeover", lambda: phase_takeover(domain,workspace,available)),
            ("screenshots", lambda: phase_screenshots(domain,workspace,available) if not args.skip_screenshots else None),
            ("content", lambda: phase_content_discovery(domain,workspace,available)),
            ("js", lambda: phase_js_recon(domain,workspace,available) if not args.skip_js else None),
            ("leakix", lambda: phase_leakix(domain,workspace,available)),
        ]
        
        for phase_name, phase_func in phases:
            if not skip_until or skip_until == phase_name:
                skip_until = ""
                if not args_resume or skip_until != phase_name:
                    try:
                        res = phase_func()
                        if res is not None:
                            if phase_name == "passive": passive = res
                            elif phase_name == "waf": 
                                waf = res
                                GLOBAL_WAF_TYPE = res.get("waf_type", "default")
                            elif phase_name == "response": response = res
                            elif phase_name == "tech": tech = res
                            elif phase_name == "ports": ports = res
                            elif phase_name == "takeover": takeover = res
                            elif phase_name == "content": urls = res
                            elif phase_name == "js": js = res
                            elif phase_name == "leakix": leakix = res
                        save_checkpoint(phase_name)
                    except KeyboardInterrupt:
                        print(f"{Y}[!] Phase {phase_name} interrupted by user{RST}")
                        continue
            else:
                print(f"{Y}[!] Skipping phase_{phase_name} (completed){RST}")
        
        result["targets"].append({
            "domain":domain,"passive":passive,"active":active,"response":response,
            "tech":tech,"ports":ports,"takeover":takeover,"waf":waf,
            "urls":urls,"js":js,"leakix":leakix
        })
        
        if RESUME_FILE.exists(): 
            RESUME_FILE.unlink(missing_ok=True)
        
        if not args.keep_sources:
            print(f"\n{DIM}🧹 Final cleanup for {domain}...{RST}")
            target_dir=workspace/domain
            for root,dirs,files in os.walk(target_dir,topdown=False):
                for d in dirs:
                    dp=Path(root)/d
                    try:
                        if not any(dp.iterdir()): 
                            dp.rmdir()
                            print(f"  {Y}[!]{RST} Removed empty directory: {dp.relative_to(workspace)}{RST}")
                    except: pass
            total_size=sum(f.stat().st_size for f in target_dir.rglob('*') if f.is_file())
            print(f"  {G}✔{RST} Target workspace: {C}{total_size/1024:.1f} KB{RST} in {DIM}{target_dir.relative_to(workspace)}{RST}")
    
    print(f"\n{BOLD}{B}{'═'*60}{RST}\n{BOLD}{C}  Writing Reports{RST}\n{BOLD}{B}{'═'*60}{RST}")
    
    json_path=workspace/"report.json"
    json_path.write_text(json.dumps(result,indent=2),encoding="utf-8")
    print(f"  {G}✔{RST} JSON  → {json_path}")
    
    if args.report_format in {"txt","both"}: 
        tp=workspace/"report.txt"
        write_txt(tp,result)
        print(f"  {G}✔{RST} TXT   → {tp}")
    
    if args.report_format in {"html","both"}: 
        hp=workspace/"report.html"
        write_html(hp,result)
        print(f"  {G}✔{RST} HTML  → {hp}")
    
    if args.pdf: 
        pp=workspace/"report.pdf"
        if write_pdf(pp,result): 
            print(f"  {G}✔{RST} PDF   → {pp}")
    
    print(f"\n{BOLD}{G}[✔] Clicker {VERSION} completed. Output → {workspace}/{RST}\n{DIM}Follow updates: {Y}{INSTAGRAM}{RST}\n")

if __name__=="__main__": 
    main()
