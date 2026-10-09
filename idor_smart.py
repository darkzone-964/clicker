"""
idor_smart.py — Smart JS/API discovery for Clicker.

Automatically discovers:
  - JS files (downloads them locally)
  - API endpoints from JS content (jsluice + regex + xnLinkFinder)
  - Firebase configs (firebaseConfig, cloudfunctions.net)
  - Login endpoints (via JS regex)
  - External API bases (Cloud Functions, Supabase, AWS)
"""
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

R, G, Y, C, DIM, RST, BOLD = "\033[91m", "\033[92m", "\033[93m", "\033[96m", "\033[2m", "\033[0m", "\033[1m"


# ============================================================================
# JS file collection
# ============================================================================
def collect_js_urls(urls):
    """Filter URLs to JS files only."""
    js_urls = []
    seen = set()
    for u in urls:
        u = u.strip()
        if not u or u in seen:
            continue
        u_lower = u.lower()
        # Match .js with optional query
        if re.search(r'\.js(?:\?|#|$)', u_lower) or "javascript" in u_lower:
            seen.add(u)
            js_urls.append(u)
    return js_urls


def download_js_files(js_urls, outdir, cookies=None, headers=None, timeout=15):
    """Download JS files locally using curl (with fallback to subjs)."""
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    downloaded = []
    print(f"  {C}[smart] Downloading {len(js_urls)} JS files...{RST}")

    for i, url in enumerate(js_urls[:100], 1):  # cap at 100
        # Sanitize filename
        safe = re.sub(r'[^a-zA-Z0-9._-]', '_', url.split("//", 1)[-1])[:120]
        if not safe.endswith(".js"):
            safe += ".js"
        outfile = outdir / safe

        if outfile.exists() and outfile.stat().st_size > 0:
            downloaded.append(outfile)
            continue

        cmd = ["curl", "-sS", "-k", "--max-time", str(timeout), "-L"]
        if cookies:
            cmd += ["-b", cookies]
        cmd += ["-H", "User-Agent: Mozilla/5.0 Clicker/2.3"]
        if headers:
            for k, v in headers.items():
                cmd += ["-H", f"{k}: {v}"]
        cmd += ["-o", str(outfile), url]

        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            if outfile.exists() and outfile.stat().st_size > 50:
                downloaded.append(outfile)
            elif outfile.exists():
                outfile.unlink()  # too small = probably error
        except Exception:
            continue

        time.sleep(0.15)  # light rate limit

    print(f"  {G}[smart] Downloaded {len(downloaded)} JS files{RST}")
    return downloaded


# ============================================================================
# Extract endpoints from JS
# ============================================================================
def extract_endpoints_from_js(js_files):
    """Run jsluice, xnLinkFinder, and regex on local JS files."""
    if not js_files:
        return set()

    endpoints = set()
    js_dir = Path(js_files[0]).parent if js_files else None
    if not js_dir:
        return set()

    # 1. jsluice urls
    if shutil.which("jsluice"):
        try:
            r = subprocess.run(
                ["jsluice", "urls", *[str(f) for f in js_files[:30]]],
                capture_output=True, text=True, timeout=120
            )
            for line in r.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    url = data.get("url") or data.get("path") or ""
                    if url:
                        endpoints.add(url)
                except Exception:
                    if line.startswith(("http", "/")):
                        endpoints.add(line)
            print(f"  {DIM}[smart] jsluice urls → {len(endpoints)}{RST}")
        except Exception as e:
            print(f"  {Y}[smart] jsluice failed: {e}{RST}")

    # 2. Regex on JS content (fallback + augmentation)
    url_re = re.compile(
        r'["\'`](https?://[^"\'`\s]+|/[a-zA-Z0-9_\-/]+(?:\?[^"\'`\s]*)?)["\'`]'
    )
    api_re = re.compile(
        r'["\'`](/(?:api|v\d|rest|cloudfunctions|login|auth|user|admin|account|profile)[^"\'`\s]*)["\'`]',
        re.IGNORECASE,
    )
    full_url_re = re.compile(r'https?://[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}[^\s"\'`<>]*')

    for jf in js_files[:50]:
        try:
            content = Path(jf).read_text(errors="ignore")
        except Exception:
            continue

        # All /path style URLs
        for m in url_re.findall(content):
            if m.startswith(("/", "http")):
                endpoints.add(m)

        # API-ish paths
        for m in api_re.findall(content):
            endpoints.add(m)

        # Full external URLs (limited)
        for m in full_url_re.findall(content):
            endpoints.add(m)

    # 3. xnLinkFinder if available
    if shutil.which("xnLinkFinder") and js_dir:
        try:
            combined = js_dir / "_combined_for_xn.txt"
            combined.write_text("\n".join(str(f) for f in js_files[:30]))
            out = js_dir / "xnlinkfinder.txt"
            subprocess.run(
                ["xnLinkFinder", "-i", str(combined), "-o", str(out), "-sf", "any"],
                capture_output=True, text=True, timeout=180
            )
            if out.exists():
                for line in out.read_text(errors="ignore").splitlines():
                    line = line.strip()
                    if line.startswith(("/", "http")):
                        endpoints.add(line)
        except Exception:
            pass

    return endpoints


# ============================================================================
# Firebase + API base detection
# ============================================================================
def detect_firebase_config(js_content):
    """Extract firebaseConfig object from JS."""
    result = {}
    # Match: firebaseConfig = {...} or const firebaseConfig = {...}
    m = re.search(
        r'firebaseConfig\s*[:=]\s*\{([^}]{50,2000})\}',
        js_content, re.DOTALL
    )
    if not m:
        return result
    body = m.group(1)
    for key in ["apiKey", "authDomain", "projectId", "storageBucket",
                "messagingSenderId", "appId", "measurementId", "databaseURL"]:
        km = re.search(rf'{key}\s*:\s*["\']([^"\']+)["\']', body)
        if km:
            result[key] = km.group(1)
    return result


def detect_api_bases(js_content):
    """Detect external API bases (Cloud Functions, Supabase, AWS, etc.)."""
    bases = set()
    patterns = [
        r'https?://[a-z0-9-]+\.cloudfunctions\.net',
        r'https?://[a-z0-9-]+\.firebaseio\.com',
        r'https?://[a-z0-9-]+\.firebaseapp\.com',
        r'https?://[a-z0-9-]+\.supabase\.co',
        r'https?://[a-z0-9-]+\.execute-api\.[a-z0-9-]+\.amazonaws\.com',
        r'https?://api\.[a-z0-9.-]+',
        r'https?://backend\.[a-z0-9.-]+',
        r'https?://auth\.[a-z0-9.-]+',
    ]
    for pat in patterns:
        for m in re.findall(pat, js_content, re.IGNORECASE):
            bases.add(m)
    return bases


def extract_login_endpoints(js_content):
    """Extract login-like endpoints from JS."""
    endpoints = set()
    patterns = [
        r'["\'`]([^"\'`\s]*login[^"\'`\s]*)["\'`]',
        r'["\'`]([^"\'`\s]*signin[^"\'`\s]*)["\'`]',
        r'["\'`]([^"\'`\s]*auth[^"\'`\s]*)["\'`]',
        r'["\'`]([^"\'`\s]*token[^"\'`\s]*)["\'`]',
        r'["\'`]([^"\'`\s]*session[^"\'`\s]*)["\'`]',
    ]
    for pat in patterns:
        for m in re.findall(pat, js_content, re.IGNORECASE):
            m = m.strip()
            if m and len(m) > 3 and len(m) < 200:
                endpoints.add(m)
    return endpoints


# ============================================================================
# MAIN: Smart extraction pipeline
# ============================================================================
def smart_extract(js_urls, workspace, cookies=None, headers=None,
                   domain=None, verbose=False):
    """
    Full smart pipeline:
      1. Download JS files locally
      2. Extract endpoints via jsluice + regex
      3. Detect Firebase configs
      4. Detect external API bases
      5. Extract login endpoints

    Returns dict with all discoveries.
    """
    result = {
        "js_files": [],
        "endpoints": set(),
        "firebase_configs": [],
        "api_bases": set(),
        "login_endpoints": set(),
    }

    if not js_urls:
        return result

    # 1. Download
    js_dir = Path(workspace) / "idor" / "_js_cache"
    js_files = download_js_files(js_urls, js_dir, cookies=cookies, headers=headers)
    result["js_files"] = [str(f) for f in js_files]

    if not js_files:
        return result

    # 2. Endpoints
    result["endpoints"] = extract_endpoints_from_js(js_files)

    # 3. Firebase + login per file
    for jf in js_files:
        try:
            content = Path(jf).read_text(errors="ignore")
        except Exception:
            continue

        fbc = detect_firebase_config(content)
        if fbc:
            result["firebase_configs"].append({"file": str(jf), "config": fbc})

        bases = detect_api_bases(content)
        result["api_bases"].update(bases)

        logins = extract_login_endpoints(content)
        result["login_endpoints"].update(logins)

    return result


# ============================================================================
# Smart login JSON builder
# ============================================================================
def build_login_payloads(email, password, extra_fields=None):
    """
    Generate list of possible login payloads (multiple JSON shapes).
    Tries:
      - flat: {email, password}
      - data-wrapped: {data: {email, password}}
      - result-wrapped: {result: {email, password}}
      - payload-wrapped: {payload: {email, password}}
      - With extra fields (deviceId, etc.)
    """
    base = {"email": email, "password": password}
    extra = extra_fields or {}
    base.update(extra)

    payloads = [base]
    for wrap in ("data", "result", "payload", "body", "auth", "credentials"):
        payloads.append({wrap: dict(base)})
    return payloads
