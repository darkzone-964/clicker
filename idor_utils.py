"""
idor_utils.py — Shared utilities for IDOR module.

Provides:
  - curl_request()      : unified HTTP client (headers, cookies, retries)
  - fetch()             : simple GET
  - fetch_json()        : GET + JSON parse
  - is_url_in_scope()   : scope validation
  - save_lines()        : write result files (sorted, unique)
  - load_lines()        : read files safely
  - log_audit()         : persistent audit trail
"""
import json
import os
import re
import subprocess
import time
import urllib.parse
import urllib.request
from pathlib import Path

# ── Colors (consistent with clicker) ──
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
B = "\033[94m"; M = "\033[95m"; C = "\033[96m"; W = "\033[97m"
DIM = "\033[2m"; BOLD = "\033[1m"; RST = "\033[0m"

# ── Global extra headers (set by clicker.py) ──
GLOBAL_EXTRA_HEADERS = []


# ═══════════════════════════════════════════════════════════
# HTTP CLIENT
# ═══════════════════════════════════════════════════════════
def _build_headers(extra=None, content_type=None):
    """Build header dict with global + local overrides."""
    h = {"User-Agent": "Mozilla/5.0 Clicker-IDOR/1.0"}
    for gh in GLOBAL_EXTRA_HEADERS:
        if ":" in gh:
            k, _, v = gh.partition(":")
            h[k.strip()] = v.strip()
    if extra:
        h.update(extra)
    if content_type:
        h["Content-Type"] = content_type
    return h


def curl_request(url, method="GET", cookies=None, headers=None, data=None,
                 content_type=None, timeout=15, follow=True, allow_redirects=None):
    """
    Execute a curl request. Returns dict:
      {status, body, headers, error}
    """
    cmd = ["curl", "-sS", "-k", "--max-time", str(timeout)]

    _curl_home = os.environ.get("CURL_HOME")
    if _curl_home:
        _curlrc = Path(_curl_home) / ".curlrc"
        if _curlrc.exists():
            cmd += ["--config", str(_curlrc)]

    if follow or allow_redirects:
        cmd += ["-L", "--max-redirs", "5"]

    if method.upper() != "GET":
        cmd += ["-X", method.upper()]

    if cookies:
        cmd += ["-b", str(cookies)]

    for k, v in _build_headers(headers, content_type).items():
        cmd += ["-H", f"{k}: {v}"]

    if data:
        if isinstance(data, dict):
            if content_type == "application/json":
                data = json.dumps(data)
            else:
                data = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in data.items())
        cmd += ["--data-raw", data]

    cmd += ["-w", "\n___HTTP_STATUS___%{http_code}"]
    cmd += ["-D", "-"]
    cmd.append(url)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, errors="replace",
            timeout=timeout + 5
        )
    except subprocess.TimeoutExpired:
        return {"status": 0, "body": "", "headers": {}, "error": "timeout"}
    except Exception as e:
        return {"status": 0, "body": "", "headers": {}, "error": str(e)}

    output = result.stdout
    status = 0
    if "___HTTP_STATUS___" in output:
        body_part, _, status_str = output.rpartition("___HTTP_STATUS___")
        try:
            status = int(status_str.strip())
        except ValueError:
            status = 0
    else:
        body_part = output

    # Parse headers
    headers_dict = {}
    lines = body_part.split("\n")
    body_start = 0
    for i, line in enumerate(lines):
        if line.startswith("HTTP/"):
            headers_dict = {}
            continue
        if ":" in line and not line.startswith((" ", "\t")):
            k, _, v = line.partition(":")
            headers_dict[k.strip().lower()] = v.strip()
        elif line.strip() == "" and headers_dict:
            body_start = i + 1
            break

    body = "\n".join(lines[body_start:])

    return {
        "status": status,
        "body": body,
        "headers": headers_dict,
        "error": result.stderr.strip() if result.returncode else "",
    }


def fetch(url, timeout=8, headers=None, cookies=None):
    """Simple GET using urllib. Returns dict {status, body, headers, error}."""
    h = _build_headers(headers)
    if cookies:
        h["Cookie"] = str(cookies)
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout) as res:
            body = res.read().decode("utf-8", errors="replace")
            return {"status": res.status, "body": body, "headers": dict(res.headers), "error": None}
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return {"status": e.code, "body": body, "headers": dict(e.headers or {}), "error": None}
    except Exception as e:
        return {"status": 0, "body": "", "headers": {}, "error": str(e)}


def fetch_json(url, timeout=8, headers=None):
    """Fetch + parse JSON. Returns (data, status, error)."""
    r = fetch(url, timeout=timeout, headers=headers)
    if r["status"] != 200 or not r["body"]:
        return None, r["status"], r["error"]
    try:
        return json.loads(r["body"]), r["status"], None
    except Exception as e:
        return None, r["status"], f"json-error: {e}"


# ═══════════════════════════════════════════════════════════
# SCOPE
# ═══════════════════════════════════════════════════════════
def is_url_in_scope(url, scope):
    """Check URL hostname against scope rules."""
    if not scope:
        return True
    try:
        host = urllib.parse.urlparse(url).hostname or ""
    except Exception:
        return True
    def matches(patterns):
        for pat in patterns:
            if pat.startswith("*."):
                if host == pat[2:] or host.endswith("." + pat[2:]):
                    return True
            elif host == pat:
                return True
        return False
    if scope.get("exclude") and matches(scope["exclude"]):
        return False
    if not scope.get("include"):
        return True
    return matches(scope["include"])


# ═══════════════════════════════════════════════════════════
# FILE I/O
# ═══════════════════════════════════════════════════════════
def load_lines(path, strip=True):
    """Read file lines safely."""
    p = Path(path)
    if not p.exists() or not p.is_file():
        return []
    try:
        content = p.read_text(encoding="utf-8", errors="ignore")
        return [l.strip() if strip else l.rstrip("\n") for l in content.splitlines() if l.strip()]
    except Exception:
        return []


def save_lines(path, lines, unique=True, sort=True):
    """Write lines to file (optionally unique + sorted)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if unique:
        lines = list(set(lines))
    if sort:
        lines = sorted(lines)
    try:
        p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    except Exception:
        pass


def save_json(path, data):
    """Write JSON to file."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        p.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


def load_json(path, default=None):
    """Read JSON file."""
    p = Path(path)
    if not p.exists():
        return default
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default


# ═══════════════════════════════════════════════════════════
# AUDIT LOG
# ═══════════════════════════════════════════════════════════
def log_audit(idir, method, url, who, status, size, note=""):
    """Append one line to today's audit log."""
    try:
        import datetime
        log_file = Path(idir) / f"audit_{datetime.date.today().isoformat()}.log"
        ts = datetime.datetime.now().isoformat(timespec="seconds")
        line = f"[{ts}] {method:6} {url} | who={who} | status={status} | size={size}b"
        if note:
            line += f" | {note}"
        with log_file.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════
# TOOL WRAPPERS
# ═══════════════════════════════════════════════════════════
def run_tool(cmd, timeout=300):
    """Run a shell command, return (exit_code, stdout, stderr)."""
    try:
        p = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            errors="replace", timeout=timeout
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except Exception as e:
        return 1, "", str(e)


def tool_available(name):
    """Check if a tool binary exists."""
    import shutil
    return shutil.which(name) is not None


if __name__ == "__main__":
    # Quick tests
    print("=== Testing idor_utils ===")
    print()
    print("1. save_lines/load_lines")
    test_path = "/tmp/idor_test.txt"
    save_lines(test_path, ["b", "a", "a", "c"])
    print(f"   Loaded: {load_lines(test_path)}")
    print()
    print("2. is_url_in_scope")
    scope = {"include": ["example.com", "*.test.com"], "exclude": ["admin.test.com"]}
    for u in ["https://example.com/x", "https://sub.test.com/y", "https://admin.test.com/z", "https://other.com/q"]:
        print(f"   {u:40} -> {is_url_in_scope(u, scope)}")
    print()
    print("3. fetch (example.com)")
    r = fetch("http://localhost:3000/", timeout=3)
    print(f"   Status: {r['status']}, body length: {len(r['body'])}")
    print()
    print("4. tool_available")
    for t in ["curl", "httpx", "nuclei", "gf", "arjun"]:
        print(f"   {t:10} -> {tool_available(t)}")
