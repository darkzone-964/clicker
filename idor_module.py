"""
IDOR Testing Module for Clicker v2.3
Auto-login, session extraction, active IDOR testing.
Save as: ~/idor_module.py
"""
import base64
import json
import re
import subprocess
import time
import urllib.parse
from pathlib import Path

# Colors (override from clicker if imported)
R, G, Y, B, M, C, W = "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[95m", "\033[96m", "\033[97m"
DIM, RST, BOLD = "\033[2m", "\033[0m", "\033[1m"

# ============================================================================
# CONSTANTS
# ============================================================================
LOGIN_PATHS = [
    "/login", "/signin", "/api/login", "/api/auth/login",
    "/api/v1/login", "/api/v1/auth/login", "/auth/login",
    "/auth/signin", "/users/login", "/account/login",
    "/api/session", "/api/token", "/api/users/sign_in",
    "/identity/api/auth/login", "/identity/api/auth/signup",
]

EMAIL_FIELDS = ["email", "username", "user", "login", "user_email", "userEmail"]
PASS_FIELDS = ["password", "pass", "passwd", "pwd", "user_password", "userPassword"]

ME_PATHS = [
    "/api/me", "/api/v1/me", "/api/user", "/api/v1/user",
    "/api/users/me", "/api/profile", "/api/v1/profile",
    "/api/account", "/api/v1/account", "/api/auth/me",
    "/identity/api/v2/user/dashboard", "/identity/api/v2/user/me",
]

API_DOC_PATHS = [
    "/swagger.json", "/openapi.json", "/api-docs",
    "/v2/api-docs", "/v3/api-docs", "/swagger-ui.html",
    "/docs", "/redoc", "/swagger/index.html",
]

GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/gql", "/query",
]

# ============================================================================
# LOGIN/SESSION HELPERS
# ============================================================================
def curl_request(url, method="GET", cookies=None, headers=None, data=None,
                 content_type=None, timeout=15, follow=True):
    """Execute a curl request and return structured result."""
    cmd = ["curl", "-sS", "-k", "--max-time", str(timeout)]

    if follow:
        cmd += ["-L", "--max-redirs", "5"]

    if method.upper() != "GET":
        cmd += ["-X", method.upper()]

    if cookies:
        cmd += ["-b", str(cookies)]

    all_headers = {"User-Agent": "Mozilla/5.0 Clicker/2.3"}
    if headers:
        all_headers.update(headers)
    if content_type:
        all_headers["Content-Type"] = content_type
    for k, v in all_headers.items():
        cmd += ["-H", f"{k}: {v}"]

    if data:
        if isinstance(data, dict):
            if content_type == "application/json":
                data = json.dumps(data)
            else:
                data = "&".join(
                    f"{k}={urllib.parse.quote(str(v))}" for k, v in data.items()
                )
        cmd += ["--data-raw", data]

    cmd += ["-w", "\n___HTTP_STATUS___%{http_code}"]
    cmd += ["-D", "-"]
    cmd.append(url)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 5
        )
    except subprocess.TimeoutExpired:
        return {"status": 0, "body": "", "headers": {}, "error": "timeout"}
    except Exception as e:
        return {"status": 0, "body": "", "headers": {}, "error": str(e)}

    output = result.stdout
    stderr = result.stderr

    status = 0
    if "___HTTP_STATUS___" in output:
        body_part, _, status_str = output.rpartition("___HTTP_STATUS___")
        try:
            status = int(status_str.strip())
        except ValueError:
            status = 0
    else:
        body_part = output

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
        "error": stderr.strip() if result.returncode else "",
    }


def detect_csrf_token(html_body):
    """Extract CSRF token from HTML."""
    patterns = [
        r'<meta\s+name=["\']csrf-token["\']\s+content=["\']([^"\']+)["\']',
        r'<meta\s+name=["\']_csrf["\']\s+content=["\']([^"\']+)["\']',
        r'<input[^>]+name=["\']csrf[_-]?token["\'][^>]+value=["\']([^"\']+)["\']',
        r'<input[^>]+name=["\']_csrf["\'][^>]+value=["\']([^"\']+)["\']',
        r'<input[^>]+name=["\']csrfmiddlewaretoken["\'][^>]+value=["\']([^"\']+)["\']',
    ]
    for pat in patterns:
        m = re.search(pat, html_body, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def try_login(domain, email, password):
    """
    Try to login using common patterns. Returns session dict.
    """
    base = f"https://{domain}"
    http_base = f"http://{domain}"

    # Try to fetch CSRF token
    csrf = None
    for path in ["/login", "/signin", "/"]:
        try:
            page = curl_request(base + path, timeout=8)
            if page["status"] == 200:
                csrf = detect_csrf_token(page["body"])
                if csrf:
                    break
        except Exception:
            continue

    # Try HTTPS first, then HTTP
    for base_url in (base, http_base):
        for login_path in LOGIN_PATHS:
            for email_field in EMAIL_FIELDS:
                for pass_field in PASS_FIELDS:
                    for is_json in (True, False):
                        payload = {email_field: email, pass_field: password}
                        if csrf and not is_json:
                            payload["_csrf"] = csrf
                            payload["csrf_token"] = csrf

                        ct = ("application/json" if is_json
                              else "application/x-www-form-urlencoded")

                        try:
                            resp = curl_request(
                                base_url + login_path,
                                method="POST",
                                data=payload,
                                content_type=ct,
                                timeout=12,
                                follow=True,
                            )
                        except Exception:
                            continue

                        if resp["status"] in (200, 201, 202, 302):
                            set_cookie = resp["headers"].get("set-cookie", "")
                            body = resp["body"]
                            token_headers = {}

                            if body.strip().startswith("{"):
                                try:
                                    data = json.loads(body)
                                    for key in ("token", "access_token",
                                                "accessToken", "jwt", "id_token"):
                                        if key in data:
                                            token_headers["Authorization"] = (
                                                f"Bearer {data[key]}"
                                            )
                                            break
                                        if "data" in data and isinstance(data["data"], dict):
                                            for k2 in ("token", "access_token",
                                                       "accessToken", "jwt"):
                                                if k2 in data["data"]:
                                                    token_headers["Authorization"] = (
                                                        f"Bearer {data['data'][k2]}"
                                                    )
                                                    break
                                            if token_headers:
                                                break
                                except (json.JSONDecodeError, ValueError):
                                    pass

                            if set_cookie or token_headers:
                                return {
                                    "success": True,
                                    "base_url": base_url,
                                    "login_url": base_url + login_path,
                                    "cookies": set_cookie,
                                    "token_headers": token_headers,
                                    "email": email,
                                }

    return {"success": False}


def validate_session(domain, session_info):
    """Validate session by hitting /me endpoints."""
    base = session_info.get("base_url") or f"https://{domain}"
    cookie_str = session_info.get("cookies", "")
    token_headers = session_info.get("token_headers", {})

    for me_path in ME_PATHS:
        try:
            resp = curl_request(
                base + me_path,
                cookies=cookie_str if cookie_str else None,
                headers=token_headers,
                timeout=8,
            )
            if resp["status"] == 200 and len(resp["body"]) > 10:
                user_id = None
                try:
                    data = json.loads(resp["body"])
                    for key in ("id", "user_id", "userId", "uid"):
                        if key in data:
                            user_id = data[key]
                            break
                        if "data" in data and isinstance(data["data"], dict):
                            for k2 in ("id", "user_id", "userId", "uid"):
                                if k2 in data["data"]:
                                    user_id = data["data"][k2]
                                    break
                            if user_id:
                                break
                except (json.JSONDecodeError, AttributeError):
                    pass

                return {
                    "valid": True,
                    "endpoint": me_path,
                    "user_id": user_id,
                }
        except Exception:
            continue

    return {"valid": False}


def collect_credentials(label):
    """Prompt user for credentials."""
    print(f"\n{BOLD}{C}[*] Account {label} credentials{RST}")
    try:
        email = input("  Email: ").strip()
        if not email:
            return None
        password = input("  Password: ").strip()
        if not password:
            return None
        return {"email": email, "password": password}
    except (EOFError, KeyboardInterrupt):
        return None


def manual_cookie_fallback(label):
    """Ask user to paste cookies if auto-login fails."""
    print(f"\n{Y}[!] Auto-login for account {label} failed.{RST}")
    print(f"{DIM}Paste the Cookie header manually, or press Enter to skip.{RST}")
    try:
        cookie = input(f"  Cookie for {label}: ").strip()
        return cookie if cookie else None
    except (EOFError, KeyboardInterrupt):
        return None
# ============================================================================
# DISCOVERY — Extract IDOR candidates
# ============================================================================
IDOR_PATTERNS = [
    r'/api/',
    r'/v\d+/',
    r'/graphql',
    r'/[a-z][a-z_-]+/\d{2,}',
    r'/[a-z][a-z_-]+/[0-9a-f]{8}-[0-9a-f]{4}-',
    r'\?(?:id|user_id|userId|order_id|orderId|invoice_id|account_id|address_id)=',
]

PRIVATE_URL_HINTS = re.compile(
    r'/(user|account|profile|order|invoice|payment|admin|dashboard|'
    r'ticket|report|setting|member|team|project|file|document|'
    r'attachment|download|export|billing|subscription|notification)',
    re.IGNORECASE,
)
PUBLIC_URL_HINTS = re.compile(
    r'/(public|blog|docs|help|about|contact|terms|privacy|sitemap|'
    r'robots|static|assets|images|css|js|news|faq|shop|products)',
    re.IGNORECASE,
)
SENSITIVE_FIELD_HINTS = re.compile(
    r'"(email|phone|address|ssn|dob|password|token|secret|'
    r'api[_-]?key|credit[_-]?card|salary|balance|is[_-]?admin|'
    r'number|vehicleid|vin)"\s*:',
    re.IGNORECASE,
)
GENERIC_RESPONSES = re.compile(
    r'^\s*(<!doctype|<html|not found|unauthorized|forbidden|'
    r'\{"error"|\{"message"\s*:\s*"not|\{"detail"\s*:\s*"not)',
    re.IGNORECASE,
)


def extract_candidates(urls):
    """Extract IDOR-suspicious URLs from a list."""
    candidates = set()
    for url in urls:
        url = url.strip()
        if not url or url.startswith("#"):
            continue
        for pat in IDOR_PATTERNS:
            if re.search(pat, url, re.IGNORECASE):
                candidates.add(url)
                break
    return sorted(candidates)


def extract_uuids(urls):
    """Extract UUIDs from URLs."""
    pattern = re.compile(
        r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',
        re.IGNORECASE,
    )
    uuids = set()
    for url in urls:
        uuids.update(pattern.findall(url))
    return sorted(uuids)


def extract_params(urls):
    """Extract parameter names from URLs."""
    params = set()
    for url in urls:
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.query:
                for k in urllib.parse.parse_qs(parsed.query).keys():
                    params.add(k)
        except Exception:
            continue
    return sorted(params)


def discover_from_js(urls, js_files, timeout=10):
    """Level 2: extract endpoints from JS files."""
    extracted = set()
    if not js_files:
        return []

    url_pattern = re.compile(r'["\'](/[a-zA-Z0-9_\-/]+(?:\?[^"\']*)?)["\']')
    full_url_pattern = re.compile(r'https?://[^\s"\']+')

    checked = 0
    for js_url in js_files[:20]:
        js_url = js_url.strip()
        if not js_url.startswith("http"):
            continue
        try:
            resp = curl_request(js_url, timeout=timeout)
            if resp["status"] != 200:
                continue
            checked += 1
            body = resp["body"]
            for m in url_pattern.findall(body):
                if re.search(r'/api/|/v\d+/', m):
                    extracted.add(m)
            for m in full_url_pattern.findall(body):
                for u in urls:
                    try:
                        base = urllib.parse.urlparse(u).netloc
                        if base and base in m:
                            extracted.add(m)
                            break
                    except Exception:
                        continue
        except Exception:
            continue

    return sorted(extracted)


def discover_api_docs(domain):
    """Level 3: check for Swagger/OpenAPI docs."""
    discovered = []
    endpoints = []
    for scheme in ("https", "http"):
        base = f"{scheme}://{domain}"
        for path in API_DOC_PATHS:
            try:
                resp = curl_request(base + path, timeout=8)
                if resp["status"] == 200 and len(resp["body"]) > 50:
                    discovered.append(base + path)
                    if resp["body"].strip().startswith("{"):
                        try:
                            data = json.loads(resp["body"])
                            paths = data.get("paths", {})
                            for p in paths.keys():
                                endpoints.append(base + p)
                        except (json.JSONDecodeError, ValueError):
                            pass
            except Exception:
                continue
        if discovered:
            break
    return discovered, endpoints


def discover_graphql(domain):
    """Level 4: check for GraphQL endpoints."""
    found = []
    for scheme in ("https", "http"):
        base = f"{scheme}://{domain}"
        for path in GRAPHQL_PATHS:
            try:
                resp = curl_request(base + path, timeout=8)
                if resp["status"] in (200, 400, 405):
                    found.append(base + path)
            except Exception:
                continue
        if found:
            break
    return found


# ============================================================================
# CLASSIFICATION
# ============================================================================
def classify_unauth_response(url, resp):
    """Classify an unauthenticated response. Returns (verdict, reason, confidence)."""
    status = resp.get("status", 0)
    body = resp.get("body", "")
    body_len = len(body)

    if status in (401, 403):
        return "protected", f"HTTP {status}", "high"
    if status == 404:
        return "protected", "Not found", "high"
    if status in (301, 302, 307, 308):
        return "protected", f"Redirect {status}", "medium"
    if status == 500:
        return "suspicious", "Server error (may leak data)", "low"
    if status != 200:
        return "protected", f"HTTP {status}", "medium"

    if not body or body_len < 20:
        return "public", "Empty/trivial body", "high"

    if GENERIC_RESPONSES.match(body):
        return "public", "Generic HTML/error page", "high"

    has_sensitive = bool(SENSITIVE_FIELD_HINTS.search(body))
    is_private_url = bool(PRIVATE_URL_HINTS.search(url))
    is_public_url = bool(PUBLIC_URL_HINTS.search(url))

    if has_sensitive and is_private_url:
        return "confirmed", "Sensitive fields + private URL, no auth", "high"
    if has_sensitive:
        return "confirmed", "Sensitive fields in unauth response", "high"
    if is_private_url and body_len > 200 and not is_public_url:
        return "suspicious", "Private URL returns data without auth", "medium"

    if body.strip().startswith(("{", "[")):
        try:
            data = json.loads(body)
            if isinstance(data, dict) and any(
                k in data for k in ("id", "user_id", "email", "data", "result")
            ):
                return "suspicious", "JSON with data, no auth", "medium"
            if isinstance(data, list) and data:
                return "suspicious", "JSON array with items, no auth", "medium"
        except (json.JSONDecodeError, ValueError):
            pass

    return "public", "No clear private signals", "low"


def test_unauth_methods(url):
    """Test different methods unauthenticated."""
    findings = []
    for method in ["POST", "PUT", "OPTIONS"]:
        try:
            resp = curl_request(url, method=method, timeout=8, follow=False)
            if resp["status"] == 200 and len(resp.get("body", "")) > 50:
                findings.append({
                    "method": method,
                    "status": resp["status"],
                    "body_len": len(resp["body"]),
                    "preview": resp["body"][:200],
                })
        except Exception:
            continue
        time.sleep(0.3)
    return findings


def analyze_idor_pair(url, resp_a, resp_b, resp_anon):
    """Compare A/B/anon responses. Returns classification."""
    sa, sb, sn = resp_a.get("status", 0), resp_b.get("status", 0), resp_anon.get("status", 0)
    ba, bb = resp_a.get("body", ""), resp_b.get("body", "")

    # Confirmed: anonymous access
    if sn == 200 and sa != 200 and sb != 200:
        return {
            "type": "confirmed",
            "reason": "Anonymous access allowed",
            "status": {"A": sa, "B": sb, "anon": sn},
        }

    # Confirmed: cross-account leak
    if sa == 200 and sb == 200 and sn in (401, 403, 0):
        if ba and bb and ba != bb and abs(len(ba) - len(bb)) > 20:
            has_sensitive = bool(SENSITIVE_FIELD_HINTS.search(ba) or
                                 SENSITIVE_FIELD_HINTS.search(bb))
            if has_sensitive:
                return {
                    "type": "confirmed",
                    "reason": "A and B receive different sensitive data",
                    "status": {"A": sa, "B": sb, "anon": sn},
                }
            return {
                "type": "suspicious",
                "reason": "A and B receive different bodies",
                "status": {"A": sa, "B": sb, "anon": sn},
            }

    # Suspicious: A gets 200, B gets 403
    if sa == 200 and sb == 403 and sn in (401, 403, 0):
        return {
            "type": "suspicious",
            "reason": "A=200 B=403 — verify ownership",
            "status": {"A": sa, "B": sb, "anon": sn},
        }

    return None
# ============================================================================
# PLAYBOOK GENERATION
# ============================================================================
def generate_playbook(idir_dir, candidates, unauth_findings=None, auth_findings=None):
    """Generate markdown playbook."""
    playbook = idir_dir / "PLAYBOOK.md"
    lines = [
        "# IDOR Testing Playbook",
        "",
        f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"## Summary",
        f"- Total candidates: {len(candidates)}",
        f"- Unauthenticated findings: {len(unauth_findings or [])}",
        f"- Authenticated findings: {len(auth_findings or [])}",
        "",
        "## Bypass Checklist",
        "",
        "For each candidate, try:",
        "",
        "### URL Manipulation",
        "- [ ] Change API version: `/api/v1/` → `/api/v2/`",
        "- [ ] Add extension: `.json`, `.xml`",
        "- [ ] Remove ID entirely",
        "- [ ] Pluralize: `/user/` → `/users/`",
        "- [ ] Trailing slash",
        "- [ ] Case change: `/USER/`",
        "- [ ] Path traversal: `/your-id/../victim-id`",
        "- [ ] Double URL-encode ID",
        "",
        "### Parameter Injection",
        "- [ ] Add `?include=email,phone`",
        "- [ ] Add `?fields=all`",
        "- [ ] Add `?format=json`",
        "- [ ] Add `?page=1&pageSize=100`",
        "",
        "### HTTP Method Change",
        "- [ ] GET → POST → PUT → PATCH → DELETE",
        "- [ ] Add header: `X-HTTP-Method-Override: PUT`",
        "- [ ] Body param: `_method=PUT`",
        "",
        "### ID Location Conflict",
        "- [ ] Your ID in path + victim ID in query",
        "- [ ] Your ID in path + victim ID in body",
        "- [ ] Your ID in query + victim ID in body",
        "- [ ] Add `X-User-Id: victim_id` header",
        "",
        "### Body Manipulation",
        "- [ ] Change Content-Type: json ↔ form",
        "- [ ] Wrap ID: `{\"id\": [VICTIM_ID]}`",
        "- [ ] Nested: `{\"id\": {\"id\": VICTIM_ID}}`",
        "",
    ]

    if unauth_findings:
        lines.append("## CONFIRMED Unauthenticated Findings")
        lines.append("")
        for f in unauth_findings:
            lines.append(f"### {f.get('type', 'unknown')}: `{f.get('url', '')}`")
            lines.append(f"- Reason: {f.get('reason', 'N/A')}")
            lines.append(f"- Confidence: {f.get('confidence', 'N/A')}")
            lines.append("")

    if auth_findings:
        lines.append("## CONFIRMED Authenticated Findings")
        lines.append("")
        for f in auth_findings:
            lines.append(f"### {f.get('type', 'unknown')}: `{f.get('url', '')}`")
            lines.append(f"- Reason: {f.get('reason', 'N/A')}")
            if f.get("status"):
                lines.append(f"- Status: {f['status']}")
            lines.append("")

    lines.append("## Candidates")
    lines.append("")
    for i, url in enumerate(candidates[:200], 1):
        lines.append(f"{i}. `{url}`")

    playbook.write_text("\n".join(lines), encoding="utf-8")
    return playbook


# ============================================================================
# PHASE: UNAUTHENTICATED SCAN
# ============================================================================
def phase_unauthenticated_scan(domain, workspace, candidates, PhaseProgress,
                                log_info, log_ok, log_warn):
    """Test candidates without auth."""
    idir = Path(workspace) / domain / "idor"
    idir.mkdir(parents=True, exist_ok=True)

    prog = PhaseProgress("IDOR — Unauthenticated Scan", 2)
    confirmed, suspicious = [], []
    protected_count, public_count = 0, 0

    max_check = min(len(candidates), 150)
    rate = 3.0

    log_info(f"Testing {max_check} candidates without authentication...")

    for url in candidates[:max_check]:
        try:
            resp = curl_request(url, timeout=8)
        except Exception:
            continue

        verdict, reason, confidence = classify_unauth_response(url, resp)

        if verdict == "confirmed":
            entry = {
                "type": "missing-auth",
                "url": url,
                "reason": reason,
                "confidence": confidence,
                "status": resp["status"],
                "body_len": len(resp.get("body", "")),
                "preview": resp.get("body", "")[:300],
            }
            confirmed.append(entry)
            print(f"  {R}🔥 MISSING AUTH: {url}{RST}")
            print(f"     {DIM}{reason}{RST}")
        elif verdict == "suspicious":
            suspicious.append({
                "type": "missing-auth-suspicious",
                "url": url,
                "reason": reason,
                "confidence": confidence,
                "status": resp["status"],
            })
        elif verdict == "public":
            public_count += 1
        else:
            protected_count += 1

        time.sleep(1.0 / rate)

    prog.step(f"Tested {max_check} candidates")
    prog.step(f"→ {len(confirmed)} confirmed, {len(suspicious)} suspicious")

    # Method tampering on suspicious
    log_info("Testing method tampering...")
    for entry in suspicious[:15]:
        url = entry["url"]
        mf = test_unauth_methods(url)
        for m in mf:
            if m["method"] in ("POST", "PUT"):
                confirmed.append({
                    "type": "method-bypass",
                    "url": url,
                    "reason": f"{m['method']} returns 200 unauth",
                    "confidence": "high",
                    "method": m["method"],
                    "status": m["status"],
                    "preview": m["preview"],
                })
                print(f"  {R}🔥 METHOD BYPASS: {m['method']} {url}{RST}")

    prog.done_phase()

    (idir / "unauth_confirmed.json").write_text(
        json.dumps(confirmed, indent=2), encoding="utf-8"
    )
    (idir / "unauth_suspicious.json").write_text(
        json.dumps(suspicious, indent=2), encoding="utf-8"
    )

    return {"confirmed": confirmed, "suspicious": suspicious,
            "protected": protected_count, "public": public_count}


# ============================================================================
# PHASE: AUTHENTICATED TESTING
# ============================================================================
def phase_authenticated_testing(domain, workspace, candidates, session_a,
                                  session_b, PhaseProgress, log_info, log_ok, log_warn):
    """A vs B vs anon testing."""
    idir = Path(workspace) / domain / "idor"
    prog = PhaseProgress("IDOR — Authenticated Testing", 1)

    confirmed, suspicious = [], []
    tested = 0
    max_candidates = 100
    rate = 2.0

    for url in candidates[:max_candidates]:
        try:
            resp_a = curl_request(
                url,
                cookies=session_a.get("cookies"),
                headers=session_a.get("token_headers", {}),
                timeout=10,
            )
            time.sleep(1.0 / rate)

            resp_b = curl_request(
                url,
                cookies=session_b.get("cookies"),
                headers=session_b.get("token_headers", {}),
                timeout=10,
            )
            time.sleep(1.0 / rate)

            resp_anon = curl_request(url, timeout=10)
            time.sleep(1.0 / rate)

            tested += 1
            result = analyze_idor_pair(url, resp_a, resp_b, resp_anon)

            if result:
                result["url"] = url
                result["evidence"] = {
                    "a_body": resp_a.get("body", "")[:300],
                    "b_body": resp_b.get("body", "")[:300],
                }
                if result["type"] == "confirmed":
                    confirmed.append(result)
                    print(f"  {R}🔥 CONFIRMED: {url}{RST}")
                    print(f"     {DIM}{result['reason']}{RST}")
                else:
                    suspicious.append(result)
        except KeyboardInterrupt:
            raise
        except Exception:
            continue

    prog.step(f"Tested {tested} → {len(confirmed)} confirmed, {len(suspicious)} suspicious")
    prog.done_phase()

    (idir / "auth_confirmed.json").write_text(
        json.dumps(confirmed, indent=2), encoding="utf-8"
    )
    (idir / "auth_suspicious.json").write_text(
        json.dumps(suspicious, indent=2), encoding="utf-8"
    )

    return {"confirmed": confirmed, "suspicious": suspicious, "tested": tested}


# ============================================================================
# MAIN PHASE FUNCTION
# ============================================================================
def phase_idor(domain, workspace, PhaseProgress, log_info, log_ok, log_warn):
    """Full IDOR phase."""
    idir = Path(workspace) / domain / "idor"
    idir.mkdir(parents=True, exist_ok=True)

    # ===== STEP 1: DISCOVERY =====
    prog = PhaseProgress("16 — IDOR Discovery", 5)

    urls_dir = Path(workspace) / domain / "urls"
    js_dir = Path(workspace) / domain / "js"

    source_urls = []
    for fname in ("final-urls.txt", "clean_urls.txt"):
        f = urls_dir / fname
        if f.exists():
            source_urls.extend(f.read_text(errors="ignore").splitlines())

    js_files = []
    js_list = js_dir / "jsfiles.txt"
    if js_list.exists():
        js_files = [l.strip() for l in js_list.read_text(errors="ignore").splitlines() if l.strip()]

    # Level 1: Basic extraction
    candidates = set(extract_candidates(source_urls))
    prog.step(f"Level 1 (URLs) → {len(candidates)} candidates")

    # Level 2: JS mining
    if len(candidates) < 30 and js_files:
        js_endpoints = discover_from_js(source_urls, js_files)
        js_candidates = extract_candidates(js_endpoints)
        candidates.update(js_candidates)
        prog.step(f"Level 2 (JS) → +{len(js_candidates)} candidates")
    else:
        prog.step(f"Level 2 (JS) → skipped")

    # Level 3: API docs
    api_docs, api_doc_endpoints = discover_api_docs(domain)
    if api_doc_endpoints:
        candidates.update(extract_candidates(api_doc_endpoints))
    if api_docs:
        (idir / "api_docs.txt").write_text("\n".join(api_docs), encoding="utf-8")
    prog.step(f"Level 3 (API docs) → {len(api_docs)} docs")

    # Level 4: GraphQL
    gql_endpoints = discover_graphql(domain)
    if gql_endpoints:
        (idir / "graphql.txt").write_text("\n".join(gql_endpoints), encoding="utf-8")
    prog.step(f"Level 4 (GraphQL) → {len(gql_endpoints)} endpoints")

    # Save all
    candidates_list = sorted(candidates)
    (idir / "candidates.txt").write_text(
        "\n".join(candidates_list), encoding="utf-8"
    )

    uuids = extract_uuids(source_urls)
    (idir / "uuids.txt").write_text("\n".join(uuids), encoding="utf-8")

    params = extract_params(source_urls)
    (idir / "params.txt").write_text("\n".join(params), encoding="utf-8")

    prog.done_phase()

    # ===== SUMMARY =====
    print()
    print(f"{BOLD}{C}{'=' * 60}{RST}")
    print(f"{BOLD}{Y}  IDOR Discovery Complete{RST}")
    print(f"{BOLD}{C}{'=' * 60}{RST}")
    print(f"  Candidates : {G}{len(candidates_list)}{RST}")
    print(f"  UUIDs      : {G}{len(uuids)}{RST}")
    print(f"  Parameters : {G}{len(params)}{RST}")
    print(f"  API docs   : {G}{len(api_docs)}{RST}")
    print(f"  GraphQL    : {G}{len(gql_endpoints)}{RST}")
    print()

    if not candidates_list:
        log_warn("No candidates found — skipping active testing")
        playbook = generate_playbook(idir, [])
        return {"candidates": 0, "confirmed": [], "playbook": str(playbook)}

    # ===== STEP 2: UNAUTH SCAN (NO LOGIN) =====
    log_info("Starting unauthenticated scan (no login required)...")
    unauth_results = phase_unauthenticated_scan(
        domain, workspace, candidates_list, PhaseProgress,
        log_info, log_ok, log_warn
    )

    if unauth_results["confirmed"]:
        print()
        print(f"{BOLD}{R}{'=' * 60}{RST}")
        print(f"{BOLD}{R}  ⚠ {len(unauth_results['confirmed'])} UNAUTH FINDINGS{RST}")
        print(f"{BOLD}{R}{'=' * 60}{RST}")
        for f in unauth_results["confirmed"][:10]:
            print(f"  {R}●{RST} {f.get('type', '?'):20} {f.get('url', '')[:70]}")
        print()

    # ===== STEP 3: PROMPT FOR AUTH =====
    print(f"{BOLD}{Y}[?] Continue with AUTHENTICATED testing?{RST}")
    print(f"{DIM}Requires TWO accounts you own on the target.{RST}")
    print()

    try:
        ans = input(f"  {BOLD}Test with authentication? [y/N]: {RST}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        ans = "n"

    if ans not in ("y", "yes"):
        log_info("Skipping authenticated testing")
        playbook = generate_playbook(idir, candidates_list,
                                      unauth_findings=unauth_results["confirmed"])
        log_ok(f"Playbook: {playbook}")
        return {
            "candidates": len(candidates_list),
            "unauth": unauth_results,
            "confirmed": unauth_results["confirmed"],
            "playbook": str(playbook),
            "auth_tested": False,
        }

    # ===== STEP 4: CREDENTIALS =====
    creds_a = collect_credentials("A (attacker)")
    if not creds_a:
        playbook = generate_playbook(idir, candidates_list,
                                      unauth_findings=unauth_results["confirmed"])
        return {"candidates": len(candidates_list), "unauth": unauth_results,
                "confirmed": unauth_results["confirmed"],
                "playbook": str(playbook), "auth_tested": False}

    creds_b = collect_credentials("B (victim)")
    if not creds_b:
        playbook = generate_playbook(idir, candidates_list,
                                      unauth_findings=unauth_results["confirmed"])
        return {"candidates": len(candidates_list), "unauth": unauth_results,
                "confirmed": unauth_results["confirmed"],
                "playbook": str(playbook), "auth_tested": False}

    # ===== STEP 5: AUTO-LOGIN =====
    prog = PhaseProgress("17 — IDOR Login", 2)

    log_info("Auto-login for A...")
    result_a = try_login(domain, creds_a["email"], creds_a["password"])
    session_a = None
    if result_a.get("success"):
        v = validate_session(domain, result_a)
        if v.get("valid"):
            session_a = {
                "cookies": result_a.get("cookies", ""),
                "token_headers": result_a.get("token_headers", {}),
                "user_id": v.get("user_id"),
                "email": creds_a["email"],
            }
            prog.step(f"Login A → user_id={v.get('user_id', '?')}")
        else:
            prog.step("Login A → session invalid")
    else:
        prog.step("Login A → failed")

    if not session_a:
        cookie = manual_cookie_fallback("A")
        if cookie:
            session_a = {"cookies": cookie, "token_headers": {},
                         "user_id": None, "email": creds_a["email"]}
        else:
            playbook = generate_playbook(idir, candidates_list,
                                          unauth_findings=unauth_results["confirmed"])
            return {"candidates": len(candidates_list), "unauth": unauth_results,
                    "confirmed": unauth_results["confirmed"],
                    "playbook": str(playbook), "auth_tested": False}

    log_info("Auto-login for B...")
    result_b = try_login(domain, creds_b["email"], creds_b["password"])
    session_b = None
    if result_b.get("success"):
        v = validate_session(domain, result_b)
        if v.get("valid"):
            session_b = {
                "cookies": result_b.get("cookies", ""),
                "token_headers": result_b.get("token_headers", {}),
                "user_id": v.get("user_id"),
                "email": creds_b["email"],
            }
            prog.step(f"Login B → user_id={v.get('user_id', '?')}")
        else:
            prog.step("Login B → session invalid")
    else:
        prog.step("Login B → failed")

    if not session_b:
        cookie = manual_cookie_fallback("B")
        if cookie:
            session_b = {"cookies": cookie, "token_headers": {},
                         "user_id": None, "email": creds_b["email"]}
        else:
            playbook = generate_playbook(idir, candidates_list,
                                          unauth_findings=unauth_results["confirmed"])
            return {"candidates": len(candidates_list), "unauth": unauth_results,
                    "confirmed": unauth_results["confirmed"],
                    "playbook": str(playbook), "auth_tested": False}

    prog.done_phase()
    log_ok("Both sessions established")

    # ===== STEP 6: AUTH TESTING =====
    auth_results = phase_authenticated_testing(
        domain, workspace, candidates_list, session_a, session_b,
        PhaseProgress, log_info, log_ok, log_warn
    )

    all_confirmed = unauth_results["confirmed"] + auth_results["confirmed"]
    playbook = generate_playbook(idir, candidates_list,
                                  unauth_findings=unauth_results["confirmed"],
                                  auth_findings=auth_results["confirmed"])

    return {
        "candidates": len(candidates_list),
        "unauth": unauth_results,
        "auth": auth_results,
        "confirmed": all_confirmed,
        "playbook": str(playbook),
        "auth_tested": True,
    }
