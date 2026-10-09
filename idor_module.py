"""
IDOR Testing Module for Clicker v2.3
Auto-login, session extraction, active IDOR testing.
Save as: ~/idor_module.py
"""
import base64
import datetime
import json
import re
import subprocess
import sys
import time
import urllib.parse
from pathlib import Path
import idor_smart

# Colors (override from clicker if imported)
R, G, Y, B, M, C, W = "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[95m", "\033[96m", "\033[97m"
DIM, RST, BOLD = "\033[2m", "\033[0m", "\033[1m"

# ============================================================================
# GLOBAL CONFIG (set by clicker.py before calling phase_idor)
# ============================================================================
GLOBAL_SCOPE = None
GLOBAL_LOGIN_URL = None
GLOBAL_LOGIN_JSON = None
GLOBAL_A_EMAIL = None
GLOBAL_A_PASS = None
GLOBAL_B_EMAIL = None
GLOBAL_B_PASS = None
GLOBAL_EXTRA_HEADERS = []
GLOBAL_RATE_LIMIT = 5.0

# ── Advanced modules (added by C1 integration) ──
try:
    import idor_collection
    import idor_testing
    import idor_testing_advanced
    ADVANCED_AVAILABLE = True
    import idor_testing_advanced2
    import idor_testing_advanced2_fix
except ImportError:
    ADVANCED_AVAILABLE = False


# ============================================================================
# CONSTANTS
# ============================================================================
LOGIN_PATHS = [
    # ── Modern REST / SPA (high priority) ──
    "/rest/user/login",        # OWASP Juice Shop
    "/rest/auth/login",
    "/api/user/login",
    "/api/users/login",
    "/api/v1/login",
    "/user/login",
    "/rest/login",
    # ── API-style paths ──
    "/identity/api/auth/login",
    "/api/auth/login",
    "/api/v1/auth/login",
    "/auth/login",
    "/api/login",
    "/api/v1/login",
    "/api/token",
    "/api/session",
    # Traditional paths last
    "/login",
    "/signin",
    "/auth/signin",
    "/users/login",
    "/account/login",
    "/api/users/sign_in",
]

EMAIL_FIELDS = ["email", "username", "user"]
PASS_FIELDS = ["password", "pass"]

ME_PATHS = [
    # ── Juice Shop / modern REST (high priority) ──
    "/rest/user/whoami",
    "/rest/user/authentication-details",
    "/api/Users/me",
    # ── Generic /api/me style ──
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
    import os as _os
    cmd = ["curl", "-sS", "-k", "--max-time", str(timeout)]

    # Use workspace-local .curlrc if available (set by clicker.py)
    _curl_home = _os.environ.get("CURL_HOME")
    if _curl_home:
        _curlrc_file = Path(_curl_home) / ".curlrc"
        if _curlrc_file.exists():
            cmd += ["--config", str(_curlrc_file)]

    if follow:
        cmd += ["-L", "--max-redirs", "5"]

    if method.upper() != "GET":
        cmd += ["-X", method.upper()]

    if cookies:
        cmd += ["-b", str(cookies)]

    all_headers = {"User-Agent": "Mozilla/5.0 Clicker/2.3"}
    if headers:
        all_headers.update(headers)
    # Global program headers (X-Bug-Bounty, etc.)
    for gh in GLOBAL_EXTRA_HEADERS:
        if ":" in gh:
            k, _, v = gh.partition(":")
            all_headers[k.strip()] = v.strip()
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
            cmd, capture_output=True, text=True, errors="replace",
            timeout=timeout + 5
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


def _extract_jwt_from_body(body):
    """Extract JWT token from JSON body with any common nesting pattern.
    Returns tuple (jwt_token, cookies_string) or (None, None).
    """
    if not body or not body.strip().startswith("{"):
        return None, None
    try:
        data = json.loads(body)
    except Exception:
        return None, None
    if not isinstance(data, dict):
        return None, None

    jwt_token = None

    # Pattern 1: flat keys
    for key in ("token", "access_token", "accessToken", "jwt", "id_token", "idToken"):
        if key in data and isinstance(data[key], str) and len(data[key]) > 20:
            jwt_token = data[key]
            break

    # Pattern 2: data.token (Spring style)
    if not jwt_token and isinstance(data.get("data"), dict):
        for k in ("token", "access_token", "accessToken", "jwt"):
            if k in data["data"] and isinstance(data["data"][k], str):
                jwt_token = data["data"][k]
                break

    # Pattern 3: authentication.token (OWASP Juice Shop)
    if not jwt_token and isinstance(data.get("authentication"), dict):
        auth = data["authentication"]
        for k in ("token", "access_token", "accessToken", "jwt"):
            if k in auth and isinstance(auth[k], str):
                jwt_token = auth[k]
                break

    # Pattern 4: user.token / account.token / result.token / session.token / payload.token
    if not jwt_token:
        for wrap in ("user", "account", "result", "session", "payload",
                     "data", "response", "responseData", "body"):
            if isinstance(data.get(wrap), dict):
                for k in ("token", "access_token", "accessToken", "jwt",
                          "idToken", "id_token", "bearerToken"):
                    if k in data[wrap] and isinstance(data[wrap][k], str):
                        jwt_token = data[wrap][k]
                        break
                if jwt_token:
                    break

    # Pattern 5 (NEW): deep recursive — handles any nesting
    if not jwt_token:
        try:
            found = _find_token_recursive(data, max_depth=6)
            if found:
                jwt_token = found[1]
        except Exception:
            pass

    if not jwt_token:
        return None, None

    # Build cookie string (many apps read token from cookie, not Authorization header)
    cookie_str = f"token={jwt_token}"
    return jwt_token, cookie_str



# ============================================================================
# Token extraction helper (recursive, supports nested JSON)
# ============================================================================
TOKEN_KEY_NAMES = (
    "token", "access_token", "accessToken",
    "idToken", "id_token", "jwt", "bearerToken",
    "authToken", "auth_token", "id",
)


def _find_token_recursive(obj, max_depth=5):
    """Recursively search a JSON object for a token string.

    Returns (key, value) of the first match, or None.
    Skips strings that look like messages/UUIDs/IDs (too short or plain).
    """
    if max_depth <= 0:
        return None

    if isinstance(obj, dict):
        # Priority: look for token-ish keys at this level first
        for key in TOKEN_KEY_NAMES:
            if key in obj:
                val = obj[key]
                if isinstance(val, str) and _is_likely_token(val):
                    return (key, val)
        # Then recurse into nested dicts
        for key, val in obj.items():
            if isinstance(val, (dict, list)):
                result = _find_token_recursive(val, max_depth - 1)
                if result:
                    return result

    elif isinstance(obj, list):
        for item in obj[:5]:  # first 5 items only
            result = _find_token_recursive(item, max_depth - 1)
            if result:
                return result

    return None


def _is_likely_token(s):
    """Heuristic: JWT-ish string (long, has dots or high entropy)."""
    if not isinstance(s, str):
        return False
    if len(s) < 40:
        return False
    # JWT pattern: three base64url segments separated by dots
    if s.count(".") >= 2 and len(s) > 100:
        return True
    # Long random string (Bearer tokens)
    if len(s) >= 40 and any(c.isdigit() for c in s) and any(c.isalpha() for c in s):
        return True
    return False



def try_login(domain, email, password, custom_url=None, custom_json=None):
    """
    Try to login using common patterns. Returns session dict.
    If custom_url and custom_json are provided, try those first.
    custom_json is a JSON template with %EMAIL% and %PASS% placeholders.
    """
    base = f"https://{domain}"
    http_base = f"http://{domain}"

    # ===== CUSTOM LOGIN (highest priority) =====
    if custom_url and custom_json:
        print(f"  {DIM}[custom login] Trying {custom_url}{RST}")
        try:
            payload_str = custom_json.replace("%EMAIL%", email).replace("%PASS%", password)
            payload = json.loads(payload_str)
            # Build alternative payload shapes (smart fallback)
            _alt_payloads = []
            try:
                _alt_payloads = idor_smart.build_login_payloads(
                    email, password,
                    extra_fields={"deviceToken": None, "deviceId": "web_client", "deviceName": "Web App"}
                )
            except Exception:
                pass
        except Exception as e:
            print(f"  {Y}[!] Invalid custom JSON: {e}{RST}")
            payload = None
            _alt_payloads = []

        # Try custom payload first, then fallbacks
        _all_payloads = ([payload] if payload else []) + [
            p for p in _alt_payloads if p != payload
        ]

        if not _all_payloads:
            _all_payloads = [None]

        for payload in _all_payloads:
            if payload is None:
                continue
            for base_url in (http_base, base):
                try:
                    full_url = (base_url + custom_url) if custom_url.startswith("/") else custom_url
                    resp = curl_request(
                        full_url, method="POST", data=payload,
                        content_type="application/json",
                        timeout=10, follow=True,
                    )
                    if resp["status"] in (200, 201, 202, 302):
                        set_cookie = resp["headers"].get("set-cookie", "")
                        body = resp["body"]
                        token_headers = {}
                        jwt_token, jwt_cookie = _extract_jwt_from_body(body)

                        # FALLBACK: recursive finder for deeply nested tokens
                        if not jwt_token and body.strip().startswith("{"):
                            try:
                                _data = json.loads(body)
                                _found = _find_token_recursive(_data, max_depth=6)
                                if _found:
                                    _key, _val = _found
                                    jwt_token = _val
                                    jwt_cookie = f"token={jwt_token}"
                                    print(f"  {G}[custom login] Token found via recursive ({_key}){RST}")
                            except Exception as _e:
                                print(f"  {Y}[custom login] JSON parse failed: {_e}{RST}")

                        # DEBUG (verbose only)
                        if args_verbose if 'args_verbose' in dir() else False:
                            print(f"  {DIM}[custom login] status={resp['status']} body_len={len(body)}{RST}")
                            print(f"  {DIM}[custom login] token_found={bool(jwt_token)}{RST}")

                        if jwt_token:
                            token_headers["Authorization"] = f"Bearer {jwt_token}"
                            if not set_cookie:
                                set_cookie = jwt_cookie
                            elif "token=" not in set_cookie:
                                set_cookie = set_cookie + "; " + jwt_cookie

                        # NEW: Extract uid from response (for cross-account testing)
                        extracted_uid = None
                        try:
                            _d = json.loads(body)
                            for path in [
                                ("uid",), ("user_id",), ("userId",),
                                ("result", "uid"), ("result", "id"),
                                ("data", "uid"), ("data", "id"),
                                ("user", "uid"), ("user", "id"),
                            ]:
                                cur = _d
                                for k in path:
                                    if isinstance(cur, dict) and k in cur:
                                        cur = cur[k]
                                    else:
                                        cur = None
                                        break
                                if cur and isinstance(cur, (str, int)):
                                    extracted_uid = str(cur)
                                    break
                        except Exception:
                            pass

                        # Accept even cookie-only
                        if set_cookie or token_headers:
                            return {
                                "success": True,
                                "base_url": base_url,
                                "login_url": full_url,
                                "cookies": set_cookie,
                                "token_headers": token_headers,
                                "email": email,
                                "user_id": extracted_uid,
                            }
                except Exception:
                    continue

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

    # Try HTTP first (local targets often HTTP-only), then HTTPS
    for base_url in (http_base, base):
        for login_path in LOGIN_PATHS:
            # Try JSON-only first (modern APIs), then form-urlencoded
            for is_json in (True, False):
                for email_field in EMAIL_FIELDS:
                    for pass_field in PASS_FIELDS:
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
                                timeout=4,
                                follow=True,
                            )
                        except Exception:
                            continue

                        if resp["status"] in (200, 201, 202, 302):
                            set_cookie = resp["headers"].get("set-cookie", "")
                            body = resp["body"]
                            token_headers = {}

                            jwt_token, jwt_cookie = _extract_jwt_from_body(body)
                            if jwt_token:
                                token_headers["Authorization"] = f"Bearer {jwt_token}"
                                if not set_cookie:
                                    set_cookie = jwt_cookie
                                elif "token=" not in set_cookie:
                                    set_cookie = set_cookie + "; " + jwt_cookie

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
                    # Try multiple nesting levels
                    candidates = [data]
                    # Push nested dicts
                    for wrap in ("data", "user", "account", "result", "session", "payload", "authentication"):
                        if isinstance(data.get(wrap), dict):
                            candidates.append(data[wrap])
                            # Also nested user inside authentication (Juice Shop style)
                            if isinstance(data[wrap].get("user"), dict):
                                candidates.append(data[wrap]["user"])

                    for d in candidates:
                        for key in ("id", "user_id", "userId", "uid", "ID"):
                            if key in d and isinstance(d[key], (int, str)):
                                user_id = d[key]
                                break
                        if user_id is not None:
                            break
                except (json.JSONDecodeError, AttributeError):
                    pass

                return {
                    "valid": True,
                    "endpoint": me_path,
                    "user_id": user_id or session_info.get("user_id"),
                }
        except Exception:
            continue

    # If ME_PATHS didn't work but login returned uid, trust it
    if session_info.get("user_id"):
        return {
            "valid": True,
            "endpoint": "(login response)",
            "user_id": session_info.get("user_id"),
        }

    return {"valid": False}


def collect_credentials(label):
    """Prompt user for credentials, or use globals if provided via CLI."""
    label_up = (label or "").upper()
    # Use CLI-provided credentials if available
    if "A" in label_up and "ATTACK" in label_up:
        if GLOBAL_A_EMAIL and GLOBAL_A_PASS:
            print(f"\n{BOLD}{C}[*] Account {label} (from CLI){RST}")
            print(f"  Email: {GLOBAL_A_EMAIL}")
            return {"email": GLOBAL_A_EMAIL, "password": GLOBAL_A_PASS}
    elif "B" in label_up and "VICTIM" in label_up:
        if GLOBAL_B_EMAIL and GLOBAL_B_PASS:
            print(f"\n{BOLD}{C}[*] Account {label} (from CLI){RST}")
            print(f"  Email: {GLOBAL_B_EMAIL}")
            return {"email": GLOBAL_B_EMAIL, "password": GLOBAL_B_PASS}

    # Fallback: prompt
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
# AUDIT LOGGING
# ============================================================================
def audit_log(idir, method, url, who, status, size, note=""):
    """Log every IDOR request for legal audit trail."""
    try:
        log_file = idir / f"audit_{datetime.date.today().isoformat()}.log"
        ts = datetime.datetime.now().isoformat(timespec="seconds")
        line = f"[{ts}] {method:6} {url} | who={who} | status={status} | size={size}b"
        if note:
            line += f" | {note}"
        with log_file.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


# ============================================================================
# SCOPE PER-REQUEST
# ============================================================================
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

# ============================================================================
# DISCOVERY — Extract IDOR candidates
# ============================================================================
IDOR_PATTERNS = [
    # Cloud Functions / Firebase (added for Flutter/Firebase apps)
    r'/cloudfunctions\.net/',
    r'/[a-z][a-z_]+_user',          # login_user, get_user, etc.
    r'/[a-z][a-z_]+_data',          # get_data, etc.
    r'/[a-z][a-z_]+_(courses?|lessons?|quizzes?|orders?|invoices?|payments?|users?|students?)',
    r'/accounts:',
    r'/v1/projects/',
    # Standard REST patterns
    r'/api/',
    r'/v\d+/',
    r'/graphql',
    r'/[a-z][a-z_-]+/\d{2,}',
    r'/[a-z][a-z_-]+/[a-z][a-z_-]+/\d+',
    r'/[a-z][a-z_-]+/[0-9a-f]{8}-[0-9a-f]{4}-',
    r'/identity/',
    r'/workshop/',
    r'/community/',
    r'/vehicle/',
    r'/orders?/',
    r'/users?/',
    r'/accounts?/',
    r'/profiles?/',
    r'/posts?/',
    r'/comments?/',
    r'\?(?:id|user_id|userId|order_id|orderId|invoice_id|account_id|address_id|post_id|postId|comment_id|commentId|vehicle_id|vehicleId)=',
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


def _is_valid_candidate_url(url, target_domain):
    """Reject garbage: external domains, JS fragments, truncated URLs."""
    if not url or not isinstance(url, str):
        return False
    url = url.strip()
    if len(url) < 12 or len(url) > 2000:
        return False

    # Must start with http(s)://
    if not url.startswith(("http://", "https://")):
        return False

    # Reject URLs with spaces or backticks (JS fragments)
    if " " in url or "`" in url or "'" in url or '"' in url:
        return False

    # Reject if too many special chars (JS garbage)
    special = sum(1 for c in url if c in "{}<>|\\^")
    if special > 2:
        return False

    # Parse
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
    except Exception:
        return False

    host = (parsed.hostname or "").lower()
    if not host:
        return False

    # Reject known external/garbage hosts
    external_bad = (
        "w3.org", "ethereum.io", "nodesmith.io", "googleapis.com",
        "google.com", "github.com", "githubusercontent.com",
        "schema.org", "xmlns.com", "json-schema.org",
        "wikipedia.org", "mozilla.org", "creativecommons.org",
        "example.com", "example.org", "cloudflare.com",
    )
    for bad in external_bad:
        if host == bad or host.endswith("." + bad):
            return False

    # Must match target domain OR be a known external API backend
    target_host = (target_domain or "").split(":")[0].lower()

    # Whitelist of legitimate external API hosts (for SPA/Flutter apps)
    external_whitelist = (
        "cloudfunctions.net",
        "firebaseio.com",
        "firebaseapp.com",
        "firestore.googleapis.com",
        "identitytoolkit.googleapis.com",
        "firebasestorage.googleapis.com",
        "supabase.co",
        "amazonaws.com",
        "azurewebsites.net",
        "cloudfront.net",
    )
    is_external_ok = any(host.endswith(w) for w in external_whitelist)

    if target_host and not is_external_ok:
        if not (host == target_host or host.endswith("." + target_host)):
            return False

    # Reject truncated-looking URLs (only scheme + incomplete path)
    if parsed.path in ("", "/") and not parsed.query:
        # Accept root but only if no fragment
        if parsed.fragment:
            return False

    # Reject malformed paths (JS-like)
    if any(x in parsed.path for x in ("..", "%%", "<", ">", "{", "}")):
        return False

    # Reject overly long paths (JS dumps)
    if len(parsed.path) > 500:
        return False

    return True


def extract_candidates(urls, target_domain=""):
    """Extract IDOR-suspicious URLs from a list (with garbage filtering)."""
    candidates = set()
    rejected = 0
    for url in urls:
        url = url.strip()
        if not url or url.startswith("#"):
            continue

        # Pattern match first
        matched = False
        for pat in IDOR_PATTERNS:
            if re.search(pat, url, re.IGNORECASE):
                matched = True
                break
        if not matched:
            continue

        # Then validate
        if target_domain and not _is_valid_candidate_url(url, target_domain):
            rejected += 1
            continue

        candidates.add(url)

    if rejected > 0:
        try:
            print(f"  {DIM}[filter] rejected {rejected} garbage candidates{RST}")
        except Exception:
            pass
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


def _extract_url_id(url):
    """Extract the LAST numeric ID from URL path. Returns int or None."""
    try:
        from urllib.parse import urlparse
        path = urlparse(url).path
    except Exception:
        return None
    matches = re.findall(r'/(\d+)(?:/|$|\?)', path)
    if not matches:
        return None
    try:
        return int(matches[-1])
    except (ValueError, IndexError):
        return None


def analyze_idor_pair(url, resp_a, resp_b, resp_anon,
                       session_a=None, session_b=None):
    """Compare A/B/anon responses. Returns classification."""
    sa, sb, sn = resp_a.get("status", 0), resp_b.get("status", 0), resp_anon.get("status", 0)
    ba, bb = resp_a.get("body", ""), resp_b.get("body", "")

    url_id = _extract_url_id(url)
    a_uid = (session_a or {}).get("user_id")
    b_uid = (session_b or {}).get("user_id")

    # ── NEW: Ownership check (true IDOR) ──
    # A's session accessing a URL with a different ID = cross-user leak
    if url_id is not None and sn in (401, 403):
        # Check A
        if a_uid is not None and str(a_uid) != str(url_id) and sa == 200:
            if len(ba) > 50:
                return {
                    "type": "confirmed",
                    "reason": f"A (uid={a_uid}) accessed /{url_id} (not theirs), anon blocked",
                    "status": {"A": sa, "B": sb, "anon": sn},
                    "url_id": url_id,
                    "session_user_id": a_uid,
                    "evidence": ba[:300],
                }
        # Check B
        if b_uid is not None and str(b_uid) != str(url_id) and sb == 200:
            if len(bb) > 50:
                return {
                    "type": "confirmed",
                    "reason": f"B (uid={b_uid}) accessed /{url_id} (not theirs), anon blocked",
                    "status": {"A": sa, "B": sb, "anon": sn},
                    "url_id": url_id,
                    "session_user_id": b_uid,
                    "evidence": bb[:300],
                }

    # ── Anonymous access ──
    if sn == 200 and sa != 200 and sb != 200:
        return {
            "type": "confirmed",
            "reason": "Anonymous access allowed",
            "status": {"A": sa, "B": sb, "anon": sn},
        }

    # ── Cross-account leak: A and B see different data ──
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

    # ── Suspicious: A gets 200, B gets 403 ──
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
                                log_info, log_ok, log_warn, scope=None):
    """Test candidates without auth."""
    idir = Path(workspace) / domain / "idor"
    idir.mkdir(parents=True, exist_ok=True)

    prog = PhaseProgress("IDOR — Unauthenticated Scan", 2)
    confirmed, suspicious = [], []
    protected_count, public_count = 0, 0
    rate_limited_count = 0

    max_check = min(len(candidates), 150)
    rate = GLOBAL_RATE_LIMIT

    log_info(f"Testing {max_check} candidates without authentication...")

    for url in candidates[:max_check]:
        if not is_url_in_scope(url, scope):
            log_warn(f"Out of scope — skipping: {url[:80]}")
            continue

        try:
            resp = curl_request(url, timeout=8)
        except Exception:
            continue

        audit_log(idir, "GET", url, "anon", resp.get("status", 0),
                  len(resp.get("body", "")), "unauth")

        if resp.get("status") == 429:
            rate_limited_count += 1
            backoff = min(60, 2 ** rate_limited_count)
            log_warn(f"Rate limited (429) — backing off {backoff}s ({rate_limited_count}/3)")
            time.sleep(backoff)
            if rate_limited_count >= 3:
                log_warn("Rate limit hit 3 times — aborting unauth scan")
                break
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
                                  session_b, PhaseProgress, log_info, log_ok, log_warn,
                                  scope=None):
    """A vs B vs anon testing with session refresh + audit + rate limit."""
    idir = Path(workspace) / domain / "idor"
    prog = PhaseProgress("IDOR — Authenticated Testing", 1)

    confirmed, suspicious = [], []
    tested = 0
    max_candidates = 100
    rate = max(0.5, GLOBAL_RATE_LIMIT / 2)
    rate_limited_count = 0

    def refresh_session(session, label):
        creds = session.get("creds")
        if not creds:
            return None
        log_warn(f"Refreshing session for {label}...")
        new_login = try_login(domain, creds["email"], creds["password"],
                              GLOBAL_LOGIN_URL, GLOBAL_LOGIN_JSON)
        if not new_login.get("success"):
            return None
        v = validate_session(domain, new_login)
        if not v.get("valid"):
            return None
        return {
            "cookies": new_login.get("cookies", ""),
            "token_headers": new_login.get("token_headers", {}),
            "user_id": v.get("user_id"),
            "email": session.get("email"),
            "creds": creds,
        }

    for url in candidates[:max_candidates]:
        if not is_url_in_scope(url, scope):
            log_warn(f"Out of scope — skipping: {url[:80]}")
            continue

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

            audit_log(idir, "GET", url, "A", resp_a.get("status", 0),
                      len(resp_a.get("body", "")), "auth")
            audit_log(idir, "GET", url, "B", resp_b.get("status", 0),
                      len(resp_b.get("body", "")), "auth")
            audit_log(idir, "GET", url, "anon", resp_anon.get("status", 0),
                      len(resp_anon.get("body", "")), "auth")

            if 429 in (resp_a.get("status"), resp_b.get("status"), resp_anon.get("status")):
                rate_limited_count += 1
                backoff = min(60, 2 ** rate_limited_count)
                log_warn(f"Rate limited (429) — backing off {backoff}s ({rate_limited_count}/3)")
                time.sleep(backoff)
                if rate_limited_count >= 3:
                    log_warn("Rate limit hit 3 times — aborting auth scan")
                    break
                continue

            if resp_a.get("status") == 401:
                log_warn("Session A expired (401) — refreshing...")
                new_sess = refresh_session(session_a, "A")
                if new_sess:
                    session_a = new_sess
                    log_ok("Session A refreshed")
                    # Skip this URL (don't analyze 401 response)
                    continue
                else:
                    log_warn("Session A refresh failed — aborting")
                    break

            if resp_b.get("status") == 401:
                log_warn("Session B expired (401) — refreshing...")
                new_sess = refresh_session(session_b, "B")
                if new_sess:
                    session_b = new_sess
                    log_ok("Session B refreshed")
                    # Skip this URL
                    continue
                else:
                    log_warn("Session B refresh failed — aborting")
                    break

            tested += 1
            result = analyze_idor_pair(url, resp_a, resp_b, resp_anon, session_a, session_b)

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

# ═══════════════════════════════════════════════════════════
# ADVANCED COLLECTION (A1-A9)
# ═══════════════════════════════════════════════════════════
def phase_extended_collection(domain, workspace, PhaseProgress, log_info, log_ok, log_warn):
    """
    Run the full collection methodology:
    gf patterns, API versions, JS mining, GraphQL, lifecycle,
    field expansion, arjun, paramspider, WP REST, merge all.
    """
    if not ADVANCED_AVAILABLE:
        log_warn("Advanced collection modules not available")
        return {}

    idir = Path(workspace) / domain / "idor"
    urls_dir = Path(workspace) / domain / "urls"
    js_dir = Path(workspace) / domain / "js"

    clean_urls = urls_dir / "clean_urls.txt"
    if not clean_urls.exists():
        clean_urls = urls_dir / "final-urls.txt"
    js_files = js_dir / "jsfiles.txt"

    if not clean_urls.exists():
        log_warn(f"No clean_urls.txt found — skipping extended collection")
        return {}

    prog = PhaseProgress("IDOR — Extended Collection", 1)
    log_info("Running advanced collection (gf, jsluice, graphw00f, arjun, ...)")

    try:
        results = idor_collection.run_collection_phase(
            domain=domain,
            workspace=workspace,
            idir=str(idir),
            clean_urls_file=str(clean_urls),
            js_files_file=str(js_files) if js_files.exists() else "",
        )
        prog.step(f"Extended collection done — {len(results.get('all', []))} candidates")
    except Exception as e:
        log_warn(f"Extended collection failed: {e}")
        results = {}
    prog.done_phase()

    # ═══ SMART JS DISCOVERY (new) ═══
    try:
        _js_urls = []
        _js_file = Path(workspace) / domain / "js" / "jsfiles.txt"
        if _js_file.exists():
            _js_urls = [l.strip() for l in _js_file.read_text().splitlines() if l.strip()]
        if _js_urls:
            print(f"{C}[smart] Running smart JS extraction on {len(_js_urls)} files...{RST}")
            _smart = idor_smart.smart_extract(
                _js_urls, str(Path(workspace) / domain),
                domain=domain, verbose=args_verbose if 'args_verbose' in dir() else False,
            )
            print(f"  {G}[smart] Endpoints: {len(_smart['endpoints'])}{RST}")
            print(f"  {G}[smart] Firebase configs: {len(_smart['firebase_configs'])}{RST}")
            print(f"  {G}[smart] API bases: {len(_smart['api_bases'])}{RST}")
            print(f"  {G}[smart] Login endpoints: {len(_smart['login_endpoints'])}{RST}")
            # Write discoveries
            _sdir = Path(workspace) / domain / "idor"
            _sdir.mkdir(parents=True, exist_ok=True)
            (_sdir / "smart_endpoints.txt").write_text(
                "\n".join(sorted(_smart["endpoints"])), encoding="utf-8"
            )
            (_sdir / "smart_api_bases.txt").write_text(
                "\n".join(sorted(_smart["api_bases"])), encoding="utf-8"
            )
            (_sdir / "smart_login_endpoints.txt").write_text(
                "\n".join(sorted(_smart["login_endpoints"])), encoding="utf-8"
            )
            if _smart["firebase_configs"]:
                (_sdir / "smart_firebase.json").write_text(
                    json.dumps(_smart["firebase_configs"], indent=2), encoding="utf-8"
                )
            if args_verbose if 'args_verbose' in dir() else False:
                for _b in sorted(_smart["api_bases"])[:10]:
                    print(f"    {DIM}API: {_b}{RST}")
                for _le in sorted(_smart["login_endpoints"])[:10]:
                    print(f"    {DIM}Login: {_le}{RST}")
    except Exception as _e:
        print(f"{Y}[smart] Failed: {_e}{RST}")

    return results


# ═══════════════════════════════════════════════════════════
# ADVANCED TESTING (B1-B10)
# ═══════════════════════════════════════════════════════════
def phase_advanced_testing(domain, workspace, candidates, session_a, session_b,
                           PhaseProgress, log_info, log_ok, log_warn, scope=None):
    """
    Run all advanced IDOR testing techniques:
      B1. HPP + Method Tampering
      B2. Numeric ID Fuzzing
      B3. State-Changing IDOR
      B4. Vertical/Horizontal PrivEsc
      B5. Mass Assignment
      B6. JWT Manipulation
      B7. Path/Body + Cross-Location Conflicts
      B8. File/Search/Pagination
      B9. Predictable IDs + Time Window
      B10. Bypass Variants + Blind
    """
    if not ADVANCED_AVAILABLE:
        log_warn("Advanced testing modules not available")
        return {"confirmed": [], "suspicious": []}

    idir = Path(workspace) / domain / "idor"
    idir.mkdir(parents=True, exist_ok=True)

    confirmed = []
    suspicious = []

    # ── B1. HPP + Method Tampering ──
    prog = PhaseProgress("IDOR — HPP & Method Tampering", 2)
    tested = 0
    for url in candidates[:30]:
        # Extract first numeric or UUID id from URL
        import re as _re
        m = _re.search(r'[?&](id|user_id|userId|account_id|accountId|order_id|orderId)=([^&]+)', url)
        param_name = m.group(1) if m else "id"
        own_id = m.group(2) if m else None

        if own_id and own_id.isdigit():
            victim_id = str(int(own_id) + 1)
        else:
            victim_id = None

        # HPP
        try:
            hpp_findings = idor_testing.test_hpp(
                url, param_name, own_id, victim_id,
                cookies=session_a.get("cookies") if session_a else None,
            )
            for f in hpp_findings:
                confirmed.append(f)
                log_ok(f"HPP: {f.get('reason', '')[:60]}")
        except Exception:
            pass

        # Method Tampering
        try:
            mt_findings = idor_testing.test_method_tampering(
                url, own_id, victim_id,
                cookies=session_a.get("cookies") if session_a else None,
            )
            for f in mt_findings:
                confirmed.append(f)
                log_ok(f"Method: {f.get('reason', '')[:60]}")
        except Exception:
            pass

        tested += 1
        if tested >= 20:
            break
    prog.step(f"Tested {tested} URLs — {len(confirmed)} findings")
    prog.done_phase()

    # ── B2. Numeric ID Fuzzing (user-owned resources prioritized) ──
    if candidates:
        prog = PhaseProgress("IDOR — Numeric ID Fuzzing", 1)
        import re as _re_b2

        PRIORITY_KEYWORDS = (
            "user", "account", "profile", "order", "invoice",
            "basket", "cart", "feedback", "review", "ticket",
            "message", "payment", "address", "comment",
        )

        numeric_cands = []
        for url in candidates:
            if not url or not url.startswith("http"):
                continue
            m = _re_b2.search(r'/(\d+)(?:/|$|\?)', url)
            if not m:
                continue
            low = url.lower()
            prio = 0 if any(k in low for k in PRIORITY_KEYWORDS) else 1
            numeric_cands.append((prio, url, int(m.group(1))))

        numeric_cands.sort(key=lambda x: (x[0], x[1]))

        seen_patterns = set()
        unique_cands = []
        for prio, url, oid in numeric_cands:
            pattern = _re_b2.sub(r'/\d+', '/{ID}', url, count=1)
            if pattern in seen_patterns:
                continue
            seen_patterns.add(pattern)
            unique_cands.append((prio, url, oid))

        b2_tested = 0
        b2_found = 0
        max_urls = 3
        for prio, url, own_id in unique_cands[:max_urls]:
            template = url.replace(f"/{own_id}", "/{ID}", 1)
            b2_tested += 1
            try:
                fuzz_findings = idor_testing.fuzz_numeric_id(
                    template,
                    start=max(1, own_id - 3),
                    end=own_id + 15,
                    own_id=own_id,
                    cookies=session_a.get("cookies") if session_a else None,
                    headers=session_a.get("token_headers", {}) if session_a else {},
                    max_findings=10,
                    verbose=False,
                )
                for f in fuzz_findings:
                    suspicious.append(f)
                    b2_found += 1
                    log_ok(f"Numeric IDOR: {f.get('url', '')[:60]}")
            except Exception:
                pass
        prog.step(f"Numeric fuzzing: tested {b2_tested} URLs, {b2_found} findings")
        prog.done_phase()

    # ── B3-B5. State change + PrivEsc + Mass Assignment (on POST/PUT endpoints) ──
    prog = PhaseProgress("IDOR — State & PrivEsc", 3)
    for url in candidates[:10]:
        if not url.startswith("http"):
            continue
        import re as _re
        m = _re.search(r'/(\d+)(?:/|$)', url)
        if not m:
            continue
        own_id = m.group(1)
        victim_id = str(int(own_id) + 1)

        # State-Changing GET
        try:
            sc_findings = idor_testing.test_state_change_get(
                url, own_id, victim_id,
                cookies=session_a.get("cookies") if session_a else None,
            )
            for f in sc_findings:
                confirmed.append(f)
                log_ok(f"State-change: {f.get('reason', '')[:60]}")
        except Exception:
            pass

        # Mass Assignment (on POST endpoints)
        if any(x in url for x in ("/update", "/edit", "/profile", "/settings")):
            try:
                ma_findings = idor_testing.test_mass_assignment(
                    url, method="POST",
                    base_body={"id": own_id},
                    cookies=session_a.get("cookies") if session_a else None,
                )
                for f in ma_findings:
                    suspicious.append(f)
                    log_warn(f"Mass assign: {f.get('field', '')}")
            except Exception:
                pass

    prog.step("State + PrivEsc + Mass assignment done")
    prog.step("Reviewed 10 candidates")
    prog.step(f"{len(confirmed)} confirmed, {len(suspicious)} suspicious")
    prog.done_phase()

    # ── B7. Path/Body + Header conflicts ──
    prog = PhaseProgress("IDOR — Path/Body Conflicts", 2)
    for url in candidates[:10]:
        if not url.startswith("http"):
            continue
        import re as _re
        m = _re.search(r'/(\d+)(?:/|$)', url)
        if not m:
            continue
        own_id = m.group(1)
        victim_id = str(int(own_id) + 1)

        # Path vs Body
        try:
            pb_findings = idor_testing_advanced.test_path_body_conflict(
                url, own_id, victim_id, method="PUT",
                cookies=session_a.get("cookies") if session_a else None,
            )
            for f in pb_findings:
                confirmed.append(f)
                log_ok(f"Path/Body: {f.get('reason', '')[:60]}")
        except Exception:
            pass

        # Header conflict
        try:
            hc_findings = idor_testing_advanced.test_header_conflict(
                url, own_id, victim_id,
                cookies=session_a.get("cookies") if session_a else None,
            )
            for f in hc_findings:
                suspicious.append(f)
        except Exception:
            pass
    prog.step("Path/Body + Header tests done")
    prog.step(f"{len(confirmed)} total confirmed so far")
    prog.done_phase()

    # ═══════════════════════════════════════════════════════════════
    # B3-extended. State-Changing IDOR (DELETE/PUT on state endpoints)
    # ═══════════════════════════════════════════════════════════════
    prog = PhaseProgress("IDOR — B3 State-Changing", 2)
    a_cookies = session_a.get("cookies") if session_a else None
    a_headers = session_a.get("token_headers", {}) if session_a else {}
    own_id = session_a.get("user_id") if session_a else None
    victim_id = session_b.get("user_id") if session_b else None
    b3_count = 0
    if own_id is not None and victim_id is not None:
        state_urls = [u for u in candidates
                      if any(k in u.lower() for k in
                             ("delete", "remove", "update", "edit",
                              "cancel", "revoke", "disable", "archive"))][:10]
        for url in state_urls:
            try:
                fs = idor_testing.test_state_changing(
                    url, own_id, victim_id, method="DELETE",
                    cookies=a_cookies,
                )
                for f in fs:
                    confirmed.append(f)
                    b3_count += 1
            except Exception:
                pass
    prog.step(f"B3 state-changing → {b3_count} findings")
    prog.done_phase()

    # ═══════════════════════════════════════════════════════════════
    # B4-vertical. Privilege Escalation (low-priv → admin endpoints)
    # ═══════════════════════════════════════════════════════════════
    prog = PhaseProgress("IDOR — B4 Vertical PrivEsc", 2)
    b4v_count = 0
    if session_a:
        for url in candidates[:15]:
            try:
                fs = idor_testing.test_vertical_escalation(
                    url, session_a, method="POST", cookies=a_cookies,
                )
                for f in fs:
                    suspicious.append(f)
                    b4v_count += 1
            except Exception:
                pass
    prog.step(f"B4-vertical → {b4v_count} suspicious")
    prog.done_phase()

    # ═══════════════════════════════════════════════════════════════
    # B4-horizontal. Cross-User Access (A tries to access B's resource)
    # ═══════════════════════════════════════════════════════════════
    prog = PhaseProgress("IDOR — B4 Horizontal PrivEsc", 2)
    b4h_count = 0
    if session_a and session_b:
        for url in candidates[:15]:
            try:
                fs = idor_testing.test_horizontal_idor(
                    url, session_a, session_b, own_id_a=own_id,
                )
                for f in fs:
                    confirmed.append(f)
                    b4h_count += 1
            except Exception:
                pass
    prog.step(f"B4-horizontal → {b4h_count} findings")
    prog.done_phase()

    # ═══════════════════════════════════════════════════════════════
    # B6. JWT Manipulation (+ weak secret cracking)
    # ═══════════════════════════════════════════════════════════════
    prog = PhaseProgress("IDOR — B6 JWT Manipulation", 2)
    jwt_token = None
    if session_a:
        th = session_a.get("token_headers", {}) or {}
        for _k, _v in th.items():
            if isinstance(_v, str) and _v.count(".") == 2:
                jwt_token = _v.replace("Bearer ", "").strip()
                break
        if not jwt_token:
            _cookies_str = session_a.get("cookies", "") or ""
            import re as _re_jwt
            _m = _re_jwt.search(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*',
                                _cookies_str)
            if _m:
                jwt_token = _m.group(0)

    b6_count = 0
    if jwt_token:
        for url in candidates[:10]:
            try:
                fs = idor_testing_advanced.test_jwt_manipulation(
                    url, jwt_token, cookies=a_cookies,
                )
                for f in fs:
                    confirmed.append(f)
                    b6_count += 1
            except Exception:
                pass
        try:
            cracked = idor_testing_advanced.crack_jwt_weak_secret(jwt_token)
            if cracked:
                suspicious.append({
                    "type": "idor-jwt-weak-secret",
                    "url": candidates[0] if candidates else "?",
                    "detail": f"JWT secret cracked: {cracked}",
                })
        except Exception:
            pass
    prog.step(f"B6 JWT → {b6_count} findings (token={'yes' if jwt_token else 'no'})")
    prog.done_phase()

    # ═══════════════════════════════════════════════════════════════
    # B7b. Query vs Body Conflict
    # ═══════════════════════════════════════════════════════════════
    prog = PhaseProgress("IDOR — B7 Query/Body Conflict", 2)
    b7b_count = 0
    for url in candidates[:15]:
        try:
            fs = idor_testing_advanced.test_query_body_conflict(
                url, own_id, victim_id,
                cookies=a_cookies, headers=a_headers,
            )
            for f in fs:
                suspicious.append(f)
                b7b_count += 1
        except Exception:
            pass
    prog.step(f"B7b query/body → {b7b_count} suspicious")
    prog.done_phase()

    # ═══════════════════════════════════════════════════════════════
    # B8. File Operations + Search + Pagination
    # ═══════════════════════════════════════════════════════════════
    prog = PhaseProgress("IDOR — B8 File/Search/Pagination", 3)
    file_urls = [u for u in candidates
                 if any(k in u.lower() for k in
                        ("file", "download", "upload", "attach", "media"))][:20]
    b8f_count = 0
    if file_urls:
        try:
            fs = idor_testing_advanced.test_file_operations(
                file_urls, own_id, victim_id, cookies=a_cookies,
            )
            for f in fs:
                confirmed.append(f)
                b8f_count += 1
        except Exception:
            pass
    prog.step(f"B8-file → {b8f_count} findings")

    search_urls = [u for u in candidates
                   if any(k in u.lower() for k in
                          ("search", "query", "find", "filter"))][:5]
    b8s_count = 0
    # Derive email prefix from A's session (e.g. "test" from "test@gmail.com")
    _email_a = (session_a or {}).get("email") or ""
    _prefix = _email_a.split("@")[0] if "@" in _email_a else (_email_a or "a")
    if not _prefix or len(_prefix) < 2:
        _prefix = "a"
    for surl in search_urls:
        try:
            fs = idor_testing_advanced.test_search_idor(
                surl, "q", _prefix, cookies=a_cookies,
                headers=a_headers,
            )
            for f in fs:
                suspicious.append(f)
                b8s_count += 1
        except Exception:
            pass
    prog.step(f"B8-search → {b8s_count} suspicious (prefix='{_prefix}')")

    b8p_count = 0
    for url in candidates[:10]:
        try:
            fs = idor_testing_advanced.test_pagination_enum(
                url, cookies=a_cookies, max_pages=10,
            )
            for f in fs:
                suspicious.append(f)
                b8p_count += 1
        except Exception:
            pass
    prog.step(f"B8-pagination → {b8p_count} suspicious")
    prog.done_phase()

    # ═══════════════════════════════════════════════════════════════
    # B9. Predictable IDs + Time Window
    # ═══════════════════════════════════════════════════════════════
    prog = PhaseProgress("IDOR — B9 Predictable IDs", 2)
    import re as _re_b9
    numeric_ids = []
    for url in candidates:
        for _m in _re_b9.finditer(r'/(\d{2,})', url):
            try:
                numeric_ids.append(int(_m.group(1)))
            except ValueError:
                pass
    b9p_count = 0
    if numeric_ids:
        try:
            pred = idor_testing_advanced.detect_predictable_ids(numeric_ids)
            if pred:
                suspicious.append({
                    "type": "idor-predictable-ids",
                    "url": candidates[0] if candidates else "?",
                    "detail": str(pred)[:200],
                })
                b9p_count = 1
        except Exception:
            pass
    prog.step(f"B9-predictable → analyzed {len(numeric_ids)} IDs, {b9p_count} findings")

    b9t_count = 0
    if own_id is not None and victim_id is not None:
        for url in candidates[:10]:
            try:
                fs = idor_testing_advanced.test_time_window(
                    url, "timestamp", 0, victim_id, own_id,
                    cookies=a_cookies, window_seconds=3600,
                )
                for f in fs:
                    suspicious.append(f)
                    b9t_count += 1
            except Exception:
                pass
    prog.step(f"B9-time-window → {b9t_count} suspicious")
    prog.done_phase()

    # ═══════════════════════════════════════════════════════════════
    # B10. Bypass Variants + Blind IDOR
    # ═══════════════════════════════════════════════════════════════
    prog = PhaseProgress("IDOR — B10 Bypass & Blind", 2)
    b10b_count = 0
    for url in candidates[:15]:
        try:
            fs = idor_testing_advanced.test_bypass_variants(
                url, cookies=a_cookies,
            )
            for f in fs:
                suspicious.append(f)
                b10b_count += 1
        except Exception:
            pass
    prog.step(f"B10-bypass → {b10b_count} suspicious")

    b10bl_count = 0
    if own_id is not None and victim_id is not None:
        for url in candidates[:10]:
            try:
                fs = idor_testing_advanced.test_blind_idor(
                    url, own_id, victim_id, cookies=a_cookies,
                )
                for f in fs:
                    suspicious.append(f)
                    b10bl_count += 1
            except Exception:
                pass
    prog.step(f"B10-blind → {b10bl_count} suspicious")
    prog.done_phase()

    # ── B11-B19. Advanced2 (config, lifecycle, graphql, auth, error, race, hpp) ──
    try:
        graphql_urls = []
        try:
            for gql_name in ("graphql_endpoints.txt", "graphql.txt"):
                gql_file = idir / gql_name
                if gql_file.exists():
                    for line in load_lines(gql_file):
                        if line and line not in graphql_urls:
                            graphql_urls.append(line)
        except Exception:
            pass
        adv2 = idor_testing_advanced2_fix.run_all_advanced2_v2(
            candidates=candidates,
            session_a=session_a,
            session_b=session_b,
            graphql_urls=graphql_urls,
            idir=idir,
            target_url=f"http://{domain}" if not domain.startswith("http") else domain,
        )
        if adv2.get("confirmed"):
            confirmed.extend(adv2["confirmed"])
        if adv2.get("suspicious"):
            suspicious.extend(adv2["suspicious"])
    except Exception as _e:
        log_warn(f"advanced2 failed: {_e}")

    # ── B10. Bypass checklist generation ──
    try:
        checklist = idor_testing_advanced.generate_bypass_checklist(idir, candidates)
        log_ok(f"Bypass checklist: {checklist}")
    except Exception:
        pass

    return {"confirmed": confirmed, "suspicious": suspicious}


def phase_idor(domain, workspace, PhaseProgress, log_info, log_ok, log_warn, scope=None):
    """Full IDOR phase."""
    idir = Path(workspace) / domain / "idor"
    idir.mkdir(parents=True, exist_ok=True)

    if scope is None:
        scope = GLOBAL_SCOPE

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
    candidates = set(extract_candidates(source_urls, target_domain=domain))
    prog.step(f"Level 1 (URLs) → {len(candidates)} candidates")

    # Level 2: JS mining
    if len(candidates) < 30 and js_files:
        js_endpoints = discover_from_js(source_urls, js_files)
        js_candidates = extract_candidates(js_endpoints, target_domain=domain)
        candidates.update(js_candidates)
        prog.step(f"Level 2 (JS) → +{len(js_candidates)} candidates")
    else:
        prog.step(f"Level 2 (JS) → skipped")

    # Level 3: API docs
    api_docs, api_doc_endpoints = discover_api_docs(domain)
    if api_doc_endpoints:
        candidates.update(extract_candidates(api_doc_endpoints, target_domain=domain))
    if api_docs:
        (idir / "api_docs.txt").write_text("\n".join(api_docs), encoding="utf-8")
    prog.step(f"Level 3 (API docs) → {len(api_docs)} docs")

    # Level 4: GraphQL
    gql_endpoints = discover_graphql(domain)
    if gql_endpoints:
        (idir / "graphql.txt").write_text("\n".join(gql_endpoints), encoding="utf-8")
    prog.step(f"Level 4 (GraphQL) → {len(gql_endpoints)} endpoints")

    # ── Level 5: Extended Collection (A1-A9) ──
    try:
        ext_res = phase_extended_collection(
            domain, workspace, PhaseProgress, log_info, log_ok, log_warn
        )
        if ext_res and ext_res.get("all"):
            for c in ext_res["all"]:
                if c.startswith("http"):
                    candidates.add(c)
            prog.step(f"Level 5 (Extended) → +{len(ext_res['all'])} candidates")
    except Exception as e:
        log_warn(f"Extended collection error: {e}")
        prog.step("Level 5 (Extended) → skipped")

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
        log_info, log_ok, log_warn, scope=scope
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
        # ── ADVANCED TESTING (B1-B19) — unauthenticated fallback ──
        adv_results = {"confirmed": [], "suspicious": []}
        if ADVANCED_AVAILABLE:
            log_info("Running advanced testing (unauthenticated mode, no sessions)...")
            try:
                adv_results = phase_advanced_testing(
                    domain, workspace, candidates_list,
                    session_a=None, session_b=None,
                    PhaseProgress=PhaseProgress,
                    log_info=log_info, log_ok=log_ok, log_warn=log_warn,
                    scope=scope,
                )
                if adv_results.get("confirmed"):
                    print()
                    print(f"{BOLD}{R}{'=' * 60}{RST}")
                    print(f"{BOLD}{R}  [!] {len(adv_results['confirmed'])} ADVANCED FINDINGS{RST}")
                    print(f"{BOLD}{R}{'=' * 60}{RST}")
                    for f in adv_results["confirmed"][:10]:
                        print(f"  {R}*{RST} {f.get('type', '?'):25} {f.get('url', '')[:70]}")
                    print()
            except Exception as e:
                log_warn(f"Advanced testing error: {e}")
        else:
            log_warn("Advanced testing modules not available")
        playbook = generate_playbook(idir, candidates_list,
                                      unauth_findings=unauth_results["confirmed"],
                                      auth_findings=adv_results.get("confirmed", []))
        log_ok(f"Playbook: {playbook}")
        return {
            "candidates": len(candidates_list),
            "unauth": unauth_results,
            "advanced": adv_results,
            "confirmed": unauth_results["confirmed"] + adv_results.get("confirmed", []),
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
    result_a = try_login(domain, creds_a["email"], creds_a["password"],
                         GLOBAL_LOGIN_URL, GLOBAL_LOGIN_JSON)
    session_a = None
    if result_a.get("success"):
        v = validate_session(domain, result_a)
        if v.get("valid"):
            session_a = {
                "cookies": result_a.get("cookies", ""),
                "token_headers": result_a.get("token_headers", {}),
                "user_id": v.get("user_id"),
                "email": creds_a["email"],
                "creds": creds_a,
            }
            _uid = v.get('user_id')
            if _uid is None:
                prog.step(f"Login A → session valid (endpoint={v.get('endpoint', '?')})")
            else:
                prog.step(f"Login A → user_id={_uid}")
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
    result_b = try_login(domain, creds_b["email"], creds_b["password"],
                         GLOBAL_LOGIN_URL, GLOBAL_LOGIN_JSON)
    session_b = None
    if result_b.get("success"):
        v = validate_session(domain, result_b)
        if v.get("valid"):
            session_b = {
                "cookies": result_b.get("cookies", ""),
                "token_headers": result_b.get("token_headers", {}),
                "user_id": v.get("user_id"),
                "email": creds_b["email"],
                "creds": creds_b,
            }
            _uid = v.get('user_id')
            if _uid is None:
                prog.step(f"Login B → session valid (endpoint={v.get('endpoint', '?')})")
            else:
                prog.step(f"Login B → user_id={_uid}")
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

    # ── ADVANCED TESTING (B1-B19) with REAL sessions ──
    adv_results = {"confirmed": [], "suspicious": []}
    if ADVANCED_AVAILABLE:
        log_info("Starting advanced testing with authenticated sessions...")
        try:
            adv_results = phase_advanced_testing(
                domain, workspace, candidates_list,
                session_a=session_a, session_b=session_b,
                PhaseProgress=PhaseProgress,
                log_info=log_info, log_ok=log_ok, log_warn=log_warn,
                scope=scope,
            )
            if adv_results.get("confirmed"):
                print()
                print(f"{BOLD}{R}{'=' * 60}{RST}")
                print(f"{BOLD}{R}  [!] {len(adv_results['confirmed'])} ADVANCED FINDINGS{RST}")
                print(f"{BOLD}{R}{'=' * 60}{RST}")
                for f in adv_results["confirmed"][:10]:
                    print(f"  {R}*{RST} {f.get('type', '?'):25} {f.get('url', '')[:70]}")
                print()
        except Exception as e:
            log_warn(f"Advanced testing error: {e}")
    else:
        log_warn("Advanced testing modules not available")

    # ===== STEP 6: AUTH TESTING =====
    auth_results = phase_authenticated_testing(
        domain, workspace, candidates_list, session_a, session_b,
        PhaseProgress, log_info, log_ok, log_warn, scope=scope
    )

    all_confirmed = (unauth_results["confirmed"] +
                     auth_results["confirmed"] +
                     adv_results.get("confirmed", []))
    all_suspicious = adv_results.get("suspicious", [])

    playbook = generate_playbook(idir, candidates_list,
                                  unauth_findings=unauth_results["confirmed"],
                                  auth_findings=auth_results["confirmed"])

    # ═══════════════════════════════════════════════════════════════
    # AI BYPASS ENGINE — auto-run on findings that got blocked
    # ═══════════════════════════════════════════════════════════════
    try:
        from ai_bypass import run_for_findings, save_results
        import clicker as _ck
        _api_key = getattr(_ck, "api_keys_global", {}).get("FREELLMAPI_API_KEY", "")
        # Fallback: read from env file
        if not _api_key:
            from pathlib import Path as _P
            _env = _P("clicker_api.env")
            if _env.exists():
                for _line in _env.read_text().splitlines():
                    if _line.startswith("FREELLMAPI_API_KEY="):
                        _api_key = _line.split("=", 1)[1].strip().strip('"').strip("'")
                        break
        if _api_key:
            # Gather all findings from this phase
            _all_findings = []
            for _k in ("auth_findings", "unauth_findings", "advanced_findings"):
                _v = locals().get(_k, [])
                if isinstance(_v, list):
                    _all_findings.extend(_v)
            # Also from the result dict
            _res_dict = locals().get("result", {})
            if isinstance(_res_dict, dict):
                for _k in ("confirmed", "suspicious", "auth_confirmed", "unauth_confirmed"):
                    _v = _res_dict.get(_k, [])
                    if isinstance(_v, list):
                        _all_findings.extend(_v)
            if _all_findings:
                log_info(f"[AI-BYPASS] Analyzing {len(_all_findings)} findings for blocks...")
                _waf = getattr(_ck, "GLOBAL_WAF_TYPE", "unknown")
                _byp_res = run_for_findings(
                    _all_findings, _waf, [], _api_key,
                    cookies={}, headers={}, verbose=True,
                )
                if _byp_res.get("successes"):
                    log_ok(f"[AI-BYPASS] {len(_byp_res['successes'])} successful bypasses!")
                save_results(domain, workspace, _byp_res, verbose=True)
    except Exception as _e:
        log_warn(f"[AI-BYPASS] skipped: {_e}")

    return {
        "candidates": len(candidates_list),
        "unauth": unauth_results,
        "auth": auth_results,
        "advanced_confirmed": adv_results.get("confirmed", []),
        "advanced_suspicious": all_suspicious,
        "confirmed": all_confirmed,
        "playbook": str(playbook),
        "auth_tested": True,
    }
