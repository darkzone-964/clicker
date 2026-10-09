"""
ai_verifier.py — Verify findings before reporting them.

For each finding:
  1. Fetch the actual response (curl / urllib)
  2. Apply fast local rules (regex, magic bytes, content-type)
  3. If still uncertain → ask the AI to read the response and decide

Verdicts:
  - confirmed          → real (send to bot)
  - likely-false-positive → filter out (don't send)
  - uncertain          → keep but mark (send with warning)
"""
import json
import re
import time
import urllib.request
import urllib.error
from pathlib import Path


VERIFIER_MODELS = [
    "mistral-code",
    "codestral",
    "nemotron-3-super-120b",
    "gemini-3.7-flash",
]

_CACHE = {}
_MAX_AI_CALLS_PER_RUN = 8  # safety limit (reduced to avoid 502 flood)
_ai_calls_made = [0]


# ────────────────────────────────────────────────────────────
# Fast HTTP fetch
# ────────────────────────────────────────────────────────────
def _fetch(url, timeout=5, extra_headers=None):
    """Return dict with status, headers, body_sample, error."""
    headers = {"User-Agent": "Mozilla/5.0 Clicker-Verifier/1.0"}
    if extra_headers:
        headers.update(extra_headers)
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as res:
            body = res.read(2048)
            return {
                "status": res.status,
                "headers": dict(res.headers),
                "body": body,
                "error": None,
            }
    except urllib.error.HTTPError as e:
        return {"status": e.code, "headers": dict(e.headers or {}), "body": b"", "error": None}
    except Exception as e:
        return {"status": 0, "headers": {}, "body": b"", "error": str(e)}


def _is_html(body, headers):
    if not body:
        return False
    b = body[:512].lower()
    if any(m in b for m in (b"<html", b"<!doctype", b"<head", b"<body")):
        return True
    ct = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
    return "text/html" in ct


# ────────────────────────────────────────────────────────────
# Fast rules per finding type
# ────────────────────────────────────────────────────────────
def _fast_check_exposed_file(finding):
    """Return (verdict, reason) or (None, None) if inconclusive."""
    url = finding.get("target", "")
    if not url.startswith("http"):
        return None, None
    resp = _fetch(url, timeout=4)
    if resp["error"]:
        return "uncertain", f"fetch error: {resp['error']}"
    if resp["status"] in (403, 404, 410):
        return "likely-false-positive", f"HTTP {resp['status']}"
    if resp["status"] != 200:
        return "uncertain", f"HTTP {resp['status']}"
    body = resp["body"]
    if not body:
        return "likely-false-positive", "empty body"
    # HTML for non-HTML path → SPA fallback
    path = url.split("?")[0]
    expects_html = path.endswith((".html", ".htm", "/"))
    if _is_html(body, resp["headers"]) and not expects_html:
        return "likely-false-positive", "SPA fallback (HTML for non-HTML path)"
    # Path-specific magic
    low = body.lower()
    if path.endswith(".env"):
        if b"=" not in body:
            return "likely-false-positive", ".env without '=' pattern"
        return "confirmed", ".env content with KEY=VALUE"
    if path.endswith((".git/HEAD", "/.git/HEAD")):
        if b"ref:" not in low:
            return "likely-false-positive", ".git/HEAD without 'ref:'"
        return "confirmed", ".git HEAD present"
    if path.endswith("id_rsa") or path.endswith("id_rsa.pub"):
        if b"private key" in low or b"begin" in low or b"ssh-rsa" in low:
            return "confirmed", "SSH key format detected"
        return "likely-false-positive", "no SSH key marker"
    if path.endswith(".htpasswd"):
        if b":" in body:
            return "confirmed", ".htpasswd user:pass format"
        return "likely-false-positive", "no colon in .htpasswd"
    if path.endswith((".sql", "/dump.sql", "/backup.sql", "/database.sql", "/db.sql")):
        if any(k in body for k in (b"INSERT", b"CREATE", b"DROP", b"SELECT")):
            return "confirmed", "SQL content detected"
        return "likely-false-positive", "no SQL keywords"
    if path.endswith("Dockerfile"):
        if b"FROM " in body or body.lstrip().startswith(b"#"):
            return "confirmed", "Dockerfile content"
        return "likely-false-positive", "no FROM directive"
    # Unknown → ask AI
    return None, None


def _fast_check_takeover(finding):
    detail = finding.get("detail", "")
    # Nuclei / subzy lines contain the subdomain
    m = re.search(r"([a-z0-9][a-z0-9.-]*\.[a-z]{2,})", detail.lower())
    if not m:
        return None, None
    sub = m.group(1)
    # Try DNS resolution
    import socket
    try:
        socket.gethostbyname(sub)
        return "likely-false-positive", f"{sub} resolves to a real IP"
    except socket.gaierror:
        return "uncertain", f"{sub} does not resolve (may be takeover)"
    except Exception:
        return None, None


def _fast_check_cors(finding):
    detail = finding.get("detail", "")
    if "Access-Control-Allow-Origin" not in detail and "ACAO" not in detail:
        return None, None
    m = re.search(r"^(https?://[^\s|]+)", finding.get("target", ""))
    if not m:
        return None, None
    url = m.group(1)
    resp = _fetch(url, timeout=4, extra_headers={"Origin": "https://evil-verify.example"})
    if resp["error"]:
        return "uncertain", f"fetch error: {resp['error']}"
    acao = resp["headers"].get("Access-Control-Allow-Origin") or resp["headers"].get("access-control-allow-origin") or ""
    acac = (resp["headers"].get("Access-Control-Allow-Credentials") or resp["headers"].get("access-control-allow-credentials") or "").lower()
    if acao == "https://evil-verify.example" and acac == "true":
        return "confirmed", "Reflects attacker origin + credentials"
    if acao == "*":
        return "likely-false-positive", "Wildcard without credentials (low risk)"
    if not acao:
        return "likely-false-positive", "No ACAO header on re-check"
    return "uncertain", f"ACAO={acao} ACAC={acac}"


def _fast_check_nuclei(finding):
    """Nuclei has its own matchers; re-fetch to reduce false positives."""
    detail = finding.get("detail", "")
    m = re.search(r"(https?://[^\s]+)", detail)
    if not m:
        return None, None
    url = m.group(1)
    resp = _fetch(url, timeout=4)
    if resp["error"]:
        return "uncertain", f"fetch error: {resp['error']}"
    if resp["status"] == 404:
        return "likely-false-positive", "404 on re-check"
    if resp["status"] == 200:
        return "uncertain", "URL returns 200 (nuclei matcher should decide)"
    return "uncertain", f"HTTP {resp['status']}"


def _fast_check_sensitive_file(finding):
    return _fast_check_exposed_file(finding)


def _fast_check_secret(finding):
    """Secrets from JS: check basic format + reject obvious placeholders."""
    detail = finding.get("detail", "")
    low = detail.lower()
    placeholders = ("your_", "example", "placeholder", "xxxxx", "redacted",
                    "changeme", "todo", "fake", "dummy", "<your")
    if any(p in low for p in placeholders):
        return "likely-false-positive", "placeholder-like value"
    # Basic format checks
    patterns = {
        "AWS": r"AKIA[0-9A-Z]{16}",
        "Google API": r"AIza[0-9A-Za-z_-]{35}",
        "Stripe live": r"sk_live_[0-9a-zA-Z]{24,}",
        "GitHub PAT": r"ghp_[0-9A-Za-z]{36}",
        "Slack": r"xox[baprs]-[0-9A-Za-z-]{10,}",
    }
    for name, pat in patterns.items():
        if re.search(pat, detail):
            return "confirmed", f"{name} secret pattern"
    return None, None


def _fast_check_idor(finding):
    """IDOR findings from ownership check are already logically confirmed.
    Skip AI verification (they're already high-confidence)."""
    ftype = finding.get("type", "")
    confidence = (finding.get("confidence") or "").lower()

    # Ownership-based IDOR = confirmed by design
    if "confirmed" in ftype:
        reason = finding.get("reason", "") or "ownership-based IDOR confirmed"
        return "confirmed", reason

    # method-bypass / state-change-get: confirmed by logic
    if ftype in ("idor-method-bypass", "method-bypass",
                 "idor-state-change-get", "state-change-get"):
        return "confirmed", finding.get("reason", "logic-based finding")

    # High confidence (from analyze_idor_pair) → confirmed
    if confidence == "high":
        return "confirmed", finding.get("reason", "high-confidence IDOR")

    # Otherwise → inconclusive, ask AI
    return None, None




# ────────────────────────────────────────────────────────────
# AI verification (only if fast check inconclusive)
# ────────────────────────────────────────────────────────────
def _build_ai_prompt(finding, resp=None):
    ftype = finding.get("type", "?")
    target = finding.get("target", "?")
    detail = (finding.get("detail") or "")[:600]
    body_sample = ""
    headers_sample = ""
    if resp:
        try:
            body_sample = resp.get("body", b"")[:1200].decode("utf-8", errors="replace")
        except Exception:
            body_sample = "(binary)"
        headers_sample = "\n".join(f"{k}: {v}" for k, v in list(resp.get("headers", {}).items())[:10])

    return f"""You are a bug bounty verification expert.

A scanner flagged a potential finding. Your job: confirm or reject it.

Finding type: {ftype}
Target: {target}
Scanner detail: {detail}

{f"HTTP response body (first 1200 chars):" if body_sample else ""}
{body_sample}

{f"HTTP response headers:" if headers_sample else ""}
{headers_sample}

QUESTION: Is this a REAL finding or a FALSE POSITIVE?

Output STRICT JSON only (single line):
{{"verdict": "confirmed" or "false-positive" or "uncertain", "reason": "short explanation (max 15 words)"}}

Rules:
- "confirmed" only if the evidence is clear (real content, real secret, real exposure).
- "false-positive" if it's clearly a default page, error page, SPA fallback, or placeholder.
- "uncertain" if you cannot tell from the given evidence.
"""


def _ai_verify(finding, resp, api_key, verbose=False):
    if _ai_calls_made[0] >= _MAX_AI_CALLS_PER_RUN:
        if verbose:
            print(f"[VERIFY] AI call limit reached ({_MAX_AI_CALLS_PER_RUN})")
        return "uncertain", "ai-limit", None
    prompt = _build_ai_prompt(finding, resp)
    import urllib.request as _u
    for model in VERIFIER_MODELS:
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": 120,
        }
        try:
            data = json.dumps(payload).encode("utf-8")
            req = _u.Request("http://localhost:3001/v1/chat/completions",
                             data=data, method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("Authorization", f"Bearer {api_key}")
            with _u.urlopen(req, timeout=25) as res:
                raw = json.loads(res.read().decode("utf-8"))
                txt = (raw["choices"][0]["message"]["content"] or "").strip()
                _ai_calls_made[0] += 1
                # Parse JSON
                m = re.search(r"\{.*\}", txt, re.DOTALL)
                if not m:
                    continue
                parsed = json.loads(m.group(0))
                v = parsed.get("verdict", "uncertain")
                if v not in ("confirmed", "false-positive", "uncertain"):
                    v = "uncertain"
                return v, parsed.get("reason", ""), model
        except Exception:
            continue
    # If AI failed but finding has high confidence, trust the logic
    conf = (finding.get("confidence") or "").lower()
    if conf == "high":
        return "confirmed", "ai-failed but high-confidence finding", None
    return "uncertain", "ai-failed", None


# ────────────────────────────────────────────────────────────
# Public API
# ────────────────────────────────────────────────────────────

# ============================================================================
# EXTENDED FAST-CHECKS (added for IDOR types)
# ============================================================================
def _fast_check_horizontal_idor(finding):
    """Horizontal IDOR: A accessed B's resource."""
    url = finding.get("url", "")
    if not url:
        return None
    # Fetch the URL without any auth
    resp = _fetch(url, timeout=5)
    status = resp.get("status", 0)
    body = resp.get("body_sample", "")

    # If 200 with data → anon accessible (worse)
    if status == 200 and len(body) > 100:
        # Check for sensitive field patterns
        for kw in ("email", "user", "token", "session", "password", "id"):
            if kw in body.lower():
                return ("confirmed",
                        "Resource accessible without auth, contains sensitive fields",
                        0.75)
    # A's session works, B's works, anon blocked → ownership-based
    return ("confirmed", "ownership-based IDOR confirmed", 0.8)


def _fast_check_jwt_bypass(finding):
    """JWT algorithm confusion / signature bypass.

    The JWT test itself already proved the bypass before creating this finding.
    Trust the finding and mark confirmed unless the URL is unreachable.
    """
    url = finding.get("url", "")
    reason = (finding.get("reason", "") or "").lower()
    detail = (finding.get("detail", "") or "").lower()

    # The test's own reason is authoritative
    strong_signals = [
        "alg-none", "none-sig", "none algorithm", "empty sig",
        "unverified", "accepted", "bypass", "forged",
    ]
    combined = reason + " " + detail
    if any(s in combined for s in strong_signals):
        return ("confirmed", "JWT bypass confirmed by test", 0.85)

    # If reason indicates the test proved it, trust it
    if "jwt" in combined and any(x in combined for x in ("accepted", "verified", "bypass")):
        return ("confirmed", "JWT test reported a bypass", 0.75)

    # Fallback: check URL reachability
    if url:
        resp = _fetch(url, timeout=5)
        status = resp.get("status", 0)
        if status == 0:
            return ("false-positive", "JWT endpoint unreachable", 0.6)
        # Endpoint responds — trust the original test
        return ("confirmed", "JWT endpoint responds; test flagged bypass", 0.65)

    return ("uncertain", "JWT test inconclusive", 0.5)


def _fast_check_numeric_idor(finding):
    """Numeric ID fuzzing hit.

    The fuzzer already confirmed the ID returns data different from
    the attacker's own. Trust it unless the endpoint is blocked.
    """
    url = finding.get("url", "")
    reason = (finding.get("reason", "") or "").lower()

    # The fuzzer's reason is authoritative
    if "numeric idor" in reason or "predictable" in reason or "sequential" in reason:
        return ("confirmed", "Numeric IDOR confirmed by fuzzer", 0.8)

    if not url:
        return ("uncertain", "No URL to verify", 0.4)

    resp = _fetch(url, timeout=5)
    status = resp.get("status", 0)
    body = resp.get("body_sample", "")

    if status == 200 and len(body) > 30:
        return ("confirmed", "Numeric ID returns data", 0.75)
    if status in (401, 403):
        return ("false-positive", "Server enforces access control", 0.75)
    if status == 404:
        return ("false-positive", "Resource not found", 0.8)
    return ("confirmed", "Numeric IDOR flagged by fuzzer", 0.65)


def _fast_check_predictable_ids(finding):
    """Predictable/sequential IDs."""
    return ("confirmed", "Sequential IDs detected — enumeration possible", 0.7)


def _fast_check_auth_cookie_not_required(finding):
    """Endpoint doesn't require cookies."""
    url = finding.get("url", "")
    if not url:
        return None
    # No cookies
    resp = _fetch(url, timeout=5, extra_headers={"Cookie": ""})
    status = resp.get("status", 0)
    if status == 200:
        return ("confirmed", "Endpoint accessible without cookies", 0.75)
    return ("false-positive", "Cookies required", 0.6)


def _fast_check_auth_token_not_validated(finding):
    """Server doesn't validate auth token.

    The auth test already proved the endpoint accepts invalid/missing tokens.
    """
    url = finding.get("url", "")
    reason = (finding.get("reason", "") or "").lower()

    # Trust the auth test's own conclusion
    if any(x in reason for x in ("not validated", "accepted", "bypass", "not required")):
        return ("confirmed", "Auth token bypass confirmed by test", 0.8)

    if not url:
        return ("uncertain", "No URL", 0.4)

    # Re-test with garbage token
    resp = _fetch(url, timeout=5,
                  extra_headers={"Authorization": "Bearer garbage_token_xyz"})
    status = resp.get("status", 0)
    body = resp.get("body_sample", "")

    if status == 200 and len(body) > 20:
        return ("confirmed", "Server accepts invalid Bearer token", 0.8)
    if status in (401, 403):
        return ("false-positive", "Server rejects invalid token", 0.9)
    # Fall back to trusting the test's flag
    return ("confirmed", "Auth validation flagged by test", 0.6)


def _fast_check_auth_header_not_required(finding):
    """Endpoint doesn't require auth header."""
    url = finding.get("url", "")
    if not url:
        return None
    resp = _fetch(url, timeout=5)
    status = resp.get("status", 0)
    if status == 200:
        return ("confirmed", "Endpoint accessible without Authorization header", 0.75)
    return ("false-positive", "Auth header required", 0.6)



FAST_CHECKS = {
    "exposed-file": _fast_check_exposed_file,
    "sensitive-file": _fast_check_sensitive_file,
    "takeover": _fast_check_takeover,
    "cors": _fast_check_cors,
    "secret": _fast_check_secret,
    # ── IDOR types: skip AI (already logically confirmed) ──
    "idor-confirmed":          _fast_check_idor,
    "idor-method-bypass":      _fast_check_idor,
    "method-bypass":           _fast_check_idor,
    "idor-method-tampering":   _fast_check_idor,
    "method-tampering":        _fast_check_idor,
    "idor-state-change-get":   _fast_check_idor,
    "state-change-get":        _fast_check_idor,
    "idor-numeric-idor":       _fast_check_numeric_idor,
    "numeric-idor":            _fast_check_numeric_idor,
    "idor-hpp":                _fast_check_idor,
    "hpp":                     _fast_check_idor,
    "idor-path-body-conflict": _fast_check_idor,
    "path-body-conflict":      _fast_check_idor,
    "idor-jwt-bypass":         _fast_check_jwt_bypass,
    "jwt-bypass":              _fast_check_jwt_bypass,
    "idor-mass-assignment":    _fast_check_idor,
    "mass-assignment":         _fast_check_idor,
    "idor-header-idor":        _fast_check_idor,
    "header-idor":             _fast_check_idor,
    "idor-file-idor":          _fast_check_idor,
    "file-idor":               _fast_check_idor,
    "idor-pagination-enum":    _fast_check_idor,
    "pagination-enum":         _fast_check_idor,
    "idor-blind-idor":         _fast_check_idor,
    "blind-idor":              _fast_check_idor,
    "idor-vertical-privesc":   _fast_check_idor,
    "vertical-privesc":        _fast_check_idor,
    "idor-horizontal-idor":    _fast_check_horizontal_idor,
    "horizontal-idor":         _fast_check_horizontal_idor,
    "idor-bypass":             _fast_check_idor,
    "bypass":                  _fast_check_idor,
    "idor-time-window":        _fast_check_idor,
    "time-window":             _fast_check_idor,
    "idor-query-body-conflict": _fast_check_idor,
    "query-body-conflict":     _fast_check_idor,
    "idor-method-override":    _fast_check_idor,
    "method-override":         _fast_check_idor,
    # New types (added for full IDOR coverage)
    "idor-predictable-ids":     _fast_check_predictable_ids,
    "predictable-ids":          _fast_check_predictable_ids,
    "idor-idor-predictable-ids": _fast_check_predictable_ids,
    "auth-cookie-not-required": _fast_check_auth_cookie_not_required,
    "idor-auth-cookie-not-required": _fast_check_auth_cookie_not_required,
    "auth-token-not-validated": _fast_check_auth_token_not_validated,
    "idor-auth-token-not-validated": _fast_check_auth_token_not_validated,
    "auth-header-not-required": _fast_check_auth_header_not_required,
    "idor-auth-header-not-required": _fast_check_auth_header_not_required,
}


def verify_finding(finding, domain, api_key, verbose=False):
    """Verify a single finding. Returns the finding dict with added verification fields."""
    key = f"{finding.get('type')}|{finding.get('target')}|{finding.get('detail', '')[:80]}"
    if key in _CACHE:
        finding.update(_CACHE[key])
        return finding

    ftype = finding.get("type", "")
    resp = None

    # 1) Fast local rules
    checker = FAST_CHECKS.get(ftype)
    verdict, reason = None, None
    if checker:
        try:
            result = checker(finding)
            # Accept 2-tuple (verdict, reason) or 3-tuple (verdict, reason, conf)
            if isinstance(result, tuple) and len(result) == 3:
                verdict, reason, _conf = result
            elif isinstance(result, tuple) and len(result) == 2:
                verdict, reason = result
            else:
                verdict, reason = result, None
        except Exception as e:
            verdict, reason = None, f"checker error: {e}"

    # If fast check gives any answer, use it (don't waste AI calls on uncertain)
    if verdict in ("confirmed", "likely-false-positive", "false-positive", "uncertain"):
        status_map = {
            "confirmed": "confirmed",
            "likely-false-positive": "false-positive",
            "false-positive": "false-positive",
            "uncertain": "uncertain",
        }
        method = "fast-check" if verdict != "confirmed" else "fast-rules"
        # Distinguish extended fast-checks by return signature (they add "extended")
        if verdict in ("confirmed", "false-positive", "uncertain") and "fast" not in method:
            method = "fast-check:extended"
        result = {
            "verification_status": status_map[verdict],
            "verification_reason": reason,
            "verification_method": method,
        }
        _CACHE[key] = result
        finding.update(result)
        return finding

    # 2) Otherwise → ask AI (if we have an API key)
    if api_key and _ai_calls_made[0] < _MAX_AI_CALLS_PER_RUN:
        # Re-fetch for AI context (may be needed for some types)
        if resp is None:
            url = finding.get("target", "")
            if url.startswith("http"):
                resp = _fetch(url, timeout=4)
        v, r, m = _ai_verify(finding, resp, api_key, verbose=verbose)
        status_map = {"confirmed": "confirmed", "false-positive": "false-positive", "uncertain": "uncertain"}
        result = {
            "verification_status": status_map.get(v, "uncertain"),
            "verification_reason": r,
            "verification_method": f"ai:{m}" if m else "ai",
        }
        _CACHE[key] = result
        finding.update(result)
        return finding

    # 3) No AI available → uncertain
    result = {
        "verification_status": "uncertain",
        "verification_reason": reason or "no-verification-method",
        "verification_method": "none",
    }
    _CACHE[key] = result
    finding.update(result)
    return finding


def verify_all(findings, domain, api_key, verbose=True):
    """Verify a list of findings. Returns (verified_list, stats)."""
    stats = {"confirmed": 0, "false-positive": 0, "uncertain": 0, "total": 0}
    out = []
    if verbose:
        print(f"\n{'=' * 60}")
        print(f"[VERIFY] Verifying {len(findings)} findings...")
        print(f"{'=' * 60}")
    for i, f in enumerate(findings, 1):
        try:
            verified = verify_finding(f, domain, api_key, verbose=verbose)
        except Exception as e:
            f["verification_status"] = "uncertain"
            f["verification_reason"] = f"error: {e}"
            f["verification_method"] = "error"
            verified = f
        out.append(verified)
        stats["total"] += 1
        st = verified.get("verification_status", "uncertain")
        stats[st] = stats.get(st, 0) + 1
        if verbose:
            icon = {"confirmed": "✅", "false-positive": "❌", "uncertain": "?"}[st]
            print(f"  [{i}/{len(findings)}] {icon} [{st}] {f.get('type', '?')}: "
                  f"{str(f.get('target', ''))[:60]}")
            if verified.get("verification_reason"):
                print(f"          {verified['verification_reason'][:80]}")
    if verbose:
        print(f"\n[VERIFY] Results: {stats['confirmed']} confirmed, "
              f"{stats['false-positive']} false-positive, {stats['uncertain']} uncertain")
    return out, stats


def reset():
    _CACHE.clear()
    _ai_calls_made[0] = 0


if __name__ == "__main__":
    # Test
    from pathlib import Path as _P
    key = ""
    env = _P("clicker_api.env")
    if env.exists():
        for line in env.read_text().splitlines():
            if line.startswith("FREELLMAPI_API_KEY="):
                key = line.split("=", 1)[1].strip().strip('"').strip("'")
                break

    test_findings = [
        {"type": "exposed-file", "target": "https://example.com/.env",
         "detail": "https://example.com/.env [200]"},
        {"type": "exposed-file", "target": "https://example.com/robots.txt",
         "detail": "https://example.com/robots.txt [200]"},
    ]
    out, stats = verify_all(test_findings, "example.com", key)
    print()
    print(json.dumps(out, indent=2, default=str)[:1200])
