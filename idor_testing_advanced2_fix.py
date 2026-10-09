"""
Patch for idor_testing_advanced2.py — Make ALL techniques work.

Fixes:
  - B13: Read graphql endpoints from correct file
  - B11/B12: Test even without keywords (broader)
  - B14: Test on more URLs
  - B15: Move findings to confirmed (they're real findings)
  - B18: Test more URLs
  - B19: Test more URLs
  - Show detailed output for each technique
"""
import json
import re
import time
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from idor_utils import (
    C, G, Y, R, M, BOLD, RST, DIM,
    curl_request, fetch, load_lines, save_lines,
    run_tool, tool_available,
)


# ── Reuse helpers from original ──
from idor_testing_advanced2 import (
    INFRA_KEYWORDS, INFRA_SENSITIVE_KEYS,
    ERROR_MARKERS,
    test_config_idor, test_lifecycle_mismatch, test_graphql_nested,
    test_auth_validation_logic, test_error_based_disclosure,
    test_race_condition, test_hpp_url_and_body,
    _extract_url_id, _is_sensitive_field,
)


# ═══════════════════════════════════════════════════════════════════
# B15 quality filter — remove false positives from HTML error pages
# ═══════════════════════════════════════════════════════════════════
_GENERIC_ERROR_WORDS = {
    # English words commonly appearing in error messages (NOT params)
    "path", "url", "method", "endpoint", "error", "request", "response",
    "page", "file", "data", "body", "header", "route", "handler",
    "not", "found", "bad", "invalid", "unknown", "unexpected", "missing",
    "message", "server", "client", "resource", "action", "type",
    "format", "content", "value", "name", "string", "number", "object",
    "array", "list", "field", "input", "output", "code", "status",
    "detail", "info", "reason", "cause", "source", "target",
}


def _is_likely_real_param(param):
    """
    Decide whether a regex match is likely a real parameter name.
    Filters generic English words; keeps names that look like:
      - camelCase           (userId, accountId)
      - snake_case          (user_id, account_id)
      - ends with known ID/key suffix (id, ids, key, token, uid, ...)
    """
    if not param or len(param) < 3:
        return False
    low = param.lower()
    if low in _GENERIC_ERROR_WORDS:
        return False
    # camelCase (has uppercase after first char)
    if len(param) > 1 and any(c.isupper() for c in param[1:]):
        return True
    # snake_case
    if "_" in param:
        return True
    # known suffixes
    for sfx in ("id", "ids", "key", "keys", "token", "tokens",
                "uid", "uuid", "guid", "sid", "ref", "slug"):
        if low.endswith(sfx) and len(low) > len(sfx):
            return True
    # known prefixes
    for pfx in ("user", "account", "order", "product", "item",
                "cart", "customer", "owner", "admin", "session",
                "invoice", "payment", "ticket", "project"):
        if low.startswith(pfx):
            return True
    return False



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




def run_all_advanced2_v2(candidates, session_a, session_b, graphql_urls, idir,
                          target_url=None, api_token=None, verbose=True):
    """
    Enhanced version: every technique ACTUALLY runs and reports
    what it tested and what it found.
    """
    idir = Path(idir)
    idir.mkdir(parents=True, exist_ok=True)

    confirmed = []
    suspicious = []
    diagnostics = {}  # technique → (tested, found)

    a_uid = (session_a or {}).get("user_id")
    b_uid = (session_b or {}).get("user_id")
    a_cookies = (session_a or {}).get("cookies")
    a_headers = (session_a or {}).get("token_headers", {})

    print(f"\n{BOLD}{C}{'=' * 60}{RST}")
    print(f"{BOLD}{C}  IDOR Advanced Testing — Full Suite (B11-B19){RST}")
    print(f"{BOLD}{C}{'=' * 60}{RST}")
    print(f"{DIM}  User A: uid={a_uid} | User B: uid={b_uid}{RST}")
    print(f"{DIM}  Candidates: {len(candidates)}{RST}")
    print(f"{DIM}  GraphQL endpoints: {len(graphql_urls)}{RST}\n")

    # ═══════════════════════════════════════════════════════════
    # B11. Configuration & Infrastructure IDOR
    # ═══════════════════════════════════════════════════════════
    print(f"{BOLD}[B11] Configuration & Infrastructure IDOR{RST}")
    infra_candidates = [u for u in candidates
                        if any(k in u.lower() for k in INFRA_KEYWORDS)]

    # Broaden: if no keyword matches, test all candidates for path-based config access
    if not infra_candidates:
        infra_candidates = candidates[:30]
        print(f"    {DIM}No keyword matches — testing first 30 URLs broadly{RST}")

    b11_count = 0
    tested_b11 = 0
    for url in infra_candidates[:30]:
        tested_b11 += 1
        try:
            fs = test_config_idor(url, a_uid, b_uid, cookies=a_cookies, headers=a_headers)
            for f in fs:
                confirmed.append(f)
                b11_count += 1
        except Exception as e:
            if verbose:
                print(f"    {R}[!]{RST} B11 error on {url[:50]}: {e}")
    diagnostics["B11"] = (tested_b11, b11_count)
    print(f"    {G}+{RST} Tested: {tested_b11} | Findings: {b11_count}")

    # ═══════════════════════════════════════════════════════════
    # B12. Lifecycle State Mismatch
    # ═══════════════════════════════════════════════════════════
    print(f"{BOLD}[B12] Lifecycle State Mismatch{RST}")
    lifecycle_candidates = [u for u in candidates
                            if any(k in u.lower() for k in
                                   ("delete", "archive", "expire", "inactive",
                                    "draft", "revoke", "disable", "deactivat"))]

    # Broaden: test all
    if not lifecycle_candidates:
        lifecycle_candidates = candidates[:20]
        print(f"    {DIM}No lifecycle URLs found — testing first 20 broadly{RST}")

    b12_count = 0
    tested_b12 = 0
    for url in lifecycle_candidates[:20]:
        tested_b12 += 1
        try:
            fs = test_lifecycle_mismatch(url, cookies=a_cookies, headers=a_headers)
            for f in fs:
                suspicious.append(f)
                b12_count += 1
        except Exception:
            pass
    diagnostics["B12"] = (tested_b12, b12_count)
    print(f"    {G}+{RST} Tested: {tested_b12} | Findings: {b12_count}")

    # ═══════════════════════════════════════════════════════════
    # B13. GraphQL Nested Data
    # ═══════════════════════════════════════════════════════════
    print(f"{BOLD}[B13] GraphQL Nested Data{RST}")
    print(f"    {DIM}GraphQL endpoints: {graphql_urls[:3] if graphql_urls else '(none)'}{RST}")

    b13_count = 0
    tested_b13 = 0
    if graphql_urls:
        for gql_url in graphql_urls[:5]:
            tested_b13 += 1
            try:
                fs = test_graphql_nested([gql_url], b_uid, cookies=a_cookies, headers=a_headers)
                for f in fs:
                    confirmed.append(f)
                    b13_count += 1
            except Exception as e:
                if verbose:
                    print(f"    {R}[!]{RST} B13 error on {gql_url[:50]}: {e}")
    else:
        print(f"    {Y}[!]{RST} No GraphQL endpoints passed — skipping")
    diagnostics["B13"] = (tested_b13, b13_count)
    print(f"    {G}+{RST} Tested: {tested_b13} | Findings: {b13_count}")

    # ═══════════════════════════════════════════════════════════
    # B14. Auth Validation Logic
    # ═══════════════════════════════════════════════════════════
    print(f"{BOLD}[B14] Auth Validation Logic{RST}")
    # Test on authenticated-relevant endpoints
    auth_candidates = [u for u in candidates
                       if any(k in u.lower() for k in
                              ("user", "account", "profile", "me", "whoami",
                               "basket", "cart", "order", "private"))]
    if not auth_candidates:
        auth_candidates = candidates[:20]

    b14_count = 0
    tested_b14 = 0
    for url in auth_candidates[:20]:
        tested_b14 += 1
        try:
            fs = test_auth_validation_logic(url, session_a, a_uid, b_uid,
                                            cookies=a_cookies, headers=a_headers)
            for f in fs:
                suspicious.append(f)
                b14_count += 1
        except Exception:
            pass
    diagnostics["B14"] = (tested_b14, b14_count)
    print(f"    {G}+{RST} Tested: {tested_b14} | Findings: {b14_count}")

    # ═══════════════════════════════════════════════════════════
    # B15. Error-Based Parameter Disclosure
    # ═══════════════════════════════════════════════════════════
    print(f"{BOLD}[B15] Error-Based Parameter Disclosure{RST}")
    b15_count = 0
    tested_b15 = 0
    b15_filtered = 0
    b15_deduped = 0
    seen_b15_urls = set()
    for url in candidates[:40]:
        tested_b15 += 1
        try:
            fs = test_error_based_disclosure(url, cookies=a_cookies, headers=a_headers)
            for f in fs:
                # ── Filter 1: drop findings where all params are generic words ──
                params = f.get("params") or []
                real_params = [p for p in params if _is_likely_real_param(p)]
                if not real_params:
                    b15_filtered += 1
                    continue
                # keep only the real ones
                f["params"] = real_params
                # ── Filter 2: dedup by URL (1 finding per URL max) ──
                if url in seen_b15_urls:
                    b15_deduped += 1
                    continue
                seen_b15_urls.add(url)
                # ── Accepted ──
                f["type"] = "error-disclosure"  # prefix added upstream
                confirmed.append(f)
                b15_count += 1
        except Exception:
            pass
    diagnostics["B15"] = (tested_b15, b15_count)
    print(f"    {G}+{RST} Tested: {tested_b15} | Findings: {b15_count} "
          f"| Filtered: {b15_filtered} | Deduped: {b15_deduped}")

    # ═══════════════════════════════════════════════════════════
    # B16. clairvoyance (GraphQL schema)
    # ═══════════════════════════════════════════════════════════
    print(f"{BOLD}[B16] clairvoyance (GraphQL Schema Recovery){RST}")
    b16_count = 0
    if not tool_available("clairvoyance"):
        print(f"    {Y}[!]{RST} clairvoyance not installed — install: pip install clairvoyance")
    elif graphql_urls:
        clair_results = []
        for gql in graphql_urls[:3]:
            safe = re.sub(r'[^a-zA-Z0-9]', '_', gql)[:50]
            out = idir / f"clairvoyance_{safe}.json"
            cmd = f"clairvoyance {gql} -o {out} 2>/dev/null"
            run_tool(cmd, timeout=120)
            if out.exists() and out.stat().st_size > 0:
                clair_results.append(str(out))
                b16_count += 1
                print(f"    {G}+{RST} Schema recovered: {out.name}")
        if not clair_results:
            print(f"    {DIM}No schemas recovered (introspection may be disabled){RST}")
    else:
        print(f"    {Y}[!]{RST} No GraphQL endpoints — skipping")
    diagnostics["B16"] = (len(graphql_urls[:3]), b16_count)

    # ═══════════════════════════════════════════════════════════
    # B17. wpscan
    # ═══════════════════════════════════════════════════════════
    print(f"{BOLD}[B17] wpscan (WordPress){RST}")
    b17_count = 0
    if not tool_available("wpscan"):
        print(f"    {Y}[!]{RST} wpscan not installed — install: gem install wpscan")
    else:
        has_wp = any("wp-json" in u or "wp-content" in u or "wp-login" in u
                     for u in candidates)
        if has_wp and target_url:
            out = idir / "wpscan_results.txt"
            token_arg = f"--api-token {api_token}" if api_token else ""
            cmd = (f"wpscan --url {target_url} --enumerate p,t,vp,vt "
                   f"--plugins-detection aggressive --random-user-agent "
                   f"--disable-tls-checks {token_arg} -o {out} 2>/dev/null")
            run_tool(cmd, timeout=600)
            if out.exists() and out.stat().st_size > 0:
                b17_count = 1
                print(f"    {G}+{RST} Results saved: {out.name}")
        else:
            print(f"    {DIM}Not a WordPress target — skipping (correct){RST}")
    diagnostics["B17"] = (1 if b17_count else 0, b17_count)

    # ═══════════════════════════════════════════════════════════
    # B18. Race Conditions
    # ═══════════════════════════════════════════════════════════
    print(f"{BOLD}[B18] Race Conditions{RST}")
    # Test on POST endpoints OR state-changing endpoints
    state_urls = [u for u in candidates
                  if any(k in u.lower() for k in
                         ("update", "edit", "delete", "create", "change",
                          "add", "remove", "set", "post", "put"))]
    if not state_urls:
        state_urls = candidates[:5]

    b18_count = 0
    tested_b18 = 0
    for url in state_urls[:5]:
        tested_b18 += 1
        try:
            fs = test_race_condition(url, method="GET", cookies=a_cookies,
                                     headers=a_headers, concurrency=10, attempts=3)
            for f in fs:
                suspicious.append(f)
                b18_count += 1
        except Exception:
            pass
    diagnostics["B18"] = (tested_b18, b18_count)
    print(f"    {G}+{RST} Tested: {tested_b18} | Findings: {b18_count}")

    # ═══════════════════════════════════════════════════════════
    # B19. HPP URL + Body
    # ═══════════════════════════════════════════════════════════
    print(f"{BOLD}[B19] HPP URL + Body{RST}")
    b19_count = 0
    tested_b19 = 0
    # Test on URLs with query params
    query_urls = [u for u in candidates if "?" in u]
    if not query_urls:
        query_urls = candidates[:20]

    for url in query_urls[:20]:
        tested_b19 += 1
        try:
            fs = test_hpp_url_and_body(url, a_uid, b_uid,
                                       cookies=a_cookies, headers=a_headers)
            for f in fs:
                confirmed.append(f)
                b19_count += 1
        except Exception:
            pass
    diagnostics["B19"] = (tested_b19, b19_count)
    print(f"    {G}+{RST} Tested: {tested_b19} | Findings: {b19_count}")

    # ═══════════════════════════════════════════════════════════
    # Save results
    # ═══════════════════════════════════════════════════════════
    if confirmed:
        save_lines(idir / "advanced2_confirmed.txt",
                   [json.dumps(f, ensure_ascii=False) for f in confirmed])
    if suspicious:
        save_lines(idir / "advanced2_suspicious.txt",
                   [json.dumps(f, ensure_ascii=False) for f in suspicious])
    # Diagnostics
    save_lines(idir / "advanced2_diagnostics.txt",
               [f"{k}: tested={v[0]} found={v[1]}" for k, v in diagnostics.items()])

    print(f"\n{BOLD}{G}✓ Advanced Testing Complete{RST}")
    print(f"  Confirmed: {G}{len(confirmed)}{RST}")
    print(f"  Suspicious: {Y}{len(suspicious)}{RST}")

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
                for f in rl:
                    confirmed.append(f)
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
                for f in int_f:
                    confirmed.append(f)
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
                for f in byp:
                    confirmed.append(f)
                    print(f"    ! {f['type']}: {f['url'][:80]}")
                b22_count += len(byp)
        except Exception:
            pass
    print(f"    + Tested: {len(blocked_urls)} blocked URLs | Findings: {b22_count}")

    return {"confirmed": confirmed, "suspicious": suspicious,
            "diagnostics": diagnostics}
