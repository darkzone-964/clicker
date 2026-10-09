"""
test_coverage.py v2 — Correct signatures for all 38 methodology items.
"""
import inspect
import json
import re
import sys
import traceback
from pathlib import Path

sys.path.insert(0, ".")

# ============================================================================
# Config
# ============================================================================
TARGET = "juice.local:3000"
WORKSPACE = Path(f"clicker_output/{TARGET}")
IDOR_DIR = WORKSPACE / "idor"
URLS_FILE = WORKSPACE / "urls" / "clean_urls.txt"
JS_FILE = WORKSPACE / "js" / "jsfiles.txt"
API_EPS_FILE = IDOR_DIR / "api_endpoints.txt"

# Ensure JS file exists (collection_js_mining needs it)
JS_FILE.parent.mkdir(parents=True, exist_ok=True)
if not JS_FILE.exists():
    JS_FILE.touch()

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"
DIM = "\033[2m"; RST = "\033[0m"; BOLD = "\033[1m"

# ============================================================================
# HELPERS (must be defined BEFORE tests)
# ============================================================================
def _extract_id(url):
    m = re.search(r"/(\d+)", url)
    return int(m.group(1)) if m else 1

def _A8_api_docs():
    """A8 — Swagger/OpenAPI discovery"""
    import idor_module
    docs, _ = idor_module.discover_api_docs(TARGET)
    return docs

def _B4_rate_limit():
    """B4 — Rate limiting check"""
    import idor_module
    return [idor_module.curl_request(TEST_URL, timeout=3).get("status") for _ in range(5)]

def _B9_config_idor():
    """B9 — Configuration IDOR"""
    import idor_testing_advanced2 as ITA2
    return ITA2.test_config_idor(TEST_URL, UID_A, UID_B, cookies=COOKIES_A)

# ============================================================================
# Pre-load
# ============================================================================
CANDIDATES = []
if URLS_FILE.exists():
    CANDIDATES = [l.strip() for l in URLS_FILE.read_text().splitlines() if l.strip()]

TEST_URL = CANDIDATES[0] if CANDIDATES else f"http://{TARGET}/"
TEST_URL_ID = _extract_id(TEST_URL)



# Login
import idor_module
SESSIONS = {"A": None, "B": None}
TOKEN_A = ""

try:
    for key, email in (("A", "test@gmail.com"), ("B", "test2@gmail.com")):
        res = idor_module.try_login(TARGET, email, "12345678Aa@")
        if res.get("success"):
            v = idor_module.validate_session(TARGET, res)
            if v.get("valid"):
                SESSIONS[key] = {
                    "cookies": res.get("cookies", ""),
                    "headers": res.get("token_headers", {}),
                    "user_id": v.get("user_id"),
                }
                if key == "A":
                    auth = res.get("token_headers", {}).get("Authorization", "")
                    if auth.startswith("Bearer "):
                        TOKEN_A = auth[7:]
except Exception as e:
    print(f"Login failed: {e}")

UID_A = SESSIONS["A"]["user_id"] if SESSIONS["A"] else 26
UID_B = SESSIONS["B"]["user_id"] if SESSIONS["B"] else 25
COOKIES_A = SESSIONS["A"]["cookies"] if SESSIONS["A"] else ""
COOKIES_B = SESSIONS["B"]["cookies"] if SESSIONS["B"] else ""

# ── Smart URL selector ──
def pick_url(predicate, default=None):
    """Pick first URL matching predicate."""
    for u in CANDIDATES:
        if predicate(u):
            return u
    return default or TEST_URL

# URL with query params (?x=y)
URL_WITH_QUERY = pick_url(lambda u: "?" in u)

# URL with numeric ID in path (/api/Users/1)
URL_WITH_ID = pick_url(lambda u: bool(re.search(r"/\d+(?:/|$)", u)))

# URL with search/query endpoint
URL_SEARCH = pick_url(lambda u: "search" in u.lower() or "?" in u)

# URL belonging to User A (Users/26) or B (Users/25)
URL_USER_A = pick_url(lambda u: f"/Users/{UID_A}" in u, default=URL_WITH_ID)
URL_USER_B = pick_url(lambda u: f"/Users/{UID_B}" in u, default=URL_WITH_ID)

# Product/basket URL (for horizontal tests)
URL_BASKET = pick_url(lambda u: "basket" in u.lower(), default=URL_WITH_ID)

# Admin/privileged URL (vertical test)
URL_ADMIN = pick_url(lambda u: any(x in u.lower() for x in ["admin", "users"]), default=URL_WITH_ID)

print(f"\n{DIM}── Smart URL picker ──{RST}")
print(f"  URL_WITH_QUERY: {URL_WITH_QUERY}")
print(f"  URL_WITH_ID:    {URL_WITH_ID}")
print(f"  URL_SEARCH:     {URL_SEARCH}")
print(f"  URL_USER_A:     {URL_USER_A}")
print(f"  URL_USER_B:     {URL_USER_B}")
print(f"  URL_BASKET:     {URL_BASKET}")
print(f"  URL_ADMIN:      {URL_ADMIN}")

# ============================================================================
# Test runner
# ============================================================================
RESULTS = []

def record(name, status, detail=""):
    RESULTS.append((name, status, detail))

def head(title):
    print()
    print(f"{BOLD}{C}{'═' * 70}{RST}")
    print(f"{BOLD}{C}  {title}{RST}")
    print(f"{BOLD}{C}{'═' * 70}{RST}")

def ok(m):   print(f"  {G}✅{RST} {m}")
def warn(m): print(f"  {Y}⚠️ {RST} {m}")
def fail(m): print(f"  {R}❌{RST} {m}")

def test(name, fn):
    print(f"\n{DIM}── {name} ──{RST}")
    try:
        result = fn()
        if result is None:
            warn(f"{name}: None"); record(name, "⚠️", "None")
        elif isinstance(result, (list, dict, set, tuple)):
            n = len(result)
            if n == 0:
                warn(f"{name}: empty"); record(name, "⚠️", "empty")
            else:
                ok(f"{name}: {n} items"); record(name, "✅", f"{n}")
        else:
            ok(f"{name}: ran"); record(name, "✅", "ran")
    except Exception as e:
        fail(f"{name}: {type(e).__name__} — {str(e)[:80]}")
        if "--trace" in sys.argv:
            traceback.print_exc()
        record(name, "❌", f"{type(e).__name__}: {str(e)[:60]}")

# ============================================================================
# Banner
# ============================================================================
print(f"{BOLD}Target:{RST}     {TARGET}")
print(f"{BOLD}Candidates:{RST} {len(CANDIDATES)}")
print(f"{BOLD}Test URL:{RST}   {TEST_URL}")
print(f"{BOLD}User A:{RST}     uid={UID_A}  cookies={'yes' if COOKIES_A else 'no'}")
print(f"{BOLD}User B:{RST}     uid={UID_B}  cookies={'yes' if COOKIES_B else 'no'}")
print(f"{BOLD}Token A:{RST}    {TOKEN_A[:30]}..." if TOKEN_A else f"{BOLD}Token A:{RST}    (none)")

# ============================================================================
# COLLECTION (A1-A15)
# ============================================================================
head("COLLECTION — A1 to A15")

import idor_collection as IC

test("A1 API endpoints",     lambda: IC.collection_api_versions(str(URLS_FILE), IDOR_DIR))
test("A2 gf patterns",        lambda: IC.collection_gf_patterns(str(URLS_FILE), IDOR_DIR))
test("A3 API versions",       lambda: IC.collection_api_versions(str(URLS_FILE), IDOR_DIR))
test("A4-A5 UUIDs+Tokens",    lambda: IC.collection_tokens_uuids(str(URLS_FILE), IDOR_DIR))
test("A6-A7 Params",          lambda: IC.collection_params_active(
                                    TARGET, str(URLS_FILE),
                                    str(API_EPS_FILE), IDOR_DIR))
test("A8 API docs",           lambda: _A8_api_docs())
test("A9-A10 GraphQL",        lambda: IC.collection_graphql(str(URLS_FILE), str(JS_FILE), IDOR_DIR))
test("A11 Lifecycle",         lambda: IC.collection_lifecycle(str(URLS_FILE), IDOR_DIR))
test("A12 Field expansion",   lambda: IC.collection_field_expansion(
                                    str(URLS_FILE), str(JS_FILE), IDOR_DIR))
test("A13-A14 JS mining",     lambda: IC.collection_js_mining(str(JS_FILE), IDOR_DIR, TARGET))
test("A15 Merge all",         lambda: IC.collection_merge_all(IDOR_DIR))

# ============================================================================
# TESTING Basic
# ============================================================================
head("TESTING — Basic (B1-B10)")

import idor_testing as IT

test("B1 HPP",                lambda: IT.test_hpp(
                                    URL_WITH_QUERY, "q" if "?" in URL_WITH_QUERY else "id",
                                    UID_A, UID_B,
                                    cookies=COOKIES_A))
test("B2-B3 Numeric fuzz",    lambda: IT.fuzz_numeric_id(
                                    URL_WITH_ID, start=max(1, UID_A - 3),
                                    end=UID_A + 15, own_id=UID_A,
                                    cookies=COOKIES_A,
                                    headers=SESSIONS["A"]["headers"],
                                    max_findings=5))
test("B4 Rate limit",         lambda: _B4_rate_limit())
test("B5 State-changing",     lambda: IT.test_state_changing(
                                    URL_BASKET, UID_A, UID_B,
                                    method="DELETE", cookies=COOKIES_A))
test("B5b State GET",         lambda: IT.test_state_change_get(
                                    URL_BASKET, own_id=UID_A, victim_id=UID_B,
                                    cookies=COOKIES_A))
test("B6 Vertical",           lambda: IT.test_vertical_escalation(
                                    URL_ADMIN, SESSIONS["A"],
                                    method="POST", cookies=COOKIES_A))
test("B7 Horizontal",         lambda: IT.test_horizontal_idor(
                                    URL_BASKET, SESSIONS["A"], SESSIONS["B"],
                                    own_id_a=UID_A) if SESSIONS["A"] else [])
test("B8 Mass assign",        lambda: IT.test_mass_assignment(
                                    URL_BASKET, method="PUT",
                                    base_body={"id": UID_A},
                                    cookies=COOKIES_A))
test("B9 Config IDOR",        lambda: _B9_config_idor())
test("B10 Method tamper",     lambda: IT.test_method_tampering(
                                    URL_WITH_ID, own_id=UID_A, victim_id=UID_B,
                                    cookies=COOKIES_A))

# ============================================================================
# TESTING Advanced
# ============================================================================
head("TESTING — Advanced (B11-B24)")

import idor_testing_advanced as ITA
import idor_testing_advanced2 as ITA2

test("B11 Lifecycle mismatch", lambda: ITA2.test_lifecycle_mismatch(TEST_URL, cookies=COOKIES_A))
test("B12 Blind IDOR",        lambda: ITA.test_blind_idor(TEST_URL, UID_A, UID_B, cookies=COOKIES_A))
test("B13 GraphQL nested",    lambda: ITA2.test_graphql_nested([], UID_B, cookies=COOKIES_A))
test("B14 Auth validation",   lambda: ITA2.test_auth_validation_logic(
                                    TEST_URL, SESSIONS["A"], UID_A, UID_B,
                                    cookies=COOKIES_A,
                                    headers=SESSIONS["A"]["headers"]))
test("B15 Error-based",       lambda: ITA2.test_error_based_disclosure(TEST_URL, cookies=COOKIES_A))
test("B16 Pagination",        lambda: ITA.test_pagination_enum(TEST_URL, cookies=COOKIES_A))
test("B17 Predictable IDs",   lambda: ITA.detect_predictable_ids([1, 2, 3, 4, 5]))
test("B18 JWT",               lambda: ITA.test_jwt_manipulation(
                                    TEST_URL, TOKEN_A, cookies=COOKIES_A) if TOKEN_A else [])
test("B19 Time window",       lambda: ITA.test_time_window(
                                    TEST_URL, "timestamp", 0, UID_B, UID_A,
                                    cookies=COOKIES_A, window_seconds=3600))
test("B20 File ops",          lambda: ITA.test_file_operations(
                                    CANDIDATES[:5], UID_A, UID_B,
                                    cookies=COOKIES_A))
test("B21 Search IDOR",       lambda: ITA.test_search_idor(
                                    URL_SEARCH, "q", "test",
                                    cookies=COOKIES_A,
                                    headers=SESSIONS["A"]["headers"]))
test("B22 Path vs Body",      lambda: ITA.test_path_body_conflict(
                                    URL_WITH_ID, UID_A, UID_B,
                                    method="PUT", cookies=COOKIES_A))
test("B23 Query vs Body",     lambda: ITA.test_query_body_conflict(
                                    URL_WITH_ID, UID_A, UID_B,
                                    cookies=COOKIES_A,
                                    headers=SESSIONS["A"]["headers"]))
test("B24 Bypass checklist",  lambda: ITA.generate_bypass_checklist(IDOR_DIR, CANDIDATES[:5]))

# ============================================================================
# ADVANCED2
# ============================================================================
head("ADVANCED2 — run_all_advanced2")

test("Advanced2 full",        lambda: ITA2.run_all_advanced2(
                                    CANDIDATES[:10], SESSIONS["A"], SESSIONS["B"],
                                    [], IDOR_DIR,
                                    target_url=TEST_URL, api_token=TOKEN_A) if SESSIONS["A"] else [])

# ============================================================================
# SUMMARY
# ============================================================================
head("SUMMARY")

total = len(RESULTS)
w_ok = sum(1 for _, s, _ in RESULTS if s == "✅")
w_warn = sum(1 for _, s, _ in RESULTS if s == "⚠️")
w_fail = sum(1 for _, s, _ in RESULTS if s == "❌")

print(f"  Total: {total}  |  {G}✅ {w_ok}{RST}  |  {Y}⚠️  {w_warn}{RST}  |  {R}❌ {w_fail}{RST}")

if w_fail:
    print(f"\n{BOLD}{R}Failed:{RST}")
    for n, s, d in RESULTS:
        if s == "❌":
            print(f"  {R}●{RST} {n} — {d}")

if w_warn:
    print(f"\n{BOLD}{Y}Empty:{RST}")
    for n, s, d in RESULTS:
        if s == "⚠️":
            print(f"  {Y}●{RST} {n}")

report = {
    "target": TARGET,
    "candidates": len(CANDIDATES),
    "uid_a": UID_A, "uid_b": UID_B,
    "summary": {"ok": w_ok, "warn": w_warn, "fail": w_fail, "total": total},
    "results": [{"item": n, "status": s, "detail": d} for n, s, d in RESULTS],
}
Path("test_coverage_report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
print(f"\n{DIM}Report: test_coverage_report.json{RST}")
