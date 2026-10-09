"""
idor_playwright.py — Runtime network capture via Playwright.

Opens a headless browser, navigates to target, captures:
  - All XHR/Fetch requests
  - API endpoints
  - Login request shapes
  - External API bases (Firebase, Supabase, etc.)
"""
import json
import time
import threading
import re
from pathlib import Path
from urllib.parse import urlparse

R, G, Y, C, W, DIM, RST, BOLD = "\033[91m", "\033[92m", "\033[93m", "\033[96m", "\033[97m", "\033[2m", "\033[0m", "\033[1m"


def is_available():
    try:
        import playwright  # noqa
        return True
    except ImportError:
        return False


def _looks_like_login(path):
    return bool(re.search(
        r"(login|signin|sign-in|auth|session|token|register|signup)",
        path, re.IGNORECASE))


def _looks_like_api(path):
    """Detect real API endpoints (not fonts/images/storage)."""
    # Reject known noise
    noise = re.compile(
        r"\.(woff2?|ttf|eot|otf|svg|png|jpg|jpeg|gif|webp|ico|css|map|mp4|mp3)$",
        re.IGNORECASE)
    if noise.search(path):
        return False
    # Reject firebase storage (not API, just static content)
    if "firebasestorage.googleapis.com" in path:
        return False
    # Reject fonts
    if "/fonts/" in path or "gstatic.com" in path:
        return False
    # Accept real API patterns
    return bool(re.search(
        r"/(api|v\d+|rest|graphql|cloudfunctions|identitytoolkit|firestore|"
        r"user|users|account|accounts|admin|profile|profiles|"
        r"course|courses|quiz|quizzes|lesson|lessons|"
        r"payment|payments|order|orders|invoice|invoices|"
        r"login|signup|register|auth|session|token)",
        path, re.IGNORECASE))


def _detect_backend_type(full_url):
    """Identify backend type for IDOR testing."""
    if "firestore.googleapis.com" in full_url:
        return "firestore"
    if "cloudfunctions.net" in full_url:
        return "cloudfunctions"
    if "firebaseio.com" in full_url or "firebaseapp.com" in full_url:
        return "firebase-rtdb"
    if "supabase.co" in full_url:
        return "supabase"
    if ".amazonaws.com" in full_url:
        return "aws"
    if "identitytoolkit.googleapis.com" in full_url:
        return "firebase-auth"
    return "generic"


# ============================================================================
# Auto-login via API (to inject token into browser)
# ============================================================================
def auto_login_via_api(login_url, login_json_template, email, password,
                        timeout=15):
    """
    Login via API to get a token. Returns {"token": ..., "raw_response": ...}
    or None on failure.
    """
    import subprocess
    import json as _json

    payload_str = (login_json_template
                   .replace("%EMAIL%", email)
                   .replace("%PASS%", password))

    cmd = [
        "curl", "-sS", "-k", "--max-time", str(timeout), "-X", "POST",
        login_url,
        "-H", "Content-Type: application/json",
        "-H", "User-Agent: Mozilla/5.0",
        "-d", payload_str,
    ]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=timeout + 5)
        body = r.stdout.strip()
        if not body.startswith("{"):
            return None
        data = _json.loads(body)

        def find_token(obj, depth=0):
            if depth > 6:
                return None
            if isinstance(obj, dict):
                for k in ("token", "access_token", "accessToken",
                          "idToken", "id_token", "jwt", "bearerToken"):
                    v = obj.get(k)
                    if isinstance(v, str) and len(v) > 40:
                        return v
                for v in obj.values():
                    if isinstance(v, (dict, list)):
                        t = find_token(v, depth + 1)
                        if t:
                            return t
            elif isinstance(obj, list):
                for item in obj[:5]:
                    t = find_token(item, depth + 1)
                    if t:
                        return t
            return None

        token = find_token(data)
        if not token:
            return None
        return {"token": token, "raw_response": data}
    except Exception as e:
        print(f"  [PW-Login] Exception: {e}")
        return None


def capture_network(target_url, duration=30, headless=True, scroll=True,
                     follow_links=False, timeout=30,
                     auth_token=None, auth_cookies=None, extra_headers=None,
                     wait_for_enter=False,
                     auto_quiet=8, auto_min_wait=15, auto_max_wait=180):
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    except ImportError:
        print(f"{R}❌ Playwright not installed{RST}")
        return None

    result = {
        "requests": [], "endpoints": set(), "full_urls": set(),
        "domains": set(), "api_calls": set(),
        "login_endpoints": set(), "post_jsons": [], "methods": {},
        "backends": {},          # backend_type → set of URLs
        "firestore_base": None,  # e.g. general-hussein
        "cloudfunc_base": None,  # e.g. us-central1-general-hussein.cloudfunctions.net
    }

    print(f"{C}[PW] Launching browser → {target_url}{RST}")
    print(f"{DIM}[PW] Capture: {duration}s wait{RST}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)

        ctx_kwargs = {
            "user_agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/120.0.0.0 Safari/537.36"),
            "viewport": {"width": 1366, "height": 900},
            "ignore_https_errors": True,
        }
        if extra_headers:
            ctx_kwargs["extra_http_headers"] = extra_headers

        context = browser.new_context(**ctx_kwargs)

        # NOTE: Never inject Authorization header to Flutter/browser apps —
        # it makes them think the session is invalid and shows login screen.
        # Instead: rely on manual login in --idor-pw-visible mode.
        if auth_token and args_verbose if False else False:
            pass  # placeholder
        # (auth injection intentionally disabled to avoid breaking SPA logins)

        # Add cookies if provided
        if auth_cookies and target_url:
            try:
                from urllib.parse import urlparse as _up
                parsed = _up(target_url)
                cookies_list = []
                for part in auth_cookies.split(";"):
                    part = part.strip()
                    if "=" in part:
                        k, _, v = part.partition("=")
                        cookies_list.append({
                            "name": k.strip(),
                            "value": v.strip(),
                            "domain": parsed.hostname,
                            "path": "/",
                        })
                if cookies_list:
                    context.add_cookies(cookies_list)
                    print(f"{G}[PW] Injected {len(cookies_list)} cookie(s){RST}")
            except Exception as e:
                print(f"{Y}[PW] Cookie injection failed: {e}{RST}")
        page = context.new_page()
        captured_bodies = []

        def on_request(request):
            try:
                url = request.url
                parsed = urlparse(url)
                if not parsed.hostname:
                    return
                method = request.method.upper()
                result["requests"].append({
                    "url": url, "method": method, "host": parsed.hostname})
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                result["full_urls"].add(clean_url)
                result["endpoints"].add(parsed.path or "/")
                result["domains"].add(parsed.hostname)
                result["methods"][parsed.path or "/"] = method

                # Track backends
                bt = _detect_backend_type(url)
                if bt != "generic":
                    result["backends"].setdefault(bt, set()).add(clean_url)

                # Detect Firestore project (from any firestore URL)
                if "firestore.googleapis.com" in url:
                    m = re.search(r"/projects/([^/]+)/", url)
                    if m:
                        result["firestore_base"] = m.group(1)

                # Detect Cloud Functions base (from any URL OR hostname)
                if "cloudfunctions.net" in url:
                    result["cloudfunc_base"] = f"{parsed.scheme}://{parsed.netloc}"

                # Also detect from hostname alone (even for CSS/JS requests)
                host = parsed.hostname or ""
                if "cloudfunctions.net" in host and not result["cloudfunc_base"]:
                    result["cloudfunc_base"] = f"{parsed.scheme}://{host}"

                # Detect firebase project from firebaseapp.com / firebaseio.com
                if "firebaseapp.com" in host and not result.get("firebase_project"):
                    m = re.match(r"([a-z0-9-]+)\.(web\.)?firebaseapp\.com", host)
                    if m:
                        result["firebase_project"] = m.group(1)
                if "firebaseio.com" in host and not result.get("firebase_project"):
                    m = re.match(r"([a-z0-9-]+)\.firebaseio\.com", host)
                    if m:
                        result["firebase_project"] = m.group(1)

                # Detect cloudfunctions project from hostname (e.g. us-central1-general-hussein.cloudfunctions.net)
                if "cloudfunctions.net" in host and not result.get("firebase_project"):
                    m = re.match(r"[a-z0-9-]+-([a-z0-9-]+)\.cloudfunctions\.net", host)
                    if m:
                        result["firebase_project"] = m.group(1)

                if _looks_like_api(parsed.path):
                    result["api_calls"].add(clean_url)
                if method == "POST" and _looks_like_login(parsed.path):
                    result["login_endpoints"].add(clean_url)
                    try:
                        body = request.post_data
                        if body and len(body) < 5000:
                            captured_bodies.append({
                                "url": clean_url, "body": body,
                                "content_type": request.headers.get("content-type", ""),
                            })
                    except Exception:
                        pass
            except Exception:
                pass

        page.on("request", on_request)

        try:
            page.goto(target_url, timeout=timeout * 1000, wait_until="networkidle")
            print(f"{G}[PW] Page loaded{RST}")
        except PWTimeout:
            print(f"{Y}[PW] networkidle timeout, fallback{RST}")
            try:
                page.goto(target_url, timeout=20000, wait_until="domcontentloaded")
            except Exception:
                pass
        except Exception as e:
            print(f"{Y}[PW] Nav error: {e}{RST}")

        # ── INTERACTIVE MODE: wait for user to press Enter ──
        if wait_for_enter:
            # ══════════════════════════════════════════════════════
            # AUTO-CLOSE MODE — ينتظر ثم يسكّر تلقائياً عند الهدوء
            # ══════════════════════════════════════════════════════
            print()
            print(f"{BOLD}{Y}{'═' * 60}{RST}")
            print(f"{BOLD}{C}  🖥️  المتصفح فتح — سجّل دخول وتصفّح{RST}")
            print(f"{BOLD}{Y}{'═' * 60}{RST}")
            print(f"  {W}1. سجّل دخول بحسابك في المتصفح{RST}")
            print(f"  {W}2. تصفّح الموقع (كورسات، بروفايل، إلخ){RST}")
            print()
            print(f"  {G}✓{RST} {W}سيسكّر المتصفح تلقائياً بعد ما يهدأ النشاط{RST}")
            print(f"  {DIM}  quiet={auto_quiet}s | min={auto_min_wait}s | max={auto_max_wait}s{RST}")
            print()

            start_time = time.time()
            last_activity_time = time.time()
            last_count = 0
            last_print = time.time()
            close_reason = "unknown"

            while True:
                try:
                    page.wait_for_timeout(500)
                except Exception:
                    close_reason = "page_closed"
                    break

                elapsed = time.time() - start_time
                cur_count = len(result["requests"])

                if cur_count > last_count:
                    last_activity_time = time.time()
                    last_count = cur_count

                quiet_time = time.time() - last_activity_time

                if time.time() - last_print >= 5:
                    print(f"  {DIM}[PW] {int(elapsed):>3}s | req={cur_count:<4} "
                          f"api={len(result['api_calls']):<3} "
                          f"login={len(result['login_endpoints']):<2} "
                          f"quiet={int(quiet_time):>2}s{RST}")
                    last_print = time.time()

                has_login = len(result["login_endpoints"]) >= 1
                has_apis = len(result["api_calls"]) >= 3

                # Condition 1: enough data + quiet
                if elapsed >= auto_min_wait and has_login and has_apis and quiet_time >= auto_quiet:
                    close_reason = f"complete (login+apis, quiet {int(quiet_time)}s)"
                    print(f"  {G}[PW] ✓ Enough data — closing browser{RST}")
                    break

                # Condition 2: at least some data + long quiet
                if elapsed >= auto_min_wait and cur_count >= 30 and quiet_time >= (auto_quiet * 2):
                    close_reason = f"quiet {int(quiet_time)}s"
                    print(f"  {G}[PW] ✓ Browser quiet — closing{RST}")
                    break

                # Condition 3: max wait
                if elapsed >= auto_max_wait:
                    close_reason = f"max wait {auto_max_wait}s"
                    print(f"  {Y}[PW] Max wait reached — closing{RST}")
                    break

            print(f"  {G}[PW] Browser closed ({close_reason}){RST}")
        else:
            try:
                page.wait_for_timeout(duration * 1000)
            except Exception:
                pass

        if scroll:
            try:
                for y in (500, 1000, 2000, 4000, 8000):
                    page.evaluate(f"window.scrollTo(0, {y})")
                    page.wait_for_timeout(1500)
                page.evaluate("window.scrollTo(0, 0)")
            except Exception:
                pass

        if follow_links:
            try:
                links = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                base_host = urlparse(target_url).hostname
                internal = [l for l in set(links)
                            if urlparse(l).hostname == base_host and l != target_url][:5]
                for link in internal:
                    try:
                        page.goto(link, timeout=15000, wait_until="domcontentloaded")
                        page.wait_for_timeout(3000)
                    except Exception:
                        continue
            except Exception:
                pass

        for cb in captured_bodies:
            ct = cb.get("content_type", "")
            body_text = cb["body"]
            if "json" in ct:
                try:
                    body_obj = json.loads(body_text)
                    result["post_jsons"].append({
                        "url": cb["url"],
                        "shape": _shape_of(body_obj),
                        "raw": body_obj,
                    })
                except Exception:
                    pass
            elif "form" in ct:
                pairs = {}
                for part in body_text.split("&"):
                    if "=" in part:
                        k, _, v = part.partition("=")
                        pairs[k] = v
                result["post_jsons"].append({
                    "url": cb["url"], "shape": {k: "str" for k in pairs},
                    "raw": pairs, "content_type": "form",
                })

        browser.close()

    return result


def _shape_of(obj, depth=0):
    if depth > 5:
        return "..."
    if isinstance(obj, dict):
        return {k: _shape_of(v, depth + 1) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_shape_of(obj[0], depth + 1)] if obj else []
    if obj is None:
        return "null"
    return type(obj).__name__


def display_summary(result):
    if not result:
        return
    print()
    print(f"{BOLD}{C}{'═' * 60}{RST}")
    print(f"{BOLD}{C}  Playwright Capture Summary{RST}")
    print(f"{BOLD}{C}{'═' * 60}{RST}")
    print(f"  Requests:    {G}{len(result['requests'])}{RST}")
    print(f"  Endpoints:   {G}{len(result['endpoints'])}{RST}")
    print(f"  Domains:     {G}{len(result['domains'])}{RST}")
    print(f"  API calls:   {G}{len(result['api_calls'])}{RST}")
    print(f"  Login URLs:  {Y}{len(result['login_endpoints'])}{RST}")
    print(f"  POST shapes: {Y}{len(result['post_jsons'])}{RST}")
    print()

    if result["domains"]:
        print(f"{BOLD}Domains:{RST}")
        for d in sorted(result["domains"]):
            print(f"  {C}→{RST} {d}")
        print()
    if result["login_endpoints"]:
        print(f"{BOLD}{Y}Login endpoints:{RST}")
        for le in sorted(result["login_endpoints"]):
            print(f"  {Y}★{RST} {le}")
        print()
    if result["post_jsons"]:
        print(f"{BOLD}{Y}POST JSON shapes:{RST}")
        for pj in result["post_jsons"][:5]:
            print(f"  {Y}→{RST} {pj['url']}")
            print(f"    shape: {json.dumps(pj['shape'])[:250]}")
        print()
    if result.get("backends"):
        print(f"{BOLD}{C}Backends detected:{RST}")
        for bt, urls in sorted(result["backends"].items()):
            print(f"  {C}★ {bt}{RST}: {len(urls)} URLs")
        print()

    if result.get("firestore_base"):
        print(f"{BOLD}{G}Firestore project: {result['firestore_base']}{RST}")
        print()
    if result.get("cloudfunc_base"):
        print(f"{BOLD}{G}Cloud Functions base: {result['cloudfunc_base']}{RST}")
        print()

    if result["api_calls"]:
        print(f"{BOLD}API endpoints (top 30):{RST}")
        for ac in sorted(result["api_calls"])[:30]:
            print(f"  {G}•{RST} {ac}")
        print()


def write_findings(result, outdir):
    if not result:
        return None
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "pw_urls.txt").write_text(
        "\n".join(sorted(result["full_urls"])), encoding="utf-8")
    (outdir / "pw_api_urls.txt").write_text(
        "\n".join(sorted(result["api_calls"])), encoding="utf-8")
    (outdir / "pw_login_urls.txt").write_text(
        "\n".join(sorted(result["login_endpoints"])), encoding="utf-8")
    (outdir / "pw_domains.txt").write_text(
        "\n".join(sorted(result["domains"])), encoding="utf-8")
    if result["post_jsons"]:
        (outdir / "pw_login_shapes.json").write_text(
            json.dumps(result["post_jsons"], indent=2), encoding="utf-8")

    # ── NEW: Generate Firestore IDOR probes ──
    if result.get("firestore_base"):
        project = result["firestore_base"]
        # Common collections in educational apps
        collections = [
            "users", "courses", "students", "teachers", "instructors",
            "enrollments", "quizzes", "lessons", "videos", "payments",
            "orders", "invoices", "certificates", "notifications",
            "chats", "messages", "comments", "reviews", "assignments",
        ]
        # Common document IDs (likely sequential or predictable)
        doc_ids = [str(i) for i in range(1, 20)] + [
            "admin", "root", "test", "demo", "user1", "user2", "instructor1",
        ]

        firestore_probes = []
        base = f"https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents"
        for coll in collections:
            # List collection
            firestore_probes.append(f"{base}/{coll}")
            # Try specific docs
            for did in doc_ids[:10]:  # cap
                firestore_probes.append(f"{base}/{coll}/{did}")

        (outdir / "pw_firestore_probes.txt").write_text(
            "\n".join(firestore_probes), encoding="utf-8")
        print(f"{G}[PW] Firestore probes: {len(firestore_probes)}{RST}")

    # ── Cloud Functions enumeration ──
    if result.get("cloudfunc_base"):
        base = result["cloudfunc_base"]
        # Common function names (snake_case in this app based on login_user)
        funcs = [
            "login_user", "register_user", "get_user", "get_profile",
            "update_profile", "delete_user", "get_users", "get_all_users",
            "get_courses", "get_course", "create_course", "update_course",
            "delete_course", "get_lesson", "get_lessons",
            "get_quiz", "get_quizzes", "get_questions",
            "get_progress", "get_certificate", "get_certificates",
            "get_payment", "get_payments", "create_payment",
            "get_order", "get_orders", "get_invoice", "get_invoices",
            "get_notifications", "send_notification",
            "get_chat", "get_messages", "send_message",
            "get_enrollment", "enroll", "get_enrollments",
        ]
        func_urls = [f"{base}/{f}" for f in funcs]
        (outdir / "pw_cloudfunc_probes.txt").write_text(
            "\n".join(func_urls), encoding="utf-8")
        print(f"{G}[PW] Cloud Function probes: {len(func_urls)}{RST}")

    print(f"{G}[PW] Saved to {outdir}{RST}")
    return outdir


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 idor_playwright.py <target_url> [duration]")
        sys.exit(1)
    target = sys.argv[1]
    dur = int(sys.argv[2]) if len(sys.argv) > 2 else 30
    if not is_available():
        print(f"{R}❌ Playwright not installed{RST}")
        sys.exit(1)
    res = capture_network(target, duration=dur, headless=True,
                           scroll=True, follow_links=False)
    if res:
        display_summary(res)
        outdir = Path("clicker_output") / urlparse(target).hostname / "idor"
        write_findings(res, outdir)
        print(f"\n{G}✅ Done. Check {outdir}{RST}")
