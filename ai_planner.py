"""
ai_planner.py — Phase planning module for Clicker.

Task 1: AI reads each phase's output and decides:
  - What the next phase(s) should be
  - If there is a vulnerability hint, propose a CUSTOM phase
  - Store reasoning in memory for the next model (Task 3)

Uses FreeLLMAPI to route to the best available model.
Falls back gracefully on any error.
"""
import json
import time
import urllib.request

# ────────────────────────────────────────────────────────────
# Configuration
# ────────────────────────────────────────────────────────────
FREELLMAPI_URL = "http://localhost:3001/v1/chat/completions"

# Model priority chain for planning
PLANNER_MODELS = [
    "nemotron-3-ultra-550b",   # primary: best JSON, deep reasoning
    "nemotron-3-super-120b",   # fallback: fast, reliable
    "north-mini-code",         # last resort
]

# Default if all models fail
SAFE_DEFAULT = {
    "next_phases": [],
    "reasoning": "AI planning unavailable — using pipeline default order.",
    "custom_phases_added": [],
    "confidence": "low",
    "planner_used": None,
}


# ────────────────────────────────────────────────────────────
# Prompt builder
# ────────────────────────────────────────────────────────────
def _build_prompt(domain, waf, completed_phase, phase_result_summary, available_phases):
    return f"""You are a bug bounty automation assistant planning the next phase.

Target: {domain}
WAF: {waf}
Completed phase: {completed_phase}

Phase result summary:
{phase_result_summary}

Available standard phases: {", ".join(available_phases)}

Task:
1. Analyze the phase result above.
2. Decide what the NEXT phase(s) should be.
3. If you detect a hint of a potential vulnerability (e.g., staging subdomains,
   admin panels, API endpoints, unusual ports), propose ONE custom phase
   targeting those specific assets.
4. If no hint, propose standard next phases only.

Output STRICT JSON ONLY (no markdown, no explanation, single object):
{{
  "next_phases": ["phase_name_1", "phase_name_2"],
  "reasoning": "2-3 sentences explaining your choice",
  "custom_phases_added": [
    {{"name": "custom_phase_name", "reason": "why", "target_subs": ["sub1", "sub2"]}}
  ],
  "confidence": "high"
}}

Rules:
- next_phases must be a list of strings
- If no custom phase is needed, use an empty list: []
- confidence must be one of: high, medium, low
- Return only the JSON object, nothing else.
- Do NOT wrap in markdown. Do NOT write "```json". Start with {{ and end with }}.
- Do NOT include any text before {{ or after }}.
"""


# ────────────────────────────────────────────────────────────
# HTTP call
# ────────────────────────────────────────────────────────────
def _call_model(model, prompt, api_key, timeout=60):
    """Call one model. Returns (parsed_json_or_None, error_str_or_None)."""
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 1024,
        # NOTE: response_format removed — nemotron-ultra returns empty content with it
        # The prompt enforces JSON; _parse_json handles any stray text.
    }
    data = json.dumps(payload).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    import time as _t
    last_err = None
    for attempt in range(3):  # initial + 2 retries
        try:
            req = urllib.request.Request(FREELLMAPI_URL, data=data, method="POST")
            for k, v in headers.items():
                req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=timeout) as res:
                raw = json.loads(res.read().decode("utf-8"))
                content = raw["choices"][0]["message"]["content"].strip()
                parsed = _parse_json(content)
                if parsed is None:
                    return None, "invalid_json"
                return parsed, None
        except urllib.error.HTTPError as e:
            last_err = f"HTTP Error {e.code}"
            if e.code in (500, 502, 503, 504) and attempt < 2:
                _t.sleep(2.0 * (attempt + 1))
                continue
            return None, last_err
        except Exception as e:
            last_err = str(e)
            if attempt < 2:
                _t.sleep(2.0 * (attempt + 1))
                continue
            return None, last_err
    return None, last_err or "unknown"


# ────────────────────────────────────────────────────────────
# JSON parser (robust)
# ────────────────────────────────────────────────────────────
def _parse_json(text):
    """Parse JSON from text, stripping common wrappers."""
    if not text:
        return None
    s = text.strip()

    # Strip markdown code fences
    if s.startswith("```"):
        s = s.split("```", 2)
        s = s[1] if len(s) > 1 else text
        if s.startswith("json"):
            s = s[4:]
        s = s.strip()

    # Find first { and last } (handles preamble/postamble)
    start = s.find("{")
    end = s.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None
    s = s[start:end + 1]

    try:
        parsed = json.loads(s)
        if isinstance(parsed, dict):
            return parsed
    except Exception:
        return None
    return None


# ────────────────────────────────────────────────────────────
# Validation
# ────────────────────────────────────────────────────────────
def _validate_plan(plan):
    """Ensure the plan has the required shape."""
    if not isinstance(plan, dict):
        return False
    if not isinstance(plan.get("next_phases"), list):
        return False
    if not isinstance(plan.get("reasoning"), str):
        return False
    if not isinstance(plan.get("custom_phases_added"), list):
        return False
    if plan.get("confidence") not in ("high", "medium", "low"):
        return False
    return True


# ────────────────────────────────────────────────────────────
# Public API
# ────────────────────────────────────────────────────────────
def plan_next_phase(domain, waf, completed_phase, phase_result_summary,
                    available_phases, api_key, verbose=True):
    """
    Ask the AI to plan the next phase(s) based on a completed phase's result.

    Returns a dict:
        {
            "next_phases": [...],
            "reasoning": "...",
            "custom_phases_added": [...],
            "confidence": "...",
            "planner_used": "<model name>",
            "elapsed_sec": <float>,
        }
    """
    if not api_key:
        return dict(SAFE_DEFAULT)

    prompt = _build_prompt(
        domain=domain,
        waf=waf,
        completed_phase=completed_phase,
        phase_result_summary=phase_result_summary,
        available_phases=available_phases,
    )

    if verbose:
        print(f"\n[PLANNER] 🧠 Planning next phase after '{completed_phase}'...")

    for model in PLANNER_MODELS:
        t0 = time.time()
        plan, err = _call_model(model, prompt, api_key)
        elapsed = time.time() - t0

        if plan is None:
            if verbose:
                print(f"[PLANNER] ⚠️  {model}: {err} ({elapsed:.1f}s) — trying next")
            continue

        if not _validate_plan(plan):
            if verbose:
                print(f"[PLANNER] ⚠️  {model}: invalid plan shape ({elapsed:.1f}s) — trying next")
            continue

        plan["planner_used"] = model
        plan["elapsed_sec"] = round(elapsed, 2)

        if verbose:
            print(f"[PLANNER] ✅ {model} ({elapsed:.1f}s)")
            print(f"[PLANNER] 📋 Next phases: {plan['next_phases']}")
            print(f"[PLANNER] 💭 Reasoning: {plan['reasoning'][:200]}")
            if plan["custom_phases_added"]:
                for cp in plan["custom_phases_added"]:
                    print(f"[PLANNER] 🎯 Custom phase: {cp.get('name')} → {cp.get('target_subs', [])}")

        return plan

    # All models failed
    if verbose:
        print(f"[PLANNER] ❌ All models failed — using safe default")
    return dict(SAFE_DEFAULT)


# ────────────────────────────────────────────────────────────
# CLI test
# ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    from pathlib import Path as _P

    # Read API key
    api_key = ""
    env_file = _P("clicker_api.env")
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("FREELLMAPI_API_KEY="):
                api_key = line.split("=", 1)[1].strip().strip('"').strip("'")
                break

    if not api_key:
        print("❌ FREELLMAPI_API_KEY not found in clicker_api.env")
        sys.exit(1)

    # Test with real phase output
    test_result = """- 655 subdomains discovered
- 5 high-value subdomains: api.leakix.net, beta.leakix.net, mgmt.leakix.net,
  portal.mgmt.leakix.net, staging.leakix.net
- 1617 hosts resolved
- No exposed files detected in passive phase"""

    plan = plan_next_phase(
        domain="leakix.net",
        waf="cloudflare",
        completed_phase="passive_subdomain_enum",
        phase_result_summary=test_result,
        available_phases=[
            "response_filter", "tech_detect", "takeover",
            "vuln_scan", "ports", "content_discovery",
            "sensitive_files", "js_recon", "idor"
        ],
        api_key=api_key,
        verbose=True,
    )

    print("\n" + "=" * 70)
    print("FINAL PLAN (as JSON):")
    print("=" * 70)
    print(json.dumps(plan, indent=2, ensure_ascii=False))
