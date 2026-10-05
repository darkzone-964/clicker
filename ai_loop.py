"""
ai_loop.py — 7-model team loop for Clicker.

Team (all optional — failures skip, loop continues):
  1. Planner    — nemotron-3-ultra-550b   → plan
  2. Analyst    — nemotron-3-super-120b   → plan
  3. Critic     — mistral-code            → plan
  4. Coder      — codestral               → plan
  5. Vision     — llama-3.2-90b-vision    → plan
  6. Refiner    — poolside-laguna-s-2.1   → plan
  7. Summarizer — north-mini-code         → summary

Stops on convergence or max rounds.
Saves each round + final plan as .md.
"""
import json
import time
from pathlib import Path

from ai_planner import _call_model, _validate_plan
from ai_handoff import build_handoff_package, format_round_markdown

# ── Team roles ──
# ── Team with per-role fallback pools ──
# If primary fails or is too slow, try next in `fallbacks` (with same handoff).
TEAM = [
    {
        "role": "Planner",
        "model": "nemotron-3-ultra-550b",
        "fallbacks": ["nemotron-3-super-120b", "gemini-3.7-flash", "muse-glimmer-30b"],
        "output": "plan",
    },
    {
        "role": "Analyst",
        "model": "gemini-3.7-flash",
        "fallbacks": ["nemotron-3-super-120b", "mistral-code", "muse-glimmer-30b"],
        "output": "plan",
    },
    {
        "role": "Critic",
        "model": "mistral-code",
        "fallbacks": ["codestral", "gemini-3.7-flash", "north-mini-code"],
        "output": "plan",
    },
    {
        "role": "Coder",
        "model": "codestral",
        "fallbacks": ["mistral-code", "north-mini-code", "muse-glimmer-30b"],
        "output": "plan",
    },
    {
        "role": "Refiner",
        "model": "nemotron-3-super-120b",
        "fallbacks": ["muse-glimmer-30b", "gemini-3.7-flash", "north-mini-code"],
        "output": "plan",
    },
    {
        "role": "Summarizer",
        "model": "gpt-oss-120b",
        "fallbacks": ["north-mini-code", "gemini-3.7-flash", "muse-glimmer-30b"],
        "output": "summary",
    },
]

# ── Model health tracking (persists across rounds within one run) ──
MODEL_HEALTH = {}
SLOW_THRESHOLD = 45.0
HEALTH_FAIL_LIMIT = 3        # raised from 2 → more tolerant

# ── Provider map (to avoid hitting same provider after 429) ──
PROVIDER_MAP = {
    "nemotron-3-ultra-550b": "nvidia",
    "nemotron-3-super-120b": "nvidia",
    "llama-3.2-90b-vision": "nvidia",
    "muse-glimmer-30b": "nvidia",
    "gemini-3.7-flash": "google",
    "gemini-3.6-flash": "google",
    "mistral-code": "mistral",
    "codestral": "mistral",
    "gpt-oss-120b": "groq",
    "north-mini-code": "openrouter",
    "poolside-laguna-s-2.1": "openrouter",
    "dots3-note-preview": "openrouter",
}

# provider -> epoch time until which we should NOT try it
PROVIDER_COOLDOWN = {}
PROVIDER_COOLDOWN_SECS = 90   # after 429, skip provider for 90s
FALLBACK_DELAY_SECS = 1.5     # small pause between fallback attempts

import time as _time


def _provider_of(model):
    return PROVIDER_MAP.get(model, model.split("-")[0])


def _mark_provider_429(model):
    PROVIDER_COOLDOWN[_provider_of(model)] = _time.time() + PROVIDER_COOLDOWN_SECS


def _is_provider_cooling(model):
    until = PROVIDER_COOLDOWN.get(_provider_of(model), 0)
    return _time.time() < until


DEFAULT_MAX_ROUNDS = 3
CONVERGENCE_THRESHOLD = 0.10


# ────────────────────────────────────────────────────────────
def _plan_signature(plan):
    if not isinstance(plan, dict):
        return set()
    parts = list(plan.get("next_phases", []))
    for cp in plan.get("custom_phases_added", []):
        parts.append(cp.get("name", ""))
    return set(p for p in parts if p)


def _has_converged(prev_plan, curr_plan):
    if not prev_plan or not curr_plan:
        return False
    a, b = _plan_signature(prev_plan), _plan_signature(curr_plan)
    if not a or not b:
        return False
    inter = len(a & b)
    union = len(a | b)
    if union == 0:
        return True
    return (inter / union) >= (1 - CONVERGENCE_THRESHOLD)


def _build_plan_prompt(handoff, available_phases):
    return handoff + f"""

Available standard phases: {", ".join(available_phases)}

Output STRICT JSON ONLY (single object, no markdown, no explanation):
{{
  "next_phases": ["phase_name_1", "phase_name_2"],
  "reasoning": "2-3 sentences",
  "custom_phases_added": [{{"name": "...", "reason": "...", "target_subs": [...]}}],
  "confidence": "high"
}}

Rules:
- Only JSON, nothing else
- confidence: high, medium, or low
- Use empty list [] if no custom phases
- Start with {{ and end with }}
"""


def _build_summary_prompt(handoff):
    return handoff + """

YOUR OUTPUT:
Write a concise summary (5-8 sentences) of this round:
- What plan was proposed?
- What changed across roles?
- What was the final consensus?
- Any unresolved disagreements?

Output plain text only. No JSON. No markdown. No code fences.
"""


def _health_init(model):
    if model not in MODEL_HEALTH:
        MODEL_HEALTH[model] = {"fails": 0, "slow": 0, "total_time": 0.0, "samples": 0}
    return MODEL_HEALTH[model]


def _health_record(model, elapsed, ok):
    """Record one attempt. Successes reset the fail counter (avoids cascading penalties)."""
    h = _health_init(model)
    h["samples"] += 1
    h["total_time"] += elapsed
    if ok:
        # A success resets the consecutive-fail counter
        h["fails"] = 0
    else:
        h["fails"] += 1
    if elapsed > SLOW_THRESHOLD:
        h["slow"] += 1


def _health_is_unhealthy(model):
    h = MODEL_HEALTH.get(model)
    if not h or h["samples"] < 2:
        return False
    # Unhealthy if: >=2 fails OR (slow in >=60% of recent runs)
    if h["fails"] >= HEALTH_FAIL_LIMIT:
        return True
    slow_ratio = h["slow"] / max(h["samples"], 1)
    if h["samples"] >= 3 and slow_ratio >= 0.6:
        return True
    return False


def _health_summary():
    lines = []
    for m, h in MODEL_HEALTH.items():
        avg = h["total_time"] / max(h["samples"], 1)
        lines.append(f"  {m}: fails={h['fails']} slow={h['slow']} avg={avg:.1f}s")
    return "\n".join(lines) if lines else "  (no data)"


def _build_handoff_for(role, model, target, waf, phase_name, phase_summary,
                       previous_rounds, state_summary):
    return build_handoff_package(
        target=target, waf=waf, phase_name=phase_name,
        phase_summary=phase_summary,
        previous_rounds=previous_rounds,
        current_model=model, model_role=role,
        state_summary=state_summary,
    )


def _try_one_model(role, model, output_type, target, waf, phase_name,
                   phase_summary, previous_rounds, available_phases,
                   api_key, state_summary):
    """Try one model. Returns (stage_dict, ok_bool)."""
    t0 = time.time()
    try:
        handoff = _build_handoff_for(role, model, target, waf, phase_name,
                                     phase_summary, previous_rounds, state_summary)
        if output_type == "summary":
            prompt = _build_summary_prompt(handoff)
            out, err = _call_model(model, prompt, api_key)
            elapsed = time.time() - t0
            if out is None and err:
                out_text, err2 = _call_model_raw(model, prompt, api_key)
                elapsed = time.time() - t0
                if out_text:
                    _health_record(model, elapsed, True)
                    return {"model": model, "output": out_text, "elapsed": elapsed, "error": None}, True
                _health_record(model, elapsed, False)
                if err2 and "429" in str(err2):
                    _mark_provider_429(model)
                return {"model": model, "output": None, "elapsed": elapsed, "error": err2 or err}, False
            ok = out is not None
            _health_record(model, elapsed, ok)
            if not ok and err and "429" in str(err):
                _mark_provider_429(model)
            return {"model": model, "output": out, "elapsed": elapsed, "error": err}, ok
        else:
            prompt = _build_plan_prompt(handoff, available_phases)
            out, err = _call_model(model, prompt, api_key)
            elapsed = time.time() - t0
            if out and _validate_plan(out):
                _health_record(model, elapsed, True)
                return {"model": model, "output": out, "elapsed": elapsed, "error": None}, True
            _health_record(model, elapsed, False)
            return {"model": model, "output": None, "elapsed": elapsed,
                    "error": err or "invalid_plan"}, False
    except Exception as e:
        elapsed = time.time() - t0
        _health_record(model, elapsed, False)
        return {"model": model, "output": None, "elapsed": elapsed, "error": str(e)}, False


def _run_stage(role_cfg, target, waf, phase_name, phase_summary,
               available_phases, previous_rounds, api_key, state_summary=None):
    """Try primary model, then fallbacks. Hand off same context to each."""
    role = role_cfg["role"]
    primary = role_cfg["model"]
    fallbacks = role_cfg.get("fallbacks", [])
    output_type = role_cfg["output"]

    # Build candidate list, skip known-unhealthy ones (keep primary first)
    candidates = [primary]
    for m in fallbacks:
        if m not in candidates:
            candidates.append(m)

    # Prioritize healthy models; keep primary first unless it's very unhealthy
    if _health_is_unhealthy(primary):
        healthy = [m for m in candidates[1:] if not _health_is_unhealthy(m)]
        if healthy:
            candidates = healthy + [primary]

    attempts = []
    for model in candidates:
        if _health_is_unhealthy(model) and model != primary:
            attempts.append(f"{model}: skipped (unhealthy)")
            continue
        stage, ok = _try_one_model(
            role=role, model=model, output_type=output_type,
            target=target, waf=waf, phase_name=phase_name,
            phase_summary=phase_summary,
            previous_rounds=previous_rounds,
            available_phases=available_phases,
            api_key=api_key, state_summary=state_summary,
        )
        if ok:
            if model != primary:
                stage["replaced_primary"] = primary
                if verbose_global() if False else False:
                    pass
            return stage
        attempts.append(f"{model}: {stage.get('error', 'unknown')[:60]}")

    # All failed
    return {
        "model": primary,
        "output": None,
        "elapsed": 0.0,
        "error": "all fallbacks failed: " + " | ".join(attempts[-3:]),
    }


def verbose_global():
    return False


def _call_model_raw(model, prompt, api_key, timeout=60):
    """Call without JSON parsing — returns raw text."""
    import urllib.request
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 800,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request("http://localhost:3001/v1/chat/completions",
                                  data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            raw = json.loads(res.read().decode("utf-8"))
            return raw["choices"][0]["message"]["content"].strip(), None
    except Exception as e:
        return None, str(e)


# ────────────────────────────────────────────────────────────
def run_planning_loop(domain, waf, phase_name, phase_summary,
                      available_phases, api_key, output_dir,
                      max_rounds=DEFAULT_MAX_ROUNDS,
                      stop_on_convergence=True, verbose=True,
                      state_summary=None):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    rounds_dir = output_dir / "ai_rounds"
    rounds_dir.mkdir(exist_ok=True)

    previous_rounds = []
    last_plan = None
    final_plan = None
    last_round_num = 0
    last_summary = None

    if verbose:
        print(f"\n{'='*70}")
        print(f"AI TEAM LOOP — {domain} / {phase_name}")
        print(f"Max rounds: {max_rounds} | Team size: {len(TEAM)}")
        for r in TEAM:
            print(f"  {r['role']:12} → {r['model']}")
        print(f"{'='*70}")

    for round_num in range(1, max_rounds + 1):
        last_round_num = round_num
        if verbose:
            print(f"\n--- ROUND {round_num} ---\n")

        stages = {}
        for role_cfg in TEAM:
            role = role_cfg["role"]
            model = role_cfg["model"]
            if verbose:
                print(f"[LOOP] {role:12} ({model})...")

            stage = _run_stage(
                role_cfg=role_cfg, target=domain, waf=waf,
                phase_name=phase_name, phase_summary=phase_summary,
                available_phases=available_phases,
                previous_rounds=previous_rounds,
                api_key=api_key,
                state_summary=state_summary,
            )
            stages[role] = stage

            if verbose:
                if stage["error"]:
                    print(f"       ❌ {stage['error'][:70]} ({stage['elapsed']:.1f}s) — skipped")
                else:
                    out = stage["output"]
                    actual_model = stage.get("model", "?")
                    replaced = stage.get("replaced_primary")
                    tag = ""
                    if replaced:
                        tag = f" (replaced {replaced})"
                    if isinstance(out, dict):
                        print(f"       ✅ {out.get('confidence', '?')} ({stage['elapsed']:.1f}s) — used {actual_model}{tag}")
                        print(f"       📋 {out.get('next_phases')}")
                    else:
                        print(f"       ✅ summary ({stage['elapsed']:.1f}s) — used {actual_model}{tag}")

        # Extract summary (from Summarizer role)
        round_summary = None
        sum_stage = stages.get("Summarizer")
        if sum_stage and sum_stage.get("output") and isinstance(sum_stage["output"], str):
            round_summary = sum_stage["output"]
        elif sum_stage and sum_stage.get("output") and isinstance(sum_stage["output"], dict):
            round_summary = sum_stage["output"].get("reasoning") or str(sum_stage["output"])

        # Save round markdown
        md = format_round_markdown(domain, waf, phase_name, round_num, stages, summary=round_summary)
        round_file = rounds_dir / f"round_{round_num:02d}.md"
        round_file.write_text(md, encoding="utf-8")
        if verbose:
            print(f"\n[LOOP] 💾 Saved: {round_file}")

        previous_rounds.append({
            "round_num": round_num,
            "stages": stages,
            "summary": round_summary,
        })

        # Take last successful plan (prefer later roles)
        this_plan = None
        for role_cfg in reversed(TEAM):
            role = role_cfg["role"]
            if role_cfg["output"] != "plan":
                continue
            st = stages.get(role)
            if st and st.get("output") and isinstance(st["output"], dict):
                this_plan = st["output"]
                break
        if this_plan:
            final_plan = this_plan

        # Convergence
        if stop_on_convergence and last_plan and this_plan:
            if _has_converged(last_plan, this_plan):
                if verbose:
                    print(f"\n[LOOP] ✅ Converged after round {round_num}")
                break

        last_plan = this_plan
        last_summary = round_summary

    # Save final
    if verbose and MODEL_HEALTH:
        print(f"\n[LOOP] Model health summary:")
        print(_health_summary())

    if final_plan:
        final_file = rounds_dir / "final_plan.md"
        last_stages = previous_rounds[-1].get("stages", {}) if previous_rounds else {}
        final_file.write_text(
            format_round_markdown(domain, waf, phase_name, last_round_num,
                                  last_stages, summary=last_summary),
            encoding="utf-8"
        )
        if verbose:
            print(f"[LOOP] 💾 Final plan: {final_file}")

    return final_plan or {}


if __name__ == "__main__":
    from pathlib import Path as _P

    api_key = ""
    env_file = _P("clicker_api.env")
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("FREELLMAPI_API_KEY="):
                api_key = line.split("=", 1)[1].strip().strip('"').strip("'")
                break

    if not api_key:
        print("❌ FREELLMAPI_API_KEY not found")
        raise SystemExit(1)

    test_summary = """- 655 subdomains discovered
- 5 high-value: api, beta, mgmt, portal.mgmt, staging
- 1617 hosts resolved"""

    final = run_planning_loop(
        domain="leakix.net",
        waf="cloudflare",
        phase_name="passive_subdomain_enum",
        phase_summary=test_summary,
        available_phases=[
            "response_filter", "tech_detect", "takeover", "vuln_scan",
            "ports", "content_discovery", "sensitive_files",
            "js_recon", "idor",
        ],
        api_key=api_key,
        output_dir="clicker_output/leakix.net",
        max_rounds=2,
        verbose=True,
    )

    print("\n" + "=" * 70)
    print("FINAL PLAN:")
    print("=" * 70)
    print(json.dumps(final, indent=2, ensure_ascii=False))
