"""
ai_memory.py — Persistent learning memory for Clicker's AI orchestrator.

Stores every tool-run experience and uses it to:
  • Suggest better commands for similar targets (global patterns)
  • Learn from errors (timeouts, exit codes) to warn future AI calls
  • Build a per-target profile ("shortcut") for repeat scans
  • Upgrade global patterns when 3+ similar targets agree

Storage:
  ~/.clicker/ai_memory/
      experiences.jsonl      (last 5000 runs, capped)
      target_profiles.json   (per-target summary)
      global_patterns.json   (upgraded from 3+ targets)
      error_patterns.json    (per tool+waf error tracking)
"""
import json
import datetime
import os
from pathlib import Path
from collections import defaultdict

# ────────────────────────────────────────────────────────────
# Paths
# ────────────────────────────────────────────────────────────
MEMORY_DIR   = Path.home() / ".clicker" / "ai_memory"
EXP_FILE     = MEMORY_DIR / "experiences.jsonl"
PROFILES_FILE= MEMORY_DIR / "target_profiles.json"
PATTERNS_FILE= MEMORY_DIR / "global_patterns.json"
ERRORS_FILE  = MEMORY_DIR / "error_patterns.json"

KEEP_LAST    = 5000
MAX_AGE_DAYS = 60


def _ensure_dir():
    MEMORY_DIR.mkdir(parents=True, exist_ok=True)


# ────────────────────────────────────────────────────────────
# Low-level IO
# ────────────────────────────────────────────────────────────
def _load_experiences():
    _ensure_dir()
    if not EXP_FILE.exists():
        return []
    out = []
    try:
        for line in EXP_FILE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    except Exception:
        return []
    return out


def _append_experience(entry):
    _ensure_dir()
    try:
        with EXP_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _rewrite_experiences(entries):
    _ensure_dir()
    try:
        with EXP_FILE.open("w", encoding="utf-8") as f:
            for e in entries:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
    except Exception:
        pass


def _load_json(path, default):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default


def _save_json(path, data):
    _ensure_dir()
    try:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass


# ────────────────────────────────────────────────────────────
# Public API — Recording
# ────────────────────────────────────────────────────────────
def record_experience(target, waf, phase, tool,
                      cmd_original, cmd_ai, chosen,
                      exit_code, duration_sec, output_lines,
                      output_sample=""):
    """Record one tool-run experience."""
    # Compute performance tier
    if exit_code != 0:
        tier = "failed"
        success = False
    elif output_lines == 0:
        tier = "empty"
        success = False
    elif duration_sec < 60:
        tier = "fast"
        success = True
    elif duration_sec < 180:
        tier = "slow"
        success = True
    else:
        tier = "timeout"
        success = False

    entry = {
        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
        "target": str(target or ""),
        "waf": str(waf or "default"),
        "phase": str(phase or ""),
        "tool": str(tool or ""),
        "cmd_original": str(cmd_original or ""),
        "cmd_ai": str(cmd_ai or ""),
        "chosen": str(chosen or "original"),
        "exit_code": int(exit_code),
        "duration_sec": round(float(duration_sec), 2),
        "output_lines": int(output_lines),
        "success": bool(success),
        "tier": tier,
        "output_sample": str(output_sample)[:2000],
    }
    _append_experience(entry)

    # Update target profile (increment counts)
    _touch_target_profile(target, phase, tool, success, output_lines, duration_sec)

    # Update error pattern if failed
    if not success:
        _record_error(tool, waf, cmd_original, cmd_ai, chosen, exit_code, duration_sec, output_lines)

    # Try upgrading patterns
    _maybe_upgrade_patterns(tool, waf)


# ────────────────────────────────────────────────────────────
# Public API — Retrieval
# ────────────────────────────────────────────────────────────
def _extract_flag_values(cmd):
    """Extract {flag: next_token} pairs from a command string."""
    tokens = cmd.split()
    result = {}
    for i, t in enumerate(tokens):
        if t.startswith("-") and i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
            result[t] = tokens[i + 1]
    return result


def _get_tier(e):
    """Return tier for an experience (with fallback for old entries)."""
    t = e.get("tier")
    if t:
        return t
    # Legacy fallback
    dur = e.get("duration_sec", 999)
    out = e.get("output_lines", 0)
    exit_code = e.get("exit_code", 0)
    if exit_code != 0:
        return "failed"
    if out == 0:
        return "empty"
    if dur < 60:
        return "fast"
    if dur < 180:
        return "slow"
    return "timeout"


def retrieve_similar(target, waf, tool, limit=10):
    """Return up to `limit` past experiences, ranked by relevance."""
    exps = _load_experiences()
    if not exps:
        return []

    target = str(target or "").lower()
    waf = str(waf or "default").lower()
    tool = str(tool or "").lower()
    now = datetime.datetime.now()

    scored = []
    for e in exps:
        if not isinstance(e, dict):
            continue
        if str(e.get("tool", "")).lower() != tool:
            continue
        try:
            age_days = (now - datetime.datetime.fromisoformat(e.get("ts", ""))).days
        except Exception:
            age_days = 999
        if age_days > MAX_AGE_DAYS:
            continue

        score = 0
        if str(e.get("target", "")).lower() == target:
            score += 100
        if str(e.get("waf", "")).lower() == waf:
            score += 50
        if e.get("success"):
            score += 20
        score -= min(age_days, 30)
        scored.append((score, e))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [e for _, e in scored[:limit]]


def compute_tool_stats(waf, tool):
    """Return aggregated stats for a (tool, waf) pair across all experiences."""
    exps = _load_experiences()
    waf = str(waf or "default").lower()
    tool = str(tool or "").lower()
    matched = [e for e in exps
               if str(e.get("tool", "")).lower() == tool
               and str(e.get("waf", "")).lower() == waf]
    if not matched:
        return None

    total = len(matched)
    succ = sum(1 for e in matched if e.get("success"))
    durations = [e.get("duration_sec", 0) for e in matched if isinstance(e.get("duration_sec"), (int, float))]
    avg_dur = sum(durations) / len(durations) if durations else 0
    unique_targets = len(set(e.get("target", "") for e in matched))

    return {
        "tool": tool,
        "waf": waf,
        "total": total,
        "success": succ,
        "fail": total - succ,
        "success_rate": round(succ / total * 100, 1) if total else 0,
        "avg_duration": round(avg_dur, 1),
        "unique_targets": unique_targets,
    }


# ────────────────────────────────────────────────────────────
# Error patterns
# ────────────────────────────────────────────────────────────
def _record_error(tool, waf, cmd_original, cmd_ai, chosen, exit_code, duration_sec, output_lines):
    errors = _load_json(ERRORS_FILE, {})
    key = f"{tool}|{waf}"
    slot = errors.setdefault(key, {
        "tool": tool, "waf": waf,
        "timeouts": 0,
        "exit_nonzero": 0,
        "empty_output": 0,
        "bad_cmds": [],
    })
    if duration_sec >= 120:
        slot["timeouts"] += 1
    if exit_code != 0:
        slot["exit_nonzero"] += 1
    if output_lines == 0:
        slot["empty_output"] += 1

    # remember bad command (bounded list, dedup)
    bad = slot["bad_cmds"]
    cand = cmd_ai if chosen == "ai" else cmd_original
    if cand and cand not in bad:
        bad.append(cand)
        slot["bad_cmds"] = bad[-20:]  # cap at 20

    _save_json(ERRORS_FILE, errors)


def get_error_warnings(tool, waf):
    """Return a list of warning strings to pass to the AI."""
    errors = _load_json(ERRORS_FILE, {})
    key = f"{tool}|{waf}"
    slot = errors.get(key)
    if not slot:
        return []
    warn = []
    if slot.get("timeouts", 0) >= 2:
        warn.append(f"{tool} on {waf}: previous runs timed out {slot['timeouts']}x — reduce rate/scope.")
    if slot.get("exit_nonzero", 0) >= 2:
        warn.append(f"{tool} on {waf}: previous runs exited non-zero {slot['exit_nonzero']}x — check flags.")
    if slot.get("empty_output", 0) >= 3:
        warn.append(f"{tool} on {waf}: previous runs produced empty output {slot['empty_output']}x — verify input.")
    for bad in slot.get("bad_cmds", [])[-3:]:
        warn.append(f"AVOID this exact command (previously failed): {bad[:160]}")
    return warn


# ────────────────────────────────────────────────────────────
# Target profiles ("shortcut" for repeat scans)
# ────────────────────────────────────────────────────────────
def _touch_target_profile(target, phase, tool, success, output_lines, duration_sec):
    if not target:
        return
    profiles = _load_json(PROFILES_FILE, {})
    now = datetime.datetime.now().isoformat(timespec="seconds")
    p = profiles.setdefault(target, {
        "first_seen": now,
        "last_scan": now,
        "waf": "",
        "phases": {},
        "runs": 0,
    })
    p["last_scan"] = now
    p["runs"] = p.get("runs", 0) + 1

    ph = p["phases"].setdefault(phase, {
        "runs": 0,
        "empty_runs": 0,
        "success_runs": 0,
        "last_output_lines": 0,
    })
    ph["runs"] += 1
    ph["last_output_lines"] = output_lines
    if success:
        ph["success_runs"] += 1
    if output_lines == 0:
        ph["empty_runs"] += 1

    _save_json(PROFILES_FILE, profiles)


def set_target_waf(target, waf):
    if not target or not waf:
        return
    profiles = _load_json(PROFILES_FILE, {})
    p = profiles.setdefault(target, {"phases": {}, "runs": 0})
    p["waf"] = str(waf)
    _save_json(PROFILES_FILE, profiles)


def get_target_profile(target):
    profiles = _load_json(PROFILES_FILE, {})
    return profiles.get(str(target or ""))


def suggest_skip_phases(target, min_empty_runs=2):
    """Return list of phases that were consistently empty for this target."""
    p = get_target_profile(target)
    if not p:
        return []
    out = []
    for phase, st in (p.get("phases") or {}).items():
        runs = st.get("runs", 0)
        empty = st.get("empty_runs", 0)
        if runs >= min_empty_runs and empty >= runs:
            out.append(phase)
    return out


def list_similar_targets(waf, tech_stack=None, limit=5):
    """Return targets that share the same WAF (and optionally tech)."""
    profiles = _load_json(PROFILES_FILE, {})
    waf = str(waf or "").lower()
    matched = []
    for tgt, p in profiles.items():
        if str(p.get("waf", "")).lower() == waf:
            matched.append((tgt, p))
    matched.sort(key=lambda x: x[1].get("last_scan", ""), reverse=True)
    return [t for t, _ in matched[:limit]]


# ────────────────────────────────────────────────────────────
# Global patterns (upgrade when 3+ similar targets agree)
# ────────────────────────────────────────────────────────────
def _maybe_upgrade_patterns(tool, waf):
    exps = _load_experiences()
    tool_l = str(tool or "").lower()
    waf_l = str(waf or "").lower()

    # Gather per-target best success rates for this (tool,waf)
    per_target = defaultdict(lambda: {"ok": 0, "total": 0, "durations": []})
    for e in exps:
        if str(e.get("tool", "")).lower() != tool_l:
            continue
        if str(e.get("waf", "")).lower() != waf_l:
            continue
        t = e.get("target", "")
        if not t:
            continue
        per_target[t]["total"] += 1
        if e.get("success"):
            per_target[t]["ok"] += 1
        d = e.get("duration_sec")
        if isinstance(d, (int, float)):
            per_target[t]["durations"].append(d)

    # Need >= 3 distinct targets to consider a global pattern
    if len(per_target) < 3:
        return

    # Compute average success across targets
    rates = []
    for t, s in per_target.items():
        if s["total"] >= 1:
            rates.append(s["ok"] / s["total"])
    if not rates:
        return
    avg_rate = sum(rates) / len(rates)

    patterns = _load_json(PATTERNS_FILE, {})
    key = f"{tool_l}|{waf_l}"
    patterns[key] = {
        "tool": tool_l,
        "waf": waf_l,
        "targets_seen": list(per_target.keys())[:20],
        "avg_success_rate": round(avg_rate * 100, 1),
        "last_updated": datetime.datetime.now().isoformat(timespec="seconds"),
    }
    _save_json(PATTERNS_FILE, patterns)


def get_global_hints(waf, tool):
    """Return best-of global hints for this (tool, waf)."""
    patterns = _load_json(PATTERNS_FILE, {})
    key = f"{str(tool or '').lower()}|{str(waf or '').lower()}"
    p = patterns.get(key)
    if not p:
        return None
    return p


# ────────────────────────────────────────────────────────────
# Prompt-injection builder
# ────────────────────────────────────────────────────────────
def detect_patterns(tool, waf, min_samples=3):
    """Compare fast vs slow/failed runs to find numeric flag patterns."""
    exps = _load_experiences()
    tool_l = str(tool or "").lower()
    waf_l = str(waf or "default").lower()
    now = datetime.datetime.now()

    matched = []
    for e in exps:
        if str(e.get("tool", "")).lower() != tool_l:
            continue
        if str(e.get("waf", "")).lower() != waf_l:
            continue
        try:
            age = (now - datetime.datetime.fromisoformat(e.get("ts", ""))).days
        except Exception:
            continue
        if age > 60:
            continue
        matched.append(e)

    if len(matched) < min_samples:
        return ""

    fast = [e for e in matched if _get_tier(e) == "fast"]
    problem = [e for e in matched if _get_tier(e) in ("problem", "timeout", "failed", "empty")]

    if not fast or not problem:
        return ""

    all_flags = set()
    for e in fast + problem:
        cmd = e.get("cmd_ai") or e.get("cmd_original", "")
        all_flags.update(_extract_flag_values(cmd).keys())

    insights = []
    for flag in sorted(all_flags):
        f_vals, p_vals = [], []
        for e in fast:
            cmd = e.get("cmd_ai") or e.get("cmd_original", "")
            v = _extract_flag_values(cmd).get(flag)
            if v:
                f_vals.append(v)
        for e in problem:
            cmd = e.get("cmd_ai") or e.get("cmd_original", "")
            v = _extract_flag_values(cmd).get(flag)
            if v:
                p_vals.append(v)
        if not f_vals or not p_vals:
            continue
        try:
            f_nums = [float(v) for v in f_vals]
            p_nums = [float(v) for v in p_vals]
        except (ValueError, TypeError):
            continue

        f_avg = sum(f_nums) / len(f_nums)
        p_avg = sum(p_nums) / len(p_nums)
        denom = max(abs(f_avg), abs(p_avg), 1.0)
        if abs(f_avg - p_avg) / denom > 0.15:
            insights.append(
                f"`{flag}` — fast avg={f_avg:.0f} ({len(f_nums)}x), problem avg={p_avg:.0f} ({len(p_nums)}x)"
            )

    slow = [e for e in matched if _get_tier(e) == "slow"]

    if not insights and not slow:
        return ""

    lines = []
    if insights:
        lines.append(f"PATTERNS DETECTED ({tool} on {waf}):")
        lines.append(f"  fast={len(fast)}, slow={len(slow)}, problem={len(problem)}")
        for i in insights:
            lines.append(f"  - {i}")
        lines.append("  Recommendation: adjust flags toward the fast-run values.")

    return "\n".join(lines)


def build_ai_context(target, waf, tool):
    """Build a compact string to inject in the AI prompt."""
    parts = []

    # 1. Similar experiences (10 by default)
    sims = retrieve_similar(target, waf, tool, limit=10)
    if sims:
        parts.append(f"Past runs of `{tool}` (showing exact commands):")
        for e in sims[:10]:
            tier = _get_tier(e).upper()
            dur = e.get("duration_sec", "?")
            ln = e.get("output_lines", "?")
            cmd = e.get("cmd_ai") or e.get("cmd_original", "")
            cmd_short = cmd[:160] + ("..." if len(cmd) > 160 else "")
            parts.append(f"  [{tier:8}] {dur:>6}s, {ln:>5} lines | {cmd_short}")

    # 2. Detected patterns (fast vs problem)
    pat = detect_patterns(tool, waf)
    if pat:
        parts.append(pat)

    # 3. Global stats
    stats = compute_tool_stats(waf, tool)
    if stats:
        parts.append(
            f"Global stats for `{tool}` on `{waf}`: "
            f"{stats['success']}/{stats['total']} succeeded "
            f"(avg {stats['avg_duration']}s, {stats['unique_targets']} targets)."
        )

    # 3. Error warnings
    warns = get_error_warnings(tool, waf)
    if warns:
        parts.append("WARNINGS (learned from past failures):")
        for w in warns:
            parts.append(f"  - {w}")

    # 4. Global pattern hint
    hint = get_global_hints(waf, tool)
    if hint and hint.get("avg_success_rate", 0) >= 60:
        parts.append(
            f"Pattern: `{tool}` on `{waf}` succeeds {hint['avg_success_rate']}% "
            f"across {len(hint.get('targets_seen', []))} targets."
        )

    return "\n".join(parts) if parts else ""


# ────────────────────────────────────────────────────────────
# Pruning + maintenance
# ────────────────────────────────────────────────────────────
def prune(keep_last=KEEP_LAST, max_age_days=MAX_AGE_DAYS):
    exps = _load_experiences()
    if not exps:
        return 0
    now = datetime.datetime.now()
    kept = []
    for e in exps:
        try:
            age = (now - datetime.datetime.fromisoformat(e.get("ts", ""))).days
        except Exception:
            continue
        if age <= max_age_days:
            kept.append(e)

    # Cap to last N
    if len(kept) > keep_last:
        kept = kept[-keep_last:]

    removed = len(exps) - len(kept)
    if removed > 0:
        _rewrite_experiences(kept)
    return removed


def print_summary():
    """Debug helper for CLI."""
    exps = _load_experiences()
    profiles = _load_json(PROFILES_FILE, {})
    patterns = _load_json(PATTERNS_FILE, {})
    errors = _load_json(ERRORS_FILE, {})
    print(f"Memory dir   : {MEMORY_DIR}")
    print(f"Experiences  : {len(exps)}")
    print(f"Targets      : {len(profiles)}")
    print(f"Patterns     : {len(patterns)}")
    print(f"Error slots  : {len(errors)}")
    if exps:
        last = exps[-1]
        print(f"Last run     : {last.get('ts')} | {last.get('tool')} on {last.get('target')} ({'OK' if last.get('success') else 'FAIL'})")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "prune":
        n = prune()
        print(f"Pruned {n} old experience(s).")
    elif len(sys.argv) > 1 and sys.argv[1] == "clear":
        for f in (EXP_FILE, PROFILES_FILE, PATTERNS_FILE, ERRORS_FILE):
            if f.exists():
                f.unlink()
        print("Memory cleared.")
    else:
        print_summary()
