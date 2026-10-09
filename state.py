"""
state.py — Per-target scan state (files + counts) for AI planning.

Location: clicker_output/<domain>/state.json
Purpose:
  - Track which files exist (so AI doesn't reorder broken dependencies)
  - Track counts (subdomains, alive hosts, etc.)
  - Give AI an accurate snapshot before planning
"""
import json
from datetime import datetime
from pathlib import Path


def state_path(workspace, domain):
    return Path(workspace) / domain / "state.json"


def default_state(domain):
    return {
        "target": domain,
        "started": datetime.now().isoformat(timespec="seconds"),
        "updated": None,
        "waf": None,
        "waf_category": None,
        "phases_completed": [],
        "phases_skipped": [],
        "files": {},
        "counts": {},
    }


def load_state(workspace, domain):
    p = state_path(workspace, domain)
    if not p.exists():
        return default_state(domain)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return default_state(domain)
        # Ensure required keys
        base = default_state(domain)
        for k, v in base.items():
            data.setdefault(k, v)
        return data
    except Exception:
        return default_state(domain)


def save_state(workspace, domain, state):
    p = state_path(workspace, domain)
    p.parent.mkdir(parents=True, exist_ok=True)
    state["updated"] = datetime.now().isoformat(timespec="seconds")
    p.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


def _safe_lines_count(path):
    """Count non-empty lines in a file if it exists."""
    if not path:
        return 0
    p = Path(path)
    if not p.exists() or not p.is_file():
        return 0
    try:
        with p.open("r", encoding="utf-8", errors="ignore") as f:
            return sum(1 for line in f if line.strip())
    except Exception:
        return 0


def _exists(path):
    if not path:
        return False
    return Path(path).exists() and Path(path).is_file()


def update_after_phase(workspace, domain, state, phase_name, res):
    """
    Update the state after a phase runs.
    Reads `res` (phase result dict) and stores files + counts.
    """
    if not isinstance(res, dict):
        res = {}

    # Mark skipped vs completed
    if res.get("_skipped"):
        if phase_name not in state["phases_skipped"]:
            state["phases_skipped"].append(phase_name)
        save_state(workspace, domain, state)
        return state

    if phase_name not in state["phases_completed"]:
        state["phases_completed"].append(phase_name)

    files = state.setdefault("files", {})
    counts = state.setdefault("counts", {})

    # ── Per-phase updates ──
    if phase_name == "passive":
        f = res.get("allsubs_file")
        if f:
            files["allsubs"] = f
        subs = res.get("all_subdomains") or []
        hv = res.get("sensitive_subs") or []
        counts["subdomains"] = len(subs)
        counts["high_value_subs"] = len(hv)

    elif phase_name == "active":
        f = res.get("active_subs_file")
        if f:
            files["allsubs_final"] = f
        if f and _exists(f):
            counts["subdomains_total"] = _safe_lines_count(f)

    elif phase_name == "dns_resolution":
        f = res.get("resolved_file")
        if f:
            files["resolved"] = f
        if f and _exists(f):
            counts["resolved_hosts"] = _safe_lines_count(f)

    elif phase_name == "response":
        # update per-section
        alive = res.get("alive") or []
        f403 = res.get("f403") or []
        f404 = res.get("f404") or []
        counts["alive_hosts"] = len(alive)
        counts["f403"] = len(f403)
        counts["f404"] = len(f404)

    elif phase_name == "tech":
        f = res.get("ips_file")
        if f:
            files["ips"] = f
        af = res.get("alive_final")
        if af:
            files["alive_final"] = af

    elif phase_name == "ports":
        f = res.get("open_ports_file")
        if f:
            files["open_ports"] = f
        if f and _exists(f):
            counts["open_ports"] = _safe_lines_count(f)

    elif phase_name == "content":
        f = res.get("final_urls")
        if f:
            files["final_urls"] = f
        cf = res.get("clean_urls")
        if cf:
            files["clean_urls"] = cf
        if f and _exists(f):
            counts["urls_found"] = _safe_lines_count(f)

    elif phase_name == "js":
        f = res.get("js_file")
        if f:
            files["js_file"] = f
        sf = res.get("secrets_file")
        if sf:
            files["secrets_file"] = sf
        if sf and _exists(sf):
            counts["secrets_found"] = _safe_lines_count(sf)

    elif phase_name == "sensitive":
        p1 = res.get("passive")
        if p1:
            files["sensitive_passive"] = p1
        d1 = res.get("dirsearch")
        if d1:
            files["dirsearch"] = d1
        ff = res.get("ffuf")
        if ff:
            files["ffuf"] = ff

    elif phase_name == "waf":
        w = res.get("waf_type")
        if w:
            state["waf"] = w

    elif phase_name == "takeover":
        findings = res.get("findings") or []
        counts["takeover_findings"] = len(findings)

    elif phase_name == "vuln":
        n = len(res.get("nuclei") or [])
        c = len(res.get("cors") or [])
        e = len(res.get("exposed") or [])
        counts["nuclei_findings"] = n
        counts["cors_findings"] = c
        counts["exposed_findings"] = e

    elif phase_name == "dns":
        files["dns_records"] = res.get("dns_records")
        files["spf"] = res.get("spf")
        files["dmarc"] = res.get("dmarc")

    save_state(workspace, domain, state)
    return state


def summary_for_ai(state):
    """Return a compact human-readable summary of the state for AI prompts."""
    lines = []
    lines.append(f"Target: {state.get('target', '?')}")
    _waf = state.get('waf') or 'unknown'
    _waf_cat = state.get('waf_category') or 'unknown'
    lines.append(f"WAF: {_waf} (category: {_waf_cat})")

    done = state.get("phases_completed") or []
    skip = state.get("phases_skipped") or []
    if done:
        lines.append(f"Phases completed: {', '.join(done)}")
    if skip:
        lines.append(f"Phases skipped by user: {', '.join(skip)}")

    counts = state.get("counts") or {}
    if counts:
        lines.append("Counts:")
        for k, v in counts.items():
            lines.append(f"  {k}: {v}")

    files = state.get("files") or {}
    available = {k: v for k, v in files.items() if v and _exists(v)}
    missing = {k: v for k, v in files.items() if not v or not _exists(v)}
    if available:
        lines.append("Files available:")
        for k in available:
            lines.append(f"  {k}: EXISTS")
    if missing:
        lines.append("Files missing/not-yet-created:")
        for k in missing:
            lines.append(f"  {k}: MISSING")

    return "\n".join(lines)
