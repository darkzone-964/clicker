"""
ai_thinker.py — Task 2: Per-phase AI reflection.

After each phase completes, ask ONE fast model to briefly analyze
the output. Display + save as markdown.

Env:
  CLICKER_AI_THINK=yes|no   (default: yes)
"""
import os
import time
import hashlib
from datetime import datetime
from pathlib import Path

# ── Fast models only (order = priority) ──
THINKER_MODELS = [
    "mistral-code",       # ~1s, reliable
    "codestral",          # ~1s
    "gpt-oss-120b",       # ~3s
    "gemini-3.7-flash",   # slower but capable
]

# ── Phases to skip (trivial or duplicate) ──
SKIP_PHASES = {
    "quick",
    "leakix",
    "screenshots",
    "dns_resolution",   # dnsx output is boring
}

# ── In-memory cache ──
_THINKING_CACHE = {}


def _cache_key(phase_name, summary):
    h = hashlib.md5(summary.encode("utf-8", errors="replace")).hexdigest()[:10]
    return f"{phase_name}|{h}"


def _is_enabled():
    return os.environ.get("CLICKER_AI_THINK", "yes").lower() not in ("no", "0", "false", "off")


def _read_file_sample(path, max_lines=20, max_chars=1200):
    """Read a file's first N non-empty lines (truncated) for AI summary."""
    if not path:
        return None
    try:
        fp = Path(path)
        if not fp.exists() or not fp.is_file():
            return None
        lines = []
        total = 0
        with fp.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                lines.append(line[:200])
                total += len(line)
                if len(lines) >= max_lines or total >= max_chars:
                    break
        return lines if lines else None
    except Exception:
        return None


def _build_summary(phase_name, res):
    """Build a human-readable summary from a phase result dict."""
    if not isinstance(res, dict):
        return "(no output)"

    lines = []

    if phase_name == "passive":
        subs = res.get("all_subdomains", [])
        hv = res.get("sensitive_subs", [])
        lines.append(f"- {len(subs)} subdomains discovered")
        if hv:
            lines.append(f"- {len(hv)} high-value subdomains:")
            for s in hv[:8]:
                lines.append(f"    * {s}")
        else:
            lines.append("- No high-value subdomains")

    elif phase_name == "active":
        count = res.get("active_count", 0)
        lines.append(f"- {count} new subs from active enumeration")
        f = res.get("active_subs_file")
        if f:
            lines.append(f"- Output file: {f}")

    elif phase_name == "waf":
        waf = res.get("waf_type", "unknown")
        lines.append(f"- Detected WAF: {waf}")

    elif phase_name == "response":
        alive = res.get("alive", [])
        f403 = res.get("f403", [])
        f404 = res.get("f404", [])
        lines.append(f"- Alive hosts: {len(alive)}")
        lines.append(f"- 403 hosts: {len(f403)}")
        lines.append(f"- 404 hosts: {len(f404)}")
        if alive[:5]:
            lines.append("- Sample alive:")
            for a in alive[:5]:
                lines.append(f"    * {a[:150]}")

    elif phase_name == "tech":
        ips_sample = _read_file_sample(res.get("ips_file"), max_lines=15)
        if ips_sample:
            lines.append(f"- IPs ({len(ips_sample)}):")
            for line in ips_sample:
                lines.append(f"    {line}")
        alive_sample = _read_file_sample(res.get("alive_final"), max_lines=10)
        if alive_sample:
            lines.append(f"- Alive endpoints:")
            for line in alive_sample:
                lines.append(f"    {line[:180]}")

    elif phase_name == "takeover":
        findings = res.get("findings", [])
        lines.append(f"- {len(findings)} potential takeovers")
        for f in findings[:5]:
            lines.append(f"    * {f[:150]}")

    elif phase_name == "vuln":
        n = len(res.get("nuclei", []))
        c = len(res.get("cors", []))
        e = len(res.get("exposed", []))
        lines.append(f"- Nuclei findings: {n}")
        lines.append(f"- CORS issues: {c}")
        lines.append(f"- Exposed files: {e}")
        for item in (res.get("nuclei") or [])[:3]:
            lines.append(f"    * nuclei: {item[:120]}")
        for item in (res.get("exposed") or [])[:3]:
            lines.append(f"    * exposed: {item[:120]}")

    elif phase_name == "ports":
        pf = res.get("open_ports_file")
        sample = _read_file_sample(pf, max_lines=25)
        if sample:
            lines.append(f"- Open ports found ({len(sample)} lines):")
            for line in sample:
                lines.append(f"    {line}")
        else:
            lines.append(f"- Ports file: {pf or 'N/A'} (empty or missing)")

    elif phase_name == "content":
        urls_sample = _read_file_sample(res.get("final_urls"), max_lines=20)
        if urls_sample:
            lines.append(f"- Discovered URLs ({len(urls_sample)}):")
            for line in urls_sample:
                lines.append(f"    {line[:180]}")
        else:
            lines.append(f"- Final URLs: {res.get('final_urls', 'N/A')} (empty)")

    elif phase_name == "sensitive":
        passive_sample = _read_file_sample(res.get("passive"), max_lines=15)
        if passive_sample:
            lines.append(f"- Passive-sensitive URLs ({len(passive_sample)}):")
            for line in passive_sample:
                lines.append(f"    {line[:180]}")
        if res.get("dirsearch"):
            lines.append(f"- Dirsearch output: {res.get('dirsearch')}")
        if res.get("ffuf"):
            lines.append(f"- FFUF output: {res.get('ffuf')}")

    elif phase_name == "js":
        js_sample = _read_file_sample(res.get("js_file"), max_lines=15)
        if js_sample:
            lines.append(f"- JS files found ({len(js_sample)}):")
            for line in js_sample:
                lines.append(f"    {line[:180]}")
        secrets_sample = _read_file_sample(res.get("secrets_file"), max_lines=10)
        if secrets_sample:
            lines.append(f"- Secrets detected:")
            for line in secrets_sample:
                lines.append(f"    {line[:200]}")
        elif res.get("secrets_file"):
            lines.append(f"- Secrets file empty (no secrets found)")

    elif phase_name == "dns":
        lines.append(f"- DNS records: {res.get('dns_records', 'N/A')}")
        lines.append(f"- SPF: {res.get('spf', 'N/A')}")
        lines.append(f"- DMARC: {res.get('dmarc', 'N/A')}")

    elif phase_name == "idor":
        candidates = res.get("candidates", 0)
        confirmed = res.get("confirmed", [])
        lines.append(f"- Candidates: {candidates}")
        lines.append(f"- Confirmed: {len(confirmed)}")

    else:
        for k, v in list(res.items())[:6]:
            if k.startswith("_"):
                continue
            v_str = str(v)
            if len(v_str) > 120:
                v_str = v_str[:120] + "..."
            lines.append(f"- {k}: {v_str}")

    return "\n".join(lines) if lines else "(no meaningful output)"


def _build_prompt(domain, waf, phase_name, summary):
    return f"""You are analyzing a bug bounty reconnaissance phase output.

Target: {domain}
WAF: {waf}
Phase: {phase_name}

Phase output:
---
{summary}
---

YOUR TASK:
Analyze this output in 2-4 SHORT sentences.

Focus on:
- What did we discover? (be specific with numbers)
- Anything unusual, suspicious, or interesting?
- What does this suggest about the target's attack surface?
- What should we focus on next?

STRICT RULES:
- Plain text only. No JSON. No markdown. No headers.
- 2-4 sentences maximum.
- Be concrete and specific.
- If nothing interesting, say so briefly.

Analysis:"""


def think_about_phase(domain, phase_name, res, waf, api_key, verbose=True):
    """Ask one fast model to reflect on a phase's output."""
    if not _is_enabled():
        return None
    if not api_key:
        return None
    if phase_name in SKIP_PHASES:
        return None

    summary = _build_summary(phase_name, res)
    if not summary or summary == "(no meaningful output)":
        return None

    # Cache
    ck = _cache_key(phase_name, summary)
    if ck in _THINKING_CACHE:
        return _THINKING_CACHE[ck]

    prompt = _build_prompt(domain, waf, phase_name, summary)

    try:
        from ai_orchestrator import _call_model_raw
    except Exception:
        return None

    for model in THINKER_MODELS:
        try:
            t0 = time.time()
            text, err = _call_model_raw(model, prompt, api_key, timeout=25)
            elapsed = time.time() - t0
            if err or not text:
                continue
            text = text.strip()
            # Reject obvious junk
            if len(text) < 20 or len(text) > 1500:
                continue
            if text.startswith("{") or text.startswith("["):
                continue
            # Reject if it echoes the prompt
            if "YOUR TASK" in text or "Phase output" in text:
                continue

            result = {
                "analysis": text,
                "model": model,
                "elapsed": round(elapsed, 2),
                "summary": summary,
                "phase": phase_name,
            }
            _THINKING_CACHE[ck] = result
            return result
        except Exception:
            continue

    return None


def save_thinking(domain, phase_name, thinking, output_dir):
    """Save thinking as markdown under ai_thoughts/."""
    if not thinking:
        return None
    output_dir = Path(output_dir)
    thoughts_dir = output_dir / "ai_thoughts"
    thoughts_dir.mkdir(parents=True, exist_ok=True)

    fpath = thoughts_dir / f"{phase_name}.md"

    lines = []
    lines.append(f"# AI Thinking — {phase_name}")
    lines.append("")
    lines.append(f"**Target:** `{domain}`  ")
    lines.append(f"**Model:** `{thinking['model']}`  ")
    lines.append(f"**Timestamp:** {datetime.now().isoformat(timespec='seconds')}  ")
    lines.append(f"**Elapsed:** {thinking['elapsed']}s")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Phase Output Summary")
    lines.append("")
    lines.append("```")
    lines.append(thinking["summary"])
    lines.append("```")
    lines.append("")
    lines.append("## AI Analysis")
    lines.append("")
    lines.append(thinking["analysis"])
    lines.append("")

    fpath.write_text("\n".join(lines), encoding="utf-8")
    return str(fpath)


def reset_cache():
    _THINKING_CACHE.clear()


if __name__ == "__main__":
    # Test
    from pathlib import Path as _P
    api_key = ""
    env = _P("clicker_api.env")
    if env.exists():
        for line in env.read_text().splitlines():
            if line.startswith("FREELLMAPI_API_KEY="):
                api_key = line.split("=", 1)[1].strip().strip('"').strip("'")
                break

    test_res = {
        "all_subdomains": [f"sub{i}.test.com" for i in range(655)],
        "sensitive_subs": [
            "api.test.com", "beta.test.com", "mgmt.test.com",
            "portal.mgmt.test.com", "staging.test.com",
        ],
    }
    r = think_about_phase("test.com", "passive", test_res, "cloudflare", api_key)
    if r:
        print(f"Model: {r['model']} ({r['elapsed']}s)")
        print(f"Analysis:\n{r['analysis']}")
    else:
        print("No thinking returned")
