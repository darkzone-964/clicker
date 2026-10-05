"""
ai_executor.py — Execute custom phases proposed by AI.

When the AI Loop proposes `custom_phases_added`, we ask a fast model to
generate a shell command that achieves the custom phase's goal, then
execute it and save the output.
"""
import json
import subprocess
import time
import urllib.request
from datetime import datetime
from pathlib import Path

try:
    import ai_retry
except ImportError:
    ai_retry = None


# ── Models that excel at writing shell commands ──
EXECUTOR_MODELS = [
    "mistral-code",
    "codestral",
    "qwen3.8-27b",
    "nemotron-3-super-120b",
]

# ── Available tools for custom commands ──
TOOL_HINTS = (
    "nuclei, httpx, dnsx, subfinder, katana, gau, waybackurls, nmap, naabu, "
    "ffuf, dirsearch, curl, openssl, sslscan, testssl, wpscan, whatweb, wafw00f, "
    "sqlmap, subzy, subjack, jq, grep, awk, sed"
)


def _safe_name(s):
    import re
    return re.sub(r"[^a-zA-Z0-9_-]", "_", str(s))[:40]


def _build_prompt(domain, cp, target_subs, state_summary):
    name = cp.get("name", "custom_phase")
    reason = cp.get("reason", "no reason provided")
    return f"""You are an elite bug bounty automation engineer.

The AI planning team proposed a CUSTOM reconnaissance phase for target `{domain}`.

Custom Phase: {name}
Reason: {reason}
Target subdomains (if any): {", ".join(target_subs) if target_subs else "any"}

Current scan state (what exists on disk):
---
{state_summary}
---

Available tools:
{TOOL_HINTS}

YOUR TASK:
Write a SINGLE valid shell command (one line) that accomplishes the custom phase.

STRICT RULES:
1. Output ONLY the command. No markdown, no explanation.
2. Use standard recon tools. Piping with | and && is allowed.
3. Save output to: clicker_output/{domain}/custom/{_safe_name(name)}.txt
4. If WAF is Cloudflare, use low rate limits (≤ 10 req/s).
5. If target_subs given, use them; otherwise use the main domain.
6. Command must complete within 5 minutes.
7. Do NOT use `sudo`, `apt`, `pip install` (assume tools are installed).
8. Start the command with a valid tool name (e.g., nuclei, httpx, curl).

Command:"""


def _call_ai(model, prompt, api_key, timeout=45):
    """Call AI and return (text, err)."""
    url = "http://localhost:3001/v1/chat/completions"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 500,
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as res:
            response = json.loads(res.read().decode("utf-8"))
            text = (response["choices"][0]["message"]["content"] or "").strip()
            # Strip markdown fences
            if text.startswith("```"):
                text = text.split("```", 2)
                text = text[1] if len(text) > 1 else text[0]
                if text.startswith("bash") or text.startswith("sh"):
                    text = text.split("\n", 1)[1] if "\n" in text else text
                text = text.strip()
            return text, None
    except Exception as e:
        return None, str(e)


def _validate_cmd(cmd):
    """Basic safety: reject obviously wrong commands."""
    if not cmd or len(cmd) > 1500:
        return False, "length"
    # Reject markdown/JSON/prose
    if cmd.startswith("{") or cmd.startswith("[") or cmd.startswith("#"):
        return False, "format"
    if cmd.startswith("```") or "\n" in cmd:
        return False, "multi-line"
    # Must start with a recognizable tool/verb
    allowed_starters = ("nuclei", "httpx", "dnsx", "subfinder", "katana",
                        "gau", "waybackurls", "nmap", "naabu", "ffuf",
                        "dirsearch", "curl", "openssl", "sslscan",
                        "testssl", "wpscan", "whatweb", "wafw00f",
                        "sqlmap", "subzy", "subjack", "grep", "cat",
                        "for ", "while ", "if ", "echo ")
    if not cmd.lstrip().startswith(allowed_starters):
        return False, "unknown-starter"
    # Reject dangerous commands
    bad = ("rm -rf /", "dd if=", "mkfs", ":(){", "sudo rm")
    if any(b in cmd for b in bad):
        return False, "dangerous"
    return True, None


def execute_custom_phase(domain, cp, api_key, workspace, state_summary=None,
                         available_tools=None, verbose=True):
    """
    Execute a custom phase proposed by AI.
    Returns result dict with: name, command, exit_code, duration, output_file, output_sample
    """
    name = cp.get("name", "custom_phase")
    target_subs = cp.get("target_subs", []) or []
    safe = _safe_name(name)

    cdir = Path(workspace) / domain / "custom"
    cdir.mkdir(parents=True, exist_ok=True)
    out_file = cdir / f"{safe}.txt"
    log_file = cdir / f"{safe}.log"

    if verbose:
        print()
        print(f"{'=' * 70}")
        print(f"[EXECUTOR] Custom phase: {name}")
        print(f"[EXECUTOR] Reason: {cp.get('reason', '?')[:200]}")
        if target_subs:
            print(f"[EXECUTOR] Targets: {', '.join(target_subs[:5])}")
        print(f"{'=' * 70}")

    # Ask AI to write the command
    prompt = _build_prompt(domain, cp, target_subs, state_summary or "(no state)")
    cmd = None
    used_model = None

    for model in EXECUTOR_MODELS:
        if verbose:
            print(f"[EXECUTOR] Asking {model} for command...")
        text, err = _call_ai(model, prompt, api_key)
        if err or not text:
            if verbose:
                print(f"[EXECUTOR]   ❌ {err or 'empty'}")
            continue
        # Take first line only
        text = text.split("\n")[0].strip()
        # Remove any leading/trailing quotes
        if text.startswith('"') and text.endswith('"'):
            text = text[1:-1]
        if text.startswith("'") and text.endswith("'"):
            text = text[1:-1]

        ok, reason = _validate_cmd(text)
        if ok:
            cmd = text
            used_model = model
            break
        else:
            if verbose:
                print(f"[EXECUTOR]   ⚠️ rejected ({reason}): {text[:120]}")

    if not cmd:
        if verbose:
            print(f"[EXECUTOR] ❌ No valid command from any model")
        return {
            "name": name,
            "custom_phase": cp,
            "command": None,
            "exit_code": -1,
            "duration": 0,
            "output_file": None,
            "output_sample": "",
            "error": "no valid command",
            "model": None,
        }

    # Capture output: prefer stdout, but honor tool's own -o if present.
    # NOTE: if the command already contains an -o <our_file>, do NOT append tee
    # to the same file (would corrupt). Instead, read from that file afterward.
    has_own_o = f"-o {out_file}" in cmd or f"-o={out_file}" in cmd
    if has_own_o:
        # Tool writes directly to the file. Let it.
        pass
    else:
        # No -o: wrap stdout with tee to our file.
        if f"2>&1 | tee {out_file}" not in cmd:
            cmd = f"{cmd} 2>&1 | tee {out_file}"

    if verbose:
        print(f"[EXECUTOR] ✅ {used_model} proposed:")
        print(f"[EXECUTOR]    {cmd[:200]}")

    # Execute
    t0 = time.time()
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=300
        )
        elapsed = time.time() - t0
        stdout = result.stdout or ""
        stderr = result.stderr or ""

        # Save log
        try:
            log_file.write_text(
                f"# {name}\n# Model: {used_model}\n# Cmd: {cmd}\n"
                f"# Exit: {result.returncode}\n# Time: {elapsed:.1f}s\n"
                f"\n--- STDOUT ---\n{stdout}\n\n--- STDERR ---\n{stderr}\n",
                encoding="utf-8"
            )
        except Exception:
            pass

        output_lines = len(stdout.splitlines()) if stdout else 0

        # If stdout empty but tool wrote to file, read it back
        if not stdout and out_file.exists():
            try:
                file_content = out_file.read_text(encoding="utf-8", errors="replace")
                if file_content.strip():
                    stdout = file_content
                    output_lines = len(file_content.splitlines())
            except Exception:
                pass

        if verbose:
            status = "✅" if result.returncode == 0 else "⚠️"
            print(f"[EXECUTOR] {status} exit={result.returncode} "
                  f"time={elapsed:.1f}s lines={output_lines}")

        result_dict = {
            "name": name,
            "custom_phase": cp,
            "command": cmd,
            "exit_code": result.returncode,
            "duration": round(elapsed, 2),
            "output_file": str(out_file) if out_file.exists() else None,
            "output_sample": stdout[:2000],
            "stderr_sample": stderr[:500],
            "output_lines": output_lines,
            "error": None if result.returncode == 0 else "non-zero exit",
            "model": used_model,
        }

        # ── AI Retry: if failed, ask AI for a fix and try once ──
        if ai_retry is not None and ai_retry.should_retry(result_dict):
            if verbose:
                print(f"[EXECUTOR] 🔁 Failed — calling ai_retry...")
            try:
                retry_out = ai_retry.retry_command(
                    domain=domain,
                    tool_name=cmd.split()[0] if cmd else "unknown",
                    original_cmd=cmd,
                    result=result_dict,
                    api_key=api_key,
                    state_summary=state_summary,
                    verbose=verbose,
                )
                if retry_out.get("success") and retry_out.get("fixed_cmd"):
                    fixed = retry_out["fixed_cmd"]
                    if verbose:
                        print(f"[EXECUTOR] 🔁 Retrying with fixed command...")
                        print(f"[EXECUTOR]    {fixed[:200]}")
                    t1 = time.time()
                    try:
                        r2 = subprocess.run(
                            fixed, shell=True, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=300
                        )
                        elapsed2 = time.time() - t1
                        stdout2 = r2.stdout or ""
                        stderr2 = r2.stderr or ""
                        # Read file back if stdout empty
                        if not stdout2 and out_file.exists():
                            try:
                                fc = out_file.read_text(encoding="utf-8", errors="replace")
                                if fc.strip():
                                    stdout2 = fc
                            except Exception:
                                pass
                        lines2 = len(stdout2.splitlines()) if stdout2 else 0
                        if verbose:
                            s2 = "✅" if r2.returncode == 0 and lines2 > 0 else "⚠️"
                            print(f"[EXECUTOR] {s2} retry exit={r2.returncode} "
                                  f"time={elapsed2:.1f}s lines={lines2}")
                        result_dict["retry"] = {
                            "model": retry_out.get("model"),
                            "fixed_cmd": fixed,
                            "exit_code": r2.returncode,
                            "duration": round(elapsed2, 2),
                            "output_lines": lines2,
                            "output_sample": stdout2[:2000],
                            "improved": lines2 > output_lines,
                        }
                        # If retry succeeded, prefer its output
                        if lines2 > output_lines:
                            result_dict["command"] = fixed
                            result_dict["exit_code"] = r2.returncode
                            result_dict["duration"] = round(elapsed + elapsed2, 2)
                            result_dict["output_sample"] = stdout2[:2000]
                            result_dict["stderr_sample"] = stderr2[:500]
                            result_dict["output_lines"] = lines2
                            result_dict["error"] = None if r2.returncode == 0 else "non-zero exit"
                            result_dict["model"] = retry_out.get("model")
                    except subprocess.TimeoutExpired:
                        result_dict["retry"] = {
                            "model": retry_out.get("model"),
                            "fixed_cmd": fixed,
                            "error": "timeout",
                        }
                    except Exception as e:
                        result_dict["retry"] = {
                            "model": retry_out.get("model"),
                            "fixed_cmd": fixed,
                            "error": str(e),
                        }
            except Exception as _re:
                if verbose:
                    print(f"[EXECUTOR] ai_retry error: {_re}")

        return result_dict
    except subprocess.TimeoutExpired:
        if verbose:
            print(f"[EXECUTOR] ⏱️ timeout after 300s")
        return {
            "name": name,
            "custom_phase": cp,
            "command": cmd,
            "exit_code": 124,
            "duration": 300,
            "output_file": str(out_file) if out_file.exists() else None,
            "output_sample": "",
            "error": "timeout",
            "model": used_model,
        }
    except Exception as e:
        if verbose:
            print(f"[EXECUTOR] ❌ {e}")
        return {
            "name": name,
            "custom_phase": cp,
            "command": cmd,
            "exit_code": -1,
            "duration": round(time.time() - t0, 2),
            "output_file": None,
            "output_sample": "",
            "error": str(e),
            "model": used_model,
        }


def save_custom_summary(domain, results, workspace):
    """Save a markdown summary of all custom phase executions."""
    if not results:
        return None
    cdir = Path(workspace) / domain / "custom"
    cdir.mkdir(parents=True, exist_ok=True)
    summary_file = cdir / "SUMMARY.md"

    lines = ["# Custom Phases Executed", ""]
    lines.append(f"**Target:** `{domain}`  ")
    lines.append(f"**Timestamp:** {datetime.now().isoformat(timespec='seconds')}  ")
    lines.append(f"**Total:** {len(results)}")
    lines.append("")

    for r in results:
        lines.append(f"## {r['name']}")
        lines.append("")
        lines.append(f"- **Model:** `{r.get('model', '?')}`")
        lines.append(f"- **Exit:** {r.get('exit_code', '?')}")
        lines.append(f"- **Duration:** {r.get('duration', 0)}s")
        lines.append(f"- **Output lines:** {r.get('output_lines', 0)}")
        if r.get("error"):
            lines.append(f"- **Error:** {r['error']}")
        lines.append("")
        lines.append("**Command:**")
        lines.append("```bash")
        lines.append(r.get("command") or "(none)")
        lines.append("```")
        lines.append("")
        if r.get("custom_phase", {}).get("reason"):
            lines.append("**Reason:**")
            lines.append(r["custom_phase"]["reason"])
            lines.append("")
        sample = r.get("output_sample", "").strip()
        if sample:
            lines.append("**Output (first 30 lines):**")
            lines.append("```")
            for ln in sample.splitlines()[:30]:
                lines.append(ln)
            lines.append("```")
        lines.append("")
        lines.append("---")
        lines.append("")

    summary_file.write_text("\n".join(lines), encoding="utf-8")
    return str(summary_file)


if __name__ == "__main__":
    # Test with a simple custom phase
    from pathlib import Path as _P
    key = ""
    env = _P("clicker_api.env")
    if env.exists():
        for line in env.read_text().splitlines():
            if line.startswith("FREELLMAPI_API_KEY="):
                key = line.split("=", 1)[1].strip().strip('"').strip("'")
                break

    cp = {
        "name": "test_basic_recon",
        "reason": "Quick check of target's HTTP headers and technologies",
        "target_subs": [],
    }
    r = execute_custom_phase("leakix.net", cp, key, "clicker_output")
    print()
    print(f"Result: {json.dumps(r, indent=2, ensure_ascii=False)[:800]}")
