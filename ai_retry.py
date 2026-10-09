"""
ai_retry.py — Smart retry for commands that failed.

When a custom phase or tool command produces zero output (or non-zero exit),
we send the failure context back to the AI and ask for an improved command.
"""
import json
import time
import urllib.request
from pathlib import Path


RETRY_MODELS = [
    "mistral-code",
    "codestral",
    "nemotron-3-super-120b",
    "gemini-3.7-flash",
]

MAX_RETRIES = 2


def _build_retry_prompt(domain, tool_name, original_cmd, result, state_summary):
    exit_code = result.get("exit_code", 0)
    output_lines = result.get("output_lines", 0)
    stderr = (result.get("stderr_sample") or "")[:600]
    stdout = (result.get("output_sample") or "")[:400]

    return f"""You are an expert bug bounty engineer. Your previous command FAILED.

Target: {domain}
Tool: {tool_name}

Your command was:
{original_cmd}

It was executed with this result:
- Exit code: {exit_code}
- Output lines: {output_lines}
- STDERR (first 600 chars):
{stderr}
- STDOUT (first 400 chars):
{stdout}

Current scan state:
---
{state_summary or "(no state)"}
---

YOUR TASK:
Analyze WHY the command failed and produce a FIXED command.

Common failure causes for recon tools:
- httpx / nuclei / katana / naabu / dnsx: they do NOT accept positional targets.
  Use `-u <target>` or pipe via stdin (`echo target | tool`) or `-l <file>`.
- Missing flags required by the tool (e.g., -mode for waymore, -w for ffuf).
- Wrong flag name (e.g., `-rate-limit` vs `-rl` for httpx — use short names).
- Target in the wrong position (before the tool name).
- Piping issues that eat output.

STRICT RULES:
1. Output ONLY the fixed command. No markdown, no explanation.
2. Use the EXACT same tool.
3. Preserve the output file path.
4. If the failure was caused by the target format, fix it with -u or stdin.
5. Keep the command on ONE line.

Fixed command:"""


def _call_ai(model, prompt, api_key, timeout=45):
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
            if text.startswith("```"):
                text = text.split("```", 2)
                text = text[1] if len(text) > 1 else text[0]
                if text.startswith("bash") or text.startswith("sh"):
                    text = text.split("\n", 1)[1] if "\n" in text else text
                text = text.strip()
            return text, None
    except Exception as e:
        return None, str(e)


def should_retry(result):
    """Decide if a result warrants a retry."""
    if not result:
        return False
    if result.get("error") == "timeout":
        return True
    exit_code = result.get("exit_code", 0)
    output_lines = result.get("output_lines", 0)
    # Failed if: non-zero exit OR zero output lines
    if exit_code != 0:
        return True
    if output_lines == 0:
        return True
    return False


def retry_command(domain, tool_name, original_cmd, result, api_key,
                  state_summary=None, max_retries=MAX_RETRIES, verbose=True):
    """
    Try to fix a failed command by asking the AI.

    Returns:
        {
            "success": bool,
            "fixed_cmd": str or None,
            "model": str or None,
            "attempts": int,
        }
    """
    if not should_retry(result):
        return {"success": False, "fixed_cmd": None, "model": None, "attempts": 0,
                "reason": "not-failed"}

    if not api_key:
        return {"success": False, "fixed_cmd": None, "model": None, "attempts": 0,
                "reason": "no-api-key"}

    if verbose:
        print(f"\n[RETRY] 🔁 Command failed (exit={result.get('exit_code')}, "
              f"lines={result.get('output_lines', 0)}). Asking AI for a fix...")

    prompt = _build_retry_prompt(domain, tool_name, original_cmd, result, state_summary)

    for model in RETRY_MODELS:
        if verbose:
            print(f"[RETRY]   Trying {model}...")
        text, err = _call_ai(model, prompt, api_key)
        if err or not text:
            if verbose:
                print(f"[RETRY]   ❌ {err or 'empty'}")
            continue
        text = text.split("\n")[0].strip()
        if text.startswith('"') and text.endswith('"'):
            text = text[1:-1]
        if text.startswith("'") and text.endswith("'"):
            text = text[1:-1]
        # Basic sanity
        if not text or len(text) > 1500:
            continue
        if not text.startswith(tool_name.split()[0]):
            # Allow pipes to other tools as long as original tool is present
            if tool_name.split()[0] not in text:
                continue
        if verbose:
            print(f"[RETRY]   ✅ {model} proposed:")
            print(f"[RETRY]      {text[:200]}")
        return {
            "success": True,
            "fixed_cmd": text,
            "model": model,
            "attempts": 1,
        }

    if verbose:
        print(f"[RETRY]   ❌ No valid fix from any model")
    return {"success": False, "fixed_cmd": None, "model": None, "attempts": 0,
            "reason": "no-valid-fix"}


if __name__ == "__main__":
    # Test
    from pathlib import Path as _P
    key = ""
    env = _P("clicker_api.env")
    if env.exists():
        for line in env.read_text().splitlines():
            if line.startswith("FREELLMAPI_API_KEY="):
                key = line.split("=", 1)[1].strip().strip('"').strip("'")
                break

    # Simulate the failing httpx case
    bad_result = {
        "exit_code": 0,
        "output_lines": 0,
        "output_sample": "",
        "stderr_sample": "[INF] Current httpx version v1.9.0\n[WRN] UI Dashboard...",
    }
    bad_cmd = "httpx -title -tech-detect -status-code -rate-limit 10 -o /tmp/out.txt leakix.net"

    r = retry_command("leakix.net", "httpx", bad_cmd, bad_result, key)
    print()
    print(f"Result: {json.dumps(r, indent=2, ensure_ascii=False)}")
