import json
try:
    import ai_memory
except Exception:
    ai_memory = None
import select
import sys
import os
import re
import shutil
import urllib.request
import urllib.error
import subprocess

# ═══════════════════════════════════════════════════════════
# Global retry wrapper for urllib.request.urlopen
# Retries on 5xx (502/503/504) and network errors.
# This wraps ALL urlopen calls in this module automatically.
# ═══════════════════════════════════════════════════════════
_orig_urlopen = urllib.request.urlopen


def _urlopen_with_retry(req_or_url, timeout=90, max_retries=3, **kwargs):
    """Retry urllib.request.urlopen on 5xx and network errors.

    Skip retry for lightweight probes (timeout <= 8s) to avoid log spam.
    These are typically exposed-file / CORS / tech checks that fail fast anyway.
    """
    import time as _t
    import sys as _sys

    # Fast path: no retry for short-timeout probes
    if timeout is not None and timeout <= 8:
        return _orig_urlopen(req_or_url, timeout=timeout, **kwargs)

    for attempt in range(max_retries + 1):
        try:
            return _orig_urlopen(req_or_url, timeout=timeout, **kwargs)
        except urllib.error.HTTPError as e:
            if e.code in (500, 502, 503, 504) and attempt < max_retries:
                wait = 2.0 * (attempt + 1)
                print(f"[AI] \u21bb {e.code} retry {attempt+1}/{max_retries} after {wait:.0f}s", file=_sys.stderr)
                _t.sleep(wait)
                continue
            raise
        except Exception as e:
            if attempt < max_retries:
                wait = 2.0 * (attempt + 1)
                print(f"[AI] \u21bb network retry {attempt+1}/{max_retries} after {wait:.0f}s: {e}", file=_sys.stderr)
                _t.sleep(wait)
                continue
            raise


urllib.request.urlopen = _urlopen_with_retry


# ANSI colors (self-contained, no dependency on clicker.py)
_R = "\033[91m"
_G = "\033[92m"
_Y = "\033[93m"
_C = "\033[96m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_RST = "\033[0m"



def get_ai_decision(policy_text, api_key):
    if not api_key:
        return {"fallback": True, "message": "No AI key, using default safe mode"}

    prompt = f"""You are an expert Bug Bounty Automation Orchestrator.
Analyze this program policy and output a STRICT JSON object dictating which phases to run.
If no policy is provided, assume a standard aggressive-but-safe bug bounty methodology.

Policy Text: {policy_text[:3000] if policy_text else "NO POLICY PROVIDED. Use standard safe methodology."}

Output ONLY valid JSON with these exact boolean keys:
{{
  "run_passive": true,
  "run_active_subs": true,
  "run_vuln_scan": true,
  "run_fuzzing": true,
  "run_idor": true,
  "focus_areas": ["IDOR", "Exposed Files"]
}}
"""
    try:
        url = "http://localhost:3001/v1/chat/completions"
        payload = {
            "model": "auto",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "response_format": {"type": "json_object"}
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {api_key}")
        
        with urllib.request.urlopen(req, timeout=90) as res:
            response = json.loads(res.read().decode("utf-8"))
            return json.loads(response["choices"][0]["message"]["content"])
    except Exception:
        return {"fallback": True, "message": "AI unreachable, using default safe mode"}

def verify_and_generate_poc_real(vuln_type, target_url, api_key):
    if not api_key:
        return {"is_valid": True, "confidence": "Unknown", "error": "No AI key"}

    real_response = "Target unreachable or timeout"
    try:
        if not str(target_url).startswith("http"):
            target_url = "https://" + str(target_url)
        
        cmd = ["curl", "-s", "-I", "-m", "5", "-A", "Mozilla/5.0", str(target_url)]
        result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=6)
        if result.returncode == 0:
            real_response = result.stdout.strip()[:1000]
        else:
            real_response = f"Curl failed: {result.stderr.strip()}"
    except Exception as e:
        real_response = f"Verification error: {str(e)}"

    prompt = f"""You are a Senior Bug Bounty Hunter.
Vulnerability Type: {vuln_type}
Target: {target_url}

REAL HTTP RESPONSE HEADERS:
{real_response}

Task:
1. Based on the REAL HTTP response above, is this a TRUE POSITIVE or FALSE POSITIVE?
2. If FALSE POSITIVE (e.g., 404, 403, or parked domain), return: {{"is_valid": false, "reason": "..."}}
3. If TRUE POSITIVE, return a STRICT JSON object:
{{
  "is_valid": true,
  "confidence": "High/Medium",
  "poc_title": "Accurate title based on real headers",
  "steps_to_reproduce": ["1. Send GET request to " + "{target_url}", "2. Observe HTTP Status and Headers"],
  "impact": "Brief business impact based on the server type revealed in headers",
  "remediation": "Brief fix recommendation"
}}
Output ONLY valid JSON.
"""
    try:
        url = "http://localhost:3001/v1/chat/completions"
        payload = {
            "model": "auto",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "response_format": {"type": "json_object"}
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {api_key}")
        
        with urllib.request.urlopen(req, timeout=90) as res:
            response = json.loads(res.read().decode("utf-8"))
            content = response["choices"][0]["message"]["content"]
            content = content.replace("```json", "").replace("```", "").strip()
            return json.loads(content)
    except Exception as e:
        return {"is_valid": True, "confidence": "Unknown", "error": str(e), "real_response": real_response}

def execute_puredns_smart(domain, wordlist, resolvers, output_file, waf_type, api_key):
    ai_cmd = None
    if api_key:
        try:
            help_result = subprocess.run(["puredns", "--help"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5)
            help_text = (help_result.stdout or "") + (help_result.stderr or "")
            help_text = help_text[:25000]
            
            prompt = f"""You are an expert Bug Bounty automation engineer.
Your task: Generate ONE valid command line for puredns bruteforce.

REAL --help output for puredns:
---
{help_text}
---

Context:
- Domain: {domain}
- WAF type: {waf_type}
- Wordlist path (YOU MUST USE THIS EXACT PATH): {wordlist}
- Resolvers path (YOU MUST USE THIS EXACT PATH): {resolvers}

STRICT RULES:
1. You MUST use the exact Wordlist and Resolvers paths provided above. NEVER use generic names like 'wordlist.txt'.
2. Use ONLY flags that exist in the help text above.
3. If WAF is 'cloudflare' or 'akamai', use the lowest available rate-limit (e.g., --rate-limit 10).
4. Return ONLY the raw command line starting with 'puredns bruteforce'. No markdown, no explanation.
"""
            
            url = "http://localhost:3001/v1/chat/completions"
            payload = {
                "model": "auto",
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.0
            }
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, method="POST")
            req.add_header("Content-Type", "application/json")
            req.add_header("Authorization", f"Bearer {api_key}")
            
            with urllib.request.urlopen(req, timeout=90) as res:
                response = json.loads(res.read().decode("utf-8"))
                ai_cmd = response["choices"][0]["message"]["content"].strip()
                ai_cmd = ai_cmd.replace("```bash", "").replace("```", "").strip()
                
                if "puredns" not in ai_cmd or "bruteforce" not in ai_cmd:
                    ai_cmd = None
        except Exception:
            ai_cmd = None
    
    if not ai_cmd:
        if waf_type == "cloudflare":
            ai_cmd = f"puredns bruteforce {wordlist} {domain} -r {resolvers} --rate-limit 10"
        elif waf_type == "akamai":
            ai_cmd = f"puredns bruteforce {wordlist} {domain} -r {resolvers} --rate-limit 5"
        else:
            ai_cmd = f"puredns bruteforce {wordlist} {domain} -r {resolvers} --rate-limit 100"
    
    final_cmd = f"{ai_cmd} 2>&1 | tee {output_file}"
    print(f"\n[DEBUG] AI Generated Command: {final_cmd}")
    result = subprocess.run(final_cmd, shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
    
    if result.returncode != 0:
        print(f"[DEBUG] puredns exit code: {result.returncode}")
        print(f"[DEBUG] puredns stderr: {result.stderr[:500]}")
    return result.returncode, result.stdout, result.stderr


def _ask_user_ai_choice(tool_name, original_cmd, ai_cmd):
    """Ask user to accept AI command. 10s timeout -> auto-accept 'y'."""
    env = os.environ.get("CLICKER_AI_AUTO", "").strip().lower()
    if env in ("yes", "y", "1", "true", "always"):
        print(f"[AI] 🤖 CLICKER_AI_AUTO=yes -> auto-accepting AI command")
        return "y"
    if env in ("no", "n", "0", "false", "never"):
        print(f"[AI] 🤖 CLICKER_AI_AUTO=no -> auto-rejecting AI command")
        return "n"

    # Non-interactive stdin -> default to AI (y) as well
    if not sys.stdin.isatty():
        print(f"[AI] ⚠️ Non-interactive -> auto-accepting AI command (10s default)")
        return "y"

    prompt = f"{_G}{_BOLD}Use AI command? [Y/n] (10s): {_RST}"
    sys.stdout.write(prompt)
    sys.stdout.flush()

    try:
        rlist, _, _ = select.select([sys.stdin], [], [], 10)
        if rlist:
            ans = sys.stdin.readline().strip().lower()
            if ans in ("", "y", "yes"):
                return "y"
            return "n"
        else:
            # Timeout
            print()  # newline after prompt
            print(f"{_G}⏱️  10s timeout → auto-accepting AI command{_RST}")
            return "y"
    except (EOFError, KeyboardInterrupt):
        print()
        return "y"



def _extract_flags(cmd):
    """Extract all flag tokens (-x, --xyz) from a shell command."""
    return set(re.findall(r'(?:^|\s)(--?[a-zA-Z][a-zA-Z0-9_-]*)', cmd))


def _http_post_json(url, payload, headers, timeout=90, max_retries=3):
    """POST JSON with retry on 5xx/network errors. Returns (data_or_None, error_str_or_None)."""
    import time as _t
    last_err = None
    for attempt in range(max_retries + 1):
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, method="POST")
            for k, v in headers.items():
                req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=timeout) as res:
                return json.loads(res.read().decode("utf-8")), None
        except urllib.error.HTTPError as e:
            last_err = f"HTTP Error {e.code}"
            if e.code in (500, 502, 503, 504) and attempt < max_retries:
                import sys as _sys
                print(f"[AI] ↻ {e.code} retry {attempt+1}/{max_retries} after {2.0*(attempt+1):.0f}s", file=_sys.stderr)
                _t.sleep(2.0 * (attempt + 1))
                continue
            return None, last_err
        except Exception as e:
            last_err = str(e)
            if attempt < max_retries:
                _t.sleep(2.0 * (attempt + 1))
                continue
            return None, last_err
    return None, last_err or "unknown"


def _call_model_raw(model, prompt, api_key, timeout=25, max_tokens=600):
    """
    Call a model and return the raw text response (no JSON parsing).

    Used by ai_thinker.py (Task 2) and anywhere that expects plain text.
    Returns (text_or_None, error_str_or_None).
    """
    if not api_key or not model:
        return None, "missing api_key or model"

    url = "http://localhost:3001/v1/chat/completions"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": max_tokens,
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    data, err = _http_post_json(url, payload, headers, timeout=timeout, max_retries=2)
    if err or not data:
        return None, err or "empty response"

    try:
        choices = data.get("choices") or []
        if not choices:
            return None, "no choices in response"
        msg = choices[0].get("message") or {}
        text = (msg.get("content") or "").strip()
        # Strip common wrappers
        if text.startswith("```"):
            text = text.split("```", 2)
            text = text[1] if len(text) > 1 else text[0]
            if text.startswith("json"):
                text = text[4:]
            text = text.strip()
        return text, None
    except Exception as e:
        return None, f"parse error: {e}"


# ── Trivial tools: skip AI entirely ──
SKIP_AI_TOOLS = {
    "cat", "grep", "sort", "uniq", "mv", "echo", "awk", "sed",
    "head", "tail", "wc", "tr", "cut", "find", "tee",
}


def _should_skip_ai(tool_name):
    base = tool_name.split()[0] if tool_name else ""
    return base in SKIP_AI_TOOLS


# ── In-memory cache: (tool, waf, cmd_hash) -> ai_cmd ──
_AI_CACHE = {}


def _cache_key(tool, waf, cmd):
    import hashlib
    h = hashlib.md5(cmd.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"{tool}|{waf}|{h}"


def _cache_get(tool, waf, cmd):
    return _AI_CACHE.get(_cache_key(tool, waf, cmd))


def _cache_set(tool, waf, cmd, ai_cmd):
    _AI_CACHE[_cache_key(tool, waf, cmd)] = ai_cmd


# ── Speed-critical flags: AI should NOT make these slower ──
# If AI changes them by >30% in the SLOWER direction, we reject.
SPEED_FLAGS = {
    "ffuf":       {"-t": "lower_is_slower", "-rate": "lower_is_slower", "-p": "higher_is_slower"},
    "dirsearch":  {"-t": "lower_is_slower", "--max-rate": "lower_is_slower", "--delay": "higher_is_slower"},
    "nuclei":     {"-c": "lower_is_slower", "-rl": "lower_is_slower"},
    "katana":     {"-c": "lower_is_slower", "-rl": "lower_is_slower"},
    "httpx":      {"-t": "lower_is_slower", "-rl": "lower_is_slower"},
    "httpx-toolkit": {"-t": "lower_is_slower", "-rl": "lower_is_slower"},
    "naabu":      {"-c": "lower_is_slower", "-rate": "lower_is_slower"},
    "subfinder":  {"-rl": "lower_is_slower"},
    "gau":        {"--threads": "lower_is_slower"},
}


def _extract_flag_values(cmd):
    """Extract {flag: next_token} pairs from a command."""
    import re
    tokens = cmd.split()
    result = {}
    for i, t in enumerate(tokens):
        if t.startswith("-") and i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
            result[t] = tokens[i + 1]
    return result


def _ai_slows_down(tool_name, original_cmd, ai_cmd):
    """Return True if AI made a speed-critical tool notably slower."""
    base = tool_name.split()[0] if tool_name else ""
    rules = SPEED_FLAGS.get(base)
    if not rules:
        return False
    orig_vals = _extract_flag_values(original_cmd)
    ai_vals = _extract_flag_values(ai_cmd)
    for flag, direction in rules.items():
        o = orig_vals.get(flag)
        a = ai_vals.get(flag)
        if o is None or a is None:
            continue
        try:
            of = float(o)
            af = float(a)
        except (ValueError, TypeError):
            continue
        if of <= 0:
            continue
        if direction == "lower_is_slower":
            # Lower value = fewer threads/rate = slower
            if af < of * 0.7:  # 30%+ reduction
                return True
        elif direction == "higher_is_slower":
            # Higher value = longer delay = slower
            if af > of * 1.3:  # 30%+ increase
                return True
    return False


# ────────────────────────────────────────────────────────────
# WAF categorization (3 tiers: aggressive / moderate / lenient)
# ────────────────────────────────────────────────────────────
WAF_CATEGORIES = {
    # ── Aggressive (very strict, low rate required) ──
    "cloudflare":  "aggressive",
    "akamai":      "aggressive",
    "imperva":     "aggressive",
    "incapsula":   "aggressive",
    "f5":          "aggressive",
    "big-ip":      "aggressive",
    "aws-waf":     "aggressive",
    "aws":         "aggressive",
    "radware":     "aggressive",
    "wallarm":     "aggressive",
    "reblaze":     "aggressive",
    "citrix":      "aggressive",
    "netscaler":   "aggressive",
    "fortiweb":    "aggressive",
    "fortinet":    "aggressive",
    # ── Moderate (CDN + light WAF) ──
    "sucuri":      "moderate",
    "fastly":      "moderate",
    "azure":       "moderate",
    "google":      "moderate",
    "google-armor": "moderate",
    "stackpath":   "moderate",
    "cloudfront":  "moderate",
    "bunny":       "moderate",
    "keycdn":      "moderate",
    "gcore":       "moderate",
    # ── Lenient (rules-based only, few rate limits) ──
    "modsecurity": "lenient",
    "wordfence":   "lenient",
    "barracuda":   "lenient",
    "comodo":      "lenient",
    "sitelock":    "lenient",
    "qrator":      "lenient",
    # ── No WAF ──
    "none":        "none",
    "default":     "none",
    "unknown":     "unknown",
}

# Suggested settings per category
WAF_SPEED_HINTS = {
    "aggressive": "threads ≤ 10, rate ≤ 5, timeout ≥ 10, retries ≥ 2",
    "moderate":   "threads ≤ 20, rate ≤ 10, timeout ≥ 8, retries ≥ 1",
    "lenient":    "threads ≤ 50, rate ≤ 50, timeout ≥ 5",
    "none":       "threads 50+, rate 100+, timeout 5-7 (maximum speed)",
    "unknown":    "start moderate (threads 15, rate 8), adjust based on results",
}


def _categorize_waf(waf_type):
    """Return category string for a WAF name."""
    if not waf_type:
        return "unknown"
    waf_lower = str(waf_type).lower().strip()
    # Direct match
    if waf_lower in WAF_CATEGORIES:
        return WAF_CATEGORIES[waf_lower]
    # Substring match (e.g., "cloudflare waf" contains "cloudflare")
    for k, v in WAF_CATEGORIES.items():
        if k in waf_lower:
            return v
    return "unknown"


def optimize_tool_command(tool_name, original_cmd, context, api_key):
    """Universal AI optimizer: Reads --help, reviews original cmd, and optimizes if needed."""
    if _should_skip_ai(tool_name):
        return original_cmd

    _waf = (context or {}).get("waf_type", "default")
    _cached = _cache_get(tool_name, _waf, original_cmd)
    if _cached is not None:
        return _cached

    print(f"\n[AI] 🧠 Reviewing {tool_name} command...")
    print(f"[AI] 📜 Original: {original_cmd}")
    
    if not api_key:
        print(f"[AI] ⚠️ No API key, using original command.")
        return original_cmd
    
    try:
        base_tool = tool_name.split()[0]
        # Handle aliases like httpx-toolkit -> httpx
        if base_tool == "httpx-toolkit" and not shutil.which(base_tool):
            base_tool = "httpx"
        # Try --help first; fallback to -h; combine both if needed
        help_res = subprocess.run([base_tool, "--help"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5)
        help_text = (help_res.stdout or "") + (help_res.stderr or "")
        if len(help_text) < 200:
            # Try -h
            help_res2 = subprocess.run([base_tool, "-h"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5)
            help_text += "\n" + (help_res2.stdout or "") + (help_res2.stderr or "")
        help_text = help_text[:25000]
        

        # ── AI Memory: build historical context from past runs ──
        _mem_str = ""
        try:
            if ai_memory is not None:
                _mem_str = ai_memory.build_ai_context(
                    target=(context or {}).get("domain", ""),
                    waf=(context or {}).get("waf_type", "default"),
                    tool=tool_name,
                )
        except Exception:
            _mem_str = ""

        prompt = f"""You are an expert Bug Bounty automation engineer.
Original Command: {original_cmd}
Tool Help Reference:
---
{help_text}
---
Context:
- Domain: {context.get('domain', 'target.com')}
- WAF Type: {context.get('waf_type', 'none')}

Historical context (AI memory from past runs):
{_mem_str if _mem_str else "(no prior experience yet)"}

Task: Review the Original Command. 
1. If it needs optimization (e.g., adding rate limits for Cloudflare/Akamai, fixing paths, adding silent flags), output the improved command.
2. If the Original Command is already perfect, safe, and optimal, return it EXACTLY as is.
3. Use ONLY flags that exist in the Help Reference.
4. Return ONLY the raw command string. No markdown, no explanation, no quotes.
5. Use the Historical context above: prefer commands that succeeded before, avoid commands that timed out or produced empty output.
"""
        url = "http://localhost:3001/v1/chat/completions"
        payload = {
            "model": "auto",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {api_key}")
        
        with urllib.request.urlopen(req, timeout=90) as res:
            response = json.loads(res.read().decode("utf-8"))
            ai_cmd = response["choices"][0]["message"]["content"].strip()
            # ── DEBUG: log raw response ──
            try:
                with Path("ai_debug.log").open("a", encoding="utf-8") as _f:
                    _f.write(f"--- RAW AI RESPONSE ---\n{ai_cmd[:1500]}\n")
            except Exception:
                pass
            ai_cmd = ai_cmd.replace("```bash", "").replace("```", "").strip()
            
            # ── Strict validation of AI response ──────────────
            # 1) Must be single-line (no newlines)
            if "\n" in ai_cmd or "\r" in ai_cmd:
                print(f"[AI] ⚠️ {tool_name}: AI returned multi-line garbage. Fallback to original.")
                return original_cmd

            # 2) Must not be absurdly long
            if len(ai_cmd) > 2500:
                print(f"[AI] ⚠️ {tool_name}: AI response too long ({len(ai_cmd)} chars). Fallback to original.")
                return original_cmd

            # 3) Tool presence check (pipe-aware + flexible)
            _has_pipe = "|" in original_cmd
            _base_name = base_tool.split("/")[-1]
            if _has_pipe:
                # For pipes, the tool can appear anywhere after a `|` or at start
                if _base_name not in ai_cmd:
                    print(f"[AI] ⚠️ {tool_name}: AI response missing '{_base_name}'. Fallback to original.")
                    return original_cmd
            else:
                # For non-pipes, allow the tool to appear anywhere (some tools have wrappers)
                if _base_name not in ai_cmd:
                    print(f"[AI] ⚠️ {tool_name}: AI response missing '{_base_name}'. Fallback to original.")
                    return original_cmd

            # 4) Loop / repetition detection
            tokens = ai_cmd.split()
            if len(tokens) > 4:
                from collections import Counter
                worst = Counter(tokens).most_common(1)[0][1]
                if worst >= 5 and worst / len(tokens) > 0.25:
                    print(f"[AI] ⚠️ {tool_name}: AI response contains repeated loop. Fallback to original.")
                    return original_cmd

            # 5) Must not contain obvious prose markers
            bad_markers = ("We need to", "Let's ", "I don't", "There's ", "Actually",
                           "Wait,", "Let us", "Note:", "Explanation")
            if any(m in ai_cmd for m in bad_markers):
                print(f"[AI] ⚠️ {tool_name}: AI response contains prose. Fallback to original.")
                return original_cmd

            # 6) Tool-specific hallucinated flags
            if tool_name.startswith("puredns") and ("--domain" in ai_cmd or "--waf" in ai_cmd):
                print(f"[AI] ⚠️ {tool_name}: AI hallucinated invalid flags (--domain/--waf). Fallback to original.")
                return original_cmd

            # ── Accept ─────────────────────────────────────────
            # ── New flags: AI may only ADD flags that exist in --help ──
            _orig_flags = _extract_flags(original_cmd)
            _ai_flags = _extract_flags(ai_cmd)
            _new_flags = _ai_flags - _orig_flags
            if _new_flags and help_text:
                # Normalize: strip leading dashes for comparison
                _help_lower = help_text.lower()
                _unknown = []
                for f in _new_flags:
                    fname = f.lstrip("-")
                    # Accept if flag name appears in help (any form)
                    if fname not in _help_lower and f not in help_text:
                        _unknown.append(f)
                if _unknown:
                    print(f"[AI] ⚠️ {tool_name}: AI added unknown flags {sorted(_unknown)} (not in --help). Fallback to original.")
                    return original_cmd

            if ai_cmd.strip() == original_cmd.strip():
                print(f"[AI] ✅ {tool_name}: Command is already optimal. Kept as is.")
                _cache_set(tool_name, _waf, original_cmd, ai_cmd)
                return ai_cmd

            # ── Present choice to user (clean, colored) ─────
            print()
            print(f"{_C}{_BOLD}┌─ AI Optimization ─ {tool_name} ─────────────{_RST}")
            print(f"{_DIM}│ Original: {original_cmd}{_RST}")
            print(f"{_G}{_BOLD}│ AI-Cmd  : {ai_cmd}{_RST}")
            print(f"{_C}{_BOLD}└────────────────────────────────────────────{_RST}")
            choice = _ask_user_ai_choice(tool_name, original_cmd, ai_cmd)
            if choice == "y":
                print(f"{_G}✅ Using AI command{_RST}")
                _cache_set(tool_name, _waf, original_cmd, ai_cmd)
                return ai_cmd
            else:
                print(f"{_DIM}↩️  Using original command{_RST}")
                return original_cmd
            
            print(f"[AI] ⚠️ {tool_name}: AI returned invalid output. Fallback to original.")
            return original_cmd
    except Exception as e:
        print(f"[AI] ⚠️ {tool_name}: Error during optimization ({e}). Fallback to original.")
        return original_cmd
