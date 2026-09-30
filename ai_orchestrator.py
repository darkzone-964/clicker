import json
import urllib.request
import urllib.error
import subprocess

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
        
        with urllib.request.urlopen(req, timeout=15) as res:
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
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
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
        
        with urllib.request.urlopen(req, timeout=20) as res:
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
            help_result = subprocess.run(["puredns", "--help"], capture_output=True, text=True, timeout=5)
            help_text = (help_result.stdout + help_result.stderr)[:3000]
            
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
            
            with urllib.request.urlopen(req, timeout=20) as res:
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
    result = subprocess.run(final_cmd, shell=True, capture_output=True, text=True, timeout=1800)
    
    if result.returncode != 0:
        print(f"[DEBUG] puredns exit code: {result.returncode}")
        print(f"[DEBUG] puredns stderr: {result.stderr[:500]}")
    return result.returncode, result.stdout, result.stderr


def optimize_tool_command(tool_name, original_cmd, context, api_key):
    """Universal AI optimizer: Reads --help, reviews original cmd, and optimizes if needed."""
    print(f"\n[AI] 🧠 Reviewing {tool_name} command...")
    print(f"[AI] 📜 Original: {original_cmd}")
    
    if not api_key:
        print(f"[AI] ⚠️ No API key, using original command.")
        return original_cmd
    
    try:
        base_tool = tool_name.split()[0]
        help_res = subprocess.run([base_tool, "--help"], capture_output=True, text=True, timeout=5)
        help_text = (help_res.stdout + help_res.stderr)[:2500]
        
        prompt = f"""You are an expert Bug Bounty automation engineer.
Original Command: {original_cmd}
Tool Help Reference:
---
{help_text}
---
Context:
- Domain: {context.get('domain', 'target.com')}
- WAF Type: {context.get('waf_type', 'none')}

Task: Review the Original Command. 
1. If it needs optimization (e.g., adding rate limits for Cloudflare/Akamai, fixing paths, adding silent flags), output the improved command.
2. If the Original Command is already perfect, safe, and optimal, return it EXACTLY as is.
3. Use ONLY flags that exist in the Help Reference.
4. Return ONLY the raw command string. No markdown, no explanation, no quotes.
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
        
        with urllib.request.urlopen(req, timeout=15) as res:
            response = json.loads(res.read().decode("utf-8"))
            ai_cmd = response["choices"][0]["message"]["content"].strip()
            ai_cmd = ai_cmd.replace("```bash", "").replace("```", "").strip()
            
            if base_tool in ai_cmd:
                if ai_cmd.strip() == original_cmd.strip():
                    print(f"[AI] ✅ {tool_name}: Command is already optimal. Kept as is.")
                else:
                    print(f"[AI] 🚀 {tool_name}: Command optimized by AI!")
                    print(f"[AI] 📜 New: {ai_cmd}")
                return ai_cmd
            
            print(f"[AI] ⚠️ {tool_name}: AI returned invalid output. Fallback to original.")
            return original_cmd
    except Exception as e:
        print(f"[AI] ⚠️ {tool_name}: Error during optimization ({e}). Fallback to original.")
        return original_cmd
