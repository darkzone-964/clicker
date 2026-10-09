"""
idor_collection.py — Full IDOR Collection Phase.

Implements:
  - gf patterns (idor, interestingparams, debug_logic)
  - API version extraction
  - Token/UUID collection
  - Advanced JS mining (jsluice + xnLinkFinder)
  - GraphQL discovery + operations + fingerprinting
  - Lifecycle indicators
  - Response field expansion
  - WordPress REST
  - arjun + paramspider integration
  - Merge all candidates
"""
import re
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from idor_utils import (
    C, G, Y, R, BOLD, RST, DIM,
    curl_request, fetch, load_lines, save_lines, run_tool, tool_available,
)

# Quote-safe regex fragments (avoid parser issues)
_Q = r'["\x27]'   # matches " or '


# ═══════════════════════════════════════════════════════════
# 1. gf patterns
# ═══════════════════════════════════════════════════════════
def collection_gf_patterns(clean_urls_file, idir):
    """Run gf idor / interestingparams / debug_logic."""
    if not tool_available("gf"):
        print(f"  {Y}[!]{RST} gf not installed - skipping")
        return {}
    results = {}
    for pattern, out_name in [
        ("idor", "gf_idor_urls.txt"),
        ("interestingparams", "gf_interesting_params.txt"),
        ("debug_logic", "gf_debug_logic.txt"),
    ]:
        out = idir / out_name
        cmd = f"cat {clean_urls_file} | gf {pattern} 2>/dev/null | sort -u > {out}"
        run_tool(cmd, timeout=120)
        lines = load_lines(out)
        results[pattern] = lines
        print(f"    {G}+{RST} gf {pattern:18} -> {len(lines)} URLs")
    return results


# ═══════════════════════════════════════════════════════════
# 2. API versions + tokens + UUIDs
# ═══════════════════════════════════════════════════════════
def collection_api_versions(clean_urls_file, idir):
    """Extract API versions and versioned endpoints."""
    lines = load_lines(clean_urls_file)
    versions = set()
    versioned = set()
    for url in lines:
        for m in re.finditer(r'/api/v([0-9]+)', url, re.IGNORECASE):
            versions.add(f"v{m.group(1)}")
        if re.search(r'/api/v[0-9]+/', url, re.IGNORECASE):
            versioned.add(url)
    save_lines(idir / "api_versions.txt", sorted(versions))
    save_lines(idir / "versioned_api_endpoints.txt", versioned)
    print(f"    {G}+{RST} API versions      -> {len(versions)}: {sorted(versions)}")
    print(f"    {G}+{RST} Versioned endpoints -> {len(versioned)}")
    return {"versions": sorted(versions), "versioned": sorted(versioned)}


def collection_tokens_uuids(clean_urls_file, idir):
    """Collect UUIDs, tokens, and endpoints with references."""
    lines = load_lines(clean_urls_file)
    uuids = set()
    tokens = set()
    endpoints_refs = set()

    uuid_pat = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', re.IGNORECASE)
    token_pat = re.compile(r'(token|key|code|share|invite|preview|draft)=([A-Za-z0-9_-]{16,})', re.IGNORECASE)
    ref_pat = re.compile(r'/[a-zA-Z]+/[0-9a-f-]{8,}', re.IGNORECASE)

    for url in lines:
        uuids.update(uuid_pat.findall(url))
        tokens.update(token_pat.findall(url))
        if ref_pat.search(url):
            endpoints_refs.add(url)

    save_lines(idir / "collected_uuids.txt", sorted(uuids))
    save_lines(idir / "collected_tokens.txt", [f"{k}={v}" for k, v in tokens])
    save_lines(idir / "endpoints_with_refs.txt", endpoints_refs)
    print(f"    {G}+{RST} UUIDs              -> {len(uuids)}")
    print(f"    {G}+{RST} Tokens             -> {len(tokens)}")
    print(f"    {G}+{RST} Endpoints with refs-> {len(endpoints_refs)}")
    return {"uuids": sorted(uuids), "tokens": list(tokens), "refs": sorted(endpoints_refs)}


# ═══════════════════════════════════════════════════════════
# 3. Advanced JS mining
# ═══════════════════════════════════════════════════════════
def collection_js_mining(js_files_file, idir, target_domain=""):
    """Run jsluice + xnLinkFinder on JS files."""
    js_files = load_lines(js_files_file)
    if not js_files:
        print(f"    {Y}[!]{RST} No JS files to mine")
        return {"urls": [], "secrets": [], "endpoints": []}

    results = {"urls": [], "secrets": [], "endpoints": []}

    if tool_available("jsluice"):
        out = idir / "jsluice_urls.txt"
        cmd = f"cat {js_files_file} | jsluice urls 2>/dev/null > {out}"
        run_tool(cmd, timeout=120)
        results["urls"] = load_lines(out)
        print(f"    {G}+{RST} jsluice urls       -> {len(results['urls'])}")

        out2 = idir / "jsluice_secrets.txt"
        cmd = f"cat {js_files_file} | jsluice secrets 2>/dev/null > {out2}"
        run_tool(cmd, timeout=120)
        results["secrets"] = load_lines(out2)
        print(f"    {G}+{RST} jsluice secrets    -> {len(results['secrets'])}")

    if tool_available("xnLinkFinder"):
        out = idir / "xnlinkfinder_endpoints.txt"
        domain_flag = f"-sf {target_domain}" if target_domain else ""
        cmd = f"xnLinkFinder -i {js_files_file} -o {out} {domain_flag} 2>/dev/null"
        run_tool(cmd, timeout=180)
        results["endpoints"] = load_lines(out)
        print(f"    {G}+{RST} xnLinkFinder       -> {len(results['endpoints'])}")

    return results


# ═══════════════════════════════════════════════════════════
# 4. GraphQL full discovery
# ═══════════════════════════════════════════════════════════
def collection_graphql(clean_urls_file, js_files_file, idir):
    """GraphQL endpoint + operations + queries + fingerprint."""
    results = {"endpoints": [], "operations": [], "queries": [], "fingerprint": []}

    lines = load_lines(clean_urls_file)
    ep = set()
    for url in lines:
        if "graphql" in url.lower():
            ep.add(url)
    # Extended GraphQL URL extraction
    for m in re.findall(r'https?://\S*?graphql\S*', "\n".join(lines), re.IGNORECASE):
        ep.add(m)

    js = load_lines(js_files_file)
    for jf in js[:30]:
        r = curl_request(jf, timeout=8)
        if r["status"] == 200 and r["body"]:
            for m in re.findall(r'https?://\S*?graphql\S*', r["body"], re.IGNORECASE):
                ep.add(m)
            for m in re.findall(r'operationName\s*[:=]\s*["\x27]([A-Za-z0-9_]+)', r["body"]):
                results["operations"].append(m)
            for m in re.findall(r'(query|mutation)\s+([A-Za-z0-9_]+)', r["body"]):
                results["queries"].append(f"{m[0]} {m[1]}")

    save_lines(idir / "graphql_endpoints.txt", sorted(ep))
    save_lines(idir / "graphql_operations.txt", sorted(set(results["operations"])))
    save_lines(idir / "graphql_queries.txt", sorted(set(results["queries"])))
    results["endpoints"] = sorted(ep)
    results["operations"] = sorted(set(results["operations"]))
    results["queries"] = sorted(set(results["queries"]))

    print(f"    {G}+{RST} GraphQL endpoints  -> {len(results['endpoints'])}")
    print(f"    {G}+{RST} GraphQL operations -> {len(results['operations'])}")
    print(f"    {G}+{RST} GraphQL queries    -> {len(results['queries'])}")

    if tool_available("graphw00f") and results["endpoints"]:
        fp_file = idir / "graphql_endpoints_list.txt"
        save_lines(fp_file, results["endpoints"])
        out = idir / "graphw00f_results.txt"
        cmd = f"graphw00f -f {fp_file} -o {out} 2>/dev/null"
        run_tool(cmd, timeout=120)
        results["fingerprint"] = load_lines(out)
        print(f"    {G}+{RST} graphw00f          -> {len(results['fingerprint'])}")

    return results


# ═══════════════════════════════════════════════════════════
# 5. Lifecycle indicators
# ═══════════════════════════════════════════════════════════
def collection_lifecycle(clean_urls_file, idir):
    """Extract lifecycle / state-change indicators."""
    lines = load_lines(clean_urls_file)
    lifecycle = set()
    resource = set()
    file_export = set()
    search = set()

    lifecycle_pat = re.compile(r'(delete|archive|expire|inactive|disabled|draft|unpublish|revoke|old|removed|deprecated|deactivate)', re.IGNORECASE)
    resource_pat = re.compile(r'(form|report|ticket|order|invoice|share|invite|project|workspace|download|attachment|submission|preview|draft)', re.IGNORECASE)
    file_pat = re.compile(r'(download|upload|export|file|attachment|document|invoice|receipt|report|pdf|csv|xlsx|image|avatar)(/|\?|=)', re.IGNORECASE)
    search_pat = re.compile(r'(search|autocomplete|typeahead|lookup|suggest|filter|query|find)(/|\?|=)', re.IGNORECASE)

    for url in lines:
        if lifecycle_pat.search(url): lifecycle.add(url)
        if resource_pat.search(url): resource.add(url)
        if file_pat.search(url): file_export.add(url)
        if search_pat.search(url): search.add(url)

    save_lines(idir / "lifecycle_urls.txt", lifecycle)
    save_lines(idir / "resource_endpoints.txt", resource)
    save_lines(idir / "file_export_endpoints.txt", file_export)
    save_lines(idir / "search_endpoints.txt", search)
    print(f"    {G}+{RST} Lifecycle URLs     -> {len(lifecycle)}")
    print(f"    {G}+{RST} Resource endpoints -> {len(resource)}")
    print(f"    {G}+{RST} File/Export        -> {len(file_export)}")
    print(f"    {G}+{RST} Search endpoints   -> {len(search)}")
    return {"lifecycle": sorted(lifecycle), "resource": sorted(resource),
            "file": sorted(file_export), "search": sorted(search)}


# ═══════════════════════════════════════════════════════════
# 6. Response field expansion
# ═══════════════════════════════════════════════════════════
def collection_field_expansion(clean_urls_file, js_files_file, idir):
    """Collect field-control parameter hints."""
    lines = load_lines(clean_urls_file)

    all_params = set()
    for url in lines:
        try:
            parsed = urlparse(url)
            if parsed.query:
                for k in parse_qs(parsed.query).keys():
                    all_params.add(k)
        except Exception:
            continue

    field_params = set()
    field_pat = re.compile(r'(include|fields|select|expand|columns|attributes|embed|with|relations|populate|projection|filter)', re.IGNORECASE)
    for p in all_params:
        if field_pat.search(p):
            field_params.add(p)

    field_values = set()
    js = load_lines(js_files_file)
    for jf in js[:20]:
        r = curl_request(jf, timeout=8)
        if r["status"] == 200 and r["body"]:
            for m in re.findall(r'(include|fields|select|expand|embed|with|populate)=([^&\x22\x27]+)', r["body"]):
                field_values.add(f"{m[0]}={m[1]}")

    sensitive = set()
    sensitive_pat = re.compile(r'"(firstname|lastname|email|phone|address|password|token|secret|ssn|dob|salary|role|permissions?|isAdmin)"')
    for jf in js[:20]:
        r = curl_request(jf, timeout=8)
        if r["status"] == 200 and r["body"]:
            for m in sensitive_pat.findall(r["body"]):
                sensitive.add(m)

    save_lines(idir / "all_query_params.txt", sorted(all_params))
    save_lines(idir / "field_params.txt", sorted(field_params))
    save_lines(idir / "field_values_from_js.txt", sorted(field_values))
    save_lines(idir / "sensitive_field_names.txt", sorted(sensitive))
    print(f"    {G}+{RST} All query params   -> {len(all_params)}")
    print(f"    {G}+{RST} Field params       -> {len(field_params)}")
    print(f"    {G}+{RST} Field values (JS)  -> {len(field_values)}")
    print(f"    {G}+{RST} Sensitive fields   -> {len(sensitive)}")
    return {"params": sorted(all_params), "field_params": sorted(field_params),
            "field_values": sorted(field_values), "sensitive": sorted(sensitive)}


# ═══════════════════════════════════════════════════════════
# 7. WordPress + arjun + paramspider
# ═══════════════════════════════════════════════════════════
def collection_params_active(domain, clean_urls_file, api_endpoints_file, idir):
    """arjun + paramspider + WordPress REST."""
    results = {"arjun": [], "paramspider": [], "wp_json": []}

    if tool_available("arjun") and Path(api_endpoints_file).exists():
        out = idir / "arjun_params.txt"
        cmd = f"arjun -i {api_endpoints_file} -oT {out} --rate 5 --stable 2>/dev/null"
        run_tool(cmd, timeout=600)
        results["arjun"] = load_lines(out)
        print(f"    {G}+{RST} arjun params       -> {len(results['arjun'])}")

    if tool_available("paramspider"):
        out = idir / "paramspider_urls.txt"
        cmd = f"paramspider -d {domain} -o {out} 2>/dev/null"
        run_tool(cmd, timeout=300)
        results["paramspider"] = load_lines(out)
        print(f"    {G}+{RST} paramspider URLs   -> {len(results['paramspider'])}")

    wp_urls = set()
    for url in load_lines(clean_urls_file):
        if "/wp-json/" in url:
            wp_urls.add(url)
    if wp_urls:
        hosts = set()
        for url in wp_urls:
            try:
                p = urlparse(url)
                hosts.add(f"{p.scheme}://{p.netloc}")
            except Exception:
                continue
        common = set()
        for h in hosts:
            common.add(f"{h}/wp-json/")
            common.add(f"{h}/wp-json/wp/v2/users")
            common.add(f"{h}/wp-json/wp/v2/media")
        save_lines(idir / "wp_json_urls.txt", wp_urls | common)
        results["wp_json"] = sorted(wp_urls | common)
        print(f"    {G}+{RST} WordPress REST    -> {len(results['wp_json'])}")

    return results


# ═══════════════════════════════════════════════════════════
# 8. Merge all candidates
# ═══════════════════════════════════════════════════════════
def collection_merge_all(idir):
    """Merge all candidate files into one master list."""
    sources = [
        "gf_idor_urls.txt",
        "gf_interesting_params.txt",
        "gf_debug_logic.txt",
        "versioned_api_endpoints.txt",
        "endpoints_with_refs.txt",
        "js_discovered_api_endpoints.txt",
        "jsluice_urls.txt",
        "xnlinkfinder_endpoints.txt",
        "lifecycle_urls.txt",
        "resource_endpoints.txt",
        "file_export_endpoints.txt",
        "search_endpoints.txt",
        "wp_json_urls.txt",
    ]
    all_candidates = set()
    for name in sources:
        p = idir / name
        if p.exists():
            for line in load_lines(p):
                if line.startswith(("http://", "https://")) or line.startswith("/"):
                    all_candidates.add(line)

    out = idir / "ALL_IDOR_CANDIDATES.txt"
    save_lines(out, sorted(all_candidates))
    print(f"    {G}+{RST} {BOLD}ALL CANDIDATES{RST}     -> {len(all_candidates)} entries")
    return sorted(all_candidates)


# ═══════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════
def run_collection_phase(domain, workspace, idir, clean_urls_file, js_files_file):
    """Run all collection sub-phases."""
    idir = Path(idir)
    idir.mkdir(parents=True, exist_ok=True)

    print(f"\n{BOLD}{C}{'=' * 60}{RST}")
    print(f"{BOLD}{C}  IDOR Collection Phase — Full Methodology{RST}")
    print(f"{BOLD}{C}{'=' * 60}{RST}\n")

    results = {}

    print(f"{BOLD}[1/8] gf patterns{RST}")
    results["gf"] = collection_gf_patterns(clean_urls_file, idir)

    print(f"\n{BOLD}[2/8] API versions + tokens{RST}")
    results["api"] = collection_api_versions(clean_urls_file, idir)
    results["refs"] = collection_tokens_uuids(clean_urls_file, idir)

    print(f"\n{BOLD}[3/8] JS mining (jsluice + xnLinkFinder){RST}")
    results["js"] = collection_js_mining(js_files_file, idir, domain)

    print(f"\n{BOLD}[4/8] GraphQL discovery{RST}")
    results["graphql"] = collection_graphql(clean_urls_file, js_files_file, idir)

    print(f"\n{BOLD}[5/8] Lifecycle + resource endpoints{RST}")
    results["lifecycle"] = collection_lifecycle(clean_urls_file, idir)

    print(f"\n{BOLD}[6/8] Response field expansion{RST}")
    results["fields"] = collection_field_expansion(clean_urls_file, js_files_file, idir)

    print(f"\n{BOLD}[7/8] Active params (arjun + paramspider + WP){RST}")
    api_ep_file = idir / "api_endpoints.txt"
    if not api_ep_file.exists():
        save_lines(api_ep_file, [])
    results["active"] = collection_params_active(
        domain, clean_urls_file, api_ep_file, idir
    )

    print(f"\n{BOLD}[8/8] Merge all candidates{RST}")
    results["all"] = collection_merge_all(idir)

    print(f"\n{G}{BOLD}[+] Collection complete{RST}")
    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 idor_collection.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    workspace = "clicker_output"
    idir = Path(workspace) / domain / "idor"
    clean_urls = Path(workspace) / domain / "urls" / "clean_urls.txt"
    js_files = Path(workspace) / domain / "js" / "jsfiles.txt"

    if not clean_urls.exists():
        print(f"[x] Not found: {clean_urls}")
        print("    Run a scan first to generate this file.")
        sys.exit(1)

    run_collection_phase(domain, workspace, idir, clean_urls, js_files)
