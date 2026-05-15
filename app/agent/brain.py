import json
import re
from urllib.parse import urlparse

from app.llm.ollama_client import OllamaClient, OllamaUnavailableError
from app.core.scan_depth import ffuf_dirs_depth_allows


BRAIN_PROMPT = """You are the orchestration brain for Recon+, an AI-driven security reconnaissance agent.

YOUR 4 RULES:
1. Every finding (directory, subdomain, port, file, suspicious query parameter) must be added to the report immediately — even if you don't think it is relevant.
2. Never remove data from the report. Only add.
3. No duplicate lines. If port 80 was already found, and the version scan returns nginx info, UPDATE the existing "80/tcp open http" line to "80/tcp open http nginx 1.26.3". Do NOT write a second port-80 line.
4. Run up to 3 scripts at the same time. When one finishes, start the next.

DEPTH (from state "depth"): If depth is 0, NEVER propose ffuf_dirs on any URL except the exact target root (same host and path "/"). If depth is N>0, only propose ffuf_dirs on URLs at most N path segments deeper than the target path. If depth is null, recursion is unlimited.

DIR LIST MODE: If state has "dir_list_mode": true, the user supplied --dir bases in "dir_ffuf_normalized_bases". On any host that appears in that file, do NOT propose ffuf_dirs for a URL unless its normalized form is exactly one of those bases (the queue runs ffuf_dir_list for each line). You MAY propose ffuf_dirs on discovered vhosts whose hostname does not appear in the file. If the user included the site root in the file, it appears as a base like http://target — otherwise never propose ffuf_dirs on the bare root for that host.

PROBE / PAGE EVIDENCE: When reasoning from probe results, treat the same HTTP stack (Server / X-Powered-By repeated on many pages) as one fact. Ignore login UX ("Forgot password?", recovery forms) unless it exposes a real secret or misconfiguration.

PARAMETER DISCOVERY (evidence first — reduce false positives):
  findings.param_candidates: structured list per discovered parameter. Each has:
    endpoint, method, parameter, source, discovery_type, confidence (high|medium|low),
    vulnerability_status (candidate_only | candidate_high_priority | not_reported),
    suspected_tests, not_reported_as, reason, response_analysis (meaningful_difference, reflection_only).
  Rules:
  - ONLY trust parameters from real HTML forms, links, JavaScript, or observed URLs (discovery_type confirmed_*).
  - Do NOT invent random parameters (?a=, ?z=) or report them as findings.
  - LOW confidence / heuristic_guess / not_reported → never treat as confirmed vulnerability.
  - MEDIUM + generic names (q, search, id) + reflection_only → candidate_only (search/sql probe), NOT confirmed LFI.
  - HIGH + security names (file, path, page, include, template, view, …) → may schedule ffuf_lfi if schedule_ffuf_lfi is true in the candidate.
  - findings.lfi_fuzz_targets: only high-confidence schedulable LFI URLs — do not ffuf_lfi every form field blindly.
  - Never say "confirmed LFI" unless proof exists in findings (type lfi) or strong error signals in response_analysis.

YOUR WORKFLOW — follow this phase order:

PHASE 1 — start all 3 at once immediately:
  - ffuf_dirs with wordlist_index 0    (directory and file fuzzing)
  - ffuf_vhosts                        (subdomain / virtual host discovery)
  - nmap_ports                         (fast full TCP scan: -Pn -T<timing> -p-; timing from user -nt, default T4)

PHASE 2 — when Phase 1 tasks complete:
  - nmap_ports finished + open ports found  → start exactly ONE nmap_versions covering ALL open TCP ports together (orchestrator merges ports; do not split into multiple nmap_versions for subsets like "80" then "80,22" — that re-scans port 80).
  - ffuf_dirs(0) finished                   → start ffuf_dirs with wordlist_index 1 (second wordlist)
  - ffuf_dirs(0) finished + dirs found      → start ffuf_dirs(0) on each found DIRECTORY url — SKIP files (anything with a dot in the last path component: .htaccess, robots.txt, config.php). Prioritize HIGH-VALUE dirs first: admin, panel, dashboard, api, login, auth, config, backup, upload, secret, debug, dev, test, internal
  - ffuf_vhosts finished + vhosts found     → start ffuf_dirs(0) on each found vhost (e.g. http://cacti.TARGET/FUZZ)
  - ffuf_dirs(0) or ffuf_vhosts finished    → start probe on discovered directories/vhosts (if a slot is free)

PHASE 3 — when Phase 2 tasks complete:
  - use free slots for probe on interesting directories/vhosts while ffuf or nmap still runs when possible
  - param_candidates with schedule_ffuf_lfi true and confidence high → ffuf_lfi (URL already has FUZZ)
  - param_candidates medium (e.g. q from search form) → probe more or note candidate_only — do NOT report as confirmed LFI
  - prioritize probe on pages with forms under /admin/ etc. before guessing vulnerabilities
  - ffuf_dirs(1) finished + new dirs found + depth allows recursion           → start ffuf_dirs(0) on each new DIRECTORY (not files)
  - ffuf_dirs(1) finished + new dirs found                                    → start probe on those new dirs
  - nothing more to do                                                        → stop

CURRENT STATE:
{state}

AVAILABLE SLOTS: {slots}  (you may start at most this many new tasks right now — total running must stay ≤ 3)

VALID ACTIONS (each is a JSON object):
  {{"action": "ffuf_dirs",     "url": "http://TARGET/",                   "wordlist_index": 0}}
  {{"action": "ffuf_dirs",     "url": "http://TARGET/login/",             "wordlist_index": 0}}
  {{"action": "ffuf_dirs",     "url": "http://cacti.TARGET/",             "wordlist_index": 0}}
  {{"action": "ffuf_vhosts",   "url": "http://TARGET/"}}
  {{"action": "nmap_ports",    "target": "TARGET_HOST"}}
  {{"action": "nmap_versions", "target": "TARGET_HOST",                   "ports": "ignored — use state.open_tcp_ports_csv"}}
  {{"action": "probe",         "url": "http://TARGET/path/"}}
  {{"action": "ffuf_lfi",      "url": "http://TARGET/page.php?file=FUZZ"}}
  {{"action": "stop",          "reason": "all phases complete"}}

IMPORTANT FILE RULE: Never run ffuf_dirs on a URL whose last path component contains a dot (e.g. robots.txt, .htaccess, config.php are FILES — do not scan FILES/FUZZ).

Return ONLY a JSON array of actions to start now. Max {slots} items. No explanation. No markdown.
If nothing to start, return: [{{"action": "stop", "reason": "all phases complete"}}]
"""


def _extract_json_array(text: str) -> list:
    """Parse a JSON array from Ollama's response, stripping markdown fences."""
    cleaned = text.strip()
    if cleaned.startswith("```json"):
        cleaned = cleaned.removeprefix("```json").strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.removeprefix("```").strip()
    if cleaned.endswith("```"):
        cleaned = cleaned.removesuffix("```").strip()

    # Try direct parse first
    try:
        result = json.loads(cleaned)
        if isinstance(result, list):
            return result
        if isinstance(result, dict) and "actions" in result:
            return result["actions"]
        if isinstance(result, dict) and "action" in result:
            return [result]
    except json.JSONDecodeError:
        pass

    # Try to extract first JSON array from text
    match = re.search(r'\[.*?\]', cleaned, re.DOTALL)
    if match:
        try:
            result = json.loads(match.group())
            if isinstance(result, list):
                return result
        except json.JSONDecodeError:
            pass

    return []


def _hardcoded_workflow(state: dict, slots: int) -> list[dict]:
    """
    Fallback workflow when Ollama is unavailable or returns bad JSON.
    Replicates the phase-based logic described in the brain prompt.
    """
    target = state.get("target", "")
    running = set(state.get("running_tasks", []))
    completed = set(state.get("completed_tasks", []))
    findings = state.get("findings", {})
    dirs_used = set(state.get("wordlists_used_for_dirs", []))
    probed = set(state.get("probed_urls", []))
    lfi_tested = set(state.get("lfi_tested_urls", []))
    depth = state.get("depth")          # None = unlimited recursion, 0 = no recursion, N = max levels

    host = urlparse(target).hostname or target
    target_norm = target.rstrip("/") + "/"
    actions = []

    def is_done_or_running(prefix: str) -> bool:
        return any(t.startswith(prefix) for t in running | completed)

    def already_dir_scanned(url: str) -> bool:
        """Return True if we have run or are running a dir scan on this URL."""
        norm = url.rstrip("/") + "/"
        return any(
            (t.startswith("ffuf_dirs_0_") or t.startswith("ffuf_dirs_1_")) and
            (t.endswith("_" + norm) or t.endswith("_" + norm.rstrip("/")))
            for t in running | completed
        )

    dir_list_mode = state.get("dir_list_mode", False)

    # ------------------------------------------------------------------ #
    # Phase 1: start all 3 at once
    # ------------------------------------------------------------------ #
    if not dir_list_mode and not is_done_or_running(f"ffuf_dirs_0_{target}"):
        actions.append({"action": "ffuf_dirs", "url": target, "wordlist_index": 0})
    if not is_done_or_running("ffuf_vhosts"):
        actions.append({"action": "ffuf_vhosts", "url": target})
    if not is_done_or_running("nmap_ports"):
        actions.append({"action": "nmap_ports", "target": host})

    if actions:
        return actions[:slots]

    # ------------------------------------------------------------------ #
    # Phases 2 & 3: collect ALL possible actions by priority, pick top N
    # This allows e.g. nmap_versions + recursive_dir + probe to run in parallel.
    # ------------------------------------------------------------------ #
    priority: list[dict] = []  # ordered list of actions we WANT to start

    # Priority 1 — one nmap_versions after full port scan, all open TCP ports at once
    canonical = (state.get("open_tcp_ports_csv") or "").strip()
    if canonical and "nmap_ports" in completed:
        nmap_vid = f"nmap_versions_{canonical}"
        if nmap_vid not in running and nmap_vid not in completed:
            priority.append({"action": "nmap_versions", "target": host, "ports": canonical})

    # Priority 2 — LFI fuzz only when confidence is high (evidence-backed)
    for target in findings.get("lfi_fuzz_targets", [])[:8]:
        if (target.get("confidence") or "").lower() != "high":
            continue
        ffuf_url = (target.get("ffuf_lfi_url") or "").strip()
        if ffuf_url and ffuf_url not in lfi_tested and "FUZZ" in ffuf_url:
            priority.append({"action": "ffuf_lfi", "url": ffuf_url})
    for pc in findings.get("param_candidates", [])[:10]:
        if not pc.get("schedule_ffuf_lfi"):
            continue
        if (pc.get("confidence") or "").lower() != "high":
            continue
        ffuf_url = (pc.get("ffuf_lfi_url") or "").strip()
        if ffuf_url and ffuf_url not in lfi_tested and "FUZZ" in ffuf_url:
            priority.append({"action": "ffuf_lfi", "url": ffuf_url})

    # Priority 3 — probes (before flooding ffuf_dirs so parallel slots stay useful)
    for vhost in findings.get("vhosts", [])[:3]:
        vhost_url = f"http://{vhost}" if not vhost.startswith("http") else vhost
        if vhost_url not in probed:
            priority.append({"action": "probe", "url": vhost_url})

    for dir_url in findings.get("directories", [])[:10]:
        if dir_url not in probed:
            priority.append({"action": "probe", "url": dir_url})

    # Priority 4 — second dir wordlist on root
    root_task_1 = f"ffuf_dirs_1_{target}"
    if (
        not dir_list_mode
        and is_done_or_running(f"ffuf_dirs_0_{target}")
        and 1 not in dirs_used
        and not is_done_or_running(root_task_1)
    ):
        priority.append({"action": "ffuf_dirs", "url": target, "wordlist_index": 1})

    # Priority 5 — recursive dir scan on each found directory (if depth allows).
    # High-value directory names are scanned first so Ollama (or the fallback) focuses
    # on the most interesting attack surface before generic dirs like /static or /assets.
    _HIGH_VALUE = {
        "admin", "administrator", "panel", "dashboard", "manage", "management",
        "api", "v1", "v2", "v3", "graphql", "rest",
        "login", "auth", "oauth", "sso", "account", "accounts",
        "config", "configuration", "setup", "install",
        "backup", "backups", "bak", "old", "archive",
        "upload", "uploads", "files", "download", "downloads",
        "secret", "secrets", "private", "internal", "hidden",
        "debug", "test", "dev", "development", "staging",
    }

    all_dirs = findings.get("directories", [])[:20]

    def _dir_priority(url: str) -> int:
        name = url.rstrip("/").split("/")[-1].lower()
        return 0 if name in _HIGH_VALUE else 1

    sorted_dirs = sorted(all_dirs, key=_dir_priority)

    for dir_url in sorted_dirs:
        dir_norm = dir_url.rstrip("/") + "/"
        if dir_norm == target_norm:
            continue
        if dir_list_mode:
            continue
        if already_dir_scanned(dir_norm):
            continue
        if not ffuf_dirs_depth_allows(target, dir_norm, depth):
            continue
        priority.append({"action": "ffuf_dirs", "url": dir_norm, "wordlist_index": 0})

    # Priority 6 — ffuf_dirs on each discovered VHost (treat like a new target)
    # Only start after the vhosts scan has actually completed so we have real results.
    if "ffuf_vhosts" in completed:
        for vhost in findings.get("vhosts", [])[:5]:
            vhost_url = f"http://{vhost}/" if not vhost.startswith("http") else vhost.rstrip("/") + "/"
            if not ffuf_dirs_depth_allows(target, vhost_url, depth):
                continue
            if not already_dir_scanned(vhost_url):
                priority.append({"action": "ffuf_dirs", "url": vhost_url, "wordlist_index": 0})

    # Priority 7 — LFI only for classic strong param names in real URLs (not guessed)
    lfi_params = {"file", "page", "path", "include", "template", "view",
                  "inc", "document", "doc", "folder", "load", "read"}
    for entry in findings.get("suspicious_params", []):
        url = entry.get("url", "")
        param = entry.get("param", "").lower()
        if not url or not param or param not in lfi_params:
            continue
        lfi_url = _build_lfi_url(url, param)
        if lfi_url and lfi_url not in lfi_tested:
            priority.append({"action": "ffuf_lfi", "url": lfi_url})

    if priority:
        return priority[:slots]

    return [{"action": "stop", "reason": "all phases complete"}]


def _build_lfi_url(url: str, param: str) -> str:
    """Replace the given param's value with FUZZ in the URL."""
    from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    if param not in params:
        return ""
    new_params = {}
    for k, v in params.items():
        new_params[k] = ["FUZZ"] if k == param else v
    new_query = urlencode(new_params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


class AgentBrain:
    def __init__(self, client: OllamaClient | None = None):
        self.client = client or OllamaClient()

    def decide(self, state: dict, slots: int = 3) -> list[dict]:
        """
        Ask Ollama what to run next given current state and available slots.
        Falls back to hardcoded workflow if Ollama is unavailable or returns bad JSON.
        """
        if slots <= 0:
            return []

        state_text = json.dumps(state, indent=2, ensure_ascii=False)
        prompt = BRAIN_PROMPT.format(state=state_text, slots=slots)

        try:
            raw = self.client.ask(prompt)
            actions = _extract_json_array(raw)
            if actions:
                # Validate — only allow known action types
                valid = {"ffuf_dirs", "ffuf_vhosts", "nmap_ports", "nmap_versions", "probe", "ffuf_lfi", "stop"}
                safe = [a for a in actions if isinstance(a, dict) and a.get("action") in valid]
                if safe:
                    target = state.get("target", "")
                    depth = state.get("depth")
                    filtered: list[dict] = []
                    for a in safe:
                        if a.get("action") == "ffuf_dirs":
                            u = a.get("url") or target
                            if not ffuf_dirs_depth_allows(target, u, depth):
                                continue
                            if state.get("dir_list_mode"):
                                allow = {
                                    x.rstrip("/").lower()
                                    for x in (state.get("dir_ffuf_normalized_bases") or [])
                                    if x
                                }
                                if allow:
                                    uh = (urlparse(u).hostname or "").lower()
                                    file_hosts: set[str] = set()
                                    for item in allow:
                                        fh = (urlparse(item).hostname or "").lower()
                                        if fh:
                                            file_hosts.add(fh)
                                    if uh in file_hosts:
                                        nu = u.rstrip("/").lower()
                                        if nu not in allow:
                                            continue
                        elif a.get("action") == "nmap_versions":
                            if "nmap_ports" not in set(state.get("completed_tasks", [])):
                                continue
                        filtered.append(a)
                    if filtered:
                        return filtered[:slots]
        except OllamaUnavailableError:
            pass
        except Exception:
            pass

        # Fallback: run hardcoded workflow
        return _hardcoded_workflow(state, slots)
