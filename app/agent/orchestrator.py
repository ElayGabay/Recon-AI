"""
ReconOrchestrator — the main execution engine.

Ollama (via AgentBrain) decides what to run next.
This class executes those decisions, tracks running/completed tasks,
and writes the final report.
"""
import queue as stdlib_queue
import threading
import time
from collections import deque
from concurrent.futures import Future
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from app.agent.brain import AgentBrain
from app.agent.report_writer import OllamaReportWriter, build_inventory, load_jsonl, open_tcp_ports_csv_from_findings
from app.core.report_manager import ReportManager
from app.core.process_manager import should_stop
from app.core.output import info, warning, success, console, log
from app.tools.ffuf_runner import run_ffuf_directory, run_ffuf_vhost, LiveProbeManager
from app.tools.nmap_runner import run_nmap_scan, build_timing_flags
from app.tools.content_probe import content_probe
from app.tools.lfi_tester import lfi_triage
from app.core.seclists_catalog import get_wordlists_for_mode
from app.core.runtime_controller import RuntimeController
from app.core.scan_depth import ffuf_dirs_depth_allows, ffuf_dirs_extra_depth
from app.core.http_cookie import normalize_cookie_arg


def _dir_list_task_label(base_url: str) -> str:
    """Short path label for status table, e.g. ffuf_dir_list:/admin/login"""
    p = urlparse(base_url)
    path = (p.path or "").strip()
    if not path or path == "/":
        label = "/"
    else:
        label = path if path.startswith("/") else "/" + path
    label = label.rstrip("/") or "/"
    if len(label) > 52:
        label = label[:49] + "..."
    return f"ffuf_dir_list:{label}"


LFI_PARAMS = {
    "file", "page", "path", "include", "template", "view",
    "inc", "document", "doc", "folder", "load", "read",
}


class ReconOrchestrator:
    MAX_PARALLEL = 3
    POLL_INTERVAL = 2.0   # seconds between task completion checks
    # When some workers are busy but slots remain free, re-ask the brain at most this often
    # (avoids calling Ollama every POLL_INTERVAL while long ffuf runs).
    IDLE_SLOT_BRAIN_INTERVAL = 2.0

    def __init__(self, target: str, guard, seclists_root, args, report_path: Path):
        self.target = target
        self.guard = guard
        self.seclists_root = str(seclists_root)
        self.args = args
        self.report_path = Path(report_path)
        self.report_dir = self.report_path.parent

        self.brain = AgentBrain()
        self.controller = RuntimeController(max_workers=self.MAX_PARALLEL)

        # Task tracking
        self.running: dict[str, Future] = {}     # task_id → Future (currently running)
        self.completed: dict[str, str] = {}      # task_id → "ok" | "failed"
        self.failed: set[str] = set()

        # Prevent re-running the same probe / lfi URL twice
        self.probed_urls: set[str] = set()
        self.lfi_tested_urls: set[str] = set()
        # Track which wordlist indices have been submitted for dir fuzzing
        self.dirs_wordlist_used: set[int] = set()

        # Optional: CLI --dir file → ffuf only these bases on the main host; queue drains with slots
        bases = getattr(self.args, "dir_ffuf_bases", None) or []
        self._dir_ffuf_queue: deque[str] | None = deque(bases) if bases else None
        self._dir_ffuf_norm_allow: set[str] = {b.rstrip("/").lower() for b in bases if b}

        # Pre-load any probe URLs that were already saved in findings.jsonl
        # (guards against re-probing if the orchestrator is re-instantiated
        #  within the same session without a full reset).
        self._reload_probed_urls_from_findings()

        self.live_probe_manager = LiveProbeManager(
            max_workers=5,
            report_path=self.report_path,
            allowed_host=self.guard.allowed_host,
            analyze_every=5,
            cookie=self._http_cookie(),
            probed_urls_sync=self.probed_urls,
        )

        # Last time we asked the brain to fill spare slots while other tasks still ran
        self._last_idle_slot_brain_ts = 0.0

    def _http_cookie(self) -> str | None:
        return normalize_cookie_arg(getattr(self.args, "cookie", None))

    def _reload_probed_urls_from_findings(self) -> None:
        """
        Populate self.probed_urls from any content_probe entries already in
        findings.jsonl.  Since reset() wipes findings.jsonl at the START of
        every new run, this only matters for in-session restarts / re-runs.
        On a brand-new run the file is empty and this is a no-op.
        """
        try:
            for f in load_jsonl(self.report_dir / "findings.jsonl"):
                if f.get("type") == "content_probe":
                    url = f.get("url", "")
                    if url:
                        self.probed_urls.add(url)
        except Exception:
            pass

    def _nmap_timing_flags(self) -> list[str]:
        """
        Nmap timing template from CLI -nt / --nmap-timing (1–5), same as nmap -T1..-T5.
        If omitted, default to T4 (matches previous hardcoded behavior).
        """
        t = self.args.nmap_timing
        if t is None:
            t = 4
        return build_timing_flags(t)

    # ------------------------------------------------------------------ #
    #  State building
    # ------------------------------------------------------------------ #

    def _detect_target_os(self, findings: list[dict], inventory: dict) -> str:
        """
        Infer target OS from nmap port data and content-probe OS hints.
        Returns 'linux', 'windows', or 'unknown'.
        """
        # Strong Windows signals from nmap (WinRM on 5985, IIS, SMB on 445)
        windows_services = {"microsoft", "iis", "windows", "winrm", "msrpc", "netbios"}
        linux_services   = {"nginx", "apache", "ubuntu", "debian", "centos"}

        for port in inventory.get("ports", []):
            svc = (
                port.get("product", "") + " " +
                port.get("service", "") + " " +
                port.get("version", "")
            ).lower()
            if any(w in svc for w in windows_services):
                return "windows"
            if any(w in svc for w in linux_services):
                return "linux"

        # Fall back to probe-detected OS hints
        for f in findings:
            hint = f.get("os_hint", "")
            if hint in ("linux", "windows"):
                return hint

        return "unknown"

    def _findings_summary(self) -> dict:
        """Build a compact findings summary from findings.jsonl for the brain."""
        findings = load_jsonl(self.report_dir / "findings.jsonl")
        inventory = build_inventory(findings)

        # Collect suspicious query params from content probes
        suspicious_params = []
        for f in findings:
            if f.get("type") != "content_probe":
                continue
            # New format: list of {url, param, lfi_candidate}
            for p in f.get("suspicious_params", []):
                if isinstance(p, dict):
                    suspicious_params.append({
                        "url": p.get("url", f.get("url", "")),
                        "param": p.get("param", ""),
                        "lfi_candidate": p.get("lfi_candidate", False),
                        "categories": p.get("categories") or [],
                        "suggest_ffuf_lfi": p.get("suggest_ffuf_lfi", False),
                        "source": p.get("source", ""),
                    })
                elif isinstance(p, str) and p:
                    suspicious_params.append({"url": f.get("url", ""), "param": p})
            # Also pick up params embedded in discovered_paths URLs
            for path_item in f.get("discovered_paths", []):
                link_url = path_item.get("url", "")
                if "?" in link_url:
                    for param in parse_qs(urlparse(link_url).query).keys():
                        suspicious_params.append({"url": link_url, "param": param})

        lfi_fuzz_targets: list[dict] = []
        param_candidates_report: list[dict] = []
        seen_lfi: set[str] = set()
        probe_html_excerpts: list[dict] = []
        html_forms_from_probes: list[dict] = []
        for f in findings:
            if f.get("type") != "content_probe":
                continue
            for pc in f.get("param_candidates") or []:
                if pc.get("report_in_findings", True):
                    param_candidates_report.append(pc)
            for t in f.get("lfi_fuzz_targets") or []:
                u = (t.get("ffuf_lfi_url") or "").strip()
                if u and u.lower() not in seen_lfi:
                    seen_lfi.add(u.lower())
                    lfi_fuzz_targets.append(t)
            for pc in f.get("param_candidates") or []:
                if pc.get("schedule_ffuf_lfi") and pc.get("ffuf_lfi_url"):
                    u = pc["ffuf_lfi_url"].strip()
                    if u.lower() not in seen_lfi:
                        seen_lfi.add(u.lower())
                        lfi_fuzz_targets.append(
                            {
                                "ffuf_lfi_url": u,
                                "param": pc.get("parameter"),
                                "endpoint": pc.get("endpoint"),
                                "confidence": pc.get("confidence"),
                                "source": pc.get("discovery_type"),
                            }
                        )
            ex = f.get("html_excerpt")
            if isinstance(ex, str) and ex.strip():
                probe_html_excerpts.append({"probed_url": f.get("url", ""), "html_excerpt": ex})
            hs = f.get("html_surface") or {}
            if hs.get("forms") or hs.get("cms_hints"):
                html_forms_from_probes.append({
                    "probed_url": f.get("url", ""),
                    "forms": (hs.get("forms") or [])[:15],
                    "cms_hints": (hs.get("cms_hints") or [])[:8],
                    "js_url_literals": (hs.get("js_url_literals") or [])[:8],
                    "lfi_fuzz_targets": (hs.get("lfi_fuzz_targets") or [])[:10],
                })

        probe_html_excerpts_trimmed = [
            {
                "probed_url": item.get("probed_url", ""),
                "html_excerpt": (item.get("html_excerpt") or "")[:8500],
            }
            for item in probe_html_excerpts[-3:]
        ]

        os_hint = self._detect_target_os(findings, inventory)

        # Keep the summary compact so the brain prompt stays bounded.
        # Ollama receives structured inventory plus truncated HTML excerpts from probes.
        return {
            "ports": [
                " ".join(filter(None, [
                    f"{p['port']}/{p['protocol']}",
                    p.get("state", ""),
                    p.get("service", ""),
                    p.get("product", ""),
                    p.get("version", ""),
                ])).strip()
                for p in inventory["ports"]          # all ports (usually < 20)
            ],
            "open_port_numbers": ",".join(str(p["port"]) for p in inventory["ports"]),
            "directories": [d["url"] for d in inventory["directories"][:25]],
            "files":       [f["url"] for f in inventory["files"][:10]],
            "vhosts":      [v["host"] for v in inventory["vhosts"][:10]],
            # Only the distinct URLs that carry suspicious params — the brain
            # needs the URL to build an ffuf_lfi action, nothing else.
            "suspicious_params": suspicious_params[:20],
            "lfi_fuzz_targets": lfi_fuzz_targets[:15],
            "param_candidates": param_candidates_report[:20],
            "probe_html_excerpts": probe_html_excerpts_trimmed,
            "html_forms_from_probes": html_forms_from_probes[-6:],
            "lfi_confirmed": [f.get("url") for f in findings if f.get("type") == "lfi"][:5],
            "os_hint": os_hint,
        }

    def _current_depth(self) -> int:
        """Estimate current recursion depth by looking at the deepest scanned URL."""
        from urllib.parse import urlparse as _up
        base_parts = len(_up(self.target.rstrip("/")).path.split("/"))
        max_depth = 0
        for task_id in list(self.running.keys()) + list(self.completed.keys()):
            if not task_id.startswith("ffuf_dirs_"):
                continue
            # task_id format: ffuf_dirs_{idx}_{url}
            parts = task_id.split("_", 3)
            if len(parts) < 4:
                continue
            url_part = parts[3]
            try:
                depth = len(_up(url_part.rstrip("/")).path.split("/")) - base_parts
                if depth > max_depth:
                    max_depth = depth
            except Exception:
                pass
        return max_depth

    def _canonical_open_ports_csv(self) -> str | None:
        findings = load_jsonl(self.report_dir / "findings.jsonl")
        return open_tcp_ports_csv_from_findings(findings)

    def _brain_state(self) -> dict:
        return {
            "target": self.target,
            "running_tasks": list(self.running.keys()),
            "completed_tasks": list(self.completed.keys()),
            "failed_tasks": list(self.failed),
            "wordlists_used_for_dirs": sorted(self.dirs_wordlist_used),
            "probed_urls": sorted(self.probed_urls),
            "lfi_tested_urls": list(self.lfi_tested_urls)[:5],
            "depth": self.args.depth,          # None = unlimited, 0 = no recursion, N = max
            "current_depth": self._current_depth(),
            "findings": self._findings_summary(),
            "dir_list_mode": bool(getattr(self.args, "dir_ffuf_bases", None)),
            "dir_ffuf_normalized_bases": sorted(self._dir_ffuf_norm_allow),
            "allowed_scope_host": self.guard.allowed_host,
            "open_tcp_ports_csv": self._canonical_open_ports_csv(),
        }

    def _available_slots(self) -> int:
        return max(0, self.MAX_PARALLEL - len(self.running))

    def _flush_dir_ffuf_queue(self) -> None:
        """Submit queued CLI --dir ffuf tasks while parallel slots are free."""
        if not self._dir_ffuf_queue:
            return
        wordlists = get_wordlists_for_mode(self.seclists_root, "directories_and_files")
        if not wordlists:
            return
        wordlist = wordlists[0]["path"]
        while self._available_slots() > 0 and self._dir_ffuf_queue:
            base = self._dir_ffuf_queue.popleft()
            label = _dir_list_task_label(base)
            task_id = label
            suffix = 0
            while self._task_known(task_id):
                suffix += 1
                task_id = f"{label}#{suffix}"
            self._submit(
                task_id,
                run_ffuf_directory,
                base,
                wordlist,
                self.args.threads,
                self.report_path,
                True,
                self.live_probe_manager,
                self._http_cookie(),
            )

    # ------------------------------------------------------------------ #
    #  Task polling
    # ------------------------------------------------------------------ #

    def _poll(self) -> list[str]:
        """Move done futures out of `running` into `completed`. Return newly-done IDs."""
        done_ids = []
        for task_id in list(self.running.keys()):
            future = self.running[task_id]
            if not future.done():
                continue
            done_ids.append(task_id)
            try:
                future.result()
                self.completed[task_id] = "ok"
                log(f"Completed: {task_id}")
            except Exception as exc:
                self.completed[task_id] = "failed"
                self.failed.add(task_id)
                warning(f"Task '{task_id}' failed: {exc}")
            del self.running[task_id]
        return done_ids

    # ------------------------------------------------------------------ #
    #  Action execution
    # ------------------------------------------------------------------ #

    def _task_known(self, task_id: str) -> bool:
        return task_id in self.running or task_id in self.completed

    def _submit(self, task_id: str, func, *args) -> Future:
        future = self.controller.submit(task_id, func, *args)
        self.running[task_id] = future
        log(f"Started: {task_id}")
        return future

    def _schedule_dir_base_probes(self) -> None:
        """Probe each --dir base (e.g. /admin/) so HTML forms are parsed for LFI targets."""
        bases = getattr(self.args, "dir_ffuf_bases", None) or []
        for base in bases:
            if self._available_slots() <= 0:
                break
            probe_url = base.rstrip("/") + "/"
            if probe_url in self.probed_urls:
                continue
            self.execute({"action": "probe", "url": probe_url})

    def _auto_schedule_lfi_from_findings(self) -> None:
        """Start ffuf_lfi only for high-confidence / evidence-backed LFI candidates."""
        summary = self._findings_summary()
        for target in summary.get("lfi_fuzz_targets") or []:
            if self._available_slots() <= 0:
                break
            conf = (target.get("confidence") or "").lower()
            if conf not in {"high"} and not target.get("lfi_error_signals"):
                continue
            ffuf_url = (target.get("ffuf_lfi_url") or "").strip()
            if not ffuf_url or "FUZZ" not in ffuf_url:
                continue
            if ffuf_url in self.lfi_tested_urls:
                continue
            self.execute({"action": "ffuf_lfi", "url": ffuf_url})

    def _ffuf_dirs_blocked_on_dir_list(self, scan_url: str) -> bool:
        """
        With --dir, only URLs listed in the file may get brain-driven ffuf_dirs on
        hosts that appear in that file. Other hosts (e.g. discovered vhosts) are unchanged.
        """
        if not self._dir_ffuf_norm_allow:
            return False
        uh = (urlparse(scan_url).hostname or "").lower()
        if not uh:
            return False
        file_hosts: set[str] = set()
        for b in getattr(self.args, "dir_ffuf_bases", []) or []:
            h = (urlparse(b).hostname or "").lower()
            if h:
                file_hosts.add(h)
        if not file_hosts:
            for k in self._dir_ffuf_norm_allow:
                h = (urlparse(k).hostname or "").lower()
                if h:
                    file_hosts.add(h)
        if uh not in file_hosts:
            return False
        key = scan_url.rstrip("/").lower()
        return key not in self._dir_ffuf_norm_allow

    def execute(self, action: dict) -> str | None:
        """Execute a single brain action. Returns task_id or None if skipped."""
        act = action.get("action", "")

        if act == "ffuf_dirs":
            url = action.get("url", self.target)
            if self._ffuf_dirs_blocked_on_dir_list(url):
                log(f"Skipping ffuf_dirs (URL not in --dir file for this host): {url}")
                return None
            idx = int(action.get("wordlist_index", 0))
            wordlists = get_wordlists_for_mode(self.seclists_root, "directories_and_files")
            if idx >= len(wordlists):
                warning(f"No directory wordlist at index {idx}.")
                return None
            wordlist = wordlists[idx]["path"]
            if not ffuf_dirs_depth_allows(self.target, url, self.args.depth):
                log(
                    f"Skipping ffuf_dirs (depth={self.args.depth}): {url} "
                    f"(extra path depth {ffuf_dirs_extra_depth(self.target, url)})"
                )
                return None
            task_id = f"ffuf_dirs_{idx}_{url}"
            if self._task_known(task_id):
                return None
            self.dirs_wordlist_used.add(idx)
            self._submit(
                task_id,
                run_ffuf_directory,
                url,
                wordlist,
                self.args.threads,
                self.report_path,
                True,
                self.live_probe_manager,
                self._http_cookie(),
            )
            return task_id

        if act == "ffuf_vhosts":
            wordlists = get_wordlists_for_mode(self.seclists_root, "subdomains")
            if not wordlists:
                return None
            wordlist = wordlists[0]["path"]
            task_id = "ffuf_vhosts"
            if self._task_known(task_id):
                return None
            self._submit(
                task_id,
                run_ffuf_vhost,
                self.target,
                wordlist,
                self.args.threads,
                self.report_path,
                True,
                self._http_cookie(),
            )
            return task_id

        if act == "nmap_ports":
            task_id = "nmap_ports"
            if self._task_known(task_id):
                return None
            host = action.get("target", self.guard.allowed_host)
            timing = self._nmap_timing_flags()
            if getattr(self.args, "fast_nmap", False):
                port_flags = ["-Pn", *timing, "--top-ports", "1000"]
            else:
                port_flags = ["-Pn", *timing, "-p-"]
            self._submit(
                task_id,
                run_nmap_scan,
                host,
                self.guard.allowed_host,
                port_flags,
                self.report_path,
            )
            return task_id

        if act == "nmap_versions":
            if "nmap_ports" not in self.completed:
                log("Deferring nmap_versions until nmap_ports completes (one -sV pass on all open TCP ports).")
                return None
            findings = load_jsonl(self.report_dir / "findings.jsonl")
            ports = open_tcp_ports_csv_from_findings(findings)
            if not ports:
                log("nmap_versions skipped: no open TCP ports in findings yet.")
                return None
            task_id = f"nmap_versions_{ports}"
            if self._task_known(task_id):
                return None
            host = action.get("target", self.guard.allowed_host)
            self._submit(
                task_id,
                run_nmap_scan,
                host,
                self.guard.allowed_host,
                ["-sV", *self._nmap_timing_flags(), "-p", ports],
                self.report_path,
            )
            return task_id

        if act == "probe":
            url = action.get("url", "")
            if not url or url in self.probed_urls:
                return None
            self.probed_urls.add(url)
            task_id = f"probe_{url}"
            if self._task_known(task_id):
                return None
            self._submit(
                task_id,
                content_probe,
                url,
                self.guard.allowed_host,
                self.report_path,
                8.0,
                500_000,
                self._http_cookie(),
            )
            return task_id

        if act == "ffuf_lfi":
            url = action.get("url", "")
            if not url or url in self.lfi_tested_urls:
                return None
            if "FUZZ" not in url:
                return None
            self.lfi_tested_urls.add(url)
            task_id = f"ffuf_lfi_{url}"
            if self._task_known(task_id):
                return None

            # Pick LFI wordlists based on detected OS —
            # always include the cross-platform list, then add OS-specific ones.
            os_hint = self._findings_summary().get("os_hint", "unknown")
            if os_hint == "windows":
                lfi_mode = "lfi_windows"
            elif os_hint == "linux":
                lfi_mode = "lfi_linux"
            else:
                lfi_mode = "lfi_both"

            lfi_wls = get_wordlists_for_mode(self.seclists_root, lfi_mode)
            if not lfi_wls:
                return None
            wordlist_paths = [item["path"] for item in lfi_wls]
            self._submit(
                task_id,
                lfi_triage,
                url,
                wordlist_paths,
                self.args.threads,
                self.report_path,
                8.0,
                self._http_cookie(),
            )
            return task_id

        return None

    # ------------------------------------------------------------------ #
    #  Main orchestration loop
    # ------------------------------------------------------------------ #

    def run(self) -> None:
        """
        Main loop:
        1. Ask brain for initial actions (Phase 1).
        2. Poll for completions, ask brain for next actions whenever slots open.
        3. Write report when done or user exits.
        """
        cmd_queue: stdlib_queue.Queue = stdlib_queue.Queue()
        input_stop = threading.Event()

        def _reader():
            while not input_stop.is_set():
                try:
                    line = input("recon+> ").strip().lower()
                    cmd_queue.put(line)
                except EOFError:
                    break

        reader_thread = threading.Thread(target=_reader, daemon=True)
        reader_thread.start()

        console("Recon+ running. Commands: status | exit", "bold green")

        should_exit = False

        try:
            # Kick off Phase 1
            self._ask_brain_and_execute()

            idle_rounds = 0

            while not should_stop():
                # Check user input (non-blocking)
                try:
                    cmd = cmd_queue.get(timeout=self.POLL_INTERVAL)
                    if cmd in {"stop", "exit", "quit", "q"}:
                        info("User requested stop.")
                        should_exit = True
                        break
                    elif cmd in {"status", "s"}:
                        self.controller.status()
                except stdlib_queue.Empty:
                    pass

                # Poll for completed tasks
                newly_done = self._poll()

                slots = self._available_slots()
                now = time.monotonic()
                # Refill free slots while other tasks are still running (probe, nmap, …).
                # Previously we only called the brain when *nothing* was running, so a
                # single free slot never triggered new work until another task finished.
                refill_idle_slots = (
                    slots > 0
                    and self.running
                    and not newly_done
                    and (
                        self._last_idle_slot_brain_ts == 0.0
                        or (now - self._last_idle_slot_brain_ts) >= self.IDLE_SLOT_BRAIN_INTERVAL
                    )
                )
                if newly_done or (slots > 0 and not self.running) or refill_idle_slots:
                    if newly_done or refill_idle_slots:
                        self._last_idle_slot_brain_ts = now
                    stopped = self._ask_brain_and_execute()
                    if stopped and not self.running:
                        info("All reconnaissance phases complete.")
                        break
                    if not self.running:
                        idle_rounds += 1
                        if idle_rounds >= 3:
                            break
                else:
                    idle_rounds = 0

        except KeyboardInterrupt:
            info("Interrupted.")
            should_exit = True
        finally:
            input_stop.set()

        try:
            self.live_probe_manager.shutdown(wait=True, final_analyze=False)
        except Exception:
            pass

        # Always write report with whatever was collected
        info("Writing report...")
        writer = OllamaReportWriter(self.report_dir)
        writer.write_report()
        success(f"Report: {self.report_path.resolve()}")

        self.controller.stop()

    def _ask_brain_and_execute(self) -> bool:
        """
        Ask the brain what to do next and execute the actions.
        Returns True if the brain said 'stop' and nothing is running.
        """
        slots = self._available_slots()
        if slots <= 0:
            return False

        state = self._brain_state()
        actions = self.brain.decide(state, slots=slots)

        brain_stopped = False
        for action in actions[:slots]:
            if action.get("action") == "stop":
                brain_stopped = True
                break
            self.execute(action)

        self._flush_dir_ffuf_queue()
        self._schedule_dir_base_probes()
        self._auto_schedule_lfi_from_findings()

        return brain_stopped and not self.running
