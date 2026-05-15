"""
ffuf_runner.py — runs ffuf directory and vhost scans.

Key design: stdout is read LINE BY LINE in a background thread so every
finding appears in the report and terminal the moment ffuf prints it,
not when the whole scan finishes.
"""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from urllib.parse import urlparse
import json
import os
import queue as stdlib_queue
import re
import subprocess
import threading
import uuid

from app.tools.content_probe import content_probe
from app.core.report_manager import ReportManager
from app.core.http_cookie import normalize_cookie_arg
from app.agent.report_analyzer import ReportAnalyzer
from app.agent.report_writer import OllamaReportWriter
from app.core.output import log, info, print_ffuf_finding
from app.core.process_manager import (
    register_process,
    unregister_process,
    should_stop,
    kill_registered_processes,
)


INTERESTING_STATUS_CODES = {200, 204, 301, 302, 307, 308, 401, 403, 405, 500}

# Matches ffuf's default output line:
# contact     [Status: 200, Size: 367, Words: 34, Lines: 5, Duration: 75ms]
FFUF_LINE_RE = re.compile(
    r'^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+)'
)


def _ffuf_cookie_args(cookie: str | None) -> list[str]:
    c = normalize_cookie_arg(cookie)
    if not c:
        return []
    return ["-H", f"Cookie: {c}"]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _parse_stdout_line(line: str) -> dict | None:
    """Parse one ffuf stdout line. Returns a dict with status/size/words/lines/fuzz_value."""
    match = FFUF_LINE_RE.match(line.strip())
    if not match:
        return None
    fuzz_value = match.group(1)
    status = int(match.group(2))
    size = int(match.group(3))
    words = int(match.group(4))
    lines = int(match.group(5))
    if status not in INTERESTING_STATUS_CODES:
        return None
    # Ignore wordlist comment lines (the DirBuster list has many # lines)
    if fuzz_value.startswith("#") or fuzz_value.startswith("//"):
        return None
    return {
        "fuzz_value": fuzz_value,
        "status": status,
        "length": size,
        "words": words,
        "lines": lines,
    }


def _launch_ffuf(command: list[str]) -> subprocess.Popen:
    """Start ffuf as a subprocess with stdout piped."""
    creationflags = 0
    if os.name == "nt":
        # CREATE_NEW_PROCESS_GROUP  — lets us send CTRL_BREAK to kill ffuf gracefully
        # CREATE_NO_WINDOW          — prevents ffuf from writing a final summary
        #                             directly to the console via Windows Console API
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,   # discard progress-bar/header noise
        text=True,
        encoding="utf-8",
        errors="ignore",
        creationflags=creationflags,
    )
    register_process(process)
    return process


def _drain_stdout(process: subprocess.Popen, line_queue: stdlib_queue.Queue) -> None:
    """Background thread: push each stdout line onto line_queue, then None sentinel."""
    try:
        for line in process.stdout:
            line_queue.put(line)
    finally:
        line_queue.put(None)


def _consume_lines(process: subprocess.Popen, on_line) -> None:
    """
    Read process stdout line by line in real-time via a background thread.
    Calls on_line(line) for every line received.
    Stops early if should_stop() is True.
    """
    q: stdlib_queue.Queue = stdlib_queue.Queue()
    t = threading.Thread(target=_drain_stdout, args=(process, q), daemon=True)
    t.start()

    import time as _time

    try:
        while True:
            if should_stop():
                kill_registered_processes()
                _time.sleep(0.4)   # give ffuf time to flush its JSON output file
                break
            try:
                line = q.get(timeout=0.3)
            except stdlib_queue.Empty:
                # Check if process is done
                if process.poll() is not None:
                    # Drain anything remaining
                    while True:
                        try:
                            line = q.get_nowait()
                        except stdlib_queue.Empty:
                            break
                        if line is None:
                            break
                        on_line(line)
                    break
                continue
            if line is None:  # sentinel
                break
            on_line(line)
    except KeyboardInterrupt:
        kill_registered_processes()
    finally:
        unregister_process(process)


def parse_ffuf_json(output_path: Path) -> list[dict]:
    """Parse the final JSON output file written by ffuf on completion."""
    if not output_path.exists():
        return []
    try:
        with open(output_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
    except Exception:
        return []

    results = []
    for item in data.get("results", []):
        status = item.get("status")
        if status not in INTERESTING_STATUS_CODES:
            continue
        results.append({
            "url": item.get("url"),
            "status": status,
            "length": item.get("length"),
            "words": item.get("words"),
            "lines": item.get("lines"),
            "duration": item.get("duration"),
            "input": item.get("input", {}),
            "redirectlocation": item.get("redirectlocation", ""),
        })
    return results


# ─────────────────────────────────────────────────────────────────────────────
# LiveProbeManager (kept for callers that pass it to run_ffuf_directory)
# ─────────────────────────────────────────────────────────────────────────────

class LiveProbeManager:
    def __init__(
        self,
        max_workers: int = 1,
        report_path: Path | None = None,
        allowed_host: str | None = None,
        analyze_every: int = 3,
        cookie: str | None = None,
        probed_urls_sync: set | None = None,
    ):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.report_path = report_path or Path("app") / "reports" / "REPORT.txt"
        self.allowed_host = allowed_host
        self.cookie = cookie
        self.probed_urls_sync = probed_urls_sync
        self.seen_urls: set = set()
        self.lock = Lock()
        self.probe_count = 0
        self.analyze_every = analyze_every
        self.analyzer = ReportAnalyzer(self.report_path.parent)

    def _run_probe_then_analyze(self, url: str) -> None:
        if should_stop():
            return
        content_probe(
            url=url,
            allowed_host=self.allowed_host,
            report_path=self.report_path,
            cookie=self.cookie,
        )
        if should_stop():
            return
        with self.lock:
            self.probe_count += 1
            do_analyze = self.probe_count % self.analyze_every == 0
        if do_analyze and not should_stop():
            self.analyzer.analyze_and_update_report()

    def submit_content_probe(self, url: str) -> None:
        if should_stop():
            return
        with self.lock:
            sync = self.probed_urls_sync
            if sync is not None:
                if url in sync:
                    return
                sync.add(url)
            else:
                if url in self.seen_urls:
                    return
                self.seen_urls.add(url)
        self.executor.submit(self._run_probe_then_analyze, url)

    def shutdown(self, wait: bool = True, final_analyze: bool = True) -> None:
        if should_stop():
            self.executor.shutdown(wait=False, cancel_futures=True)
            return
        self.executor.shutdown(wait=wait, cancel_futures=True)
        if final_analyze:
            OllamaReportWriter(self.report_path.parent).write_report()


# ─────────────────────────────────────────────────────────────────────────────
# Directory fuzzing
# ─────────────────────────────────────────────────────────────────────────────

def run_ffuf_directory(
    target_url: str,
    wordlist_path: Path,
    threads: int = 50,
    report_path: Path | None = None,
    auto_calibrate: bool = True,
    live_probe_manager: LiveProbeManager | None = None,
    cookie: str | None = None,
) -> list[dict]:
    if report_path is None:
        report_path = Path("app") / "reports" / "REPORT.txt"

    output_dir = Path("app") / "data" / "ffuf"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"ffuf_dir_{uuid.uuid4().hex}.json"

    ffuf_url = target_url.rstrip("/") + "/FUZZ"

    command = [
        "ffuf",
        "-w", str(wordlist_path),
        "-u", ffuf_url,
        "-t", str(threads),
        "-of", "json",
        "-o", str(output_path),
        "-noninteractive",
        "-ac",
        "-mc", "200,204,301,302,307,308,401,403,405,500",
    ]
    command.extend(_ffuf_cookie_args(cookie))

    log(f"[ffuf-dirs] {ffuf_url}")
    log(f"[ffuf-dirs] wordlist: {Path(wordlist_path).name}  threads: {threads}  -ac")

    # Buffer live findings — we show them immediately in the terminal but
    # only commit them to the report AFTER verifying against the JSON output,
    # which eliminates ffuf's calibration-probe false positives.
    live_buffer: list[dict] = []

    def on_line(line: str) -> None:
        parsed = _parse_stdout_line(line)
        if not parsed:
            return
        fuzz_value = parsed["fuzz_value"]
        status = parsed["status"]
        length = parsed["length"]
        words = parsed["words"]
        lines = parsed["lines"]

        url = target_url.rstrip("/") + "/" + fuzz_value.lstrip("/")

        # Determine display kind
        has_dot = "." in fuzz_value.split("/")[-1]
        kind = "FILE" if has_dot else "DIR"
        print_ffuf_finding(kind, fuzz_value, status, length, words, lines, url)

        live_buffer.append({
            "type": "directory",
            "url": url,
            "status": status,
            "length": length,
            "words": words,
            "lines": lines,
            "source": "ffuf_live",
        })

    process = _launch_ffuf(command)
    _consume_lines(process, on_line)

    # Use JSON results as the authoritative, calibration-filtered list.
    # Fall back to the live buffer if the scan was stopped before JSON was written.
    json_results = parse_ffuf_json(output_path)
    if json_results:
        json_urls = {r.get("url", "").rstrip("/").lower() for r in json_results}
        verified = [f for f in live_buffer if f["url"].rstrip("/").lower() in json_urls]
    else:
        verified = live_buffer  # scan interrupted early — trust live results

    manager = ReportManager(report_path.parent)
    for finding in verified:
        manager.add_finding(finding)
        if live_probe_manager:
            live_probe_manager.submit_content_probe(finding["url"])

    count = len(json_results) if json_results else len(verified)
    log(f"[ffuf-dirs] done — {count} results")
    return json_results if json_results else verified


# ─────────────────────────────────────────────────────────────────────────────
# VHost / subdomain fuzzing
# ─────────────────────────────────────────────────────────────────────────────

def run_ffuf_vhost(
    target_url: str,
    wordlist_path: Path,
    threads: int = 50,
    report_path: Path | None = None,
    auto_calibrate: bool = True,
    cookie: str | None = None,
) -> list[dict]:
    if report_path is None:
        report_path = Path("app") / "reports" / "REPORT.txt"

    output_dir = Path("app") / "data" / "ffuf"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"ffuf_vhost_{uuid.uuid4().hex}.json"

    parsed_url = urlparse(target_url)
    scheme = parsed_url.scheme or "http"
    host = parsed_url.hostname

    if not host:
        raise ValueError(f"Invalid target URL: {target_url}")

    base_url = f"{scheme}://{host}/"

    command = [
        "ffuf",
        "-w", str(wordlist_path),
        "-u", base_url,
        "-H", f"Host: FUZZ.{host}",
        "-t", str(threads),
        "-of", "json",
        "-o", str(output_path),
        "-noninteractive",
        "-ac",
        "-mc", "200,204,301,302,307,308,401,403,405,500",
    ]
    command.extend(_ffuf_cookie_args(cookie))

    log(f"[ffuf-vhosts] {base_url}  Host: FUZZ.{host}")
    log(f"[ffuf-vhosts] wordlist: {Path(wordlist_path).name}  threads: {threads}  -ac")

    live_buffer: list[dict] = []

    def on_line(line: str) -> None:
        parsed = _parse_stdout_line(line)
        if not parsed:
            return
        fuzz_value = parsed["fuzz_value"]
        status = parsed["status"]
        length = parsed["length"]
        words = parsed["words"]
        lines = parsed["lines"]

        found_host = f"{fuzz_value}.{host}"
        print_ffuf_finding("VHOST", found_host, status, length, words, lines)

        live_buffer.append({
            "type": "vhost",
            "url": base_url,
            "host": found_host,
            "status": status,
            "length": length,
            "words": words,
            "lines": lines,
            "source": "ffuf_live",
        })

    process = _launch_ffuf(command)
    _consume_lines(process, on_line)

    # Verify against JSON (post-calibration authoritative results)
    results = parse_ffuf_json(output_path)
    for item in results:
        input_data = item.get("input", {})
        fuzz_value = input_data.get("FUZZ", "")
        item["host"] = f"{fuzz_value}.{host}" if fuzz_value else ""

    if results:
        json_hosts = {r.get("host", "").lower() for r in results}
        verified = [f for f in live_buffer if f["host"].lower() in json_hosts]
    else:
        verified = live_buffer

    manager = ReportManager(report_path.parent)
    for finding in verified:
        manager.add_finding(finding)

    count = len(results) if results else len(verified)
    log(f"[ffuf-vhosts] done — {count} results")
    return results if results else verified
