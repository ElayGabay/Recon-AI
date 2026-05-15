from pathlib import Path
from threading import Lock
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import time

from app.core.output import log
from app.core.process_manager import should_stop
from app.core.report_manager import ReportManager
from app.tools.content_probe import content_probe
from app.core.http_cookie import normalize_cookie_arg


STATIC_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".pdf",
    ".txt", ".xml", ".json", ".html", ".htm"
}

STATIC_PATH_PARTS = {
    "/static/", "/assets/", "/images/", "/img/", "/css/", "/js/", "/fonts/",
    "/media/", "/uploads/", "/files/", "/public/"
}


def get_path_depth(url: str) -> int:
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    
    if not path:
        return 0
    
    return len(path.split("/"))


def is_static_path(url: str) -> bool:
    lower = url.lower()
    
    if any(part in lower for part in STATIC_PATH_PARTS):
        return True
    
    parsed = urlparse(url)
    path = parsed.path.lower()
    
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)


def looks_like_directory(url: str) -> bool:
    parsed = urlparse(url)
    path = parsed.path or "/"
    
    if path == "/":
        return False
    
    last_part = path.rstrip("/").split("/")[-1]
    
    if "." in last_part:
        ext = "." + last_part.split(".")[-1].lower()
        if ext in STATIC_EXTENSIONS:
            return False
    
    return True


class RecursiveFuzzer:
    def __init__(
        self,
        target_url: str,
        wordlist_path: Path,
        allowed_host: str,
        report_path: Path,
        threads: int = 50,
        max_depth: int | None = None,
        max_workers: int = 2,
        cookie: str | None = None,
    ):
        self.target_url = target_url.rstrip("/")
        self.wordlist_path = wordlist_path
        self.allowed_host = allowed_host
        self.report_path = report_path
        self.threads = threads
        self.max_depth = max_depth
        self.max_workers = max_workers
        self.cookie = normalize_cookie_arg(cookie)
        
        self.pending_queue = Queue()
        self.seen_urls = set()
        self.lock = Lock()
        self.current_depth = 0
        self.total_found = 0
        
        self.executor = None

    def _normalize_url(self, url: str) -> str:
        return url.rstrip("/").lower()

    def _can_fuzz(self, url: str, depth: int) -> bool:
        if self.max_depth is not None and depth > self.max_depth:
            return False
        
        if self.max_depth == 0:
            return False
        
        if is_static_path(url):
            return False
        
        if not looks_like_directory(url):
            return False
        
        normalized = self._normalize_url(url)
        
        with self.lock:
            if normalized in self.seen_urls:
                return False
            self.seen_urls.add(normalized)
        
        return True

    def add_directory(self, url: str, depth: int = 1) -> bool:
        if not self._can_fuzz(url, depth):
            return False
        
        self.pending_queue.put((url, depth))
        log(f"[RECURSIVE] Queued for fuzzing (depth={depth}): {url}")
        return True

    def _run_ffuf_on_directory(self, url: str, depth: int) -> list[dict]:
        from app.tools.ffuf_runner import run_ffuf_directory
        
        if should_stop():
            return []
        
        log(f"[RECURSIVE] Fuzzing (depth={depth}): {url}/FUZZ")
        
        results = run_ffuf_directory(
            target_url=url,
            wordlist_path=self.wordlist_path,
            threads=self.threads,
            report_path=self.report_path,
            auto_calibrate=True,
            live_probe_manager=None,
            cookie=self.cookie,
        )
        
        for item in results:
            found_url = item.get("url", "")
            
            if looks_like_directory(found_url):
                self.add_directory(found_url, depth + 1)
            
            if not is_static_path(found_url):
                content_probe(
                    url=found_url,
                    allowed_host=self.allowed_host,
                    report_path=self.report_path,
                    cookie=self.cookie,
                )
        
        with self.lock:
            self.total_found += len(results)
        
        return results

    def _worker(self):
        while not should_stop():
            try:
                url, depth = self.pending_queue.get(timeout=2)
            except:
                if self.pending_queue.empty():
                    break
                continue
            
            try:
                self._run_ffuf_on_directory(url, depth)
            except Exception as e:
                log(f"[RECURSIVE] Error fuzzing {url}: {e}")
            finally:
                self.pending_queue.task_done()

    def run(self) -> int:
        if self.max_depth == 0:
            log("[RECURSIVE] Depth is 0, skipping recursive fuzzing")
            return 0
        
        log(f"[RECURSIVE] Starting recursive fuzzer (max_depth={self.max_depth})")
        
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        
        workers = []
        for _ in range(self.max_workers):
            future = self.executor.submit(self._worker)
            workers.append(future)
        
        try:
            self.pending_queue.join()
        except KeyboardInterrupt:
            log("[RECURSIVE] Interrupted")
        
        self.executor.shutdown(wait=False, cancel_futures=True)
        
        log(f"[RECURSIVE] Finished. Total directories found: {self.total_found}")
        return self.total_found

    def shutdown(self):
        if self.executor:
            self.executor.shutdown(wait=False, cancel_futures=True)


def run_recursive_fuzzing(
    initial_results: list[dict],
    target_url: str,
    wordlist_path: Path,
    allowed_host: str,
    report_path: Path,
    threads: int = 50,
    max_depth: int | None = None,
    cookie: str | None = None,
) -> int:
    if max_depth == 0:
        log("[RECURSIVE] Depth is 0, skipping recursive fuzzing")
        return 0
    
    fuzzer = RecursiveFuzzer(
        target_url=target_url,
        wordlist_path=wordlist_path,
        allowed_host=allowed_host,
        report_path=report_path,
        threads=threads,
        max_depth=max_depth,
        cookie=cookie,
    )
    
    for item in initial_results:
        url = item.get("url", "")
        if looks_like_directory(url):
            fuzzer.add_directory(url, depth=1)
    
    return fuzzer.run()
