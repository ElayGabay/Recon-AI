from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, parse_qs


LFI_SUSPICIOUS_PARAMS = {
    "file",
    "path",
    "page",
    "template",
    "include",
    "inc",
    "view",
    "document",
    "doc",
    "folder",
    "load",
    "read",
    "url",
    "next",
    "redirect",
}


@dataclass
class AgentState:
    target: str
    allowed_host: str
    started_at: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))

    directories: list[dict] = field(default_factory=list)
    files: list[dict] = field(default_factory=list)
    subdomains: list[dict] = field(default_factory=list)
    vhosts: list[dict] = field(default_factory=list)

    possible_lfi_urls: list[dict] = field(default_factory=list)
    sensitive_findings: list[dict] = field(default_factory=list)

    pending_content_probe_urls: list[str] = field(default_factory=list)
    pending_directory_fuzz_urls: list[str] = field(default_factory=list)
    pending_lfi_urls: list[str] = field(default_factory=list)

    completed_actions: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    max_parallel_tools: int = 3

    def add_fuzz_results(self, results: list[dict]) -> None:
        for item in results:
            if item.get("type") == "file":
                self.files.append(item)
            else:
                self.directories.append(item)

            url = item.get("url")
            if url:
                self.add_content_probe_candidate(url)

    def add_subdomain_results(self, results: list[dict]) -> None:
        for item in results:
            if item.get("finding_type") == "VHOST":
                self.vhosts.append(item)
            else:
                self.subdomains.append(item)

            url = item.get("url")
            if url:
                self.add_directory_fuzz_candidate(url)

    def add_content_probe_result(self, result: dict) -> None:
        matches = result.get("matches", [])
        discovered_paths = result.get("discovered_paths", [])

        for match in matches:
            if match.get("type") == "possible_secret_or_credential":
                self.sensitive_findings.append(
                    {
                        "source_url": result.get("url"),
                        "match": match,
                    }
                )

        for item in discovered_paths:
            url = item.get("url")
            if not url:
                continue

            self.add_content_probe_candidate(url)

            if item.get("is_directory_like"):
                self.add_directory_fuzz_candidate(url)

            self.detect_possible_lfi_url(url)

    def add_content_probe_candidate(self, url: str) -> None:
        if not self.is_allowed_url(url):
            return

        if url in self.pending_content_probe_urls:
            return

        already_seen = {item.get("url") for item in self.files + self.directories}
        if url in already_seen:
            pass

        self.pending_content_probe_urls.append(url)

    def add_directory_fuzz_candidate(self, url: str) -> None:
        if not self.is_allowed_url(url):
            return

        parsed = urlparse(url)
        path = parsed.path or "/"

        if path == "/":
            return

        last_part = path.rstrip("/").split("/")[-1]
        if "." in last_part:
            return

        if url not in self.pending_directory_fuzz_urls:
            self.pending_directory_fuzz_urls.append(url)

    def detect_possible_lfi_url(self, url: str) -> None:
        if not self.is_allowed_url(url):
            return

        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if not params:
            return

        suspicious = []

        for param in params:
            if param.lower() in LFI_SUSPICIOUS_PARAMS:
                suspicious.append(param)

        if not suspicious:
            return

        if url not in self.pending_lfi_urls:
            self.pending_lfi_urls.append(url)

        self.possible_lfi_urls.append(
            {
                "url": url,
                "params": suspicious,
                "reason": "URL contains parameter names commonly associated with file inclusion or file loading.",
            }
        )

    def is_allowed_url(self, url: str) -> bool:
        parsed = urlparse(url)

        if not parsed.hostname:
            return True

        hostname = parsed.hostname.lower()
        allowed = self.allowed_host.lower()

        return hostname == allowed or hostname.endswith("." + allowed)

    def get_priority_snapshot(self) -> dict:
        return {
            "priority_rules": [
                "If pending_lfi_urls exist, lfi_triage has highest priority.",
                "After initial directory_fuzz and subdomain_scan, run content_probe on interesting URLs.",
                "If content_probe discovers directory-like paths, queue directory_fuzz for those paths.",
                "Never run more than max_parallel_tools tools at the same time.",
                "Never use discovered credentials for authentication.",
            ],
            "queues": {
                "pending_lfi_urls": self.pending_lfi_urls[:10],
                "pending_content_probe_urls": self.pending_content_probe_urls[:20],
                "pending_directory_fuzz_urls": self.pending_directory_fuzz_urls[:20],
            },
            "max_parallel_tools": self.max_parallel_tools,
        }

    def to_summary(self) -> dict:
        return {
            "target": self.target,
            "allowed_host": self.allowed_host,
            "started_at": self.started_at,
            "counts": {
                "directories": len(self.directories),
                "files": len(self.files),
                "subdomains": len(self.subdomains),
                "vhosts": len(self.vhosts),
                "possible_lfi_urls": len(self.possible_lfi_urls),
                "sensitive_findings": len(self.sensitive_findings),
                "pending_content_probe_urls": len(self.pending_content_probe_urls),
                "pending_directory_fuzz_urls": len(self.pending_directory_fuzz_urls),
                "pending_lfi_urls": len(self.pending_lfi_urls),
            },
            "top_directories": self.directories[:20],
            "top_files": self.files[:20],
            "top_subdomains": self.subdomains[:20],
            "top_vhosts": self.vhosts[:20],
            "possible_lfi_urls": self.possible_lfi_urls[:10],
            "priority_snapshot": self.get_priority_snapshot(),
            "completed_actions": self.completed_actions,
            "notes": self.notes[-10:],
        }