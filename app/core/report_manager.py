from pathlib import Path
from datetime import datetime
from threading import Lock
from urllib.parse import urlparse, urlunparse
import json
import re


REPORT_LOCK = Lock()


def normalize_url_for_dedupe(url: str, target: str | None = None) -> str:
    if not url:
        return ""

    url = url.strip()

    target_host = ""
    target_scheme = "http"

    if target:
        parsed_target = urlparse(target)
        target_host = parsed_target.hostname or ""
        target_scheme = parsed_target.scheme or "http"

    if url.startswith("/"):
        if target_host:
            url = f"{target_scheme}://{target_host}{url}"
        else:
            return url.rstrip("/").lower()

    parsed = urlparse(url)

    scheme = parsed.scheme or target_scheme
    netloc = parsed.netloc.lower()
    path = parsed.path.rstrip("/") or "/"

    query = parsed.query

    return urlunparse((scheme, netloc, path, "", query, "")).lower()


def normalize_finding_text(text: str) -> str:
    text = (text or "").strip().lower()
    text = re.sub(r"\s+", " ", text)
    text = text.replace("found.", "found")
    text = text.replace("page found.", "page found")
    text = text.replace("admin password reset", "password reset")
    return text


class ReportManager:
    def __init__(self, report_dir: Path | None = None):
        self.report_dir = report_dir or Path("app") / "reports"
        self.report_path = self.report_dir / "REPORT.txt"
        self.findings_path = self.report_dir / "findings.jsonl"
        self.update_counter_path = self.report_dir / ".report_update_counter"

        self.report_dir.mkdir(parents=True, exist_ok=True)

    def reset(self, target: str) -> None:
        with REPORT_LOCK:
            self.findings_path.write_text("", encoding="utf-8")

            initial = {
                "type": "metadata",
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "target": target,
            }

            self._append_raw_unlocked(initial)
            
            if self.update_counter_path.exists():
                self.update_counter_path.unlink()
            
            initial_report = f"""Recon+ Report
=============

Target
------
{target}

Ports
-----

Subdomains / VHosts
-------------------

Discovered Directories
----------------------

Discovered Files
----------------

Sensitive / Confirmed Findings
------------------------------
None

Potential Vulnerability Candidates
----------------------------------
None

"""
            self.report_path.write_text(initial_report, encoding="utf-8")

    def get_target(self, findings: list[dict]) -> str:
        metadata = [item for item in findings if item.get("type") == "metadata"]
        return metadata[-1].get("target", "") if metadata else ""

    def add_finding(self, finding: dict) -> None:
        finding.setdefault("timestamp", datetime.now().isoformat(timespec="seconds"))

        with REPORT_LOCK:
            existing = self.load_findings()
            target = self.get_target(existing)

            if self.is_duplicate_finding(finding, existing, target):
                return

            self._append_raw_unlocked(finding)
            self._append_to_live_report(finding)

    def _format_status_info(self, finding: dict) -> str:
        """Return status info in (Status:200)(Size:400)(Words:56)(Lines:78) format."""
        status = finding.get("status") or finding.get("status_code")
        length = finding.get("length") or finding.get("content_length")
        words = finding.get("words")
        lines = finding.get("lines")

        parts = []
        if status not in {None, "", "-", "live", "unknown"}:
            parts.append(f"(Status:{status})")
        if length not in {None, "", "-", "unknown"}:
            parts.append(f"(Size:{length})")
        if words not in {None, "", "-"}:
            parts.append(f"(Words:{words})")
        if lines not in {None, "", "-"}:
            parts.append(f"(Lines:{lines})")

        return " " + "".join(parts) if parts else ""

    def _format_port_line(self, port: dict) -> str:
        """Format a single port as a report line."""
        port_num = port.get("port")
        proto = port.get("protocol", "tcp")
        state = port.get("state", "open")
        service = port.get("service", "")
        product = port.get("product", "")
        version = port.get("version", "")
        cpes = port.get("cpes", [])

        line = f"- {port_num}/{proto} {state}"
        if service:
            line += f" {service}"
        if product:
            line += f" {product}"
        if version:
            line += f" {version}"
        if cpes:
            line += f" (CPE: {cpes[0]})"
        return line.rstrip()

    def _port_info_score(self, port: dict) -> int:
        """Higher score = more detailed port info. Used to decide which version to keep."""
        return sum([
            bool(port.get("service")),
            bool(port.get("product")),
            bool(port.get("version")),
            bool(port.get("cpes")),
        ])

    def _update_ports_in_report(self, finding: dict) -> None:
        """
        Rule 3: Update existing port lines in-place instead of adding duplicates.
        - If a port already exists in the Ports section, replace it with the more detailed version.
        - If a port is new, append it to the Ports section.
        """
        ports = finding.get("ports", [])
        new_port_data: dict[str, dict] = {}
        for port in ports:
            port_num = port.get("port")
            if not port_num:
                continue
            proto = port.get("protocol", "tcp")
            state = port.get("state", "open")
            if state not in {"open", "filtered", "open|filtered"}:
                continue
            new_port_data[f"{port_num}/{proto}"] = port

        if not new_port_data:
            return

        try:
            report = self.report_path.read_text(encoding="utf-8")
        except Exception:
            return

        lines = report.split("\n")
        result = []
        in_ports = False
        past_sep = False
        placed = set()   # keys already written

        for line in lines:
            stripped = line.strip()

            # Detect section header
            if stripped == "Ports" and not in_ports:
                in_ports = True
                result.append(line)
                continue

            # Detect "-----" separator inside the section
            if in_ports and not past_sep and re.match(r'^-{3,}$', stripped):
                past_sep = True
                result.append(line)
                continue

            # Inside Ports content
            if in_ports and past_sep:
                if stripped.startswith("- ") and "/" in stripped:
                    # Try to match against one of our new ports
                    matched_key = None
                    for key in new_port_data:
                        # line looks like "- 80/tcp open ..."
                        if stripped.startswith(f"- {key}"):
                            matched_key = key
                            break

                    if matched_key:
                        existing_port = new_port_data[matched_key]
                        # Keep the version with more details (prefer -sV result)
                        existing_score = len(stripped.split())
                        new_score = self._port_info_score(existing_port)
                        if new_score > 0:   # new data has service/product/version
                            result.append(self._format_port_line(existing_port))
                        else:
                            result.append(line)
                        placed.add(matched_key)
                    else:
                        result.append(line)
                    continue

                # Line that ends the Ports section (blank line or next header)
                # Flush any new ports we haven't placed yet BEFORE this line
                for key, p in new_port_data.items():
                    if key not in placed:
                        result.append(self._format_port_line(p))
                        placed.add(key)
                in_ports = False
                past_sep = False
                result.append(line)
                continue

            result.append(line)

        # EOF while still in ports section — flush remaining
        for key, p in new_port_data.items():
            if key not in placed:
                result.append(self._format_port_line(p))

        self.report_path.write_text("\n".join(result), encoding="utf-8")

    def _insert_into_section(self, report: str, section_name: str, new_line: str) -> str:
        """Insert new_line right after the '---' separator of section_name."""
        lines = report.split("\n")
        new_lines = []
        found_section = False
        inserted = False

        for line in lines:
            new_lines.append(line)
            if line.strip() == section_name and not found_section:
                found_section = True
                continue
            if found_section and re.match(r'^-{3,}$', line.strip()) and not inserted:
                new_lines.append(new_line)
                inserted = True
                found_section = False

        return "\n".join(new_lines) if inserted else report

    def _append_to_live_report(self, finding: dict) -> None:
        finding_type = finding.get("type")

        if not self.report_path.exists():
            return

        # nmap_scan: use update-in-place logic (Rule 3)
        if finding_type == "nmap_scan":
            self._update_ports_in_report(finding)
            return

        try:
            report = self.report_path.read_text(encoding="utf-8")
        except Exception:
            return

        new_line = ""
        section_name = ""

        if finding_type == "directory":
            url = finding.get("url", "")
            if not url:
                return
            status_info = self._format_status_info(finding)
            new_line = f"- {url}{status_info}"
            path = url.rstrip("/").split("/")[-1] if "/" in url else url
            section_name = "Discovered Files" if ("." in path and not url.endswith("/")) else "Discovered Directories"

        elif finding_type == "vhost":
            host = finding.get("host", finding.get("url", ""))
            if not host:
                return
            status_info = self._format_status_info(finding)
            new_line = f"- {host}{status_info}"
            section_name = "Subdomains / VHosts"

        elif finding_type == "lfi":
            url = finding.get("url", "")
            evidence = finding.get("evidence", "")[:100]
            new_line = f"- LFI: {url} — {evidence}"
            section_name = "Sensitive / Confirmed Findings"

        elif finding_type == "content_probe":
            url = finding.get("url", "")
            matches = finding.get("important_matches", [])
            if matches:
                lines = [f"- {url}: {m[:80]}" for m in matches[:3]]
                new_line = "\n".join(lines)
                section_name = "Sensitive / Confirmed Findings"

        if not new_line or not section_name:
            return

        updated = self._insert_into_section(report, section_name, new_line)
        if updated != report:
            self.report_path.write_text(updated, encoding="utf-8")

    def should_update_ai_report(self, every: int = 5) -> bool:
        current = 0

        if self.update_counter_path.exists():
            try:
                current = int(self.update_counter_path.read_text().strip())
            except ValueError:
                current = 0

        current += 1
        self.update_counter_path.write_text(str(current), encoding="utf-8")

        return current % every == 0

    def is_duplicate_finding(self, finding: dict, existing: list[dict], target: str) -> bool:
        finding_type = finding.get("type")

        if finding_type in {"directory", "vhost"}:
            new_url = normalize_url_for_dedupe(finding.get("url", ""), target)

            for item in existing:
                if item.get("type") != finding_type:
                    continue

                old_url = normalize_url_for_dedupe(item.get("url", ""), target)

                if new_url and old_url and new_url == old_url:
                    return True

            return False

        if finding_type == "content_probe":
            new_url = normalize_url_for_dedupe(finding.get("url", ""), target)

            for item in existing:
                if item.get("type") != "content_probe":
                    continue

                old_url = normalize_url_for_dedupe(item.get("url", ""), target)

                if new_url and old_url and new_url == old_url:
                    return True

            return False

        # nmap_scan: never treat as duplicate. A first write may have empty ports
        # (failed XML, interrupted scan); a later run with the same flags must still
        # be recorded so REPORT.txt and findings.jsonl can show real open ports.

        if finding_type == "ai_vulnerability_candidate":
            new_url = normalize_url_for_dedupe(finding.get("url", ""), target)
            new_text = normalize_finding_text(
                finding.get("finding") or finding.get("title") or ""
            )

            for item in existing:
                if item.get("type") != "ai_vulnerability_candidate":
                    continue

                old_url = normalize_url_for_dedupe(item.get("url", ""), target)
                old_text = normalize_finding_text(
                    item.get("finding") or item.get("title") or ""
                )

                if new_url and old_url and new_url == old_url:
                    return True

                if new_url and old_url and new_url.endswith(old_url):
                    return True

                if new_url and old_url and old_url.endswith(new_url):
                    return True

                if new_text and old_text and new_text == old_text and new_url == old_url:
                    return True

            return False

        return False

    def _append_raw_unlocked(self, finding: dict) -> None:
        with open(self.findings_path, "a", encoding="utf-8") as file:
            file.write(json.dumps(finding, ensure_ascii=False) + "\n")

    def load_findings(self) -> list[dict]:
        if not self.findings_path.exists():
            return []

        findings = []

        with open(self.findings_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        return findings

    def render(self) -> None:
        findings = self.load_findings()

        metadata = [item for item in findings if item.get("type") == "metadata"]
        directories = [item for item in findings if item.get("type") == "directory"]
        vhosts = [item for item in findings if item.get("type") == "vhost"]
        content = [item for item in findings if item.get("type") == "content_probe"]
        lfi = [item for item in findings if item.get("type") == "lfi"]
        nmap_scans = [item for item in findings if item.get("type") == "nmap_scan"]
        sensitive = [
            item for item in findings
            if item.get("severity") in {"high", "critical"}
            and item.get("type") in {"content_probe", "lfi", "ai_vulnerability_candidate"}
        ]
        agent_notes = [item for item in findings if item.get("type") == "agent_note"]
        ai_candidates = [
            item for item in findings
            if item.get("type") == "ai_vulnerability_candidate"
        ]

        target = metadata[-1].get("target", "unknown") if metadata else "unknown"
        started = metadata[-1].get("timestamp", "unknown") if metadata else "unknown"

        lines = []
        lines.append("AI-Fuzzer-Agent Report")
        lines.append("======================")
        lines.append("")
        lines.append(f"Target: {target}")
        lines.append(f"Started: {started}")
        lines.append(f"Last updated: {datetime.now().isoformat(timespec='seconds')}")
        lines.append("")

        lines.append("Summary")
        lines.append("-------")
        lines.append(f"Directories found: {len(directories)}")
        lines.append(f"VHosts/Subdomains found: {len(vhosts)}")
        lines.append(f"Content probes: {len(content)}")
        lines.append(f"Nmap scans: {len(nmap_scans)}")
        lines.append(f"LFI findings: {len(lfi)}")
        lines.append(f"High/Critical findings: {len(sensitive)}")
        lines.append("")

        if sensitive:
            lines.append("High / Critical Findings")
            lines.append("------------------------")

            seen_sensitive = set()

            for item in sensitive:
                url = normalize_url_for_dedupe(item.get("url", ""), target)
                title = item.get("title", item.get("url", "unknown"))
                title_clean = normalize_finding_text(title)
                key = (url, title_clean, item.get("severity", ""))

                if key in seen_sensitive:
                    continue

                seen_sensitive.add(key)

                lines.append(
                    f"- [{item.get('severity', 'unknown').upper()}] "
                    f"{title}"
                )
                if item.get("url"):
                    lines.append(f"  URL: {item.get('url')}")
                if item.get("evidence"):
                    lines.append(f"  Evidence: {item.get('evidence')}")
            lines.append("")

        lines.append("Directories / Endpoints")
        lines.append("-----------------------")
        if directories:
            for item in directories:
                lines.append(
                    f"- {item.get('url')} "
                    f"[status={item.get('status', '-')}, length={item.get('length', '-')}]"
                )
        else:
            lines.append("- None")
        lines.append("")

        lines.append("VHosts / Subdomains")
        lines.append("-------------------")
        if vhosts:
            for item in vhosts:
                lines.append(
                    f"- {item.get('host', item.get('url'))} "
                    f"[status={item.get('status', '-')}, length={item.get('length', '-')}]"
                )
        else:
            lines.append("- None")
        lines.append("")

        lines.append("Content Probe Results")
        lines.append("---------------------")
        if content:
            for item in content:
                lines.append(f"- URL: {item.get('url')}")
                lines.append(f"  Status: {item.get('status', '-')}")
                lines.append(f"  Content-Length: {item.get('content_length', '-')}")
                lines.append(f"  Matches: {len(item.get('matches', []))}")
                lines.append(f"  Discovered paths: {len(item.get('discovered_paths', []))}")

                important_matches = []

                for match in item.get("matches", []):
                    match_type = match.get("type")
                    keyword = (match.get("keyword") or "").lower()
                    preview = (match.get("preview") or "").lower()

                    if match_type == "low_value_web_token":
                        continue

                    if match_type in {"email", "email_indicator"}:
                        continue

                    if keyword in {"email", "mail"}:
                        continue

                    if "static/admin/assets" in preview:
                        continue

                    if "/assets/" in preview or "/static/" in preview:
                        continue

                    if match_type == "possible_secret_or_credential":
                        important_matches.append(match)
                        continue

                    if keyword in {"admin", "login", "username", "token", "api", "config"}:
                        important_matches.append(match)

                for match in important_matches[:8]:
                    lines.append(
                        f"    - line {match.get('line_number')} | "
                        f"{match.get('type')} | "
                        f"{match.get('keyword')} | "
                        f"{match.get('preview')}"
                    )

                paths = item.get("discovered_paths", [])
                directory_paths = [path for path in paths if path.get("is_directory_like")]

                if directory_paths:
                    lines.append("  Directory-like links:")
                    for path in directory_paths[:10]:
                        lines.append(f"    - {path.get('url')}")

                lines.append("")
        else:
            lines.append("- None")
            lines.append("")

        lines.append("Nmap Results")
        lines.append("------------")

        if nmap_scans:
            for scan in nmap_scans[-5:]:
                lines.append(f"- Target: {scan.get('target')}")
                lines.append(f"  Flags: {' '.join(scan.get('flags', []))}")
                open_ports = scan.get("ports", [])

                if open_ports:
                    lines.append("  Open ports:")
                    for port in open_ports:
                        service_text = " ".join(
                            part for part in [
                                port.get("service", ""),
                                port.get("product", ""),
                                port.get("version", ""),
                            ]
                            if part
                        )

                        lines.append(
                            f"    - {port.get('port')}/{port.get('protocol')} "
                            f"{service_text}".rstrip()
                        )
                else:
                    lines.append("  Open ports: None")

                lines.append("")
        else:
            lines.append("- None")
            lines.append("")

        lines.append("LFI Findings")
        lines.append("------------")
        if lfi:
            for item in lfi:
                lines.append(f"- URL: {item.get('url')}")
                lines.append(f"  Severity: {item.get('severity', '-')}")
                lines.append(f"  Evidence: {item.get('evidence', '-')}")
        else:
            lines.append("- None")
        lines.append("")

        lines.append("High-Value Vulnerability Candidates")
        lines.append("-----------------------------------")

        if ai_candidates:
            severity_order = {
                "critical": 0,
                "high": 1,
                "medium": 2,
                "low": 3,
                "info": 4,
            }

            sorted_candidates = sorted(
                ai_candidates,
                key=lambda item: severity_order.get(item.get("severity", "info"), 4)
            )

            seen = set()

            for item in sorted_candidates[:15]:
                if item.get("severity", "info") == "info":
                    continue

                url = normalize_url_for_dedupe(item.get("url", ""), target)
                finding = item.get("finding") or item.get("title", "Interesting target")
                finding_clean = normalize_finding_text(finding)
                severity = item.get("severity", "info").upper()

                key = (url, finding_clean)
                if key in seen:
                    continue

                seen.add(key)

                if url:
                    lines.append(f"- [{severity}] {url} — {finding}")
                else:
                    lines.append(f"- [{severity}] {finding}")

            lines.append("")
        else:
            lines.append("- None")
            lines.append("")

        if agent_notes:
            lines.append("Agent Notes")
            lines.append("-----------")
            for item in agent_notes[-20:]:
                lines.append(f"- {item.get('note')}")
            lines.append("")

        self.report_path.write_text("\n".join(lines), encoding="utf-8")