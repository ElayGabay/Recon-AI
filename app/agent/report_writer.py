import json
from pathlib import Path
from urllib.parse import urlparse

from app.tools.cve_lookup import lookup_cves_for_port


STATIC_FILE_EXTENSIONS = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".pdf", ".txt", ".xml"
}


def normalize_url(url: str) -> str:
    if not url:
        return ""

    url = url.strip()

    if url.endswith("/") and len(url) > 1:
        url = url.rstrip("/")

    return url


def get_path_from_url(url: str) -> str:
    parsed = urlparse(url)

    if parsed.path:
        return parsed.path

    return url


def looks_like_file(url: str) -> bool:
    path = get_path_from_url(url).lower()
    last_part = path.rstrip("/").split("/")[-1]

    if "." in last_part:
        return True

    return any(path.endswith(ext) for ext in STATIC_FILE_EXTENSIONS)


def format_status_length(item: dict) -> str:
    """Return status info as (Status:200)(Size:367)(Words:34)(Lines:5)."""
    status = item.get("status") or item.get("status_code")
    length = item.get("length") or item.get("content_length")
    words = item.get("words")
    lines = item.get("lines")

    parts = []
    if status not in {"live", "unknown", "-", None, ""}:
        parts.append(f"(Status:{status})")
    if length not in {"unknown", "-", None, ""}:
        parts.append(f"(Size:{length})")
    if words not in {None, "", "-"}:
        parts.append(f"(Words:{words})")
    if lines not in {None, "", "-"}:
        parts.append(f"(Lines:{lines})")

    return " " + "".join(parts) if parts else ""


def infer_default_ports_from_findings(findings: list[dict]) -> list[dict]:
    """
    When nmap produced no rows (interrupted run, parse failure, etc.), infer the
    obvious scheme port from the last metadata target so REPORT.txt is not empty
    for a working http(s) site.
    """
    meta = [f for f in findings if f.get("type") == "metadata"]
    if not meta:
        return []

    raw = (meta[-1].get("target") or "").strip()
    if not raw:
        return []

    url = raw if "://" in raw else f"http://{raw}"
    try:
        parsed = urlparse(url)
    except Exception:
        return []

    scheme = (parsed.scheme or "http").lower()
    if scheme not in {"http", "https"}:
        return []

    explicit = parsed.port
    if explicit is not None:
        num = str(explicit)
        label = f"{scheme} (inferred from URL; no nmap port data)"
    elif scheme == "https":
        num = "443"
        label = "https (inferred from URL; no nmap port data)"
    else:
        num = "80"
        label = "http (inferred from URL; no nmap port data)"

    return [
        {
            "port": num,
            "protocol": "tcp",
            "state": "open",
            "service": label,
            "product": "",
            "version": "",
            "cpes": [],
            "is_service_scan": False,
        }
    ]


def build_inventory(findings: list[dict]) -> dict:
    directories = []
    files = []
    vhosts = []
    ports = []

    seen_dirs = set()
    seen_files = set()
    seen_vhosts = set()
    seen_ports = set()

    for item in findings:
        item_type = item.get("type")

        if item_type == "directory":
            url = normalize_url(item.get("url", ""))
            if not url:
                continue

            if looks_like_file(url):
                key = url.lower()
                if key not in seen_files:
                    seen_files.add(key)
                    files.append({
                        "url": url,
                        "status": item.get("status"),
                        "length": item.get("length"),
                        "words": item.get("words"),
                        "lines": item.get("lines"),
                    })
            else:
                key = url.lower()
                if key not in seen_dirs:
                    seen_dirs.add(key)
                    directories.append({
                        "url": url,
                        "status": item.get("status"),
                        "length": item.get("length"),
                        "words": item.get("words"),
                        "lines": item.get("lines"),
                    })

        elif item_type == "vhost":
            host = item.get("host") or item.get("url")
            if not host:
                continue

            key = host.lower()
            if key not in seen_vhosts:
                seen_vhosts.add(key)
                vhosts.append({
                    "host": host,
                    "url": item.get("url"),
                    "status": item.get("status"),
                    "length": item.get("length"),
                    "words": item.get("words"),
                    "lines": item.get("lines"),
                })

        elif item_type == "nmap_scan":
            flags = item.get("flags", [])
            open_ports = item.get("ports", [])

            is_service_scan = "-sV" in flags

            for port in open_ports:
                port_id = port.get("port")
                if port_id is None or port_id == "":
                    continue

                protocol = port.get("protocol", "tcp") or "tcp"
                state_raw = (port.get("state") or "").strip().lower()
                state = state_raw or "open"
                service = port.get("service", "")
                product = port.get("product", "")
                version = port.get("version", "")

                if state not in {"open", "filtered", "open|filtered"}:
                    continue

                key = (str(port_id), protocol)

                cves = port.get("cpes", [])
                
                port_item = {
                    "port": str(port_id),
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "product": product,
                    "version": version,
                    "cpes": cves,
                    "is_service_scan": is_service_scan,
                }
                
                cve_matches = lookup_cves_for_port(port_item)
                if cve_matches:
                    port_item["cves_found"] = cve_matches

                if key not in seen_ports:
                    seen_ports.add(key)
                    ports.append(port_item)
                else:
                    for index, existing in enumerate(ports):
                        if str(existing.get("port")) == str(port_id) and existing.get("protocol", "tcp") == protocol:
                            if is_service_scan and not existing.get("is_service_scan"):
                                ports[index] = port_item

    if not ports:
        for inferred in infer_default_ports_from_findings(findings):
            key = (str(inferred.get("port")), inferred.get("protocol", "tcp"))
            if key not in seen_ports:
                seen_ports.add(key)
                ports.append(inferred)

    return {
        "directories": directories,
        "files": files,
        "vhosts": vhosts,
        "ports": ports,
    }


def open_tcp_ports_csv_from_findings(findings: list[dict]) -> str | None:
    """
    Sorted unique TCP port list for nmap -sV, from inventory (open / filtered).
    Returns e.g. "22,80,443" or None if nothing usable.
    """
    inv = build_inventory(findings)
    nums: list[int] = []
    for p in inv.get("ports") or []:
        if (p.get("protocol") or "tcp").lower() != "tcp":
            continue
        st = (p.get("state") or "").strip().lower()
        if st not in {"open", "filtered", "open|filtered"}:
            continue
        raw = p.get("port")
        if raw is None or raw == "":
            continue
        try:
            nums.append(int(str(raw)))
        except ValueError:
            continue
    if not nums:
        return None
    return ",".join(str(x) for x in sorted(set(nums)))


def render_inventory_sections(inventory: dict) -> str:
    lines = []

    lines.append("Ports")
    lines.append("-----")
    if inventory["ports"]:
        for port in inventory["ports"]:
            service_parts = [
                port.get("service", ""),
                port.get("product", ""),
                port.get("version", ""),
            ]
            service_text = " ".join(part for part in service_parts if part).strip()

            lines.append(
                f"- {port.get('port')}/{port.get('protocol')} "
                f"{port.get('state')} {service_text}".rstrip()
            )
            
            cves_found = port.get("cves_found", [])
            for cve in cves_found[:3]:
                severity = cve.get("severity", "").upper()
                cve_id = cve.get("cve_id", "")
                title = cve.get("title", "")
                lines.append(f"  CVE: {cve_id} [{severity}] {title}")
    else:
        lines.append("- None")
    lines.append("")

    lines.append("Subdomains / VHosts")
    lines.append("-------------------")
    if inventory["vhosts"]:
        for item in inventory["vhosts"]:
            value = item.get("host") or item.get("url")
            suffix = format_status_length(item)
            lines.append(f"- {value}{suffix}")
    else:
        lines.append("- None")
    lines.append("")

    lines.append("Discovered Directories")
    lines.append("----------------------")
    if inventory["directories"]:
        for item in inventory["directories"]:
            suffix = format_status_length(item)
            lines.append(f"- {item.get('url')}{suffix}")
    else:
        lines.append("- None")
    lines.append("")

    lines.append("Discovered Files")
    lines.append("----------------")
    if inventory["files"]:
        for item in inventory["files"]:
            suffix = format_status_length(item)
            lines.append(f"- {item.get('url')}{suffix}")
    else:
        lines.append("- None")
    lines.append("")

    return "\n".join(lines)


def load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []

    items = []

    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return items


def build_factual_analysis_sections(findings: list[dict]) -> str:
    """Only evidence-backed lines (e.g. LFI). No LLM speculation."""
    sensitive_lines: list[str] = []
    for item in findings:
        if item.get("type") != "lfi":
            continue
        url = item.get("url", "") or ""
        evidence = (item.get("evidence") or "")[:160].replace("\n", " ").strip()
        suffix = f" — {evidence}" if evidence else ""
        sensitive_lines.append(f"- LFI: {url}{suffix}")

    sensitive_body = "\n".join(sensitive_lines) if sensitive_lines else "None"
    return (
        "Sensitive / Confirmed Findings\n"
        "------------------------------\n"
        f"{sensitive_body}\n\n"
        "Potential Vulnerability Candidates\n"
        "----------------------------------\n"
        "None\n"
    )


class OllamaReportWriter:
    def __init__(self, report_dir: Path | None = None):
        self.report_dir = report_dir or Path("app") / "reports"
        self.findings_path = self.report_dir / "findings.jsonl"
        self.report_path = self.report_dir / "REPORT.txt"

    def write_report(self) -> str:
        """
        Build the final REPORT.txt.
        Inventory sections are built programmatically from findings.jsonl.
        Analysis sections list only factual findings (e.g. LFI); no model prose.
        """
        findings = load_jsonl(self.findings_path)

        if not findings:
            return ""

        # Build inventory sections programmatically — these are always correct
        inventory = build_inventory(findings)
        inventory_text = render_inventory_sections(inventory)

        metadata = [f for f in findings if f.get("type") == "metadata"]
        target = metadata[-1].get("target", "unknown") if metadata else "unknown"

        analysis = build_factual_analysis_sections(findings)

        report = (
            f"Recon+ Report\n"
            f"=============\n\n"
            f"Target\n"
            f"------\n"
            f"{target}\n\n"
            f"{inventory_text}\n"
            f"{analysis}\n"
        )

        self.report_path.write_text(report.strip() + "\n", encoding="utf-8")
        return report