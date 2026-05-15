from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from app.core.report_manager import ReportManager
from datetime import datetime
import asyncio
import re

import httpx

from app.core.process_manager import should_stop
from app.core.output import log
from app.core.http_cookie import normalize_cookie_arg


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
}

LFI_SUCCESS_PATTERNS = [
    {
        "name": "linux_passwd",
        "severity": "high",
        "regex": re.compile(r"root:x:0:0:", re.IGNORECASE),
        "description": "Linux /etc/passwd pattern detected",
    },
    {
        "name": "linux_shadow_like",
        "severity": "critical",
        "regex": re.compile(r"root:\$[0-9a-zA-Z]+\$", re.IGNORECASE),
        "description": "Linux shadow/hash-like pattern detected",
    },
    {
        "name": "windows_win_ini",
        "severity": "medium",
        "regex": re.compile(r"\[fonts\]|\[extensions\]|\[mci extensions\]", re.IGNORECASE),
        "description": "Windows win.ini style pattern detected",
    },
    {
        "name": "php_config_secret",
        "severity": "high",
        "regex": re.compile(r"(DB_PASSWORD|DB_USER|DB_HOST|database_password|password\s*=)", re.IGNORECASE),
        "description": "Possible database/config secret pattern detected",
    },
    {
        "name": "env_secret",
        "severity": "high",
        "regex": re.compile(r"(APP_KEY|SECRET_KEY|API_KEY|TOKEN|PASSWORD)\s*=", re.IGNORECASE),
        "description": "Possible .env/config secret pattern detected",
    },
]


def build_lfi_template(url: str) -> str:
    if "FUZZ" in url:
        return url

    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)

    if not query:
        raise ValueError("LFI triage requires a URL with query parameters or FUZZ marker.")

    replaced = False

    for param in list(query.keys()):
        if param.lower() in LFI_SUSPICIOUS_PARAMS:
            query[param] = ["FUZZ"]
            replaced = True
            break

    if not replaced:
        first_param = list(query.keys())[0]
        query[first_param] = ["FUZZ"]

    new_query = urlencode(query, doseq=True)

    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment,
        )
    )


def load_lfi_payloads(wordlist_paths: list[Path]) -> list[str]:
    payloads = []
    seen = set()

    for wordlist_path in wordlist_paths:
        log(f"[LFI] Loading wordlist: {wordlist_path}")

        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as file:
            for line in file:
                payload = line.strip()

                if not payload:
                    continue

                if payload.startswith("#"):
                    continue

                if payload in seen:
                    continue

                seen.add(payload)
                payloads.append(payload)

    return payloads


def build_test_url(template_url: str, payload: str) -> str:
    return template_url.replace("FUZZ", payload)


def detect_lfi_success(content: str) -> list[dict]:
    findings = []

    for pattern in LFI_SUCCESS_PATTERNS:
        if pattern["regex"].search(content):
            findings.append(
                {
                    "name": pattern["name"],
                    "severity": pattern["severity"],
                    "description": pattern["description"],
                }
            )

    return findings


def safe_preview(content: str, max_chars: int = 500) -> str:
    cleaned = content.replace("\r", "")
    lines = [line.strip() for line in cleaned.splitlines() if line.strip()]
    preview = "\n".join(lines[:10])

    if len(preview) > max_chars:
        preview = preview[:max_chars] + "...[truncated]"

    return preview


def append_lfi_to_report(report_path: Path, item: dict) -> None:
    manager = ReportManager(report_path.parent)

    highest_severity = "medium"

    for finding in item.get("findings", []):
        if finding.get("severity") == "critical":
            highest_severity = "critical"
            break

        if finding.get("severity") == "high":
            highest_severity = "high"

    manager.add_finding(
        {
            "type": "lfi",
            "severity": highest_severity,
            "title": "Possible LFI file read confirmed",
            "url": item.get("url"),
            "payload": item.get("payload"),
            "status": item.get("status_code"),
            "content_length": item.get("content_length"),
            "evidence": "; ".join(
                finding.get("description", "")
                for finding in item.get("findings", [])
            ),
            "preview": item.get("preview", ""),
        }
    )


async def test_lfi_payload(
    semaphore: asyncio.Semaphore,
    client: httpx.AsyncClient,
    template_url: str,
    payload: str,
    report_path: Path,
) -> dict | None:
    if should_stop():
        return None

    test_url = build_test_url(template_url, payload)

    async with semaphore:
        try:
            response = await client.get(test_url)

            content_bytes = response.content[:500_000]

            try:
                content = content_bytes.decode(response.encoding or "utf-8", errors="ignore")
            except Exception:
                content = content_bytes.decode("utf-8", errors="ignore")

            findings = detect_lfi_success(content)

            if not findings:
                return None

            item = {
                "url": test_url,
                "payload": payload,
                "status_code": response.status_code,
                "content_length": len(response.content),
                "findings": findings,
                "preview": safe_preview(content),
            }

            append_lfi_to_report(report_path, item)

            log(
                f"[LFI] FOUND "
                f"status={item['status_code']} "
                f"len={item['content_length']} "
                f"payload={payload}"
            )

            for finding in findings:
                log(
                    f"[LFI]   {finding['severity'].upper()} "
                    f"{finding['name']} - {finding['description']}"
                )

            return item

        except httpx.RequestError:
            return None


def chunk_list(items: list[str], chunk_size: int):
    for index in range(0, len(items), chunk_size):
        yield items[index:index + chunk_size]


async def async_lfi_triage(
    target_url: str,
    wordlist_paths: list[Path],
    concurrency: int = 50,
    timeout_seconds: float = 8.0,
    report_path: Path | None = None,
    cookie: str | None = None,
) -> list[dict]:
    if report_path is None:
        report_path = Path("app") / "reports" / "REPORT.txt"

    template_url = build_lfi_template(target_url)
    payloads = load_lfi_payloads(wordlist_paths)

    log(f"[LFI] Template: {template_url}")
    log(f"[LFI] Loaded {len(payloads)} unique LFI payloads")
    log(f"[LFI] Concurrent requests: {concurrency}")

    results = []
    semaphore = asyncio.Semaphore(concurrency)

    client_headers = {
        "User-Agent": "AI-Fuzzer-Agent/1.0 Authorized-Testing",
    }
    cookie_val = normalize_cookie_arg(cookie)
    if cookie_val:
        client_headers["Cookie"] = cookie_val

    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=timeout_seconds,
        headers=client_headers,
    ) as client:
        checked = 0
        batch_size = max(concurrency * 2, 100)

        for batch in chunk_list(payloads, batch_size):
            if should_stop():
                log("[!] Stop requested. Exiting LFI triage.")
                break

            tasks = [
                test_lfi_payload(
                    semaphore=semaphore,
                    client=client,
                    template_url=template_url,
                    payload=payload,
                    report_path=report_path,
                )
                for payload in batch
            ]

            batch_results = await asyncio.gather(*tasks)

            for item in batch_results:
                if item is not None:
                    results.append(item)

            checked += len(batch)

            if checked % 1000 == 0 or checked >= len(payloads):
                log(f"[LFI] Progress: {checked}/{len(payloads)} checked")

    log(f"[LFI] Triage finished. Confirmed findings: {len(results)}")
    return results


def lfi_triage(
    target_url: str,
    wordlist_paths: list[Path],
    concurrency: int = 50,
    timeout_seconds: float = 8.0,
    report_path: Path | None = None,
    cookie: str | None = None,
) -> list[dict]:
    try:
        return asyncio.run(
            async_lfi_triage(
                target_url=target_url,
                wordlist_paths=wordlist_paths,
                concurrency=concurrency,
                timeout_seconds=timeout_seconds,
                report_path=report_path,
                cookie=cookie,
            )
        )
    except KeyboardInterrupt:
        log("[!] Ctrl+C detected. Stopping LFI triage.")
        return []