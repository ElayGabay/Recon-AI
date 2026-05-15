import json
from pathlib import Path
from datetime import datetime

from app.core.report_manager import ReportManager
from app.llm.ollama_client import OllamaClient, OllamaUnavailableError
from app.core.output import log


SYSTEM_PROMPT = """
You are analyzing an authorized web security testing report.

Your job:
- Identify high-value vulnerability candidates.
- Do not claim exploitation is confirmed unless the evidence proves it.
- Do not suggest using credentials, passwords, tokens, cookies, or secrets to log in.
- Do not suggest brute force, password spraying, destructive actions, reverse shells, persistence, or data modification.
- Focus on what a pentester should inspect next.

Return only valid JSON.
"""


def compact_findings(findings: list[dict], max_items: int = 80) -> dict:
    directories = [item for item in findings if item.get("type") == "directory"]
    vhosts = [item for item in findings if item.get("type") == "vhost"]
    content = [item for item in findings if item.get("type") == "content_probe"]
    lfi = [item for item in findings if item.get("type") == "lfi"]

    return {
        "counts": {
            "directories": len(directories),
            "vhosts": len(vhosts),
            "content_probes": len(content),
            "lfi_findings": len(lfi),
        },
        "directories": directories[-max_items:],
        "vhosts": vhosts[-max_items:],
        "content_probes": content[-20:],
        "lfi_findings": lfi[-20:],
    }


def extract_json(text: str) -> dict:
    cleaned = text.strip()

    if cleaned.startswith("```json"):
        cleaned = cleaned.removeprefix("```json").strip()

    if cleaned.startswith("```"):
        cleaned = cleaned.removeprefix("```").strip()

    if cleaned.endswith("```"):
        cleaned = cleaned.removesuffix("```").strip()

    return json.loads(cleaned)


class ReportAnalyzer:
    def __init__(
        self,
        report_dir: Path | None = None,
        client: OllamaClient | None = None,
    ):
        self.manager = ReportManager(report_dir)
        self.client = client or OllamaClient()

    def analyze_and_update_report(self) -> list[dict]:
        findings = self.manager.load_findings()

        if not findings:
            return []

        summary = compact_findings(findings)

        prompt = f"""
{SYSTEM_PROMPT}

Current report summary:
{json.dumps(summary, indent=2, ensure_ascii=False)}

Return JSON in this exact format:
{{
  "candidates": [
    {{
      "severity": "critical|high|medium|low|info",
      "url": "related URL if any",
      "finding": "very short finding, max 8 words"
    }}
  ]
}}

Rules:
- Max 5 candidates.
- Prefer real security signals over generic pages.
- Admin/login/register/forgot pages are high-value targets, but not confirmed vulnerabilities by themselves.
- CSRF tokens alone are usually informational, not a vulnerability.
- Email/contact information alone is usually low severity.
- Password input fields are not credential disclosure by themselves.
- If LFI findings exist, prioritize them.
- Keep every finding very short.
- Do not write long explanations.
- Do not include "why" or "next step".
- Format each candidate as a short actionable note.
- Avoid low-value findings like normal CSRF tokens, normal email contact info, images, CSS, JS, or generic RSS unless clearly suspicious.
- Do not duplicate candidates.
- Treat /admin/login and http://target/admin/login as the same URL.
- Do not include normal email contact information.
- Do not include normal CSRF tokens.
- Do not include static assets like images, CSS, or JS.
- Do not mark a normal password input field as a vulnerability.
- If admin/login/register/forgot are already present, return each only once.
- Prefer max 5 high-value items total.
- Do not mark static asset paths as vulnerabilities.
- Ignore admin keyword when it appears only inside CSS, JS, images, icons, fonts, or /static/admin/assets paths.
- Do not mark normal login pages as HIGH only because they contain username/password fields.
- Do not mark forgot-password as HIGH only because the word password appears.
- Email/contact information is not a vulnerability.
- CSRF token presence is not a vulnerability.
- Prefer real attack surface: auth endpoints, API endpoints, exposed panels, versioned services, LFI/SQLi-like parameters, unusual responses.
- If there is no concrete security signal, do not include it.
- Login page alone should be MEDIUM at most.
- Forgot-password page alone should be MEDIUM at most.
- Admin panel path alone should be MEDIUM unless access is confirmed without authentication.
"""

        log("[+] Ollama analyzing report for high-value vulnerability candidates")

        try:
            raw = self.client.ask(prompt)
        except OllamaUnavailableError as exc:
            log(f"[!] Ollama unavailable during analysis: {exc}")
            return []
        except Exception as exc:
            log(f"[!] Ollama error during analysis: {exc}")
            return []

        try:
            data = extract_json(raw)
        except Exception:
            self.manager.add_finding(
                {
                    "type": "agent_note",
                    "note": f"Ollama report analysis returned invalid JSON: {raw[:300]}",
                }
            )
            return []

        candidates = data.get("candidates", [])

        if not isinstance(candidates, list):
            return []

        added = []

        existing_keys = set()

        for item in findings:
            if item.get("type") == "ai_vulnerability_candidate":
                existing_keys.add(
                    (
                        item.get("finding", item.get("title", "")),
                        item.get("url", ""),
                    )
                )

        for candidate in candidates[:5]:
            severity = candidate.get("severity", "info").lower()
            url = candidate.get("url", "")
            finding_text = candidate.get("finding", candidate.get("title", "Interesting target"))

            combined = f"{url} {finding_text}".lower()

            if severity == "info":
                continue

            if any(x in combined for x in [".css", ".js", ".png", ".jpg", ".ico", ".svg", ".woff"]):
                continue

            if "/static/" in combined or "/assets/" in combined:
                continue

            if "email" in combined or "contact information" in combined:
                continue

            if "csrf token" in combined:
                continue

            if "password reset" in combined and severity == "high":
                severity = "medium"

            if "login page" in combined and severity == "high":
                severity = "medium"

            key = (finding_text, url)

            if key in existing_keys:
                continue

            finding = {
                "type": "ai_vulnerability_candidate",
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "severity": severity,
                "url": url,
                "finding": finding_text,
            }

            self.manager.add_finding(finding)
            added.append(finding)

        return added
