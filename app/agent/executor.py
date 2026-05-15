from pathlib import Path

from app.agent.state import AgentState
from app.tools.content_probe import content_probe
from app.tools.lfi_tester import lfi_triage
from app.tools.ffuf_runner import run_ffuf_directory, run_ffuf_vhost
from app.tools.nmap_runner import run_nmap_scan
from app.core.seclists_catalog import get_wordlists_for_mode
from app.core.report_manager import ReportManager
from app.core.http_cookie import normalize_cookie_arg
from app.core.process_manager import should_stop
from app.core.output import log


def remove_if_exists(items: list[str], value: str) -> None:
    try:
        items.remove(value)
    except ValueError:
        pass


def run_agent_action(
    action: dict,
    state: AgentState,
    seclists_root: str,
    threads: int = 50,
    depth: int | None = None,
    report_path: Path | None = None,
    cookie: str | None = None,
) -> dict:
    if should_stop():
        return {
            "tool": "stop",
            "target": action.get("target") or state.target,
            "message": "Stop requested by user.",
        }

    if report_path is None:
        report_path = Path("app") / "reports" / "REPORT.txt"

    cookie_val = normalize_cookie_arg(cookie)

    tool = action.get("tool")
    target = action.get("target") or state.target

    log(f"[+] Agent selected tool: {tool}")
    log(f"[+] Target: {target}")
    log(f"[+] Reason: {action.get('reason', '')}")

    if tool == "nmap_scan":
        flags = action.get("flags")

        if not flags:
            flags = ["-T3", "--top-ports", "100"]

        result = run_nmap_scan(
            target=target,
            allowed_host=state.allowed_host,
            flags=flags,
            report_path=report_path,
        )

        state.completed_actions.append("nmap_scan")

        return {
            "tool": "nmap_scan",
            "target": target,
            "result": result,
            "findings": result.get("ports", []),
        }

    if tool == "content_probe":
        remove_if_exists(state.pending_content_probe_urls, target)

        result = content_probe(
            url=target,
            allowed_host=state.allowed_host,
            report_path=report_path,
            cookie=cookie_val,
        )

        state.add_content_probe_result(result)
        state.completed_actions.append("content_probe")

        return {
            "tool": "content_probe",
            "target": target,
            "result": result,
        }

    if tool == "lfi_triage":
        remove_if_exists(state.pending_lfi_urls, target)

        wordlists = get_wordlists_for_mode(seclists_root, "lfi_both")
        wordlist_paths = [item["path"] for item in wordlists]

        results = lfi_triage(
            target_url=target,
            wordlist_paths=wordlist_paths,
            concurrency=threads,
            report_path=report_path,
            cookie=cookie_val,
        )

        state.completed_actions.append("lfi_triage")

        return {
            "tool": "lfi_triage",
            "target": target,
            "findings": results,
        }

    if tool == "directory_fuzz":
        remove_if_exists(state.pending_directory_fuzz_urls, target)

        wordlists = get_wordlists_for_mode(seclists_root, "directories_and_files")
        wordlist_path = wordlists[0]["path"]

        results = run_ffuf_directory(
            target_url=target,
            wordlist_path=wordlist_path,
            threads=threads,
            report_path=report_path,
            cookie=cookie_val,
        )

        normalized_results = []

        for item in results:
            normalized_results.append(
                {
                    "url": item.get("url"),
                    "path": item.get("url"),
                    "status_code": item.get("status"),
                    "content_length": item.get("length"),
                    "type": "directory",
                    "depth": 0,
                }
            )

        state.add_fuzz_results(normalized_results)
        state.completed_actions.append("directory_fuzz")

        return {
            "tool": "directory_fuzz",
            "target": target,
            "findings": normalized_results,
        }

    if tool == "subdomain_scan":
        wordlists = get_wordlists_for_mode(seclists_root, "subdomains")
        wordlist_path = wordlists[0]["path"]

        results = run_ffuf_vhost(
            target_url=target,
            wordlist_path=wordlist_path,
            threads=threads,
            report_path=report_path,
            cookie=cookie_val,
        )

        normalized_results = []

        for item in results:
            normalized_results.append(
                {
                    "finding_type": "VHOST",
                    "host": item.get("host", ""),
                    "url": item.get("url"),
                    "status_code": item.get("status"),
                    "content_length": item.get("length"),
                    "ips": [],
                }
            )

        state.add_subdomain_results(normalized_results)
        state.completed_actions.append("subdomain_scan")

        return {
            "tool": "subdomain_scan",
            "target": target,
            "findings": normalized_results,
        }

    if tool == "update_report":
        state.completed_actions.append("update_report")

        manager = ReportManager(report_path.parent)
        manager.add_finding(
            {
                "type": "agent_note",
                "note": action.get("reason", "Report updated."),
            }
        )

        return {
            "tool": "update_report",
            "target": target,
            "message": action.get("reason", "Report updated."),
        }

    if tool == "stop":
        state.completed_actions.append("stop")

        return {
            "tool": "stop",
            "target": target,
            "message": action.get("reason", "Agent decided to stop."),
        }

    return {
        "tool": tool,
        "target": target,
        "error": "Tool is not implemented in executor.",
    }