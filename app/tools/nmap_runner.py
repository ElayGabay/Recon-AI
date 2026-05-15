from pathlib import Path
from urllib.parse import urlparse
import subprocess
import xml.etree.ElementTree as ET
import uuid
import os
import signal
import time

from app.core.process_manager import (
    register_process,
    unregister_process,
    should_stop,
    kill_registered_processes,
)
from app.core.report_manager import ReportManager
from app.core.output import log, print_nmap_port, info


BLOCKED_FLAGS = {
    "--script",
    "-A",
    "--osscan-guess",
    "--script-args",
    "--script-help",
}

BLOCKED_SCRIPT_WORDS = {
    "brute",
    "exploit",
    "intrusive",
    "dos",
    "auth",
    "vuln",
    "malware",
    "backdoor",
}


DEFAULT_SAFE_FLAGS = [
    "-sV",
    "-T3",
    "--top-ports",
    "1000",
]


def extract_host(target: str) -> str:
    parsed = urlparse(target)

    if parsed.hostname:
        return parsed.hostname

    return target.replace("http://", "").replace("https://", "").split("/")[0]


def validate_target(target: str, allowed_host: str) -> str:
    host = extract_host(target).lower()
    allowed = allowed_host.lower()

    if host != allowed and not host.endswith("." + allowed):
        raise ValueError(f"Nmap target outside allowed scope: {host}")

    return host


def validate_flags(flags: list[str]) -> list[str]:
    clean_flags = []

    for flag in flags:
        lower = flag.lower()

        if flag in BLOCKED_FLAGS:
            raise ValueError(f"Blocked Nmap flag: {flag}")

        for blocked_word in BLOCKED_SCRIPT_WORDS:
            if blocked_word in lower:
                raise ValueError(f"Blocked Nmap script/flag content: {flag}")

        clean_flags.append(flag)

    return clean_flags


def is_service_version_scan(flags: list[str]) -> bool:
    """True for -sV (and similar) scans where product/version should appear on the terminal."""
    return any(f in {"-sV", "-A", "-sC"} for f in flags)


def parse_nmap_xml(xml_path: Path) -> dict:
    if not xml_path.exists():
        return {
            "ports": [],
            "raw_summary": "Nmap XML output was not created.",
        }

    tree = ET.parse(xml_path)
    root = tree.getroot()

    ports = []

    for host in root.findall("host"):
        ports_node = host.find("ports")

        if ports_node is None:
            continue

        for port in ports_node.findall("port"):
            port_id = port.get("portid", "")
            protocol = port.get("protocol", "")

            state_node = port.find("state")
            state = state_node.get("state", "") if state_node is not None else ""

            service_node = port.find("service")
            service = service_node.get("name", "") if service_node is not None else ""
            product = service_node.get("product", "") if service_node is not None else ""
            version = service_node.get("version", "") if service_node is not None else ""

            cpes = []

            if service_node is not None:
                for cpe_node in service_node.findall("cpe"):
                    if cpe_node.text:
                        cpes.append(cpe_node.text.strip())

            if state == "open":
                ports.append(
                    {
                        "port": port_id,
                        "protocol": protocol,
                        "state": state,
                        "service": service,
                        "product": product,
                        "version": version,
                        "cpes": cpes,
                    }
                )

    return {
        "ports": ports,
        "raw_summary": f"Open ports found: {len(ports)}",
    }


def add_nmap_to_report(report_path: Path, target: str, flags: list[str], parsed: dict) -> None:
    manager = ReportManager(report_path.parent)

    manager.add_finding(
        {
            "type": "nmap_scan",
            "severity": "info",
            "target": target,
            "flags": flags,
            "ports": parsed.get("ports", []),
            "summary": parsed.get("raw_summary", ""),
        }
    )


def run_nmap_scan(
    target: str,
    allowed_host: str,
    flags: list[str] | None = None,
    report_path: Path | None = None,
    timeout_seconds: int = 180,
) -> dict:
    if report_path is None:
        report_path = Path("app") / "reports" / "REPORT.txt"

    safe_target = validate_target(target, allowed_host)

    if flags is None:
        flags = DEFAULT_SAFE_FLAGS

    safe_flags = validate_flags(flags)

    output_dir = Path("app") / "data" / "nmap"
    output_dir.mkdir(parents=True, exist_ok=True)

    xml_path = output_dir / f"nmap_{uuid.uuid4().hex}.xml"

    command = [
        "nmap",
        *safe_flags,
        "-oX",
        str(xml_path),
        safe_target,
    ]

    log("[+] Running Nmap scan")
    log(f"[+] Target: {safe_target}")
    log(f"[+] Flags: {' '.join(safe_flags)}")

    creationflags = 0
    preexec_fn = None

    if os.name == "nt":
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    else:
        preexec_fn = os.setsid

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="ignore",
        creationflags=creationflags,
        preexec_fn=preexec_fn,
    )

    register_process(process)

    output_lines = []

    try:
        start_time = time.time()

        while process.poll() is None:
            if should_stop():
                log("[!] Stop requested. Killing Nmap scan.")
                kill_registered_processes()
                unregister_process(process)
                return {
                    "tool": "nmap_scan",
                    "target": safe_target,
                    "status": "stopped",
                    "ports": [],
                }

            if time.time() - start_time > timeout_seconds:
                log("[!] Nmap timeout reached. Killing scan.")
                kill_registered_processes()
                unregister_process(process)
                return {
                    "tool": "nmap_scan",
                    "target": safe_target,
                    "status": "timeout",
                    "ports": [],
                }

            line = process.stdout.readline() if process.stdout else ""

            if line:
                clean = line.strip()
                output_lines.append(clean)

                # Stream nmap stdout to debug log only on version scans (less terminal noise)
                if clean and is_service_version_scan(safe_flags):
                    log(f"[NMAP] {clean}")

        unregister_process(process)

    except KeyboardInterrupt:
        log("[!] Ctrl+C detected. Stopping Nmap.")
        kill_registered_processes()
        unregister_process(process)
        return {
            "tool": "nmap_scan",
            "target": safe_target,
            "status": "stopped",
            "ports": [],
        }

    parsed = parse_nmap_xml(xml_path)
    add_nmap_to_report(report_path, safe_target, safe_flags, parsed)

    open_ports = parsed.get("ports", [])
    if is_service_version_scan(safe_flags):
        if open_ports:
            info(f"Nmap service detection ({safe_target}):")
        for p in open_ports:
            print_nmap_port(
                port=p.get("port", "?"),
                protocol=p.get("protocol", "tcp"),
                state=p.get("state", "open"),
                service=p.get("service", ""),
                product=p.get("product", ""),
                version=p.get("version", ""),
            )
    else:
        n = len(open_ports)
        if n:
            log(f"[NMAP] Port discovery finished — {n} open port(s); -sV will run next.")

    return {
        "tool": "nmap_scan",
        "target": safe_target,
        "status": "finished",
        "flags": safe_flags,
        "ports": parsed.get("ports", []),
        "summary": parsed.get("raw_summary", ""),
    }


def build_timing_flags(timing_template: int | None) -> list[str]:
    if timing_template is None:
        return []

    if timing_template not in {1, 2, 3, 4, 5}:
        raise ValueError("Nmap timing must be between 1 and 5.")

    return [f"-T{timing_template}"]


def ports_to_nmap_arg(ports: list[dict], protocol: str | None = None) -> str:
    clean_ports = []

    for port in ports:
        if protocol and port.get("protocol") != protocol:
            continue

        port_id = str(port.get("port", "")).strip()

        if port_id.isdigit():
            clean_ports.append(port_id)

    return ",".join(sorted(set(clean_ports), key=int))


def run_smart_nmap_workflow(
    target: str,
    allowed_host: str,
    report_path: Path | None = None,
    udp_full_scan: bool = True,
    timing_template: int | None = None,
    fast_mode: bool = False,
) -> dict:
    log("[NMAP] Starting smart workflow")

    timing_flags = build_timing_flags(timing_template)

    workflow_results = {
        "tool": "smart_nmap_workflow",
        "target": target,
        "tcp_discovery": None,
        "tcp_service_detection": None,
        "os_detection": None,
        "udp_discovery": None,
        "udp_service_detection": None,
    }

    if should_stop():
        return workflow_results

    # 1. TCP port discovery (skip host discovery with -Pn since we know it's up)
    log("[NMAP] Step 1/5: TCP port discovery" + (" (fast mode)" if fast_mode else " (full scan -p-)"))
    tcp_result = run_nmap_scan(
        target=target,
        allowed_host=allowed_host,
        flags=["-Pn", *timing_flags, "--top-ports", "1000"] if fast_mode else ["-Pn", *timing_flags, "-p-"],
        report_path=report_path,
        timeout_seconds=900,
    )

    workflow_results["tcp_discovery"] = tcp_result

    tcp_open_ports = [
        port for port in tcp_result.get("ports", [])
        if port.get("protocol") == "tcp"
    ]

    tcp_port_arg = ports_to_nmap_arg(tcp_open_ports, protocol="tcp")
    log(f"[NMAP] Found {len(tcp_open_ports)} open TCP ports")

    if should_stop():
        return workflow_results

    # 2. TCP service/version detection only on discovered TCP ports
    if tcp_port_arg:
        log(f"[NMAP] Step 2/5: TCP service detection on ports: {tcp_port_arg}")
        tcp_service_result = run_nmap_scan(
            target=target,
            allowed_host=allowed_host,
            flags=["-sV", *timing_flags, "-p", tcp_port_arg],
            report_path=report_path,
            timeout_seconds=600,
        )

        workflow_results["tcp_service_detection"] = tcp_service_result

    if should_stop():
        return workflow_results

    # 3. OS detection only after TCP open ports exist
    if tcp_port_arg:
        log("[NMAP] Step 3/5: OS detection")
        os_result = run_nmap_scan(
            target=target,
            allowed_host=allowed_host,
            flags=["-O", *timing_flags, "-p", tcp_port_arg],
            report_path=report_path,
            timeout_seconds=600,
        )

        workflow_results["os_detection"] = os_result

    if should_stop():
        return workflow_results

    # 4. UDP discovery last
    udp_flags = ["-sU", *timing_flags]

    if udp_full_scan and not fast_mode:
        udp_flags.extend(["-p-"])
        log("[NMAP] Step 4/5: UDP discovery (full scan -p-) - this may take a while")
    else:
        udp_flags.extend(["--top-ports", "100"])
        log("[NMAP] Step 4/5: UDP discovery (top 100 ports)")

    udp_result = run_nmap_scan(
        target=target,
        allowed_host=allowed_host,
        flags=udp_flags,
        report_path=report_path,
        timeout_seconds=3600,
    )

    workflow_results["udp_discovery"] = udp_result

    udp_open_ports = [
        port for port in udp_result.get("ports", [])
        if port.get("protocol") == "udp"
    ]

    udp_port_arg = ports_to_nmap_arg(udp_open_ports, protocol="udp")
    log(f"[NMAP] Found {len(udp_open_ports)} open UDP ports")

    if should_stop():
        return workflow_results

    # 5. UDP service/version detection only on discovered UDP ports
    if udp_port_arg:
        log(f"[NMAP] Step 5/5: UDP service detection on ports: {udp_port_arg}")
        udp_service_result = run_nmap_scan(
            target=target,
            allowed_host=allowed_host,
            flags=["-sU", "-sV", *timing_flags, "-p", udp_port_arg],
            report_path=report_path,
            timeout_seconds=1200,
        )

        workflow_results["udp_service_detection"] = udp_service_result

    log("[NMAP] Workflow finished")
    return workflow_results