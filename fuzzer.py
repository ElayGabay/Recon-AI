import argparse
import os
from pathlib import Path


def _prepend_local_bin() -> None:
    """Use ffuf/nmap from ./bin/ when install.py downloaded them."""
    bin_dir = Path(__file__).resolve().parent / "bin"
    if bin_dir.is_dir():
        prefix = str(bin_dir)
        path = os.environ.get("PATH", "")
        if prefix not in path.split(os.pathsep):
            os.environ["PATH"] = prefix + os.pathsep + path


_prepend_local_bin()
from urllib.parse import urlparse, parse_qs

from app.agent.orchestrator import ReconOrchestrator
from app.agent.report_writer import OllamaReportWriter
from app.core.report_manager import ReportManager
from app.core.scope_guard import ScopeGuard
from app.core.seclists_catalog import resolve_seclists_root
from app.core.http_cookie import normalize_cookie_arg
from app.core.output import banner, log, info, success, set_verbose, error
from app.core.stop_control import reset_stop


LFI_SUSPICIOUS_PARAMS = {
    "file", "path", "page", "template", "include", "inc",
    "view", "document", "doc", "folder", "load", "read",
}


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Preserve epilog / description line breaks in -h output."""


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Recon+ — AI web recon for authorized targets only.\n"
            "Default: full auto-recon (nmap, vhosts, directory fuzz, probes, Ollama brain)."
        ),
        formatter_class=_HelpFormatter,
        epilog=(
            "examples:\n"
            "  python fuzzer.py --url http://lab/ -W C:/SecLists\n"
            "  python fuzzer.py --url http://lab/ -W C:/SecLists -D paths.txt --cookie \"sid=abc\"\n"
            "  python fuzzer.py --url http://lab/ -W C:/SecLists --depth 0 -nt 5 --fast-nmap\n"
            "  python fuzzer.py --url \"http://lab/p.php?f=FUZZ\" -W C:/SecLists -L\n"
            "  python fuzzer.py --url http://lab/ -W C:/SecLists --subdomains"
        ),
    )

    required = parser.add_argument_group("required")
    required.add_argument(
        "--url",
        required=True,
        metavar="URL",
        help="target base URL",
    )
    required.add_argument(
        "-W",
        "--wordlists-root",
        required=True,
        metavar="DIR",
        help="SecLists root (folder must contain a SecLists directory)",
    )

    modes = parser.add_argument_group(
        "mode (pick one; omit all for full auto-recon)"
    )
    modes.add_argument(
        "-L",
        "--lfi",
        action="store_true",
        help="LFI triage only (URL needs FUZZ or query params)",
    )
    modes.add_argument(
        "--subdomains",
        action="store_true",
        help="vhost/subdomain ffuf only, then report",
    )
    modes.add_argument(
        "-D",
        "--dir",
        dest="dir_targets_file",
        default=None,
        metavar="FILE",
        help=(
            "dir ffuf only on paths listed in FILE (one path/URL per line); "
            "nmap/vhosts/probes still run. Not with -L or --subdomains."
        ),
    )

    tuning = parser.add_argument_group("scan tuning")
    tuning.add_argument(
        "--depth",
        type=int,
        default=None,
        metavar="N",
        help="max extra path depth for recursive ffuf_dirs (0=off, default=unlimited)",
    )
    tuning.add_argument(
        "-t",
        "--threads",
        type=int,
        default=50,
        metavar="N",
        help="ffuf / LFI threads (default: %(default)s)",
    )
    tuning.add_argument(
        "-nt",
        "--nmap-timing",
        type=int,
        choices=[1, 2, 3, 4, 5],
        default=None,
        metavar="N",
        help="nmap -T1..-T5 (default: T4 if omitted)",
    )
    tuning.add_argument(
        "--fast-nmap",
        action="store_true",
        help="port discovery: --top-ports 1000 instead of -p-",
    )

    session = parser.add_argument_group("session")
    session.add_argument(
        "--cookie",
        default=None,
        metavar="VALUE",
        help="Cookie for ffuf/probes/LFI (name=value or bare token; not logged)",
    )

    output = parser.add_argument_group("output")
    output.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="verbose tool and agent logs",
    )

    return parser.parse_args()


def validate_mode(args):
    dfile = getattr(args, "dir_targets_file", None)
    if dfile and args.lfi:
        raise ValueError("Cannot use --dir (or -D) together with -L / --lfi.")
    if dfile and args.subdomains:
        raise ValueError("Cannot use --dir (or -D) together with --subdomains.")
    if dfile:
        return

    if args.lfi:
        has_fuzz = "FUZZ" in args.url
        has_params = bool(parse_qs(urlparse(args.url).query))
        if not has_fuzz and not has_params:
            raise ValueError(
                "LFI mode requires FUZZ in the URL or a URL with query parameters.\n"
                "  Examples:\n"
                "    http://site.com/page.php?file=FUZZ\n"
                "    http://site.com/index.php?page=home"
            )
    if not args.lfi and "FUZZ" in args.url:
        raise ValueError("FUZZ found in URL but -L was not used. Add -L for LFI mode.")


def main():
    args = parse_args()
    validate_mode(args)
    reset_stop()

    if args.verbose:
        set_verbose(True)

    try:
        seclists_root = resolve_seclists_root(args.wordlists_root)
    except ValueError as exc:
        error(str(exc) if str(exc) else "Please enter the SecLists path.")
        raise SystemExit(1) from exc
    guard = ScopeGuard(args.url)
    target = guard.require_allowed(args.url)

    report_path = Path("app") / "reports" / "REPORT.txt"
    banner(str(report_path.resolve()))

    log("[+] Recon+ started")
    log(f"[+] Target: {target}")
    log(f"[+] Allowed host: {guard.allowed_host}")
    log(f"[+] SecLists: {seclists_root}")
    if normalize_cookie_arg(args.cookie):
        log("[+] Cookie header enabled for HTTP tools (value not logged).")

    report_manager = ReportManager(report_path.parent)
    report_manager.reset(target)

    # LFI-only mode: direct LFI triage, no full recon
    if args.lfi:
        from app.tools.lfi_tester import lfi_triage
        from app.core.seclists_catalog import get_wordlists_for_mode

        info("Mode: LFI testing")
        lfi_wordlists = get_wordlists_for_mode(str(seclists_root), "lfi_both")
        if not lfi_wordlists:
            raise FileNotFoundError("No LFI wordlists found in SecLists.")

        wordlist_paths = [item["path"] for item in lfi_wordlists]
        info(f"LFI wordlists: {len(wordlist_paths)}")

        try:
            results = lfi_triage(
                target_url=args.url,
                wordlist_paths=wordlist_paths,
                concurrency=args.threads,
                report_path=report_path,
                cookie=args.cookie,
            )
        except KeyboardInterrupt:
            info("LFI triage interrupted.")
            results = []

        info(f"LFI confirmed: {len(results)}")
        info("Writing report...")
        OllamaReportWriter(report_path.parent).write_report()
        success(f"Report: {report_path.resolve()}")
        return

    # Subdomain-only mode: single ffuf vhost scan, then report
    if args.subdomains:
        from app.tools.ffuf_runner import run_ffuf_vhost
        from app.core.seclists_catalog import get_wordlists_for_mode
        from app.core.runtime_controller import RuntimeController
        import queue as stdlib_queue, threading

        info("Mode: Subdomain / VHost discovery")
        subdomain_wordlists = get_wordlists_for_mode(str(seclists_root), "subdomains")
        if not subdomain_wordlists:
            raise FileNotFoundError("No subdomain wordlists found in SecLists.")

        wordlist = subdomain_wordlists[0]["path"]
        ctrl = RuntimeController(max_workers=1)
        future = ctrl.submit(
            "ffuf_vhosts",
            run_ffuf_vhost,
            target,
            wordlist,
            args.threads,
            report_path,
            True,
            args.cookie,
        )

        from app.core.output import console
        console("Subdomain scan running. Type 'status' or 'exit'.", "bold green")

        cmd_q: stdlib_queue.Queue = stdlib_queue.Queue()
        stop_ev = threading.Event()

        def _reader():
            while not stop_ev.is_set():
                try:
                    cmd_q.put(input("recon+> ").strip().lower())
                except EOFError:
                    break

        threading.Thread(target=_reader, daemon=True).start()

        try:
            while True:
                try:
                    cmd = cmd_q.get(timeout=1.0)
                    if cmd in {"stop", "exit", "quit", "q"}:
                        break
                    if cmd in {"status", "s"}:
                        ctrl.status()
                except stdlib_queue.Empty:
                    pass
                if future.done():
                    info("Subdomain scan complete.")
                    break
        except KeyboardInterrupt:
            pass
        finally:
            stop_ev.set()

        results = future.result() if future.done() else []
        info(f"Subdomain / VHost findings: {len(results)}")
        info("Writing report...")
        OllamaReportWriter(report_path.parent).write_report()
        success(f"Report: {report_path.resolve()}")
        ctrl.stop()
        return

    # Optional --dir file: attach bases to args; full recon uses them for main-host ffuf only
    if getattr(args, "dir_targets_file", None):
        from app.core.dir_targets_file import load_directory_fuzz_targets

        list_path = Path(args.dir_targets_file).expanduser()
        if not list_path.is_file():
            raise FileNotFoundError(f"Directory list file not found: {list_path}")
        bases = load_directory_fuzz_targets(list_path, args.url, guard)
        if not bases:
            raise ValueError(
                f"No usable directory lines in {list_path}. "
                "Use paths like robots, /admin/user, or full http(s) URLs on the allowed host."
            )
        args.dir_ffuf_bases = bases
        log(f"[+] --dir: {len(bases)} fuzz base(s) from {list_path.name}")

    # Full auto-recon mode: Ollama brain drives everything
    info("Mode: Full auto-recon (Ollama brain)")
    orchestrator = ReconOrchestrator(
        target=target,
        guard=guard,
        seclists_root=seclists_root,
        args=args,
        report_path=report_path,
    )
    orchestrator.run()


if __name__ == "__main__":
    main()
