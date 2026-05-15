import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

QUIET_MODE = True
VERBOSE_MODE = False

# Force UTF-8 on Windows so block-drawing characters in the banner render correctly
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

console_obj = Console()


def log(message: str) -> None:
    """
    Internal debug/work logs.
    Hidden by default unless VERBOSE_MODE is enabled.
    """
    if VERBOSE_MODE or not QUIET_MODE:
        console_obj.print(message)


def info(message: str) -> None:
    """
    Important info messages.
    Always visible even in quiet mode.
    """
    console_obj.print(f"[cyan][+][/cyan] {message}")


def warning(message: str) -> None:
    """
    Warning messages.
    Always visible.
    """
    console_obj.print(f"[yellow][!][/yellow] {message}")


def error(message: str) -> None:
    """
    Error messages.
    Always visible.
    """
    console_obj.print(f"[red][ERROR][/red] {message}")


def success(message: str) -> None:
    """
    Success messages.
    Always visible.
    """
    console_obj.print(f"[green][+][/green] {message}")


def console(message: str = "", style: str | None = None) -> None:
    """
    User-facing terminal output.
    Always visible.
    """
    if style:
        console_obj.print(message, style=style)
    else:
        console_obj.print(message)


def set_verbose(enabled: bool) -> None:
    global VERBOSE_MODE
    VERBOSE_MODE = enabled


def show_status(tasks: dict) -> None:
    """
    Display status table for running tasks.
    """
    table = Table(title="Task Status", show_header=True, header_style="bold cyan")
    table.add_column("Task", style="white")
    table.add_column("Status", style="white")
    
    for name, status in tasks.items():
        if status == "running":
            style = "yellow"
        elif status == "done":
            style = "green"
        elif status == "failed":
            style = "red"
        else:
            style = "white"
        
        table.add_row(name, f"[{style}]{status}[/{style}]")
    
    console_obj.print(table)


def banner(report_path: str, *, show_stop_hint: bool = True) -> None:
    ascii_logo = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗      ██████╗ ██╗     ██╗   ██╗███████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║      ██╔══██╗██║     ██║   ██║██╔════╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║█████╗██████╔╝██║     ██║   ██║███████╗
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║╚════╝██╔═══╝ ██║     ██║   ██║╚════██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║      ██║     ███████╗╚██████╔╝███████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝      ╚═╝     ╚══════╝ ╚═════╝ ╚══════╝
"""

    subtitle = Text()
    subtitle.append("For results go to:\n", style="bold white")
    subtitle.append(report_path, style="green")
    if show_stop_hint:
        subtitle.append("\n\nTo stop the script type: ", style="bold white")
        subtitle.append("exit", style="bold red")
        subtitle.append(" / ", style="white")
        subtitle.append("q", style="bold red")

    try:
        console_obj.print()
        console_obj.print(Text(ascii_logo, style="bold cyan"))
        console_obj.print(
            Panel(
                subtitle,
                title=Text("Recon+", style="bold cyan"),
                border_style="cyan",
                padding=(1, 2),
            )
        )
        console_obj.print()
    except UnicodeEncodeError:
        # Fallback for terminals that cannot render Unicode block characters
        console_obj.print()
        console_obj.print("[bold cyan]  RECON+  —  AI Recon Agent[/bold cyan]")
        console_obj.print()
        console_obj.print(subtitle)
        console_obj.print()


def print_nmap_port(
    port: str,
    protocol: str,
    state: str,
    service: str,
    product: str,
    version: str,
) -> None:
    """
    Print a single nmap port result:

      port 80/tcp    open   nginx 1.18.0
      port 5985/tcp  open   Microsoft HTTPAPI httpd 2.0

    - Port label : yellow
    - State      : green (open) / dim (filtered/closed)
    - Service    : white  — shows product + version if available, service name otherwise
    - No "version" word ever appears on screen
    """
    port_label = f"port {port}/{protocol}"

    # Build service string: prefer product (+ version) over raw service name
    svc_parts: list[str] = []
    if product:
        svc_parts.append(product)
        if version:
            svc_parts.append(version)
    elif service:
        svc_parts.append(service)
    svc_str = " ".join(svc_parts)

    state_style = "bold green" if state == "open" else "dim"

    port_col  = f"[bold yellow]{port_label:<16}[/bold yellow]"
    state_col = f"[{state_style}]{state:<8}[/{state_style}]"
    svc_col   = f"[white]{svc_str}[/white]" if svc_str else ""

    console_obj.print(f"  {port_col}  {state_col}  {svc_col}")


def print_probe_finding(kind: str, url: str, detail: str) -> None:
    """
    One-line probe finding: tag | shortened URL | detail (pentester-focused).
    """

    def _short(u: str, max_len: int = 44) -> str:
        u = u.strip()
        if len(u) <= max_len:
            return u
        half = (max_len - 1) // 2
        return u[:half] + "…" + u[-half:]

    tags: dict[str, tuple[str, str, str]] = {
        "version": ("STACK", "yellow", "yellow"),
        "lfi":     (" LFI", "bold red", "red"),
        "param":   ("PARAM", "bold white", "white"),
        "email":   ("EMAIL", "bold cyan", "cyan"),
        "secret":  (" LEAK", "bold red", "red"),
        "os":      (" HOST", "bold magenta", "magenta"),
    }
    tag, tag_style, detail_style = tags.get(kind, ("PROBE", "white", "white"))
    su = _short(url)
    console_obj.print(
        f"  [bold {tag_style}]{tag}[/bold {tag_style}]  "
        f"[dim white]{su:<44}[/dim white]  "
        f"[{detail_style}]{detail}[/{detail_style}]"
    )


def prompt_text() -> str:
    return "[bold cyan]recon+>[/bold cyan] "


def _status_style(status: int) -> str:
    if status in {200, 204}:
        return "bold green"
    if status in {301, 302, 307, 308}:
        return "bold yellow"
    if status in {401, 403}:
        return "bold dark_orange"
    if status == 500:
        return "bold red"
    return "white"


def print_ffuf_finding(
    kind: str,           # "DIR", "FILE", "VHOST"
    fuzz_value: str,
    status: int,
    size: int | None,
    words: int | None,
    lines: int | None,
    full_url: str = "",
) -> None:
    """
    Print a single ffuf finding:

      dir    http://target/login                  [Status: 200, Size: 4340, Words: 1342, Lines: 96]
      file   http://target/config.php             [Status: 200, Size: 512, Words: 34, Lines: 8]
      sub    cacti.target.htb                     [Status: 200, Size: 5432, Words: 256, Lines: 78]

    Colors: dir=blue  sub=orange  file=white   status follows HTTP class.
    """
    kind_map = {
        "DIR":  ("dir ",  "bold cyan"),
        "FILE": ("file",  "bold white"),
        "VHOST":("sub ",  "bold dark_orange"),
    }
    label_text, url_style = kind_map.get(kind, ("??? ", "white"))

    # For VHOST, fuzz_value already IS the full hostname; for DIR/FILE use full_url.
    display_url = full_url if kind in {"DIR", "FILE"} else fuzz_value

    parts: list[str] = [f"Status: {status}"]
    if size  is not None: parts.append(f"Size: {size}")
    if words is not None: parts.append(f"Words: {words}")
    if lines is not None: parts.append(f"Lines: {lines}")
    meta = ", ".join(parts)

    label_col = f"[{url_style}]{label_text}[/{url_style}]"
    url_col   = f"[{url_style}]{display_url:<50}[/{url_style}]"
    meta_col  = f"[bold green][{meta}][/bold green]"

    console_obj.print(f"  {label_col}  {url_col}  {meta_col}")