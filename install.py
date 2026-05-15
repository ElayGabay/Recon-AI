#!/usr/bin/env python3
"""
Recon+ installer — Python venv, pip deps, ffuf and nmap into ./bin/

Works on Windows and Linux. Does NOT install Ollama (see README.md).

Usage:
  python install.py
  python install.py --skip-venv
  python install.py --skip-tools
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BIN_DIR = ROOT / "bin"
VENV_DIR = ROOT / ".venv"
REQUIREMENTS = ROOT / "requirements.txt"

FFUF_REPO = "ffuf/ffuf"
# Fallback if GitHub API is unavailable
FFUF_FALLBACK_VERSION = "2.1.0"

# Windows portable Nmap (official). Version pinned for reproducible installs.
NMAP_WIN_VERSION = "7.95"
NMAP_WIN_ZIP_URL = f"https://nmap.org/dist/nmap-{NMAP_WIN_VERSION}-win.zip"


def _print(msg: str) -> None:
    print(msg, flush=True)


def _ok(msg: str) -> None:
    _print(f"[+] {msg}")


def _warn(msg: str) -> None:
    _print(f"[!] {msg}")


def _fail(msg: str) -> None:
    _print(f"[ERROR] {msg}")


def check_python() -> None:
    if sys.version_info < (3, 10):
        _fail(f"Python 3.10+ required (found {sys.version.split()[0]})")
        sys.exit(1)
    _ok(f"Python {sys.version.split()[0]}")


def machine() -> tuple[str, str]:
    """Return (os_name, arch) with arch in {amd64, arm64, 386}."""
    os_name = sys.platform
    m = platform.machine().lower()
    if m in {"x86_64", "amd64", "x64"}:
        arch = "amd64"
    elif m in {"aarch64", "arm64"}:
        arch = "arm64"
    elif m in {"i386", "i686", "x86"}:
        arch = "386"
    else:
        arch = "amd64"
    return os_name, arch


def which(cmd: str) -> str | None:
    return shutil.which(cmd)


def tool_available(name: str) -> bool:
    if which(name):
        return True
    ext = ".exe" if sys.platform == "win32" else ""
    local = BIN_DIR / f"{name}{ext}"
    return local.is_file()


def download_url(url: str, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    _print(f"    Downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "ReconPlus-Installer/1.0"})
    with urllib.request.urlopen(req, timeout=300) as resp, open(dest, "wb") as out:
        shutil.copyfileobj(resp, out)


def github_latest_ffuf_asset(os_name: str, arch: str) -> tuple[str, str] | None:
    """Return (version_tag, download_url) for this platform."""
    api = f"https://api.github.com/repos/{FFUF_REPO}/releases/latest"
    try:
        req = urllib.request.Request(api, headers={"Accept": "application/vnd.github+json"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = json.load(resp)
    except Exception as exc:
        _warn(f"Could not query GitHub releases: {exc}")
        return None

    tag = (data.get("tag_name") or "").lstrip("v")
    assets = data.get("assets") or []

    if os_name == "win32":
        patterns = [f"windows_{arch}", "windows_amd64"]
        exts = (".zip",)
    else:
        patterns = [f"linux_{arch}", "linux_amd64"]
        exts = (".tar.gz", ".tgz")

    for pattern in patterns:
        for asset in assets:
            name = (asset.get("name") or "").lower()
            url = asset.get("browser_download_url") or ""
            if pattern in name and name.endswith(exts) and url:
                return tag, url
    return None


def install_ffuf() -> bool:
    if tool_available("ffuf"):
        _ok(f"ffuf already available ({which('ffuf') or BIN_DIR / 'ffuf.exe'})")
        return True

    osn, arch = machine()
    meta = github_latest_ffuf_asset(osn, arch)
    if not meta:
        ver = FFUF_FALLBACK_VERSION
        if osn == "win32":
            url = f"https://github.com/ffuf/ffuf/releases/download/v{ver}/ffuf_{ver}_windows_{arch}.zip"
        else:
            url = f"https://github.com/ffuf/ffuf/releases/download/v{ver}/ffuf_{ver}_linux_{arch}.tar.gz"
        _warn(f"Using fallback ffuf v{ver}")
    else:
        ver, url = meta
        _ok(f"Latest ffuf release: v{ver}")

    BIN_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / ("ffuf.zip" if url.endswith(".zip") else "ffuf.tar.gz")
        try:
            download_url(url, archive)
        except Exception as exc:
            _fail(f"ffuf download failed: {exc}")
            return False

        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as zf:
                zf.extractall(tmp_path)
        else:
            with tarfile.open(archive, "r:gz") as tf:
                tf.extractall(tmp_path)

        binary_name = "ffuf.exe" if osn == "win32" else "ffuf"
        found = list(tmp_path.rglob(binary_name))
        if not found:
            _fail("ffuf binary not found inside archive")
            return False

        dest = BIN_DIR / binary_name
        shutil.copy2(found[0], dest)
        if osn != "win32":
            dest.chmod(dest.stat().st_mode | 0o111)

    _ok(f"ffuf installed to {dest}")
    return True


def install_nmap_windows() -> bool:
    if tool_available("nmap"):
        _ok(f"nmap already available ({which('nmap') or BIN_DIR / 'nmap.exe'})")
        return True

    BIN_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / "nmap.zip"
        try:
            download_url(NMAP_WIN_ZIP_URL, archive)
        except Exception as exc:
            _fail(f"nmap download failed: {exc}")
            _warn("Install manually from https://nmap.org/download.html")
            return False

        with zipfile.ZipFile(archive) as zf:
            zf.extractall(tmp_path)

        found = list(tmp_path.rglob("nmap.exe"))
        if not found:
            _fail("nmap.exe not found inside Nmap zip")
            return False

        dest = BIN_DIR / "nmap.exe"
        shutil.copy2(found[0], dest)

    _ok(f"nmap installed to {dest}")
    return True


def install_nmap_linux() -> bool:
    if tool_available("nmap"):
        _ok(f"nmap already available ({which('nmap')})")
        return True

    # Try common package managers without sudo first (user may have passwordless apt)
    installers = [
        (["apt-get", "install", "-y", "nmap"], "apt"),
        (["dnf", "install", "-y", "nmap"], "dnf"),
        (["yum", "install", "-y", "nmap"], "yum"),
        (["pacman", "-S", "--noconfirm", "nmap"], "pacman"),
        (["zypper", "install", "-y", "nmap"], "zypper"),
    ]
    for cmd, name in installers:
        if not shutil.which(cmd[0]):
            continue
        _print(f"    Trying: {' '.join(cmd)}")
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if r.returncode == 0 and tool_available("nmap"):
                _ok(f"nmap installed via {name}")
                return True
        except Exception:
            continue

    _warn("nmap not found and automatic install failed (may need sudo).")
    _warn("Run one of:")
    _warn("  sudo apt install nmap        # Debian/Ubuntu")
    _warn("  sudo dnf install nmap        # Fedora")
    _warn("  sudo pacman -S nmap          # Arch")
    return False


def install_nmap() -> bool:
    if sys.platform == "win32":
        return install_nmap_windows()
    return install_nmap_linux()


def create_venv() -> bool:
    if VENV_DIR.exists() and (
        (VENV_DIR / "Scripts" / "python.exe").exists() or (VENV_DIR / "bin" / "python").exists()
    ):
        _ok(f"Virtual environment exists: {VENV_DIR}")
        return True

    _print("    Creating virtual environment...")
    try:
        subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
    except subprocess.CalledProcessError as exc:
        _fail(f"venv creation failed: {exc}")
        return False
    _ok(f"Created {VENV_DIR}")
    return True


def venv_python() -> Path:
    if sys.platform == "win32":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def pip_install() -> bool:
    py = venv_python()
    if not py.is_file():
        _fail("venv Python not found; run without --skip-venv")
        return False
    _print("    Installing Python dependencies...")
    try:
        subprocess.run(
            [str(py), "-m", "pip", "install", "--upgrade", "pip"],
            check=True,
            cwd=ROOT,
        )
        subprocess.run(
            [str(py), "-m", "pip", "install", "-r", str(REQUIREMENTS)],
            check=True,
            cwd=ROOT,
        )
    except subprocess.CalledProcessError as exc:
        _fail(f"pip install failed: {exc}")
        return False
    _ok("Python dependencies installed")
    return True


def ensure_project_dirs() -> None:
    (ROOT / "app" / "reports").mkdir(parents=True, exist_ok=True)
    (ROOT / "app" / "data" / "ffuf").mkdir(parents=True, exist_ok=True)
    (ROOT / "app" / "data" / "nmap").mkdir(parents=True, exist_ok=True)
    keep = ROOT / "app" / "reports" / ".gitkeep"
    if not keep.exists():
        keep.touch()
    _ok("Project directories ready")


def write_path_hint() -> None:
    hint = BIN_DIR / "README.txt"
    if BIN_DIR.exists() and not hint.exists():
        hint.write_text(
            "ffuf and nmap binaries installed by install.py.\n"
            "fuzzer.py prepends this folder to PATH automatically.\n",
            encoding="utf-8",
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Install Recon+ dependencies and tools")
    parser.add_argument("--skip-venv", action="store_true", help="Skip venv and pip")
    parser.add_argument("--skip-tools", action="store_true", help="Skip ffuf/nmap download")
    args = parser.parse_args()

    _print("")
    _print("Recon+ installer")
    _print("================")
    _print("")

    check_python()
    ensure_project_dirs()

    ok = True
    if not args.skip_venv:
        ok = create_venv() and ok
        ok = pip_install() and ok
    else:
        _warn("Skipping Python venv / pip")

    if not args.skip_tools:
        ok = install_ffuf() and ok
        ok = install_nmap() and ok
        write_path_hint()
    else:
        _warn("Skipping ffuf / nmap")

    _print("")
    if ok:
        _ok("Installation finished.")
        _print("")
        _print("Next steps:")
        _print("  1. Clone SecLists:  git clone https://github.com/danielmiessler/SecLists.git")
        _print("  2. Install Ollama + model (see README.md — not covered by this script)")
        _print("  3. Activate venv:")
        if sys.platform == "win32":
            _print("       .venv\\Scripts\\activate")
        else:
            _print("       source .venv/bin/activate")
        _print("  4. Run:  python fuzzer.py --url http://target/ -W /path/to/SecLists")
    else:
        _warn("Installation completed with errors — see messages above.")
        return 1
    _print("")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
