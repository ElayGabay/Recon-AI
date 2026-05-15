from pathlib import Path


MAX_WORDLISTS_PER_RUN = 3


SECLISTS_CATALOG = {
    "directories_and_files": {
        "description": "Directory and file discovery wordlists",
        "wordlists": [
            {
                "name": "dirbuster_medium",
                "relative_path": "Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt",
                "purpose": "Main directory discovery wordlist",
            },
            {
                "name": "raft_large_directories",
                "relative_path": "Discovery/Web-Content/raft-large-directories.txt",
                "purpose": "Large directory discovery wordlist",
            },
        ],
    },

    "subdomains": {
        "description": "Subdomain discovery wordlists",
        "wordlists": [
            {
                "name": "top1million_20000",
                "relative_path": "Discovery/DNS/subdomains-top1million-20000.txt",
                "purpose": "Main subdomain discovery wordlist",
            },
        ],
    },

    "lfi_common": {
        "description": "LFI wordlists that can be used for both Linux and Windows targets",
        "wordlists": [
            {
                "name": "lfi_suite_huge",
                "relative_path": "Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt",
                "purpose": "Common LFI path traversal payloads",
            },
            {
                "name": "lfi_linux_windows_crowdshield",
                "relative_path": "Fuzzing/LFI/LFI-linux-and-windows_by-1N3@CrowdShield.txt",
                "purpose": "Mixed Linux and Windows LFI paths",
            },
        ],
    },

    "lfi_linux": {
        "description": "Linux-specific LFI wordlists",
        "wordlists": [
            {
                "name": "linux_all_packages_etc_files",
                "relative_path": "Fuzzing/LFI/Linux/LFI-etc-files-of-all-linux-packages.txt",
                "purpose": "Linux /etc files from packages",
            },
            {
                "name": "linux_gracefulsecurity",
                "relative_path": "Fuzzing/LFI/Linux/LFI-gracefulsecurity-linux.txt",
                "purpose": "Linux LFI paths",
            },
        ],
    },

    "lfi_windows": {
        "description": "Windows-specific LFI wordlists",
        "wordlists": [
            {
                "name": "windows_payloads_adeadfed",
                "relative_path": "Fuzzing/LFI/Windows/Windows-LFI-Payloads_by-adeadfed.txt",
                "purpose": "Windows LFI payloads",
            },
            {
                "name": "windows_paths",
                "relative_path": "Fuzzing/LFI/Windows/Windows-Paths.txt",
                "purpose": "Windows file paths",
            },
        ],
    },
}


def resolve_seclists_root(seclists_root: str) -> Path:
    """
    Resolve the SecLists root directory from any input path.

    The resolved path **must** contain a directory component named ``SecLists``
    (case-insensitive): either an ancestor of the given path, or a child of the
    given directory. Otherwise raises ``ValueError`` so callers can ask the user
    to supply a proper SecLists tree.
    """
    raw_path = Path(seclists_root).expanduser()
    try:
        raw_path = raw_path.resolve()
    except OSError:
        raw_path = raw_path.absolute()

    candidate = raw_path if raw_path.is_dir() else raw_path.parent

    for parent in [candidate] + list(candidate.parents):
        if parent.name.lower() == "seclists":
            if parent.exists() and parent.is_dir():
                return parent

    if candidate.is_dir():
        try:
            for child in candidate.iterdir():
                if child.name.lower() == "seclists" and child.is_dir():
                    return child.resolve()
        except OSError:
            pass

    raise ValueError("Please enter the SecLists path.")


def get_category_entries(category: str) -> list[dict]:
    if category not in SECLISTS_CATALOG:
        raise ValueError(f"Unknown SecLists category: {category}")

    return SECLISTS_CATALOG[category]["wordlists"]


def get_existing_wordlists(seclists_root: str, category: str) -> list[dict]:
    root = resolve_seclists_root(seclists_root)
    existing = []

    for entry in get_category_entries(category):
        full_path = root / entry["relative_path"]

        if full_path.exists() and full_path.is_file():
            existing.append(
                {
                    "name": entry["name"],
                    "purpose": entry["purpose"],
                    "category": category,
                    "path": full_path,
                    "relative_path": entry["relative_path"],
                }
            )

    return existing


def limit_wordlists(wordlists: list[dict], limit: int = MAX_WORDLISTS_PER_RUN) -> list[dict]:
    return wordlists[:limit]


def get_wordlists_for_mode(seclists_root: str, mode: str) -> list[dict]:
    """
    Supported modes:
    - directories_and_files
    - subdomains
    - lfi_linux
    - lfi_windows
    - lfi_both
    """

    if mode == "directories_and_files":
        return limit_wordlists(
            get_existing_wordlists(seclists_root, "directories_and_files")
        )

    if mode == "subdomains":
        return limit_wordlists(
            get_existing_wordlists(seclists_root, "subdomains")
        )

    if mode == "lfi_linux":
        selected = []
        selected.extend(get_existing_wordlists(seclists_root, "lfi_common"))
        selected.extend(get_existing_wordlists(seclists_root, "lfi_linux"))
        return limit_wordlists(selected)

    if mode == "lfi_windows":
        selected = []
        selected.extend(get_existing_wordlists(seclists_root, "lfi_common"))
        selected.extend(get_existing_wordlists(seclists_root, "lfi_windows"))
        return limit_wordlists(selected)

    if mode == "lfi_both":
        selected = []
        selected.extend(get_existing_wordlists(seclists_root, "lfi_common"))
        selected.extend(get_existing_wordlists(seclists_root, "lfi_linux"))
        selected.extend(get_existing_wordlists(seclists_root, "lfi_windows"))
        return limit_wordlists(selected)

    raise ValueError(f"Unknown mode: {mode}")


def print_available_wordlists(seclists_root: str) -> None:
    print("[+] Checking allowed SecLists wordlists")

    for category, data in SECLISTS_CATALOG.items():
        print(f"\n[+] Category: {category}")
        print(f"    Description: {data['description']}")

        wordlists = get_existing_wordlists(seclists_root, category)

        if not wordlists:
            print("    [!] No matching wordlists found")
            continue

        for item in wordlists:
            print(f"    - {item['name']}")
            print(f"      Path: {item['path']}")
            print(f"      Purpose: {item['purpose']}")


def print_selected_wordlists(wordlists: list[dict]) -> None:
    if not wordlists:
        print("[!] No wordlists selected")
        return

    print(f"[+] Selected wordlists for this run: {len(wordlists)}")

    for item in wordlists:
        print(f"    - {item['name']}: {item['path']}")