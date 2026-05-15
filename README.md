# Recon+ AI

Local AI-assisted reconnaissance agent for authorized web security testing, HTB labs, CTF machines, and internal approved targets.

## Requirements

- **Python 3.10+** (3.11+ recommended)
- **ffuf** and **Nmap** — installed automatically by `install.py`, or already on your `PATH`
- **[SecLists](https://github.com/danielmiessler/SecLists)** — clone separately (large; not bundled in this repo)
- **[Ollama](https://ollama.com/)** (optional but required for full auto-recon brain) — install manually; see below

## Quick start

```bash
git clone https://github.com/ElayGabay/Recon-AI.git
cd Recon-AI

# Python venv, pip deps, ffuf + nmap into ./bin/
python install.py

# Wordlists (outside the repo — also listed in .gitignore)
git clone https://github.com/danielmiessler/SecLists.git

# Ollama (not installed by install.py)
# https://ollama.com/download
ollama pull qwen2.5-coder:7b
ollama serve   # if not already running as a service

# Activate venv, then run
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

python fuzzer.py --url http://target.htb/ -W /path/to/SecLists
```

`fuzzer.py` prepends `./bin/` to `PATH`, so tools downloaded by `install.py` are picked up without extra configuration.

### Install options

```bash
python install.py --skip-venv      # only download ffuf/nmap
python install.py --skip-tools     # only venv + pip
```

On **Linux**, if `nmap` is not on `PATH`, the installer tries common package managers (`apt`, `dnf`, `pacman`, …). You may need `sudo apt install nmap` if that fails.

On **Windows**, `install.py` downloads the official Nmap zip into `./bin/nmap.exe`.

## Ollama (manual setup)

Full auto-recon uses a local Ollama model to decide next scans. The installer does **not** install Ollama.

1. Install from [ollama.com](https://ollama.com/download).
2. Pull the default model (must match `app/llm/ollama_client.py`):

   ```bash
   ollama pull qwen2.5-coder:7b
   ```

3. Ensure the API is reachable at `http://localhost:11434` (run `ollama serve` if needed).

Without Ollama, limited modes (`-L`, `--subdomains`, raw ffuf paths) may still work; the orchestrator brain will fail if Ollama is down.

## Usage

### Full auto recon

```bash
python fuzzer.py --url http://monitorsfour.htb/ -W /path/to/SecLists -t 50 -nt 4 --depth 1
```

### Directory allowlist (`--dir`)

Fuzz only paths listed in a file (one path or URL per line). Nmap, vhosts, and probes still run.

```bash
python fuzzer.py --url http://target.htb/ -W /path/to/SecLists -D examples/dir.txt.example
```

See `examples/dir.txt.example`.

### Common arguments

| Argument | Description |
|---|---|
| `--url` | Target URL (required) |
| `-W` / `--wordlists-root` | SecLists root (folder containing `Discovery/`, `Fuzzing/`, etc.) |
| `-D` / `--dir` | File of directory bases to ffuf (allowlist) |
| `-t` / `--threads` | ffuf thread count (default: 50) |
| `--depth` | Recursive dir fuzz depth. Omit = auto. `0` = disabled |
| `-nt` / `--nmap-timing` | Nmap timing template 1–5 |
| `--fast-nmap` | Top ports instead of full `-p-` |
| `--subdomains` | Subdomain/VHost ffuf only, then report |
| `-L` / `--lfi` | LFI triage mode |
| `--cookie` | Cookie header for authenticated scans |
| `-v` / `--verbose` | Internal tool logs |

Run `python fuzzer.py -h` for the full list.

### LFI mode

```bash
python fuzzer.py --url "http://target.htb/index.php?page=FUZZ" -W /path/to/SecLists -L
python fuzzer.py --url "http://target.htb/index.php?page=home" -W /path/to/SecLists -L
```

### Subdomain / VHost only

```bash
python fuzzer.py --url http://target.htb/ -W /path/to/SecLists --subdomains
```

## Runtime commands

While Recon+ is running:

| Command | Action |
|---|---|
| `status` | Task progress |
| `exit` / `q` | Stop gracefully |

## Output

| Path | Contents |
|---|---|
| `app/reports/REPORT.txt` | Live human-readable report |
| `app/reports/findings.jsonl` | Raw evidence (source of truth) |
| `app/data/ffuf/` | ffuf JSON |
| `app/data/nmap/` | Nmap XML |

These directories are created at runtime and ignored by git (see `.gitignore`).

## Project structure

```
AI-Fuzzer-Agent/
├── app/
│   ├── agent/          # Orchestrator, Ollama brain, report writers
│   ├── core/           # Scope, wordlists, output, runtime
│   ├── llm/            # Ollama HTTP client
│   ├── tools/          # ffuf, nmap, probes, param discovery, LFI
│   ├── data/           # Scan artifacts (gitignored)
│   └── reports/        # REPORT.txt, findings.jsonl
├── bin/                # ffuf/nmap from install.py (gitignored)
├── examples/           # Sample --dir file
├── install.py          # Cross-platform setup
├── fuzzer.py           # CLI entry point
└── requirements.txt
```

## Safety

- Scope is enforced: only the target host and its subdomains
- Blocked Nmap flags: `--script`, `-A`, brute/exploit/dos/intrusive scripts
- CVE enrichment uses a local static database only — the model cannot invent CVE IDs
- Use only on targets you are authorized to test

## License

Add your license here before publishing (e.g. MIT).
