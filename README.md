# AI Recon Engine

**The terminal collects raw recon data. An AI assistant (or you) does the analysis.**

Only test targets you are authorized to test (in scope of a bug bounty / VDP, or your own).

## How it works

```
recon.py  ->  results/<target>/  ->  AI / you analyse  ->  _findings/ + _reports/
```

`recon.py` runs up to 15 collection phases with standard tools, saves raw output, and writes
`results/<target>/00_README_FOR_AI.md` (phase status + the files that actually contain data).

## Setup

```bash
bash install.sh          # Go tools, pipx tools, testssl, nuclei templates
source ~/.bashrc
```

`config.json` is optional (only for future API-key phases). Copy `config.json.example` if you need it.

## Usage

```bash
python3 recon.py example.com                      # all phases
python3 recon.py --target example.com --phases 01_subdomains,03_live_hosts
python3 recon.py example.com --max-hosts 50 --rate 5
bash scripts/generate_report.sh --scan-id 1       # markdown report from the DB
```

| Option | Default | Meaning |
|---|---|---|
| `--phases` | all | comma list of phase folder names |
| `--max-hosts` | 20 | live hosts used by per-host phases (0 = all) |
| `--rate` | 10 | requests/second for ffuf and nuclei |

## Phases

| # | Phase | Tool |
|---|---|---|
| 01 | Subdomains | subfinder |
| 02 | DNS | dnsx |
| 03 | Live hosts (status/title/tech/IP saved to DB) | httpx (ProjectDiscovery) |
| 04 | Raw HTTP headers + body | curl |
| 05 | URLs | gau |
| 06 | JavaScript URL list | built-in filter |
| 07 | Content discovery | ffuf |
| 08 | Parameters | arjun |
| 09 | API paths | ffuf |
| 10 | Screenshots | gowitness |
| 11 | Vulnerability templates | nuclei |
| 12 | Intel (Shodan/Censys/VT) | placeholder, not automated |
| 13 | SSL | testssl |
| 14 | Historical (SecurityTrails) | placeholder, not automated |
| 15 | Takeover | subzy |

Missing tools only skip their phase. Per-tool errors go to `results/<target>/_metadata/stderr.log`.

## Output

```
results/<target>/
├── 00_README_FOR_AI.md     <- start here
├── 01_subdomains/ ... 15_takeover/
├── _findings/   _reports/   _metadata/
```

Scan history lives in `bug_bounty.db` (local only, git-ignored).

## License
MIT
