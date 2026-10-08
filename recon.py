#!/usr/bin/env python3
"""AI Recon Engine (fixed version).

Collects raw recon data with standard tools. Analysis is left to the AI/human.
Only run this against targets you are authorized to test.
"""

import argparse
import functools
import json
import re
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlparse

BASE_DIR = Path(__file__).resolve().parent

# --- ANSI colors ---
GREEN, RED, YELLOW = "\033[92m", "\033[91m", "\033[93m"
CYAN, BLUE, BOLD, RESET = "\033[96m", "\033[94m", "\033[1m", "\033[0m"


def ts(): return datetime.now().strftime("%H:%M:%S")
def fmt_secs(sec):
    sec = int(sec)
    h, rem = divmod(sec, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m}m {s}s" if h else (f"{m}m {s}s" if m else f"{s}s")


def ok(msg): print(f"{GREEN}[{ts()}] [✓]{RESET} {msg}")
def fail(msg): print(f"{RED}[{ts()}] [✗]{RESET} {msg}")
def info(msg): print(f"{CYAN}[{ts()}] [*]{RESET} {msg}")
def warn(msg): print(f"{YELLOW}[{ts()}] [!]{RESET} {msg}")
def head(msg): print(f"\n{BLUE}{BOLD}[{ts()}] ═══ {msg} ═══{RESET}")


# --- Validation ---
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I
)
URL_RE = re.compile(r"^https?://[A-Za-z0-9._-]+(:\d{1,5})?(/\S*)?$")


def safe_name(value):
    """Turn a URL/host into a safe file name."""
    netloc = urlparse(value).netloc or value
    return re.sub(r"[^A-Za-z0-9._-]", "_", netloc)


# --- Config (optional: not required to run the collectors) ---
def load_config():
    path = BASE_DIR / "config.json"
    if not path.exists():
        warn("config.json not found (optional). Copy config.json.example if you need API keys.")
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        warn(f"config.json is not valid JSON: {e}")
        return {}


# --- Command runner: no shell, stderr kept separate, exit code returned ---
def run_cmd(cmd, out_file=None, stdin_file=None, timeout=None, err_log=None):
    """Run a command as an argument list (no shell). Stream stdout live.

    Returns the exit code (127 if the tool is missing, -9 on timeout).
    """
    info("Running: " + " ".join(cmd))
    started = time.monotonic()
    stdin_fh = open(stdin_file, "r") if stdin_file else None
    out_fh = None
    err_fh = open(err_log, "a") if err_log else subprocess.DEVNULL
    proc = None
    timer = None
    timed_out = threading.Event()
    try:
        if out_file:
            Path(out_file).parent.mkdir(parents=True, exist_ok=True)
            out_fh = open(out_file, "w")
        proc = subprocess.Popen(
            cmd, stdin=stdin_fh, stdout=subprocess.PIPE, stderr=err_fh,
            text=True, bufsize=1,
        )
        if timeout:
            def _kill():
                timed_out.set()
                proc.kill()
            timer = threading.Timer(timeout, _kill)
            timer.start()
        for line in proc.stdout:
            print(line, end="")
            if out_fh:
                out_fh.write(line)
        rc = proc.wait()
        if timed_out.is_set():
            warn(f"Timeout after {timeout}s: {cmd[0]}")
            return -9
        return rc
    except FileNotFoundError:
        fail(f"Tool not found: {cmd[0]}")
        return 127
    except KeyboardInterrupt:
        if proc:
            proc.kill()
        raise
    finally:
        info(f"Finished {cmd[0]} in {fmt_secs(time.monotonic() - started)}")
        if timer:
            timer.cancel()
        if stdin_fh:
            stdin_fh.close()
        if out_fh:
            out_fh.close()
        if err_log and err_fh not in (None, subprocess.DEVNULL):
            err_fh.close()


def has_data(path):
    p = Path(path)
    return p.exists() and p.stat().st_size > 0


def dedupe_file(path):
    p = Path(path)
    if not p.exists():
        return
    lines = {l.strip() for l in p.read_text().splitlines() if l.strip()}
    p.write_text("\n".join(sorted(lines)) + ("\n" if lines else ""))


def read_hosts(path, limit=0):
    """Read live hosts, keeping only well-formed http(s) URLs."""
    if not has_data(path):
        return []
    hosts = []
    for line in Path(path).read_text().splitlines():
        line = line.strip().split(" ")[0]
        if URL_RE.match(line):
            hosts.append(line)
    hosts = sorted(set(hosts))
    return hosts[:limit] if limit else hosts


def find_pd_httpx():
    """Return path to ProjectDiscovery httpx (not the Python httpx CLI)."""
    exe = shutil.which("httpx")
    if not exe:
        return None
    try:
        r = subprocess.run([exe, "-version"], capture_output=True, text=True, timeout=15)
        text = (r.stdout + r.stderr).lower()
    except (OSError, subprocess.TimeoutExpired):
        return None
    return exe if "projectdiscovery" in text else None


def status_from(codes):
    if not codes:
        return "skipped"
    if all(c == 0 for c in codes):
        return "ok"
    if any(c == 0 for c in codes):
        return "partial"
    return "failed"


# =========================== PHASES ===========================
# Every phase takes ctx and returns: ok | partial | failed | skipped | placeholder

def phase_subdomains(ctx):
    if not shutil.which("subfinder"):
        warn("subfinder missing.")
        return "skipped"
    rc = ctx.run(["subfinder", "-d", ctx.target, "-silent"], out_file=ctx.subs)
    dedupe_file(ctx.subs)
    return status_from([rc])


def phase_dns(ctx):
    if not (has_data(ctx.subs) and shutil.which("dnsx")):
        warn("dnsx missing or no subdomains.")
        return "skipped"
    rc = ctx.run(["dnsx", "-silent"], out_file=ctx.dir("02_dns") / "resolved.txt",
                 stdin_file=ctx.subs)
    return status_from([rc])


def phase_live(ctx):
    httpx = find_pd_httpx()
    if not httpx:
        warn("ProjectDiscovery httpx not found (the Python 'httpx' CLI is not the same tool).")
        return "skipped"
    if not has_data(ctx.subs):
        warn("No subdomains.")
        return "skipped"
    rc = ctx.run([httpx, "-silent", "-no-color"], out_file=ctx.live, stdin_file=ctx.subs)
    dedupe_file(ctx.live)
    return status_from([rc])


def phase_http_raw(ctx):
    hosts = read_hosts(ctx.live, ctx.args.max_hosts)
    if not hosts:
        warn("No live hosts.")
        return "skipped"
    codes = []
    for host in hosts:
        out = ctx.dir("04_http_raw") / f"{safe_name(host)}.txt"
        codes.append(ctx.run(
            ["curl", "-sS", "-i", "-m", "15", "--max-filesize", "2000000", "--", host],
            out_file=out))
    return status_from(codes)


def phase_urls(ctx):
    if not shutil.which("gau"):
        warn("gau missing.")
        return "skipped"
    if not has_data(ctx.subs):
        warn("No subdomains.")
        return "skipped"
    # gau expects domains, not full URLs
    rc = ctx.run(["gau", "--threads", "5"], out_file=ctx.urls, stdin_file=ctx.subs)
    dedupe_file(ctx.urls)
    return status_from([rc])


def phase_javascript(ctx):
    if not has_data(ctx.urls):
        warn("No URLs.")
        return "skipped"
    js_re = re.compile(r"\.js(\?|$)", re.I)
    js_urls = [l.strip() for l in ctx.urls.read_text().splitlines() if js_re.search(l)]
    out = ctx.dir("06_javascript") / "js_files.txt"
    out.write_text("\n".join(sorted(set(js_urls))) + ("\n" if js_urls else ""))
    ok(f"{len(set(js_urls))} JS URLs listed (files are not downloaded).")
    return "ok"


def _ffuf_over_hosts(ctx, wordlist_name, out_dir, tag):
    wl = ctx.wl_dir / wordlist_name
    if not shutil.which("ffuf"):
        warn("ffuf missing.")
        return "skipped"
    if not wl.exists():
        warn(f"{wordlist_name} not found.")
        return "skipped"
    hosts = read_hosts(ctx.live, ctx.args.max_hosts)
    if not hosts:
        warn("No live hosts.")
        return "skipped"
    codes = []
    for host in hosts:
        name = safe_name(host)
        codes.append(ctx.run(
            ["ffuf", "-u", f"{host.rstrip('/')}/FUZZ", "-w", str(wl),
             "-rate", str(ctx.args.rate), "-mc", "200,204,301,302,307,401,403",
             "-s", "-of", "json", "-o", str(out_dir / f"{tag}_{name}.json")],
            out_file=out_dir / f"{tag}_{name}.txt"))
    return status_from(codes)


def phase_content(ctx):
    d = ctx.dir("07_content_disc")
    results = [_ffuf_over_hosts(ctx, "common.txt", d, "common"),
               _ffuf_over_hosts(ctx, "sensitive_paths.txt", d, "sensitive")]
    return "ok" if all(r == "ok" for r in results) else (
        "skipped" if all(r == "skipped" for r in results) else "partial")


def phase_params(ctx):
    wl = ctx.wl_dir / "parameters.txt"
    if not (shutil.which("arjun") and has_data(ctx.live) and wl.exists()):
        warn("arjun missing, no live hosts, or parameters.txt not found.")
        return "skipped"
    rc = ctx.run(["arjun", "-i", str(ctx.live), "-w", str(wl)],
                 out_file=ctx.dir("08_params") / "arjun.txt")
    return status_from([rc])


def phase_api(ctx):
    return _ffuf_over_hosts(ctx, "api_endpoints.txt", ctx.dir("09_api"), "api")


def phase_screenshots(ctx):
    if not (shutil.which("gowitness") and has_data(ctx.live)):
        warn("gowitness missing or no live hosts.")
        return "skipped"
    # Verify flags for your version with: gowitness scan file --help
    rc = ctx.run(["gowitness", "scan", "file", "-f", str(ctx.live),
                  "--screenshot-path", str(ctx.dir("10_screenshots"))])
    return status_from([rc])


def phase_nuclei(ctx):
    if not (shutil.which("nuclei") and has_data(ctx.live)):
        warn("nuclei missing or no live hosts.")
        return "skipped"
    rc = ctx.run(["nuclei", "-l", str(ctx.live), "-silent", "-no-color",
                  "-severity", "low,medium,high,critical", "-rl", str(ctx.args.rate)],
                 out_file=ctx.dir("11_nuclei") / "results.txt")
    return status_from([rc])


def _placeholder(folder, instruction):
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "00_README.txt").write_text(
        f"# Data Collection\nInstruction: {instruction}\n"
        "Status: Placeholder - not automated yet.\n")
    return "placeholder"


def phase_intel(ctx):
    return _placeholder(ctx.dir("12_intel"),
                        "Query Shodan/Censys/VT using config.json API keys manually.")


def phase_ssl(ctx):
    if not (shutil.which("testssl.sh") and has_data(ctx.live)):
        warn("testssl.sh missing or no live hosts.")
        return "skipped"
    hosts = [h for h in read_hosts(ctx.live, ctx.args.max_hosts) if h.startswith("https://")]
    if not hosts:
        warn("No https hosts.")
        return "skipped"
    out = ctx.dir("13_ssl") / "ssl_analysis.txt"
    with open(out, "w") as f:
        for host in hosts:
            p = urlparse(host)
            target = f"{p.hostname}:{p.port or 443}"
            f.write(f"\n\n===== SSL Analysis for: {target} =====\n")
            info(f"testssl.sh {target}")
            try:
                r = subprocess.run(["testssl.sh", "--quiet", target],
                                   capture_output=True, text=True, timeout=120)
                f.write(r.stdout + r.stderr)
            except subprocess.TimeoutExpired:
                f.write(f"[!] Timeout for {target}\n")
    return "ok"


def phase_historical(ctx):
    return _placeholder(ctx.dir("14_historical"), "Query SecurityTrails API manually.")


def phase_takeover(ctx):
    if not (shutil.which("subzy") and has_data(ctx.subs)):
        warn("subzy missing or no subdomains.")
        return "skipped"
    rc = ctx.run(["subzy", "run", "--targets", str(ctx.subs), "--hide_fails"],
                 out_file=ctx.dir("15_takeover") / "subzy.txt")
    return status_from([rc])


PHASES = [
    ("01_subdomains", phase_subdomains), ("02_dns", phase_dns),
    ("03_live_hosts", phase_live), ("04_http_raw", phase_http_raw),
    ("05_urls", phase_urls), ("06_javascript", phase_javascript),
    ("07_content_disc", phase_content), ("08_params", phase_params),
    ("09_api", phase_api), ("10_screenshots", phase_screenshots),
    ("11_nuclei", phase_nuclei), ("12_intel", phase_intel),
    ("13_ssl", phase_ssl), ("14_historical", phase_historical),
    ("15_takeover", phase_takeover),
]
EXTRA_FOLDERS = ["_findings", "_reports", "_metadata"]


# --- Database ---
def setup_db():
    conn = sqlite3.connect(BASE_DIR / "bug_bounty.db")  # always next to recon.py
    conn.execute("""CREATE TABLE IF NOT EXISTS scans
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     target TEXT, scan_date TEXT, status TEXT)""")
    conn.commit()
    return conn


# --- AI handover file ---
def write_ai_readme(ctx, statuses):
    lines = [f"# AI Recon Results for {ctx.target}",
             f"Scan Date: {datetime.now(timezone.utc).isoformat()}", "",
             "## Phase status"]
    lines += [f"- `{name}`: {st}" for name, st in statuses.items()]
    lines += ["", "## Files with data"]
    for p in sorted(ctx.results.rglob("*")):
        if p.is_file() and p.stat().st_size > 0 and p.name != "00_README_FOR_AI.md" \
                and "_metadata" not in p.parts:
            lines.append(f"- `{p.relative_to(ctx.results)}`")
    lines += ["", "## AI Instructions",
              "1. Start with `11_nuclei/results.txt` (if present).",
              "2. Check `05_urls/all.txt` for IDOR/XSS/SSRF-prone parameters.",
              "3. Check `07_content_disc/` and `09_api/` JSON files for exposed paths/endpoints.",
              "4. Check `08_params/arjun.txt` for hidden parameters.",
              "5. Phases marked skipped/failed/placeholder have no data: do not assume anything.",
              "6. Write reports into `_reports/`."]
    (ctx.results / "00_README_FOR_AI.md").write_text("\n".join(lines) + "\n")


# --- Main ---
def main():
    home = Path.home()
    extra_path = [str(home / "go" / "bin"), str(home / ".local" / "bin"), "/usr/local/bin"]
    import os
    os.environ["PATH"] = os.pathsep.join(extra_path + [os.environ.get("PATH", "")])

    parser = argparse.ArgumentParser(description="AI Recon Engine - raw data collector")
    parser.add_argument("target_pos", nargs="?", help="Target domain (e.g. example.com)")
    parser.add_argument("--target", "-t", help="Target domain (same as positional)")
    parser.add_argument("--phases", help="Comma list, e.g. 01_subdomains,03_live_hosts")
    parser.add_argument("--max-hosts", type=int, default=20,
                        help="Max live hosts for per-host phases (0 = all). Default 20")
    parser.add_argument("--rate", type=int, default=10,
                        help="Requests/second for ffuf and nuclei. Default 10")
    args = parser.parse_args()

    target = (args.target or args.target_pos or "").strip().lower()
    if not DOMAIN_RE.match(target):
        fail("Invalid or missing target. Use a plain domain like example.com")
        sys.exit(1)

    valid = [n for n, _ in PHASES]
    selected = valid
    if args.phases:
        selected = [p.strip() for p in args.phases.split(",") if p.strip()]
        bad = [p for p in selected if p not in valid]
        if bad:
            fail(f"Unknown phases: {', '.join(bad)}\nValid: {', '.join(valid)}")
            sys.exit(1)

    results = BASE_DIR / "results" / target
    for folder in valid + EXTRA_FOLDERS:
        (results / folder).mkdir(parents=True, exist_ok=True)

    ctx = SimpleNamespace(
        target=target, args=args, results=results, wl_dir=BASE_DIR / "wordlists",
        subs=results / "01_subdomains" / "all.txt",
        live=results / "03_live_hosts" / "live.txt",
        urls=results / "05_urls" / "all.txt",
        dir=lambda name: results / name,
        config=load_config(),
    )
    ctx.run = functools.partial(run_cmd, err_log=results / "_metadata" / "stderr.log")

    head(f"Starting AI Recon Engine for: {target}")
    info(f"Results directory: {results}")
    info(f"Rate limit: {args.rate} req/s | Max hosts per phase: {args.max_hosts or 'all'}")
    warn("Run this only against targets you are authorized to test.")

    conn = setup_db()
    cur = conn.cursor()
    cur.execute("INSERT INTO scans (target, scan_date, status) VALUES (?, ?, ?)",
                (target, datetime.now(timezone.utc).isoformat(), "running"))
    conn.commit()
    scan_id = cur.lastrowid
    ok(f"Database scan ID: {scan_id}")

    statuses = {}
    durations = {}
    final_status = "completed"
    scan_started = time.monotonic()
    to_run = [(n, f) for n, f in PHASES if n in selected]
    try:
        for idx, (name, func) in enumerate(to_run, 1):
            head(f"Phase {idx}/{len(to_run)}: {name}  (total elapsed {fmt_secs(time.monotonic() - scan_started)})")
            phase_started = time.monotonic()
            try:
                statuses[name] = func(ctx)
            except KeyboardInterrupt:
                raise
            except Exception as e:  # one broken phase must not kill the scan
                fail(f"{name} crashed: {e}")
                statuses[name] = "failed"
            durations[name] = time.monotonic() - phase_started
            (ok if statuses[name] == "ok" else warn)(
                f"{name}: {statuses[name]} ({fmt_secs(durations[name])})")
    except KeyboardInterrupt:
        final_status = "interrupted"
        warn("Interrupted by user.")
    except Exception as e:
        final_status = "failed"
        fail(f"Fatal error: {e}")
    finally:
        cur.execute("UPDATE scans SET status = ? WHERE id = ?", (final_status, scan_id))
        conn.commit()
        conn.close()
        write_ai_readme(ctx, statuses)

    head(f"Recon Engine finished ({final_status}) in {fmt_secs(time.monotonic() - scan_started)}")
    for name, st in statuses.items():
        print(f"    {name:<18} {st:<12} {fmt_secs(durations.get(name, 0))}")
    ok(f"Raw data: {results}")
    ok(f"AI handover file: {results / '00_README_FOR_AI.md'}")


if __name__ == "__main__":
    main()
