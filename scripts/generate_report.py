#!/usr/bin/env python3
# scripts/generate_report.py
import argparse
import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET_RE = re.compile(r"^[A-Za-z0-9.-]+$")


def generate_report(scan_id):
    db_path = ROOT / "bug_bounty.db"
    if not db_path.exists():
        print("[✗] Database not found! Run recon.py first.")
        return 1

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        scan = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan:
            print(f"[✗] Scan ID {scan_id} not found in database.")
            return 1
        hosts = conn.execute("SELECT * FROM hosts WHERE scan_id=?", (scan_id,)).fetchall()
    finally:
        conn.close()

    target = scan["target"]
    if not TARGET_RE.match(target):
        print("[✗] Refusing to write report: suspicious target name in DB.")
        return 1

    target_dir = ROOT / "results" / target
    report_dir = target_dir / "_reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_file = report_dir / f"scan_{scan_id}_report.md"

    nuclei = target_dir / "11_nuclei" / "results.txt"
    nuclei_lines = nuclei.read_text().splitlines() if nuclei.exists() else []

    with open(report_file, "w") as f:
        f.write(f"# Bug Bounty Report - Scan #{scan_id}\n")
        f.write(f"**Target:** {target}\n")
        f.write(f"**Started:** {scan['started_at']}\n")
        f.write(f"**Finished:** {scan['finished_at']}\n")
        f.write(f"**Status:** {scan['status']}\n")
        if scan["notes"]:
            f.write(f"**Phases:** {scan['notes']}\n")
        f.write("\n## Live Hosts Discovered\n")
        if hosts:
            f.write("| Hostname | IP | Status | Title | Tech |\n|---|---|---|---|---|\n")
            for h in hosts:
                title = (h["title"] or "").replace("|", "/")
                f.write(f"| {h['hostname']} | {h['ip'] or ''} | {h['status_code'] or ''} | "
                        f"{title} | {h['tech'] or ''} |\n")
        else:
            f.write("_No hosts stored for this scan._\n")
        f.write(f"\n## Nuclei\n{len(nuclei_lines)} result line(s) in `11_nuclei/results.txt`.\n")
        f.write("\n## AI Findings\n")
        f.write("*Review `_findings/` and paste your **manually verified** findings here.*\n")

    print(f"[✓] Report generated at: {report_file}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Markdown Report")
    parser.add_argument("--scan-id", type=int, required=True, help="Database Scan ID")
    sys.exit(generate_report(parser.parse_args().scan_id))
