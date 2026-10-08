#!/usr/bin/env python3
# scripts/generate_report.py
import argparse
import sqlite3
from pathlib import Path

def generate_report(scan_id):
    db_path = Path(__file__).parent.parent / "bug_bounty.db"
    if not db_path.exists():
        print("[✗] Database not found!")
        return

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans WHERE id=?", (scan_id,))
    scan = cursor.fetchone()
    if not scan:
        print(f"[✗] Scan ID {scan_id} not found in database.")
        return

    cursor.execute("SELECT * FROM hosts WHERE scan_id=?", (scan_id,))
    hosts = cursor.fetchall()

    report_dir = Path(__file__).parent.parent / "results" / "_reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_file = report_dir / f"scan_{scan_id}_report.md"

    with open(report_file, "w") as f:
        f.write(f"# Bug Bounty Report - Scan #{scan_id}\n")
        f.write(f"**Target:** {scan['target']}\n")
        f.write(f"**Date:** {scan['started_at']}\n")
        f.write(f"**Status:** {scan['status']}\n\n")
        
        f.write("## Live Hosts Discovered\n")
        f.write("| Hostname | IP | Status | Title | Tech |\n")
        f.write("|---|---|---|---|---|\n")
        for h in hosts:
            f.write(f"| {h['hostname']} | {h['ip']} | {h['status_code']} | {h['title']} | {h['tech']} |\n")
        
        f.write("\n## AI Findings\n")
        f.write("*Note: Please review the `_findings/` directory and paste your verified findings here.*\n")

    print(f"[✓] Report generated at: {report_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Markdown Report")
    parser.add_argument("--scan-id", type=int, required=True, help="Database Scan ID")
    args = parser.parse_args()
    generate_report(args.scan_id)
