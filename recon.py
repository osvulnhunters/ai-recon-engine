#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
import sqlite3

# --- ANSI Color Codes ---
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
BLUE = '\033[94m'
BOLD = '\033[1m'
RESET = '\033[0m'

def ok(msg):   print(f"{GREEN}[✓]{RESET} {msg}")
def fail(msg): print(f"{RED}[✗]{RESET} {msg}")
def info(msg): print(f"{CYAN}[*]{RESET} {msg}")
def warn(msg): print(f"{YELLOW}[!]{RESET} {msg}")
def head(msg): print(f"\n{BLUE}{BOLD}═══ {msg} ═══{RESET}")

# --- Configuration Loader ---
def load_config():
    config_path = os.path.join(os.path.dirname(__file__), 'config.json')
    if not os.path.exists(config_path):
        fail("config.json not found!")
        sys.exit(1)
    with open(config_path, 'r') as f:
        return json.load(f)

# --- Helper: Run Shell Command & Stream Output Live ---
def run_tool_live(command, output_file=None):
    info(f"Running: {command}")
    try:
        if output_file:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            with open(output_file, 'w') as f:
                for line in process.stdout:
                    print(line, end='')
                    f.write(line)
            process.wait()
        else:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            for line in process.stdout:
                print(line, end='')
            process.wait()
        return True
    except Exception as e:
        fail(f"Error: {e}")
        return False

# --- Helper: Check if tool exists ---
def tool_exists(tool_name):
    return subprocess.run(f"command -v {tool_name}", shell=True, capture_output=True).returncode == 0

# --- Helper: Create Placeholder ---
def create_placeholder(folder_path, instruction):
    os.makedirs(folder_path, exist_ok=True)
    readme_path = os.path.join(folder_path, "00_README.txt")
    with open(readme_path, 'w') as f:
        f.write(f"# Data Collection\nInstruction: {instruction}\n")
        f.write("Status: Placeholder - waiting for AI/Manual analysis.\n")

# --- Database Setup ---
def setup_db():
    conn = sqlite3.connect("bug_bounty.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS scans
                      (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                       target TEXT, scan_date TEXT, status TEXT)''')
    conn.commit()
    return conn

# --- Main Engine ---
def main():
    os.environ["PATH"] = os.environ.get("PATH", "") + ":/usr/local/bin:/usr/bin:/bin:/home/sabbir/go/bin:/home/sabbir/.local/bin:/root/go/bin:/root/.local/bin"
    
    parser = argparse.ArgumentParser(description="AI Recon Engine - Live Output Collector")
    parser.add_argument("--target", "-t", required=True, help="Target domain (e.g., example.com)")
    args = parser.parse_args()

    target = args.target
    config = load_config()
    
    base_dir = os.path.dirname(os.path.abspath(__file__))
    results_dir = os.path.join(base_dir, "results", target)
    wordlist_dir = os.path.join(base_dir, "wordlists")
    
    phase_folders = [
        "01_subdomains", "02_dns", "03_live_hosts", "04_http_raw", "05_urls",
        "06_javascript", "07_content_disc", "08_params", "09_api", "10_screenshots",
        "11_nuclei", "12_intel", "13_ssl", "14_historical", "15_takeover",
        "_findings", "_reports", "_metadata"
    ]
    for folder in phase_folders:
        os.makedirs(os.path.join(results_dir, folder), exist_ok=True)
    
    head(f"Starting AI Recon Engine for: {target}")
    info(f"Results directory: {results_dir}")
    info(f"Wordlist directory: {wordlist_dir}")

    conn = setup_db()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scans (target, scan_date, status) VALUES (?, ?, ?)", 
                   (target, datetime.now(timezone.utc).isoformat(), "running"))
    conn.commit()
    scan_id = cursor.lastrowid
    ok(f"Database scan ID: {scan_id}")

    # --- PHASE 01: Subdomains ---
    head("Phase 01: Subdomain Enumeration")
    subs_file = os.path.join(results_dir, "01_subdomains", "all.txt")
    if tool_exists("subfinder"):
        run_tool_live(f"subfinder -d {target}", subs_file)
        ok("Subdomains saved.")
    else:
        fail("Subfinder missing. Skipping.")

    # --- PHASE 02: DNS ---
    head("Phase 02: DNS Resolution")
    dns_file = os.path.join(results_dir, "02_dns", "resolved.txt")
    if os.path.exists(subs_file) and tool_exists("dnsx"):
        run_tool_live(f"cat {subs_file} | dnsx", dns_file)
        ok("DNS resolved.")
    else:
        warn("dnsx missing or no subdomains. Skipping.")

    # --- PHASE 03: Live Hosts ---
    head("Phase 03: Live Host Detection")
    live_file = os.path.join(results_dir, "03_live_hosts", "live.txt")
    if os.path.exists(subs_file) and tool_exists("httpx"):
        run_tool_live(f"cat {subs_file} | httpx", live_file)
        ok("Live hosts saved.")
    else:
        warn("httpx missing or no subdomains. Skipping.")

    # --- PHASE 04: HTTP Raw ---
    head("Phase 04: HTTP Raw Data")
    http_raw_dir = os.path.join(results_dir, "04_http_raw")
    if os.path.exists(live_file) and os.path.getsize(live_file) > 0:
        with open(live_file, 'r') as f:
            hosts = [line.strip() for line in f if line.strip()]
        for host in hosts[:5]:
            safe_name = host.replace("https://", "").replace("http://", "").replace("/", "_")
            out_file = os.path.join(http_raw_dir, f"{safe_name}.txt")
            run_tool_live(f"curl -s -I {host}", out_file)
        ok(f"Raw HTTP headers saved for {min(5, len(hosts))} hosts.")
    else:
        warn("No live hosts. Skipping.")

    # --- PHASE 05: URLs ---
    head("Phase 05: URL Collection")
    urls_file = os.path.join(results_dir, "05_urls", "all.txt")
    if os.path.exists(live_file) and os.path.getsize(live_file) > 0:
        if tool_exists("gau"):
            run_tool_live(f"cat {live_file} | gau --threads 5", urls_file)
            ok("URLs saved.")
        else:
            fail("gau missing. Skipping URL collection.")
    else:
        warn("No live hosts. Skipping URL collection.")

    # --- PHASE 06: JavaScript ---
    head("Phase 06: JavaScript Extraction")
    js_dir = os.path.join(results_dir, "06_javascript")
    if os.path.exists(urls_file) and os.path.getsize(urls_file) > 0:
        run_tool_live(f"grep -E '\\.js(\\?|$)' {urls_file}", os.path.join(js_dir, 'js_files.txt'))
        ok("JS files list extracted.")
    else:
        warn("No URLs. Skipping JS extraction.")

    # --- PHASE 07: Content Discovery ---
    head("Phase 07: Content Discovery")
    content_dir = os.path.join(results_dir, "07_content_disc")
    if tool_exists("ffuf") and os.path.exists(live_file) and os.path.getsize(live_file) > 0:
        common_wl = os.path.join(wordlist_dir, "common.txt")
        if os.path.exists(common_wl):
            info("Running ffuf with common.txt...")
            run_tool_live(f"ffuf -u https://FUZZ -w {common_wl} -o {os.path.join(content_dir, 'ffuf_common.json')} -of json", os.path.join(content_dir, 'ffuf_common_live.txt'))
            ok("Content discovery (common) complete.")
        
        sensitive_wl = os.path.join(wordlist_dir, "sensitive_paths.txt")
        if os.path.exists(sensitive_wl):
            info("Running ffuf with sensitive_paths.txt...")
            run_tool_live(f"ffuf -u https://FUZZ -w {sensitive_wl} -o {os.path.join(content_dir, 'ffuf_sensitive.json')} -of json", os.path.join(content_dir, 'ffuf_sensitive_live.txt'))
            ok("Content discovery (sensitive) complete.")
    else:
        warn("ffuf missing or no live hosts. Skipping.")

    # --- PHASE 08: Parameters ---
    head("Phase 08: Parameter Discovery")
    params_dir = os.path.join(results_dir, "08_params")
    param_wl = os.path.join(wordlist_dir, "parameters.txt")
    if tool_exists("arjun") and os.path.exists(live_file) and os.path.getsize(live_file) > 0 and os.path.exists(param_wl):
        info("Running arjun with parameters.txt...")
        run_tool_live(f"arjun -i {live_file} -w {param_wl}", os.path.join(params_dir, 'arjun.txt'))
        ok("Parameter discovery complete.")
    else:
        warn("arjun missing, no live hosts, or parameters.txt not found. Skipping.")

    # --- PHASE 09: API Discovery ---
    head("Phase 09: API Discovery")
    api_dir = os.path.join(results_dir, "09_api")
    api_wl = os.path.join(wordlist_dir, "api_endpoints.txt")
    if tool_exists("ffuf") and os.path.exists(live_file) and os.path.getsize(live_file) > 0 and os.path.exists(api_wl):
        info("Running ffuf with api_endpoints.txt...")
        run_tool_live(f"ffuf -u https://FUZZ -w {api_wl} -o {os.path.join(api_dir, 'ffuf_api.json')} -of json", os.path.join(api_dir, 'ffuf_api_live.txt'))
        ok("API discovery complete.")
    else:
        warn("ffuf missing, no live hosts, or api_endpoints.txt not found. Skipping.")

    # --- PHASE 10: Screenshots ---
    head("Phase 10: Screenshots")
    ss_dir = os.path.join(results_dir, "10_screenshots")
    if tool_exists("gowitness") and os.path.exists(live_file) and os.path.getsize(live_file) > 0:
        info("Running gowitness on live hosts...")
        # FIXED: gowitness v3 uses 'scan file' instead of 'file'
        run_tool_live(f"gowitness scan file -f {live_file} -P {ss_dir}")
        ok("Screenshots saved.")
    else:
        warn("gowitness missing or no live hosts. Skipping.")

    # --- PHASE 11: Nuclei ---
    head("Phase 11: Nuclei Scan")
    nuclei_file = os.path.join(results_dir, "11_nuclei", "results.txt")
    if os.path.exists(live_file) and os.path.getsize(live_file) > 0 and tool_exists("nuclei"):
        info("This may take a while...")
        run_tool_live(f"nuclei -l {live_file}", nuclei_file)
        ok("Nuclei scan complete.")
    else:
        warn("nuclei missing or no live hosts. Skipping.")

    # --- PHASE 12: Intel ---
    head("Phase 12: Intelligence Gathering")
    intel_dir = os.path.join(results_dir, "12_intel")
    create_placeholder(intel_dir, "Query Shodan/Censys/VT using config.json API keys manually.")

    # --- PHASE 13: SSL Analysis ---
    head("Phase 13: SSL Analysis")
    ssl_dir = os.path.join(results_dir, "13_ssl")
    if tool_exists("testssl.sh") and os.path.exists(live_file) and os.path.getsize(live_file) > 0:
        info("Running testssl.sh on live hosts (one by one)...")
        # FIXED: testssl.sh doesn't support batch mode. Loop through each host.
        with open(live_file, 'r') as f:
            hosts = [line.strip() for line in f if line.strip()]
        ssl_output = os.path.join(ssl_dir, 'ssl_analysis.txt')
        with open(ssl_output, 'w') as out_f:
            for host in hosts:
                out_f.write(f"\n\n===== SSL Analysis for: {host} =====\n")
                try:
                    result = subprocess.run(f"testssl.sh --quiet {host}", shell=True, capture_output=True, text=True, timeout=120)
                    out_f.write(result.stdout)
                    out_f.write(result.stderr)
                except subprocess.TimeoutExpired:
                    out_f.write(f"[!] Timeout for {host}\n")
        ok("SSL analysis complete.")
    else:
        warn("testssl.sh missing or no live hosts. Skipping.")

    # --- PHASE 14: Historical ---
    head("Phase 14: Historical Data")
    hist_dir = os.path.join(results_dir, "14_historical")
    create_placeholder(hist_dir, "Query SecurityTrails API manually.")

    # --- PHASE 15: Takeover ---
    head("Phase 15: Takeover Check")
    takeover_dir = os.path.join(results_dir, "15_takeover")
    if tool_exists("subzy") and os.path.exists(subs_file):
        info("Running subzy on subdomains...")
        run_tool_live(f"subzy run --targets {subs_file} --hide_fails", os.path.join(takeover_dir, 'subzy.txt'))
        ok("Takeover check complete.")
    else:
        warn("subzy missing or no subdomains. Skipping.")

    # --- SUMMARY FOR AI ---
    head("Recon Engine Execution Finished")
    cursor.execute("UPDATE scans SET status = ? WHERE id = ?", ("completed", scan_id))
    conn.commit()
    conn.close()

    ai_summary_file = os.path.join(results_dir, "00_README_FOR_AI.md")
    with open(ai_summary_file, 'w') as f:
        f.write(f"# AI Recon Results for {target}\n")
        f.write(f"Scan Date: {datetime.now(timezone.utc).isoformat()}\n\n")
        f.write("## Collected Data:\n")
        f.write("- `01_subdomains/all.txt`\n")
        f.write("- `02_dns/resolved.txt`\n")
        f.write("- `03_live_hosts/live.txt`\n")
        f.write("- `04_http_raw/*.txt`\n")
        f.write("- `05_urls/all.txt`\n")
        f.write("- `06_javascript/js_files.txt`\n")
        f.write("- `07_content_disc/`\n")
        f.write("- `08_params/arjun.txt`\n")
        f.write("- `09_api/ffuf_api.json`\n")
        f.write("- `10_screenshots/`\n")
        f.write("- `11_nuclei/results.txt`\n")
        f.write("- `13_ssl/ssl_analysis.txt`\n")
        f.write("\n## Placeholder Folders (For AI/Manual Analysis):\n")
        f.write("- `12_intel/`, `14_historical/`, `15_takeover/`\n")
        f.write("\n## AI Instructions:\n")
        f.write("1. Analyze `11_nuclei/results.txt` for findings.\n")
        f.write("2. Check `05_urls/all.txt` for IDOR/XSS/SSRF parameters.\n")
        f.write("3. Check `07_content_disc/ffuf_common.json` and `ffuf_sensitive.json` for hidden files.\n")
        f.write("4. Check `08_params/arjun.txt` for parameters.\n")
        f.write("5. Check `09_api/ffuf_api.json` for API endpoints.\n")
        f.write("6. Generate reports in `_reports/` folder.\n")
    
    ok(f"All raw data saved in: {results_dir}")
    ok(f"AI Handover file: {ai_summary_file}")

if __name__ == "__main__":
    main()
