bash
cd ~/ai-recon-engine && cat > README.md << 'ENDOFFILE'

markdown
# AI Recon Engine

**Terminal collects raw data. AI (OpenCode) does all analysis.**

Built for bug bounty hunters who want maximum finding coverage
with minimum AI token cost.

---

## 🎯 How It Works
┌────────────────────────────────────────────┐
│ TERMINAL (recon.py)                        │
│ ✅ Collect raw data from 15 phases         │
│ ❌ No analysis, no AI calls                │
└────────────────┬───────────────────────────┘
                 ↓
results/<target>/
                 ↓
┌────────────────────────────────────────────┐
│ AI (OpenCode)                              │
│ ✅ Read raw data                           │
│ ✅ Analyze everything                      │
│ ✅ Find bugs (XSS, IDOR, SSRF, SQLi...)    │
│ ✅ Give test plan                          │
│ ❌ Does not collect data                   │
└────────────────┬───────────────────────────┘
                 ↓
findings + reports

---

## 📁 Folder Structure
```text
ai-recon-engine/
├── recon.py                 # Main entry
├── config.json              # API keys + settings
├── requirements.txt         # Python deps
├── install.sh               # One-time setup
├── phases/                  # 15 collection phases
├── core/                    # Framework core
├── intel/                   # External APIs
├── prompts/                 # AI prompts (bug-type-wise)
├── scripts/                 # Utilities
├── wordlists/               # Small wordlists
└── results/                 # Per-target output
🚀 Quick Start
1. Setup (One-time)
bash
cd ~/ai-recon-engine
bash install.sh
source ~/.bashrc
2. Configure API Keys
bash
nano config.json
# Add: shodan, censys_token, virustotal, github_token
3. Run Recon
bash
python3 recon.py missiveapp.com
# → 15 phases run, 60-120 minutes
# → Data saved to results/missiveapp.com/

4. AI Analysis
bash
opencode
Then prompt:

text
Read results/target.com/00_README_FOR_AI.md
Then hunt for IDOR using results/target.com/08_api/

5. Generate Report
bash
bash scripts/generate_report.sh --scan-id 1
text

bash
cd ~/ai-recon-engine && cat >> README.md << 'ENDOFFILE'


markdown

## 📊 Token Usage
| Step | Old Way | This Engine |
|---|---|---|
| Recon | 50-80 requests | 0 requests |
| Analysis | 5-10 requests | 2-3 requests |
| Report | 3-5 requests | 0 requests |
| **Total** | **60-95** | **2-3** |

Result: 95% less token cost.

## 🎯 15 Phases
| # | Phase | Collects |
|---|---|---|
| 01 | Subdomains | 10 sources |
| 02 | DNS | A, CNAME, MX, TXT, NS |
| 03 | Live Hosts | httpx + naabu |
| 04 | HTTP Raw | headers + body |
| 05 | URLs | gau, waymore, katana |
| 06 | JavaScript | full JS files |
| 07 | Content Discovery | ffuf + feroxbuster |
| 08 | Parameters | arjun |
| 09 | API | kiterunner |
| 10 | Screenshots | gowitness |
| 11 | Nuclei | scan results |
| 12 | Intel | Shodan, Censys, VT, NVD |
| 13 | SSL | testssl.sh |
| 14 | Historical | SecurityTrails |
| 15 | Takeover | subzy |

## 📁 Output Example
```text
results/target.com/
├── 00_README_FOR_AI.md      ← AI starts here
├── 01_subdomains/all.txt
├── 02_dns/*.json
├── 03_live_hosts/*.json
├── 04_http_raw/<host>/
├── 05_urls/all.txt
├── 06_javascript/files/
├── 07_content_disc/
├── 08_params/
├── 09_api/
├── 10_screenshots/
├── 11_nuclei/
├── 12_intel/
├── 13_ssl/
├── 14_historical/
├── 15_takeover/
├── _findings/               ← AI findings saved
├── _reports/                ← HackerOne reports
└── _metadata/
🔧 Commands
bash
# Full recon
python3 recon.py <target>

# Specific phases only
python3 recon.py <target> --phases 01_subdomains,02_dns,03_live_hosts

# Resume interrupted scan
python3 recon.py <target> --resume

# View findings
bash scripts/view_findings.sh

# Generate reports
bash scripts/generate_report.sh --scan-id <id>
⚖️ Legal
Only test authorized targets. Never scan unauthorized systems.

📝 License
MIT

