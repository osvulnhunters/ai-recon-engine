#!/bin/bash
# AI Recon Engine - Installer
# Installs all required tools (Go-based + Python)

set +e

GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
BLUE='\033[1;34m'
NC='\033[0m'

ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
fail() { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${CYAN}[*]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
head() { echo -e "\n${BLUE}═══ $1 ═══${NC}"; }

has() { command -v "$1" >/dev/null 2>&1; }

LOG="logs/install.log"
mkdir -p logs
> "$LOG"

# ─────────────────────────────
head "1. System Packages"
# ─────────────────────────────
sudo apt update -y >> "$LOG" 2>&1

for pkg in git curl wget jq build-essential python3 python3-pip pipx \
           golang-go unzip dnsutils whois; do
  if dpkg -l "$pkg" 2>/dev/null | grep -q "^ii"; then
    ok "$pkg (already installed)"
  else
    sudo apt install -y "$pkg" >> "$LOG" 2>&1 && ok "$pkg" || fail "$pkg"
  fi
done

# Ensure Go PATH
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin"
grep -q 'go/bin' ~/.bashrc 2>/dev/null || \
  echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin:$HOME/.local/bin' >> ~/.bashrc

# ─────────────────────────────
head "2. Go-Based Tools"
# ─────────────────────────────
GO_TOOLS=(
  "subfinder:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "httpx:github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "nuclei:github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  "katana:github.com/projectdiscovery/katana/cmd/katana@latest"
  "dnsx:github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "naabu:github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "interactsh-client:github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
  "ffuf:github.com/ffuf/ffuf/v2@latest"
  "gau:github.com/lc/gau/v2/cmd/gau@latest"
  "anew:github.com/tomnomnom/anew@latest"
  "qsreplace:github.com/tomnomnom/qsreplace@latest"
  "waybackurls:github.com/tomnomnom/waybackurls@latest"
)

for entry in "${GO_TOOLS[@]}"; do
  name="${entry%%:*}"
  path="${entry#*:}"
  if has "$name"; then
    ok "$name (already installed)"
  else
    info "Installing $name..."
    go install -v "$path" >> "$LOG" 2>&1 && ok "$name" || fail "$name"
  fi
done

# ─────────────────────────────
head "3. Python Tools (via pipx)"
# ─────────────────────────────
pipx ensurepath >> "$LOG" 2>&1

PY_TOOLS=("arjun" "uro")
for pkg in "${PY_TOOLS[@]}"; do
  if pipx list 2>/dev/null | grep -q "$pkg"; then
    ok "$pkg (already installed)"
  else
    pipx install "$pkg" >> "$LOG" 2>&1 && ok "$pkg" || fail "$pkg"
  fi
done

# ─────────────────────────────
head "4. Python Dependencies"
# ─────────────────────────────
pip3 install -r requirements.txt --break-system-packages >> "$LOG" 2>&1 \
  && ok "Python requirements" || fail "Some packages failed"

# ─────────────────────────────
head "5. Nuclei Templates"
# ─────────────────────────────
if has nuclei; then
  nuclei -update-templates >> "$LOG" 2>&1 && ok "Templates updated" || fail "Templates failed"
fi

# ─────────────────────────────
head "6. Optional Tools"
# ─────────────────────────────
# gowitness for screenshots
if ! has gowitness; then
  info "Installing gowitness..."
  go install github.com/sensepost/gowitness@latest >> "$LOG" 2>&1 \
    && ok "gowitness" || warn "gowitness failed (optional)"
else
  ok "gowitness (already installed)"
fi

# subzy for takeover
if ! has subzy; then
  info "Installing subzy..."
  go install github.com/PentestPad/subzy@latest >> "$LOG" 2>&1 \
    && ok "subzy" || warn "subzy failed (optional)"
else
  ok "subzy (already installed)"
fi

# ─────────────────────────────
head "Setup Complete"
# ─────────────────────────────
echo ""
echo "Full log: $LOG"
echo ""
echo "Next steps:"
echo "  1. source ~/.bashrc"
echo "  2. python3 recon.py --help"
echo ""
