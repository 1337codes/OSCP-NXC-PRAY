#!/bin/bash
# ════════════════════════════════════════════════════════════════════════════
# install_check.sh — Tool verifier & installer for nxcspray / OSCP AD enum
# Usage: sudo bash install_check.sh [--fix]   (--fix installs missing tools)
# ════════════════════════════════════════════════════════════════════════════

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;96m'; GRAY='\033[0;90m'; WHITE='\033[1;37m'; NC='\033[0m'
ORANGE='\033[0;33m'

FIX_MODE=false
[[ "${1:-}" == "--fix" ]] && FIX_MODE=true

PASS=0; WARN=0; FAIL=0

chk() {
    local label="$1" cmd="$2" install_hint="$3"
    if command -v "$cmd" &>/dev/null; then
        local ver; ver=$("$cmd" --version 2>/dev/null | head -1 | cut -c1-60 || echo "found")
        echo -e "  ${GREEN}[✓]${NC} $label — ${GRAY}$ver${NC}"
        (( PASS++ ))
        return 0
    else
        echo -e "  ${RED}[✗]${NC} $label — NOT FOUND"
        [[ -n "$install_hint" ]] && echo -e "      ${GRAY}→ $install_hint${NC}"
        (( FAIL++ ))
        return 1
    fi
}

chk_opt() {
    local label="$1" cmd="$2" install_hint="$3"
    if command -v "$cmd" &>/dev/null; then
        echo -e "  ${GREEN}[✓]${NC} $label (optional)"
        (( PASS++ ))
    else
        echo -e "  ${YELLOW}[○]${NC} $label — optional, not found"
        [[ -n "$install_hint" ]] && echo -e "      ${GRAY}→ $install_hint${NC}"
        (( WARN++ ))
    fi
}

echo -e "${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  NXCSPRAY — Tool Dependency Check                         ║${NC}"
echo -e "${CYAN}║  Run with --fix to auto-install missing tools              ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Core scanning ─────────────────────────────────────────────────────────────
echo -e "${WHITE}── Core (required) ─────────────────────────────────────────${NC}"
chk  "NetExec (nxc)"        nxc         "sudo apt install netexec OR pipx install netexec"
chk  "nmap"                 nmap        "sudo apt install nmap"
chk  "smbclient"            smbclient   "sudo apt install smbclient"
chk  "ldapsearch"           ldapsearch  "sudo apt install ldap-utils"
echo ""

# ── Impacket suite ────────────────────────────────────────────────────────────
echo -e "${WHITE}── Impacket (AS-REP / Kerberoast / lateral movement) ───────${NC}"
chk  "impacket-GetUserSPNs"   impacket-GetUserSPNs   "sudo apt install python3-impacket impacket-scripts"
chk  "impacket-GetNPUsers"    impacket-GetNPUsers    "sudo apt install python3-impacket impacket-scripts"
chk  "impacket-secretsdump"   impacket-secretsdump   "sudo apt install impacket-scripts"
chk  "impacket-psexec"        impacket-psexec        "sudo apt install impacket-scripts"
chk  "impacket-wmiexec"       impacket-wmiexec       "sudo apt install impacket-scripts"
chk  "impacket-smbexec"       impacket-smbexec       "sudo apt install impacket-scripts"
chk  "impacket-smbclient"     impacket-smbclient     "sudo apt install impacket-scripts"
chk  "impacket-lookupsid"     impacket-lookupsid     "sudo apt install impacket-scripts"
chk  "impacket-findDelegation" impacket-findDelegation "sudo apt install impacket-scripts"
chk  "impacket-ticketer"      impacket-ticketer      "sudo apt install impacket-scripts"
chk  "impacket-getST"         impacket-getST         "sudo apt install impacket-scripts"
echo ""

# ── AD Certificate Services ──────────────────────────────────────────────────
echo -e "${WHITE}── ADCS / Certipy (ESC1-ESC16 checks) ──────────────────────${NC}"
chk  "certipy-ad"             certipy-ad   "pip install certipy-ad --break-system-packages"
echo ""

# ── BloodHound ────────────────────────────────────────────────────────────────
echo -e "${WHITE}── BloodHound ───────────────────────────────────────────────${NC}"
chk_opt "bloodhound-python"  bloodhound-python  "pip install bloodhound --break-system-packages"
chk_opt "bloodhound (GUI)"   bloodhound         "sudo apt install bloodhound"
echo ""

# ── Remote access ────────────────────────────────────────────────────────────
echo -e "${WHITE}── Remote Access ────────────────────────────────────────────${NC}"
chk  "evil-winrm"             evil-winrm   "sudo gem install evil-winrm"
chk_opt "xfreerdp3"           xfreerdp3    "sudo apt install freerdp3-x11"
chk_opt "xfreerdp"            xfreerdp     "sudo apt install freerdp2-x11"
chk  "ssh"                    ssh          "sudo apt install openssh-client"
echo ""

# ── Password cracking ─────────────────────────────────────────────────────────
echo -e "${WHITE}── Password Cracking ────────────────────────────────────────${NC}"
chk  "hashcat"                hashcat      "sudo apt install hashcat"
chk_opt "john"                john         "sudo apt install john"
echo ""

# ── Enumeration / username tools ─────────────────────────────────────────────
echo -e "${WHITE}── Enumeration Tools ────────────────────────────────────────${NC}"
chk_opt "kerbrute"            kerbrute     "Download: https://github.com/ropnop/kerbrute/releases (set KERBRUTE=/path/to/kerbrute)"
chk_opt "enum4linux-ng"       enum4linux-ng "sudo apt install enum4linux-ng OR pip install enum4linux-ng"
chk_opt "enum4linux"          enum4linux   "sudo apt install enum4linux"
chk_opt "windapsearch"        windapsearch "pip install windapsearch --break-system-packages"
chk_opt "rpcclient"           rpcclient    "sudo apt install smbclient"
chk_opt "ntpdate"             ntpdate      "sudo apt install ntpdate  (required for Kerberos clock sync)"
chk_opt "fping"               fping        "sudo apt install fping"
echo ""

# ── Web enumeration ──────────────────────────────────────────────────────────
echo -e "${WHITE}── Web Enumeration (shown as hints when HTTP open) ─────────${NC}"
chk_opt "whatweb"             whatweb      "sudo apt install whatweb"
chk_opt "gobuster"            gobuster     "sudo apt install gobuster"
chk_opt "nikto"               nikto        "sudo apt install nikto"
chk_opt "ffuf"                ffuf         "sudo apt install ffuf"
echo ""

# ── Misc ──────────────────────────────────────────────────────────────────────
echo -e "${WHITE}── Misc ─────────────────────────────────────────────────────${NC}"
chk  "python3"                python3      "sudo apt install python3"
chk  "curl"                   curl         "sudo apt install curl"
chk_opt "redis-cli"           redis-cli    "sudo apt install redis-tools"
chk_opt "mysql"               mysql        "sudo apt install default-mysql-client"
chk_opt "psql"                psql         "sudo apt install postgresql-client"
chk_opt "hydra"               hydra        "sudo apt install hydra"
echo ""

# ── Summary ──────────────────────────────────────────────────────────────────
echo -e "${WHITE}═══════════════════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}[✓] Installed: $PASS${NC}   ${YELLOW}[○] Optional missing: $WARN${NC}   ${RED}[✗] Required missing: $FAIL${NC}"
echo ""

if [[ "$FAIL" -gt 0 ]]; then
    echo -e "${RED}[!] $FAIL required tool(s) missing — some features will not work${NC}"
    echo -e "${YELLOW}    Run: sudo bash install_check.sh --fix  to auto-install${NC}"
fi
if [[ "$WARN" -gt 3 ]]; then
    echo -e "${YELLOW}[!] Several optional tools missing — install for full coverage${NC}"
fi

# ── Auto-fix mode ─────────────────────────────────────────────────────────────
if [[ "$FIX_MODE" == true ]]; then
    echo ""
    echo -e "${CYAN}[*] Fix mode: installing missing packages...${NC}"

    # APT packages
    _apt_pkgs=()
    command -v nxc           &>/dev/null || _apt_pkgs+=(netexec)
    command -v nmap          &>/dev/null || _apt_pkgs+=(nmap)
    command -v smbclient     &>/dev/null || _apt_pkgs+=(smbclient)
    command -v ldapsearch    &>/dev/null || _apt_pkgs+=(ldap-utils)
    command -v hashcat       &>/dev/null || _apt_pkgs+=(hashcat)
    command -v ntpdate       &>/dev/null || _apt_pkgs+=(ntpdate)
    command -v enum4linux    &>/dev/null || _apt_pkgs+=(enum4linux)
    command -v enum4linux-ng &>/dev/null || _apt_pkgs+=(enum4linux-ng)
    command -v whatweb       &>/dev/null || _apt_pkgs+=(whatweb)
    command -v gobuster      &>/dev/null || _apt_pkgs+=(gobuster)
    command -v nikto         &>/dev/null || _apt_pkgs+=(nikto)
    command -v hydra         &>/dev/null || _apt_pkgs+=(hydra)
    command -v fping         &>/dev/null || _apt_pkgs+=(fping)
    command -v redis-cli     &>/dev/null || _apt_pkgs+=(redis-tools)
    command -v mysql         &>/dev/null || _apt_pkgs+=(default-mysql-client)
    command -v psql          &>/dev/null || _apt_pkgs+=(postgresql-client)
    command -v john          &>/dev/null || _apt_pkgs+=(john)
    command -v rpcclient     &>/dev/null || _apt_pkgs+=(smbclient)

    # Impacket
    command -v impacket-GetUserSPNs &>/dev/null || _apt_pkgs+=(impacket-scripts python3-impacket)

    if [[ ${#_apt_pkgs[@]} -gt 0 ]]; then
        echo -e "${CYAN}[*] apt install: ${_apt_pkgs[*]}${NC}"
        sudo apt-get update -qq && sudo apt-get install -y "${_apt_pkgs[@]}"
    fi

    # pip: certipy-ad
    if ! command -v certipy-ad &>/dev/null; then
        echo -e "${CYAN}[*] pip install certipy-ad...${NC}"
        pip install certipy-ad --break-system-packages 2>/dev/null || \
        pipx install certipy-ad 2>/dev/null || \
        pip3 install certipy-ad --break-system-packages
    fi

    # pip: bloodhound-python
    if ! command -v bloodhound-python &>/dev/null; then
        echo -e "${CYAN}[*] pip install bloodhound...${NC}"
        pip install bloodhound --break-system-packages 2>/dev/null || \
        pip3 install bloodhound --break-system-packages
    fi

    # gem: evil-winrm
    if ! command -v evil-winrm &>/dev/null; then
        echo -e "${CYAN}[*] gem install evil-winrm...${NC}"
        sudo gem install evil-winrm
    fi

    # kerbrute: download latest binary
    if ! command -v kerbrute &>/dev/null; then
        echo -e "${CYAN}[*] Downloading kerbrute...${NC}"
        _arch=$(uname -m)
        [[ "$_arch" == "x86_64" ]] && _kb_arch="amd64" || _kb_arch="arm64"
        _kb_url=$(curl -s https://api.github.com/repos/ropnop/kerbrute/releases/latest \
            2>/dev/null | grep "browser_download_url" | grep "linux_${_kb_arch}" | head -1 | \
            grep -oP '"https://[^"]+kerbrute[^"]+linux[^"]+"' | tr -d '"')
        if [[ -n "$_kb_url" ]]; then
            sudo curl -L "$_kb_url" -o /usr/local/bin/kerbrute 2>/dev/null && \
                sudo chmod +x /usr/local/bin/kerbrute && \
                echo -e "${GREEN}[+] kerbrute installed to /usr/local/bin/kerbrute${NC}"
        else
            echo -e "${YELLOW}[!] Could not auto-download kerbrute — get it from:${NC}"
            echo -e "${GRAY}    https://github.com/ropnop/kerbrute/releases${NC}"
        fi
    fi

    echo ""
    echo -e "${GREEN}[+] Fix mode complete — re-run without --fix to verify${NC}"
fi

# ── Kerberos tips ─────────────────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}── Clock skew tips (Kerberos fails if >5 min off) ──────────${NC}"
echo -e "${GRAY}  Fix immediately: sudo ntpdate -u <DC_IP>${NC}"
echo -e "${GRAY}  Disable NTP:     sudo timedatectl set-ntp false${NC}"
echo -e "${GRAY}  Manual sync:     sudo hwclock --systohc${NC}"
echo ""
echo -e "${YELLOW}── dc.txt / domain.txt shortcut ────────────────────────────${NC}"
echo -e "${GRAY}  echo '10.10.80.250' > dc.txt      # pins DC regardless of scan${NC}"
echo -e "${GRAY}  echo 'SKYLARK.com' > domain.txt   # skips domain auto-detect${NC}"
echo ""
