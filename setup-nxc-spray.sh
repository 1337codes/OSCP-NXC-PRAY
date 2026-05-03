#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────
# setup-nxc-spray.sh — installs everything nxc_spray.sh needs on Kali
#
#   Repo:   https://github.com/1337codes/OSCP-NXC-PREY
#   Usage:  chmod +x setup-nxc-spray.sh && sudo bash setup-nxc-spray.sh
# ─────────────────────────────────────────────────────────────────────

set -u

R='\033[91m'; G='\033[92m'; Y='\033[93m'; C='\033[96m'; B='\033[1m'; N='\033[0m'

banner() { echo -e "\n${C}${B}[*]${N} ${B}$1${N}"; }
ok()     { echo -e "${G}[+]${N} $1"; }
warn()   { echo -e "${Y}[!]${N} $1"; }
fail()   { echo -e "${R}[-]${N} $1" >&2; }

if [[ $EUID -ne 0 ]]; then
    if ! command -v sudo &>/dev/null; then
        fail "Run as root or install sudo."; exit 1
    fi
    SUDO="sudo"
else
    SUDO=""
fi

# Target user (the one who'll actually run the tool, not root)
TARGET_USER="${SUDO_USER:-$USER}"
TARGET_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)

# ── helper: run a command AS the target user, regardless of whether
#    we're currently root or not. Use this for pipx and anything else
#    that should land under the user's home, not /root.
run_as_user() {
    if [[ $EUID -eq 0 ]] && [[ "$TARGET_USER" != "root" ]]; then
        sudo -u "$TARGET_USER" -H "$@"
    else
        "$@"
    fi
}

MISSING=()
INSTALLED_VIA_PIPX=()

banner "NXC-PREY (nxc_spray.sh) installer"

# ─── apt update ──────────────────────────────────────────────────────
banner "Updating package index"
$SUDO apt-get update -qq && ok "apt index updated" || warn "apt update had warnings (continuing)"

# ─── tier 1: rock-solid AD enum stack ────────────────────────────────
# NOTE: ntpdate moved out of Debian/Kali main — use ntpsec-ntpdate which
# still provides the `ntpdate` binary the script literally calls.
banner "Installing core AD enum dependencies"
$SUDO apt-get install -y -qq \
    python3 python3-pip pipx \
    nmap \
    ldap-utils \
    smbmap smbclient \
    enum4linux-ng \
    hydra medusa \
    python3-impacket impacket-scripts \
    evil-winrm \
    john hashcat \
    curl wget git \
    netcat-openbsd ncat \
    telnet \
    dnsutils \
    sshpass
ok "core AD stack installed"

# ─── ntpdate — try old name, then ntpsec-ntpdate, then chrony fallback
banner "Installing ntpdate (Kerberos clock sync)"
if command -v ntpdate &>/dev/null; then
    ok "ntpdate already on PATH ($(command -v ntpdate))"
elif $SUDO apt-get install -y -qq ntpdate 2>/dev/null; then
    ok "ntpdate installed (legacy package)"
elif $SUDO apt-get install -y -qq ntpsec-ntpdate 2>/dev/null; then
    ok "ntpsec-ntpdate installed (provides /usr/bin/ntpdate)"
elif $SUDO apt-get install -y -qq chrony 2>/dev/null; then
    warn "no ntpdate package available — installed chrony as fallback"
    warn "you may need to manually sync time: sudo chronyd -q 'server <DC_IP> iburst'"
else
    fail "couldn't install any time-sync tool — Kerberos may fail with KRB_AP_ERR_SKEW"
fi

# ─── tier 2: variable packages ───────────────────────────────────────
banner "Installing packages that vary by Kali version"

OPTIONAL_APT_PKGS=(
    smtp-user-enum
    kerbrute              # may be in apt on Kali 2024+
    windapsearch          # Python LDAP enumeration
    certipy-ad            # AD CS attacks
    bloodhound.py
    bloodhound-ce-python
    coercer
    seclists
    wordlists
)

for pkg in "${OPTIONAL_APT_PKGS[@]}"; do
    if $SUDO apt-get install -y -qq "$pkg" 2>/dev/null; then
        ok "$pkg installed (apt)"
    else
        warn "$pkg unavailable in apt — will try fallback if applicable"
        MISSING+=("$pkg")
    fi
done

# ─── pipx environment for $TARGET_USER ───────────────────────────────
banner "Setting up pipx for $TARGET_USER"
run_as_user pipx ensurepath >/dev/null 2>&1 || true
export PATH="$TARGET_HOME/.local/bin:$PATH"
ok "pipx ready (binaries → $TARGET_HOME/.local/bin)"

# Helper: install a tool via pipx as the target user
pipx_install() {
    local spec="$1" name="$2"
    if run_as_user pipx install --force "$spec" >/dev/null 2>&1; then
        ok "$name installed via pipx"
        INSTALLED_VIA_PIPX+=("$name")
        return 0
    else
        warn "$name pipx install failed"
        return 1
    fi
}

# ─── NetExec (nxc) — THE main tool ───────────────────────────────────
banner "Installing NetExec (nxc) — primary tool for this script"
if command -v nxc &>/dev/null; then
    ok "nxc already on PATH ($(command -v nxc))"
elif $SUDO apt-get install -y -qq netexec 2>/dev/null && command -v nxc &>/dev/null; then
    ok "netexec installed via apt"
else
    warn "netexec not in apt — falling back to pipx"
    pipx_install "git+https://github.com/Pennyw0rth/NetExec" "NetExec (nxc)" || \
        fail "NetExec install failed — script will not work without it!"
fi

# ─── kerbrute (Go binary, install from GitHub release if missing) ────
if ! command -v kerbrute &>/dev/null; then
    banner "Installing kerbrute (binary from GitHub release)"
    KERB_URL="https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64"
    if $SUDO curl -fsSL -o /usr/local/bin/kerbrute "$KERB_URL"; then
        $SUDO chmod +x /usr/local/bin/kerbrute
        ok "kerbrute installed at /usr/local/bin/kerbrute"
    else
        warn "kerbrute download failed — script will skip Phase 2 validation"
    fi
else
    ok "kerbrute already on PATH"
fi

# ─── certipy-ad fallback via pipx ────────────────────────────────────
if ! command -v certipy-ad &>/dev/null && ! command -v certipy &>/dev/null; then
    banner "Installing certipy-ad via pipx"
    pipx_install "certipy-ad" "certipy-ad"
fi

# ─── windapsearch fallback (Go binary from GitHub) ───────────────────
# Note: ropnop's windapsearch.py is unmaintained and breaks on modern Python.
# The Go rewrite is the working one but isn't in apt. Script falls back to
# impacket-GetADUsers if windapsearch is missing — totally fine.
if ! command -v windapsearch &>/dev/null; then
    banner "Installing windapsearch (Go binary)"
    WIN_URL="https://github.com/ropnop/go-windapsearch/releases/latest/download/windapsearch-linux-amd64"
    if $SUDO curl -fsSL -o /usr/local/bin/windapsearch "$WIN_URL" 2>/dev/null; then
        $SUDO chmod +x /usr/local/bin/windapsearch
        ok "windapsearch installed at /usr/local/bin/windapsearch"
    else
        warn "windapsearch optional — script falls back to impacket-GetADUsers"
    fi
fi

# ─── coercer fallback via pipx ───────────────────────────────────────
if ! command -v coercer &>/dev/null; then
    pipx_install "coercer" "coercer" >/dev/null 2>&1 || true
fi

# ─── decompress rockyou ──────────────────────────────────────────────
if [[ -f /usr/share/wordlists/rockyou.txt.gz ]]; then
    banner "Decompressing rockyou.txt"
    $SUDO gzip -d /usr/share/wordlists/rockyou.txt.gz && ok "rockyou.txt ready"
fi

# ─── verification ────────────────────────────────────────────────────
banner "Verifying critical tools"
declare -A CRITICAL_TOOLS=(
    [nxc]="NetExec (PRIMARY — script will not work without this)"
    [kerbrute]="Phase 2 username validation"
    [ntpdate]="Kerberos clock sync"
    [ldapsearch]="LDAP enumeration"
    [nmap]="Port scanning"
    [hydra]="Credential spraying"
    [smbclient]="SMB enumeration"
    [impacket-GetADUsers]="AD user enumeration"
)

ALL_GOOD=true
for tool in "${!CRITICAL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool ✓ ${CRITICAL_TOOLS[$tool]}"
    else
        fail "$tool ✗ MISSING — ${CRITICAL_TOOLS[$tool]}"
        ALL_GOOD=false
    fi
done

# ─── summary ─────────────────────────────────────────────────────────
echo
if [[ ${#INSTALLED_VIA_PIPX[@]} -gt 0 ]]; then
    warn "Installed via pipx (binaries in $TARGET_HOME/.local/bin):"
    printf '       %s\n' "${INSTALLED_VIA_PIPX[@]}"
    echo
    warn "If a command isn't found, open a NEW terminal or run:"
    echo -e "       ${C}source ~/.zshrc${N}  # or ~/.bashrc"
    echo
fi

if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Skipped from apt: ${MISSING[*]}"
    warn "(check the install log above — most got handled via pipx/binary fallback)"
fi

echo
if $ALL_GOOD; then
    echo -e "${G}${B}[✓] nxc_spray.sh ready to roll.${N}"
    echo -e "    ${C}Run:${N}      bash nxc_spray.sh -t <target> -d <DOMAIN>"
    echo -e "    ${C}Help:${N}     bash nxc_spray.sh --help"
    echo -e "    ${C}Cheatsheet:${N} bash nxc_spray.sh --cheatsheet"
else
    fail "Some critical tools are missing — see above. Fix before running."
fi

echo
echo -e "${Y}${B}[!] Reminder:${N} this script auto-modifies /etc/hosts and runs ntpdate."
echo -e "    Always run from an authorized lab/exam environment only."
