#!/bin/bash
# MODULE: init.sh - validate(), print_startup_overview(), init_files()

# ── Output directory and key file paths ──────────────────────────────────────
# These are set inline at source time so all modules can reference them.
# OUTDIR uses a timestamp so each run gets a fresh directory.
OUTDIR="nxc_$(date +%Y%m%d_%H%M%S)"
RESULTS="$OUTDIR/all_results.txt"
CREDS_FILE="$OUTDIR/found_creds.txt"
HYDRA_CMDS="$OUTDIR/hydra_commands.sh"
ALL_USERS="$OUTDIR/all_users.txt"
ENUM_USERS="$OUTDIR/enumerated_users.txt"

# ── init_boot: called from orchestrator after arg parsing ────────────────────
# Prints banner, creates OUTDIR, initialises phase state.
# Must NOT run at source time — args must be parsed first (e.g. --resume).
init_boot() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║                        NXC Spray                          ║"
    echo "║                  Created by 1337.codes                    ║"
    echo "║                                                           ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    mkdir -p "$OUTDIR"
    init_phase_state
    show_resume_status
}



validate() {
    if [[ -f "$TARGETS" ]]; then
        TARGET_ARG="$TARGETS"
        DC_IP=""   # Set by domain auto-detection after port scan (or -dc flag)
        echo -e "${GREEN}[+] Targets:   $TARGETS ($(count_lines "$TARGETS") hosts)${NC}"
    elif [[ -n "$TARGETS" ]]; then
        # Enkele doelhost - could be IP, hostname, or FQDN
        TARGET_ARG="$TARGETS"
        DC_IP="$TARGETS"
        if [[ -n "$SINGLE_TARGET" ]]; then
            echo -e "${GREEN}[+] Target:    $TARGETS (-T flag)${NC}"
        else
            echo -e "${GREEN}[+] Target:    $TARGETS${NC}"
        fi
    else
        if [[ "$GENERATE_ONLY" == true ]]; then
            TARGET_ARG=""
            DC_IP=""
            echo -e "${YELLOW}[!] Generate-only mode: no target required${NC}"
        else
            echo -e "${RED}[X] No target specified. Use -T <target> or create targets.txt${NC}"; exit 1
        fi
    fi

    HAS_USERS=false; HAS_PASSWORDS=false; HAS_HASHES=false

    # Treat combo modes as credential input (even if temp files are not yet on disk for some reason)
    [[ "$COMBO_MODE" == "pass" ]] && HAS_PASSWORDS=true
    [[ "$COMBO_MODE" == "hash" ]] && HAS_HASHES=true
    ANON_ONLY=false

    # ── Combo mode: show what was actually provided instead of "not found" ────
    if [[ -n "$COMBO_MODE" ]]; then
        local _combo_pairs=0
        [[ -f "$COMBO_PAIRS_FILE" ]] && _combo_pairs=$(wc -l < "$COMBO_PAIRS_FILE" 2>/dev/null || echo 0)
        if [[ "$COMBO_MODE" == "pass" ]]; then
            echo -e "${GREEN}[+] Combo:     -c mode ($COMBO_CRED) — $_combo_pairs user:pass pair(s)${NC}"
            HAS_USERS=true
        else
            echo -e "${GREEN}[+] Combo:     -ch mode ($COMBO_HASH) — $_combo_pairs user:hash pair(s) [PTH]${NC}"
            HAS_USERS=true
        fi
    else
        if [[ -f "$USERS" ]]; then
        local user_count=$(count_lines "$USERS")
        if [[ -n "$SINGLE_USER" && -f "$SINGLE_USER" ]]; then
            echo -e "${GREEN}[+] Users:     $USERS ($user_count users) (-U flag, file)${NC}"
        elif [[ -z "$COMBO_MODE" && -n "$SINGLE_USER" ]]; then
            echo -e "${GREEN}[+] User:      $SINGLE_USER (-U flag)${NC}"
        else
            echo -e "${GREEN}[+] Users:     $USERS ($user_count users)${NC}"
        fi
        HAS_USERS=true
    else
        echo -e "${YELLOW}[○] Users:     not found (will enumerate)${NC}"
        fi  # end -f "$USERS"
    fi  # end combo else

    # Skip individual passwords/hashes display in combo mode (already shown above)
    if [[ -z "$COMBO_MODE" ]]; then
    if [[ -f "$PASSWORDS" ]]; then
        local pass_count=$(count_lines "$PASSWORDS")
        if [[ -n "$SINGLE_PASS" && -f "$SINGLE_PASS" ]]; then
            echo -e "${GREEN}[+] Passwords: $PASSWORDS ($pass_count passwords) (-P flag, file)${NC}"
        elif [[ -n "$SINGLE_PASS" ]]; then
            echo -e "${GREEN}[+] Password:  $SINGLE_PASS (-P flag)${NC}"
        else
            echo -e "${GREEN}[+] Passwords: $PASSWORDS ($pass_count passwords)${NC}"
        fi
        HAS_PASSWORDS=true
    else
        echo -e "${YELLOW}[○] Passwords: not found${NC}"
    fi

    if [[ -f "$HASHES" ]]; then
        local hash_count=$(count_lines "$HASHES")
        if [[ -n "$SINGLE_HASH" && -f "$SINGLE_HASH" ]]; then
            echo -e "${GREEN}[+] Hashes:    $HASHES ($hash_count hashes) (-H flag, file)${NC}"
        elif [[ -n "$SINGLE_HASH" ]]; then
            echo -e "${GREEN}[+] Hash:      ${SINGLE_HASH:0:32}... (-H flag)${NC}"
        else
            echo -e "${GREEN}[+] Hashes:    $HASHES ($hash_count hashes)${NC}"
        fi
        echo -e "${GRAY}    Format: NT hash only OR LM:NT (NXC accepts both)${NC}"
        HAS_HASHES=true
    else
        echo -e "${YELLOW}[○] Hashes:    not found${NC}"
    fi
    fi  # end -z COMBO_MODE
    
    if [[ "$HAS_USERS" == false ]] && [[ "$HAS_PASSWORDS" == false ]] && [[ "$HAS_HASHES" == false ]]; then
        ANON_ONLY=true
        echo -e "${YELLOW}[!] MODE: Anonymous enumeration + user discovery${NC}"
    elif [[ "$HAS_USERS" == true ]] && [[ "$HAS_PASSWORDS" == false ]] && [[ "$HAS_HASHES" == false ]]; then
        echo -e "${YELLOW}[!] MODE: User enum + AS-REP + -e nsr spray${NC}"
    else
        echo -e "${GREEN}[!] MODE: Full credential spray${NC}"
    fi
    
    if [[ -n "$SINGLE_DOMAIN" ]]; then
        echo -e "${GREEN}[+] Domain:    $DOMAIN (-D flag)${NC}"
    elif [[ -n "$DOMAIN" ]]; then
        echo -e "${GREEN}[+] Domain:    $DOMAIN${NC}"
    else
        echo -e "${YELLOW}[○] Domain:    not set (will auto-detect)${NC}"
    fi
    [[ "$GENERATE_USERS" == true ]] && echo -e "${GREEN}[+] Generate:  username variations enabled (-g)${NC}" || echo -e "${GRAY}[○] Generate:  disabled (use -g to generate username variations)${NC}"
    [[ "$GENERATE_ONLY" == true ]] && echo -e "${GREEN}[+] Mode:      generate-only (no scanning)${NC}"
    [[ "$SKIP_ENUM" == true ]] && echo -e "${GREEN}[+] Fast mode: skipping slow enumeration/modules (RID brute, kerbrute, extras/vuln checks)${NC}" || echo -e "${GRAY}[○] Fast mode: disabled (use -f to skip enumeration)${NC}"
    [[ "$STANDALONE" == true ]] && echo -e "${YELLOW}[+] Standalone: AD enumeration DISABLED (-s) - SMB/SSH/FTP spray only${NC}"
    [[ "$NO_CACHE" == true ]] && echo -e "${YELLOW}[!] No cache:  port scan cache disabled (--no-cache)${NC}" || { [[ -f ".nxc_ports_cache" ]] && echo -e "${GREEN}[+] Port cache: .nxc_ports_cache found (use --no-cache to rescan)${NC}"; }
    
    # Show custom ports if set
    if [[ -n "$CUSTOM_SMB_PORT" || -n "$CUSTOM_FTP_PORT" || -n "$CUSTOM_SSH_PORT" || -n "$CUSTOM_MSSQL_PORT" || -n "$CUSTOM_WINRM_PORT" ]]; then
        echo -e "${YELLOW}[+] Custom ports:${NC}"
        [[ -n "$CUSTOM_SMB_PORT" ]] && echo -e "    ${YELLOW}SMB: $CUSTOM_SMB_PORT${NC}"
        [[ -n "$CUSTOM_FTP_PORT" ]] && echo -e "    ${YELLOW}FTP: $CUSTOM_FTP_PORT${NC}"
        [[ -n "$CUSTOM_SSH_PORT" ]] && echo -e "    ${YELLOW}SSH: $CUSTOM_SSH_PORT${NC}"
        [[ -n "$CUSTOM_MSSQL_PORT" ]] && echo -e "    ${YELLOW}MSSQL: $CUSTOM_MSSQL_PORT${NC}"
        [[ -n "$CUSTOM_WINRM_PORT" ]] && echo -e "    ${YELLOW}WinRM: $CUSTOM_WINRM_PORT${NC}"
    fi
    
    if [[ "$STANDALONE" != true ]]; then
        [[ -n "$KERBRUTE_BIN" ]] && echo -e "${GREEN}[+] Kerbrute:  $KERBRUTE_BIN${NC}" || echo -e "${YELLOW}[○] Kerbrute:  not found (set KERBRUTE=/path/to/kerbrute)${NC}"
    fi
    echo -e "${BLUE}[*] Output:    $OUTDIR/${NC}"
    echo -e "${BLUE}[*] Commands shown with ${GRAY}>> prefix${BLUE} - copy/paste to replicate${NC}"
}

print_startup_overview() {
    # Ik toon hier altijd een korte samenvatting zodat ik direct zie wat fast mode wel/niet doet.
    echo ""
    echo -e "${MAGENTA}┌───────────────────────────────────────────────────────────┐${NC}"
    echo -e "${MAGENTA}│ STARTUP OVERVIEW                                          │${NC}"
    echo -e "${MAGENTA}└───────────────────────────────────────────────────────────┘${NC}"

    # OSCP mode: silently gate active coercion modules
    if [[ "$OSCP_MODE" == true ]]; then
        echo -e "${YELLOW}[*] OSCP mode active — exam-safe enumeration only${NC}"
        echo -e "${GRAY}    Skipped (active exploitation / coercion):${NC}"
        echo -e "${GRAY}      petitpotam, coerce_plus        — active NTLM coercion triggers${NC}"
        echo -e "${GRAY}      secretsdump, --sam/--lsa/--ntds — post-exploit dumps (run manually)${NC}"
        echo -e "${GRAY}      --dpapi, -M lsassy              — post-exploit dumps (run manually)${NC}"
        echo -e "${GRAY}    Runs normally (passive recon + enumeration):${NC}"
        echo -e "${GRAY}      certipy-ad find, nxc -M adcs    — ADCS vulnerability scanning${NC}"
        echo -e "${GRAY}      AS-REP roasting, kerberoasting  — offline hash collection${NC}"
        echo -e "${GRAY}      LDAP dump, SMB shares, RID brute — enumeration${NC}"
        echo -e "      MySQL/MSSQL/PostgreSQL/Redis     — default credential checks (OSCP-safe)${NC}"
        echo ""
    fi

    if [[ "$SKIP_ENUM" == true ]]; then
        echo -e "${GREEN}[+] FAST MODE keeps (main flow):${NC} port checks + protocol spray/checks for smb, winrm, rdp, ssh, ftp, ldap, mssql, wmi"
        echo -e "${GREEN}[+] FAST MODE keeps (visibility only):${NC} vnc, nfs in port scan summary (if configured/open)"
        if [[ "$FORCE_ANON_SCAN" == true ]]; then
            echo -e "${YELLOW}[!] FAST MODE skips:${NC} nsr spray, extras/vuln modules"
            echo -e "${GREEN}[+] --anonymous-scan OVERRIDES fast mode:${NC} anonymous/null/guest enum, RID brute, LDAP user-enum WILL run"
            echo -e "${YELLOW}[!] FAST MODE also skips:${NC} user descriptions (--skip-desc-users), SID/lookupsid enumeration (--skip-domain-sids)"
            echo -e "${GRAY}    Remove -f entirely to also re-enable kerbrute, nsr spray, and extras${NC}"
        else
            echo -e "${YELLOW}[!] FAST MODE skips:${NC} kerbrute validation, anonymous/null/guest enum, RID brute, LDAP user-enum phase, nsr spray, extras/vuln modules"
            echo -e "${YELLOW}[!] FAST MODE also skips:${NC} user descriptions (--skip-desc-users), SID/lookupsid enumeration (--skip-domain-sids)"
            echo -e "${GRAY}    Use --anonymous-scan to re-enable anon/RID/LDAP enum while keeping -f speed${NC}"
            echo -e "${GRAY}    Remove -f entirely to re-enable all enumeration phases${NC}"
        fi
    else
        echo -e "${GREEN}[+] FULL MODE:${NC} main protocol checks + LDAP/user enumeration + slower modules (unless separate skip flags are used)"
    fi

    echo -e "${GRAY}    Tip :${NC} Use ${YELLOW}--no-cache${NC} if targets/services changed."
}

init_files() {
    touch "$OUTDIR/successful_logins.txt" "$OUTDIR/pwned_hosts.txt" "$CREDS_FILE"
    touch "$OUTDIR/kerberoast.txt" "$OUTDIR/asrep.txt" "$OUTDIR/null_sessions.txt"
    touch "$OUTDIR/anon_access.txt" "$ALL_USERS" "$ENUM_USERS"
    
    [[ -f "$USERS" ]] && cat "$USERS" >> "$ALL_USERS"
    
    cat > "$HYDRA_CMDS" << 'EOF'
# Auto-genereerd Hydra commandoo's
# Run: bash this_file.sh

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

EOF
    chmod +x "$HYDRA_CMDS"
}

# ============================================================================
# Credentials parsen
# ============================================================================
