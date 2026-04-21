#!/bin/bash
# MODULE: extras.sh - Advanced/vuln-only checks (--extras-only mode)

run_extras_only() {
    # Use global TARGET_ARG (set by validate() from -T flag or targets.txt).
    # Fall back to TARGET_IP for backward compatibility.
    local TARGET_ARG="${TARGET_ARG:-${TARGET_IP:-}}"
    # Ik bouw auth-argumenten uit de opgegeven CLI-input (USERS/PASSWORDS/HASHES).
    local AUTH_ARGS=""
    if [[ -n "$USERS" ]]; then
        if [[ -n "$HASHES" ]]; then
            AUTH_ARGS="-u '$USERS' -H '$HASHES'"
        elif [[ -n "$PASSWORDS" ]]; then
            AUTH_ARGS="-u '$USERS' -p '$PASSWORDS'"
        fi
    elif [[ -n "$SINGLE_USER" ]]; then
        if [[ -n "$SINGLE_HASH" ]]; then
            AUTH_ARGS="-u '$SINGLE_USER' -H '$SINGLE_HASH'"
        elif [[ -n "$SINGLE_PASS" ]]; then
            AUTH_ARGS="-u '$SINGLE_USER' -p '$SINGLE_PASS'"
        fi
    fi

    # Ik draai SMB-gerichte extras.
    if [[ -s "$OUTDIR/targets_smb.txt" ]]; then
        echo -e "\n${CYAN}[*] EXTRAS: SMB vuln/modules...${NC}"
        run_cmd "sudo nxc smb $OUTDIR/targets_smb.txt $AUTH_ARGS -M ms17-010 $NXC_WORKERS_FLAG" "$OUTDIR/extras_ms17-010.txt"
        run_cmd "sudo nxc smb $OUTDIR/targets_smb.txt $AUTH_ARGS -M smbghost $NXC_WORKERS_FLAG" "$OUTDIR/extras_smbghost.txt"
        run_cmd "sudo nxc smb $OUTDIR/targets_smb.txt $AUTH_ARGS -M zerologon $NXC_WORKERS_FLAG" "$OUTDIR/extras_zerologon.txt"
        run_cmd "sudo nxc smb $OUTDIR/targets_smb.txt $AUTH_ARGS -vulnerable -stdout $NXC_WORKERS_FLAG" "$OUTDIR/extras_vulnerable.txt"
        run_cmd "sudo nxc smb $OUTDIR/targets_smb.txt $AUTH_ARGS -M spooler $NXC_WORKERS_FLAG" "$OUTDIR/extras_spooler.txt"
        run_cmd "sudo nxc smb $OUTDIR/targets_smb.txt $AUTH_ARGS -M webdav $NXC_WORKERS_FLAG" "$OUTDIR/extras_webdav.txt"
        run_cmd "sudo nxc smb $OUTDIR/targets_smb.txt $AUTH_ARGS -M veeam $NXC_WORKERS_FLAG" "$OUTDIR/extras_veeam.txt"
        run_cmd "sudo nxc smb $OUTDIR/targets_smb.txt $AUTH_ARGS -M reg-winlogon $NXC_WORKERS_FLAG" "$OUTDIR/extras_reg-winlogon.txt"
        # petitpotam / coerce_plus: actively trigger NTLM auth coercion (not just a check)
        # Skipped in --oscp mode - these send live exploitation requests, not passive probes
        if [[ "$OSCP_MODE" == true ]]; then
            echo -e "${YELLOW}[OSCP] Skipping -M petitpotam (active coercion) - run manually outside exam:${NC}"
            echo -e "${GRAY}  >> sudo nxc smb $OUTDIR/targets_smb.txt $AUTH_ARGS -M petitpotam${NC}"
            echo -e "${YELLOW}[OSCP] Skipping -M coerce_plus (active coercion) - run manually outside exam:${NC}"
            echo -e "${GRAY}  >> sudo nxc smb $OUTDIR/targets_smb.txt $AUTH_ARGS -M coerce_plus${NC}"
        else
            run_cmd "sudo nxc smb $OUTDIR/targets_smb.txt $AUTH_ARGS -M petitpotam $NXC_WORKERS_FLAG" "$OUTDIR/extras_petitpotam.txt"
            run_cmd "sudo nxc smb $OUTDIR/targets_smb.txt $AUTH_ARGS -M coerce_plus $NXC_WORKERS_FLAG" "$OUTDIR/extras_coerce_plus.txt"
        fi
        run_cmd "sudo nxc smb $OUTDIR/targets_smb.txt $AUTH_ARGS -M nopac $NXC_WORKERS_FLAG" "$OUTDIR/extras_nopac.txt"
        run_cmd "sudo nxc smb $OUTDIR/targets_smb.txt $AUTH_ARGS -M pre2k $NXC_WORKERS_FLAG" "$OUTDIR/extras_pre2k.txt"
    fi

    # Ik draai MSSQL-gerichte extras.
    if [[ -s "$OUTDIR/targets_mssql.txt" ]]; then
        echo -e "\n${CYAN}[*] EXTRAS: MSSQL modules...${NC}"
        # mssql_priv: checks SA role, xp_cmdshell, impersonation, db_owner for privilege escalation
        run_cmd "sudo nxc mssql $OUTDIR/targets_mssql.txt $AUTH_ARGS -M mssql_priv $NXC_WORKERS_FLAG" "$OUTDIR/extras_mssql_priv.txt"
        # Try SQL auth (--local-auth) variants as well
        run_cmd "sudo nxc mssql $OUTDIR/targets_mssql.txt $AUTH_ARGS --local-auth -M mssql_priv $NXC_WORKERS_FLAG" "$OUTDIR/extras_mssql_priv_sqlauth.txt"
        # Check for linked servers (lateral movement)
        run_cmd "sudo nxc mssql $OUTDIR/targets_mssql.txt $AUTH_ARGS -q 'SELECT name, product, provider, data_source FROM sys.servers;' $NXC_WORKERS_FLAG" "$OUTDIR/extras_mssql_linked_servers.txt"
        if grep -qi "1 rows" "$OUTDIR/extras_mssql_linked_servers.txt" 2>/dev/null; then
            echo -e "${RED}[!] Linked servers found! Check extras_mssql_linked_servers.txt${NC}"
        fi
        # xp_cmdshell status
        run_cmd "sudo nxc mssql $OUTDIR/targets_mssql.txt $AUTH_ARGS -q 'SELECT name, CAST(value_in_use AS INT) AS enabled FROM sys.configurations WHERE name = '\''xp_cmdshell'\'';' $NXC_WORKERS_FLAG" "$OUTDIR/extras_mssql_xpcmdshell.txt"
        if grep -qi "1" "$OUTDIR/extras_mssql_xpcmdshell.txt" 2>/dev/null; then
            echo -e "${RED}[!] xp_cmdshell is ENABLED on MSSQL! RCE possible.${NC}"
            echo -e "${GRAY}    >> nxc mssql target -u user -p pass -x 'whoami'${NC}"
        fi
    fi

    # Ik draai LDAP-gerichte extras.
    if [[ -s "$OUTDIR/targets_ldap.txt" ]]; then
        echo -e "\n${CYAN}[*] EXTRAS: LDAP modules...${NC}"
        run_cmd "sudo nxc ldap $OUTDIR/targets_ldap.txt $LDAP_PORT_FLAG $AUTH_ARGS -M ldap-checker $NXC_WORKERS_FLAG" "$OUTDIR/extras_ldap-checker.txt"
        run_cmd "sudo nxc ldap $OUTDIR/targets_ldap.txt $LDAP_PORT_FLAG $AUTH_ARGS --gmsa $NXC_WORKERS_FLAG" "$OUTDIR/extras_gmsa.txt"
        run_cmd "sudo nxc ldap $OUTDIR/targets_ldap.txt $LDAP_PORT_FLAG $AUTH_ARGS --find-delegation $NXC_WORKERS_FLAG" "$OUTDIR/extras_find-delegation.txt"
        run_cmd "sudo nxc ldap $OUTDIR/targets_ldap.txt $LDAP_PORT_FLAG $AUTH_ARGS --trusted-for-delegation $NXC_WORKERS_FLAG" "$OUTDIR/extras_trusted-for-delegation.txt"
        run_cmd "sudo nxc ldap $OUTDIR/targets_ldap.txt $LDAP_PORT_FLAG $AUTH_ARGS --password-not-required $NXC_WORKERS_FLAG" "$OUTDIR/extras_password-not-required.txt"
        run_cmd "sudo nxc ldap $OUTDIR/targets_ldap.txt $LDAP_PORT_FLAG $AUTH_ARGS --admin-count $NXC_WORKERS_FLAG" "$OUTDIR/extras_admin-count.txt"
        run_cmd "sudo nxc ldap $OUTDIR/targets_ldap.txt $LDAP_PORT_FLAG $AUTH_ARGS -M adcs $NXC_WORKERS_FLAG" "$OUTDIR/extras_adcs.txt"
        run_cmd "sudo nxc ldap $OUTDIR/targets_ldap.txt $LDAP_PORT_FLAG $AUTH_ARGS -M laps $NXC_WORKERS_FLAG" "$OUTDIR/extras_laps.txt"
        # Ik gebruik impacket findDelegation (als het domein bekend is).
        if [[ -n "$DOMAIN" ]]; then
            run_cmd "impacket-findDelegation '$DOMAIN/' -dc-ip '$DC_IP'" "$OUTDIR/extras_impacket-findDelegation.txt"
        fi
    fi

    echo -e "\n${GREEN}[+] EXTRAS-ONLY complete. Outputs are in: $OUTDIR${NC}"
}
