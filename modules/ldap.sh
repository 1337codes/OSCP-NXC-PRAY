#!/bin/bash
# MODULE: ldap.sh - LDAP highlight, show_results, Phase 4.2 dump, retry dump

# Colour codes used only inside this module
ORANGE='\033[0;33m'
_RED='\033[0;31m'
_GREEN='\033[0;32m'
_CYAN='\033[0;36m'
_GRAY='\033[0;37m'
_NC='\033[0m'
_WHITE='\033[1;37m'

_LDAP_DUMP_DONE=false

ldap_highlight() {
    local infile="$1"
    [[ -f "$infile" ]] || return

    # Known-normal AD/LDIF attributes — dim these, they're structural noise
    local _NORM="dn|objectclass|objectcategory|objectguid|objectsid|whencreated|whenchanged|usnchanged|usncreated|instancetype|distinguishedname|dscorepropagationdata|lastlogontimestamp|lastlogon|lastlogoff|badpasswordtime|badpwdcount|codepage|countrycode|primarygroupid|logonhours|userworkstations|profilepath|scriptpath|homedirectory|homedrive|ref|userprincipalname|displayname|givenname|sn|mail|proxyaddresses|department|title|company|streetaddress|postalcode|l|st|co|physicaldeliveryofficename|telephonenumber|facsimiletelephonenumber|mobile|pager|ipphone|member|memberof|samaccountname|cn|dnshostname|operatingsystem|operatingsystemversion|useraccountcontrol|admincount|serviceprincipalname|pwdlastset|lastlogon|logoncount|pwdlastset|logoncount"

    # Track whether current LDIF entry is a machine account (sAMAccountName ends with $)
    # Machine account SPNs are expected/normal; user account SPNs are kerberoastable
    local _is_machine=false

    while IFS= read -r _line; do
        # ── Comment / header lines → dim gray ─────────────────────────────
        if [[ "$_line" =~ ^#.*$ ]]; then
            echo -e "${_GRAY}${_line}${_NC}"
            continue
        fi

        # ── Blank lines → reset machine-account tracker ────────────────────
        if [[ -z "$_line" ]]; then
            echo ""
            _is_machine=false
            continue
        fi

        # ── LDIF folded continuation lines → dim ───────────────────────────
        if [[ "$_line" =~ ^[[:space:]] ]]; then
            echo -e "${_GRAY}${_line}${_NC}"
            continue
        fi

        # ── Parse attribute name (lowercase) and value ─────────────────────
        local _attr _val
        _attr=$(echo "$_line" | cut -d: -f1 | tr '[:upper:]' '[:lower:]')
        _val=$(echo "$_line" | cut -d: -f2- | sed 's/^:* //')

        # ── Track machine accounts (sAMAccountName ending in $) ───────────
        if [[ "$_attr" == "samaccountname" ]]; then
            if [[ "$_val" =~ \$[[:space:]]*$ ]]; then
                _is_machine=true
            else
                _is_machine=false
            fi
        fi

        # ══ TIER 1 — RED: Immediate action / high value ══════════════════

        # Password attributes stored directly in the directory
        if [[ "$_attr" =~ ^(userpassword|unicodepwd|msds-managedpassword|msds-managedpasswordid|currentvalue|supplementalcredentials)$ ]]; then
            echo -e "${_RED}${_line}  ◄ PASSWORD ATTRIBUTE${_NC}"
            continue
        fi

        # adminCount=1 → privileged account
        if [[ "$_attr" == "admincount" && "$_val" =~ ^[[:space:]]*1 ]]; then
            echo -e "${_RED}${_line}  ◄ PRIVILEGED (adminCount=1)${_NC}"
            continue
        fi

        # memberOf — only high-priv groups in RED, the rest dimmed
        if [[ "$_attr" == "memberof" ]]; then
            if echo "$_val" | grep -qiE '(Domain Admins|Enterprise Admins|Schema Admins|Administrators|Backup Operators|Account Operators|Server Operators|Print Operators|Remote Management)'; then
                echo -e "${_RED}${_line}  ◄ HIGH-PRIV GROUP${_NC}"
            else
                echo -e "${_GRAY}${_line}${_NC}"
            fi
            continue
        fi

        # servicePrincipalName — RED for user accounts (kerberoastable), ORANGE for machine accounts (expected/normal)
        if [[ "$_attr" == "serviceprincipalname" ]]; then
            if [[ "$_is_machine" == true ]]; then
                echo -e "${ORANGE}${_line}  ◄ SPN → MACHINE ACCT (normal)${_NC}"
            else
                echo -e "${_RED}${_line}  ◄ SPN → KERBEROASTABLE${_NC}"
            fi
            continue
        fi

        # ══ TIER 2 — WHITE: Interesting, read carefully ═══════════════════

        # The money fields: free-text notes operators leave in the directory.
        # Tightened regex: require credential keyword adjacent to an assignment character
        # (: or =), or a (default|temp|initial|welcome) prefix before a pass/pwd/cred keyword.
        # This avoids false positives from AD boilerplate like "Key Distribution Center",
        # "passwords replicated", "tokenGroupsGlobal", "logon remotely", "key objects", etc.
        if [[ "$_attr" =~ ^(info|comment|notes|description)$ ]]; then
            if echo "$_val" | grep -qiE \
               '\b(pass(w(or)?d)?|pwd|passwd)[[:space:]]*[:=]|\bsecret[[:space:]]*[:=]|\bcred(ential)?[[:space:]]*[:=]|\b(default|temp|initial|welcome)[[:space:]]+(pass|pwd|cred|password)\b|password[[:space:]]+is[[:space:]]+\S{4}'; then
                echo -e "${_RED}${_line}  ◄ POSSIBLE CREDENTIAL${_NC}"
            else
                echo -e "${_WHITE}${_line}  ◄ NOTE${_NC}"
            fi
            continue
        fi

        # userAccountControl — decode flags; highlight attack-relevant combos
        if [[ "$_attr" == "useraccountcontrol" ]]; then
            local _uac _uac_str=""
            _uac=$(echo "$_val" | tr -d ' ')
            (( _uac & 2       )) && _uac_str+="DISABLED "
            (( _uac & 16      )) && _uac_str+="LOCKOUT "
            (( _uac & 32      )) && _uac_str+="PASSWD_NOTREQD "
            (( _uac & 64      )) && _uac_str+="PASSWD_CANT_CHANGE "
            (( _uac & 512     )) && _uac_str+="NORMAL_ACCOUNT "
            (( _uac & 65536   )) && _uac_str+="DONT_EXPIRE_PASSWORD "
            (( _uac & 4194304 )) && _uac_str+="DONT_REQ_PREAUTH "
            if echo "$_uac_str" | grep -qE 'PASSWD_NOTREQD|DONT_REQ_PREAUTH'; then
                echo -e "${_WHITE}${_line}  ← ${_uac_str}${_NC}"
            elif [[ -n "$_uac_str" ]]; then
                echo -e "${_GRAY}${_line}  ← ${_uac_str}${_NC}"
            else
                echo -e "${_GRAY}${_line}${_NC}"
            fi
            continue
        fi

        # sAMAccountName / CN / dNSHostName — identity anchors, show clearly
        if [[ "$_attr" =~ ^(samaccountname|cn|dnshostname)$ ]]; then
            echo -e "${_WHITE}${_line}${_NC}"
            continue
        fi

        # Base64-encoded values (attribute:: value) — could hide anything
        if [[ "$_line" =~ ^[a-zA-Z]+::[[:space:]] ]]; then
            echo -e "${_WHITE}${_line}  ◄ BASE64-ENCODED${_NC}"
            continue
        fi

        # Unknown / non-standard attribute → WHITE (custom schema extensions = juicy)
        if ! echo "$_attr" | grep -qiE "^(${_NORM})$"; then
            echo -e "${_WHITE}${_line}  ◄ CUSTOM ATTR${_NC}"
            continue
        fi

        # ══ TIER 3 — DIM GRAY: Normal structural noise, safe to skim ════
        echo -e "${_GRAY}${_line}${_NC}"

    done < "$infile"
}


ldap_show_results() {
    local _rawfile="$1"
    local _label="$2"
    [[ -s "$_rawfile" ]] || return

    local _obj_count
    _obj_count=$(grep -c "^dn:" "$_rawfile" 2>/dev/null); _obj_count=${_obj_count:-0}
    local _info_count
    _info_count=$(grep -ci "^info:" "$_rawfile" 2>/dev/null); _info_count=${_info_count:-0}
    local _desc_count
    _desc_count=$(grep -ci "^description:" "$_rawfile" 2>/dev/null); _desc_count=${_desc_count:-0}
    local _spn_count
    _spn_count=$(grep -ci "^servicePrincipalName:" "$_rawfile" 2>/dev/null); _spn_count=${_spn_count:-0}
    local _cred_hint
    # Tightened: only count lines with a credential keyword adjacent to an assignment (:=)
    # or a (default|temp|initial|welcome) prefix pattern — avoids boilerplate false positives
    _cred_hint=$(grep -cEi '(pass(w(or)?d)?|pwd|passwd)[[:space:]]*[:=]|secret[[:space:]]*[:=]|cred[[:space:]]*[:=]|(default|temp|initial|welcome)[[:space:]]+(pass|pwd|cred|password)' "$_rawfile" 2>/dev/null); _cred_hint=${_cred_hint:-0}

    echo -e "\n${_GREEN}[+] $_label: ${_obj_count} objects${_NC}"
    [[ "$_info_count"  -gt 0 ]] && echo -e "    ${ORANGE}► ${_info_count} info: attribute(s)  ◄ READ THESE${_NC}"
    [[ "$_desc_count"  -gt 0 ]] && echo -e "    ${ORANGE}► ${_desc_count} description attribute(s)${_NC}"
    [[ "$_spn_count"   -gt 0 ]] && echo -e "    ${_RED}► ${_spn_count} SPN(s) found - potential Kerberoast targets${_NC}"
    [[ "$_cred_hint"   -gt 0 ]] && echo -e "    ${_RED}► ${_cred_hint} line(s) with possible credential keywords${_NC}"

    echo -e "\n${_CYAN}── Highlighted dump: ${_rawfile} ──────────────────────────────${_NC}"
    ldap_highlight "$_rawfile"
    echo -e "${_CYAN}── End of dump ───────────────────────────────────────────────${_NC}"
}


ldap_dump_phase42() {
if [[ "$FAST_MODE" == true ]] && [[ "$LDAP_ONLY" != true ]]; then
    echo -e "\n${YELLOW}[!] Skipping PHASE 4.2: LDAP full dump (-f fast mode - remove -f to enable)${NC}"
elif [[ -n "$DOMAIN" ]] && [[ "$STANDALONE" != true ]] && \
   { [[ -s "$OUTDIR/targets_ldap.txt" ]] || [[ -s "$OUTDIR/targets_ldaps.txt" ]]; } && \
   command -v ldapsearch &>/dev/null; then

    echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║  PHASE 4.2: LDAPSEARCH - FULL DOMAIN DUMP                 ║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}"

    # Build base DN from domain (support.htb → DC=support,DC=htb)
    _BASE_DN=""
    _BASE_DN=$(echo "$DOMAIN" | awk -F'.' '{for(i=1;i<=NF;i++) printf "DC=%s%s", $i, (i<NF?",":""); print ""}')

    _LDAP_HOST="$DC_IP"
    # Always try plain ldap:// first (ldaps TLS certs often fail on HTB/PG)
    # ldaps is used only if ldap:389 is unavailable
    if [[ -s "$OUTDIR/targets_ldap.txt" ]]; then
        _LDAP_PROTO="ldap"
    elif [[ "$LDAPS_AVAILABLE" == true ]]; then
        _LDAP_PROTO="ldaps"
    else
        _LDAP_PROTO="ldap"
    fi
    _LDAP_URI="${_LDAP_PROTO}://${_LDAP_HOST}"

    # ── Try auth methods in order ──────────────────────────────────────────
    _ldap_authed=false
    _ldap_auth_label=""
    _ldap_auth_args=""   # kept for queue_phase_cmd display only
    _ldap_bind_dn=""     # actual bind DN passed directly to ldapsearch (no eval)
    _ldap_bind_pw=""     # actual bind password passed directly to ldapsearch (no eval)

    # Helper: test if ldapsearch output indicates a successful bind
    # _ldap_bind_ok: verify both bind AND read access using a real ldapsearch.
    # ldapwhoami only tests the TCP bind - many DCs (incl. AD) allow anonymous bind
    # but block anonymous searches, giving a false positive. A real base search confirms
    # the creds can actually read the directory.
    _ldap_bind_ok() {
        local _uri="$1" _bind_dn="$2" _bind_pw="$3"
        local _out
        # Primary: test with real base search (confirms read access, not just bind)
        _out=$(LDAPTLS_REQCERT=never ldapsearch -x -H "$_uri" \
            ${_bind_dn:+-D "$_bind_dn"} ${_bind_pw:+-w "$_bind_pw"} \
            -b "$_BASE_DN" -s base "(objectClass=*)" 2>&1 | head -20)
        echo "$_out" | grep -qE "^dn:|numEntries:|result: 0 Success" && return 0
        # Fallback: if URI was ldaps://, also try plain ldap://
        if [[ "$_uri" == ldaps://* ]]; then
            local _plain_uri="ldap://${_uri#ldaps://}"
            _out=$(LDAPTLS_REQCERT=never ldapsearch -x -H "$_plain_uri" \
                ${_bind_dn:+-D "$_bind_dn"} ${_bind_pw:+-w "$_bind_pw"} \
                -b "$_BASE_DN" -s base "(objectClass=*)" 2>&1 | head -20)
            echo "$_out" | grep -qE "^dn:|numEntries:|result: 0 Success" && return 0
        fi
        return 1
    }

    # Method 1: null bind (empty DN + empty password)
    echo -e "\n${_CYAN}[*] LDAP null bind attempt...${_NC}"
    if _ldap_bind_ok "$_LDAP_URI" "" ""; then
        _ldap_auth_label="null bind"
        _ldap_auth_args='-D "" -w ""'
        _ldap_bind_dn=""; _ldap_bind_pw=""
        _ldap_authed=true
        echo -e "${_GREEN}[+] Null bind succeeded!${_NC}"
    else
        echo -e "${_GRAY}[-] Null bind failed${_NC}"
    fi

    # Method 2: anonymous (no -D/-w at all) - test via ldapsearch directly
    if [[ "$_ldap_authed" == false ]]; then
        echo -e "${_CYAN}[*] LDAP anonymous bind attempt...${_NC}"
        _anon_test=$(LDAPTLS_REQCERT=never ldapsearch -x -H "$_LDAP_URI" \
            -b "$_BASE_DN" -s base "(objectClass=*)" 2>&1 | head -20)
        if echo "$_anon_test" | grep -qE "^dn:|numEntries:|result: 0 Success"; then
            _ldap_auth_label="anonymous"
            _ldap_auth_args=""
            _ldap_bind_dn=""; _ldap_bind_pw=""
            _ldap_authed=true
            echo -e "${_GREEN}[+] Anonymous bind succeeded!${_NC}"
        else
            echo -e "${_GRAY}[-] Anonymous bind failed${_NC}"
        fi
    fi

    # Method 3: guest account
    if [[ "$_ldap_authed" == false ]]; then
        echo -e "${_CYAN}[*] LDAP guest bind attempt...${_NC}"
        if _ldap_bind_ok "$_LDAP_URI" "guest@${DOMAIN}" ""; then
            _ldap_auth_label="guest@${DOMAIN}"
            _ldap_auth_args="-D \"guest@${DOMAIN}\" -w \"\""
            _ldap_bind_dn="guest@${DOMAIN}"; _ldap_bind_pw=""
            _ldap_authed=true
            echo -e "${_GREEN}[+] Guest bind succeeded!${_NC}"
        else
            echo -e "${_GRAY}[-] Guest bind failed${_NC}"
        fi
    fi

    # Method 4: credentials from input files - loop all users x all passwords
    if [[ "$_ldap_authed" == false ]] && [[ -s "$USERS" ]] && [[ -s "$PASSWORDS" ]]; then
        echo -e "${_CYAN}[*] LDAP authenticated bind (trying input credentials)...${_NC}"
        echo -e "${_GRAY}    USERS file:     $USERS ($(wc -l < "$USERS") lines)${_NC}"
        echo -e "${_GRAY}    PASSWORDS file: $PASSWORDS ($(wc -l < "$PASSWORDS") lines)${_NC}"
        while IFS= read -r _inp_user && [[ "$_ldap_authed" == false ]]; do
            [[ -z "$_inp_user" ]] && continue
            # Skip machine accounts and known-bad accounts for LDAP bind
            [[ "$_inp_user" == *'$' || "$_inp_user" == "Guest" || "$_inp_user" == "krbtgt" ]] && continue
            while IFS= read -r _inp_pass && [[ "$_ldap_authed" == false ]]; do
                [[ -z "$_inp_pass" ]] && continue
                echo -e "${_GRAY}    Trying: ${_inp_user}@${DOMAIN}${_NC}"
                if _ldap_bind_ok "$_LDAP_URI" "${_inp_user}@${DOMAIN}" "$_inp_pass"; then
                    _ldap_auth_label="${_inp_user}@${DOMAIN} (input file)"
                    _ldap_auth_args="-D \"${_inp_user}@${DOMAIN}\" -w \"${_inp_pass}\""
                    _ldap_bind_dn="${_inp_user}@${DOMAIN}"; _ldap_bind_pw="$_inp_pass"
                    _ldap_authed=true
                    echo -e "${_GREEN}[+] Authenticated bind succeeded as ${_inp_user}!${_NC}"
                fi
            done < "$PASSWORDS"
        done < "$USERS"
        [[ "$_ldap_authed" == false ]] && echo -e "${_GRAY}[-] Input credentials failed${_NC}"
    fi

    # Method 5: first valid credential from found_creds.txt (--extras-only / re-run)
    if [[ "$_ldap_authed" == false ]] && [[ -s "$CREDS_FILE" ]]; then
        echo -e "${_CYAN}[*] LDAP authenticated bind (using found credential)...${_NC}"
        _fc_line=$(head -1 "$CREDS_FILE")
        IFS='|' read -r _ _ _fc_domain _fc_user _fc_secret _ _fc_type _ <<< "$_fc_line"
        if [[ "$_fc_type" != "hash" ]] && [[ -n "$_fc_user" ]] && [[ -n "$_fc_secret" ]]; then
            if _ldap_bind_ok "$_LDAP_URI" "${_fc_user}@${DOMAIN}" "$_fc_secret"; then
                _ldap_auth_label="${_fc_user}@${DOMAIN}"
                _ldap_auth_args="-D \"${_fc_user}@${DOMAIN}\" -w \"${_fc_secret}\""
                _ldap_bind_dn="${_fc_user}@${DOMAIN}"; _ldap_bind_pw="$_fc_secret"
                _ldap_authed=true
                echo -e "${_GREEN}[+] Authenticated bind succeeded as ${_fc_user}!${_NC}"
            fi
        fi
    fi

    # Method 6: CWD found_creds.txt (copied from previous run) - catches re-runs without --extras-only
    if [[ "$_ldap_authed" == false ]] && [[ -s "./found_creds.txt" ]]; then
        echo -e "${_CYAN}[*] LDAP authenticated bind (using ./found_creds.txt from previous run)...${_NC}"
        while IFS='|' read -r _ _ _cwd_domain _cwd_user _cwd_secret _ _cwd_type _ && [[ "$_ldap_authed" == false ]]; do
            [[ "$_cwd_type" == "hash" ]] && continue
            [[ -z "$_cwd_user" || -z "$_cwd_secret" ]] && continue
            if _ldap_bind_ok "$_LDAP_URI" "${_cwd_user}@${DOMAIN}" "$_cwd_secret"; then
                _ldap_auth_label="${_cwd_user}@${DOMAIN} (found_creds.txt)"
                _ldap_auth_args="-D \"${_cwd_user}@${DOMAIN}\" -w \"${_cwd_secret}\""
                _ldap_bind_dn="${_cwd_user}@${DOMAIN}"; _ldap_bind_pw="$_cwd_secret"
                _ldap_authed=true
                echo -e "${_GREEN}[+] Authenticated bind succeeded as ${_cwd_user}!${_NC}"
            fi
        done < "./found_creds.txt"
        [[ "$_ldap_authed" == false ]] && echo -e "${_GRAY}[-] CWD found_creds.txt credentials failed${_NC}"
    fi

    if [[ "$_ldap_authed" == false ]]; then
        echo -e "${ORANGE}[!] All LDAP bind methods failed - cannot enumerate via ldapsearch${_NC}"
        echo -e "${_GRAY}    Try manually: ldapsearch -x -H ldap://$_LDAP_HOST -b '$_BASE_DN' '(objectClass=user)'${_NC}"
    else
        echo -e "${_GREEN}[+] Using: ${_ldap_auth_label}${_NC}"
        echo -e "${_GRAY}    Base DN: $_BASE_DN${_NC}"

        # ── Query 1: All users ──────────────────────────────────────────
        echo -e "\n${_CYAN}[*] Querying all users...${_NC}"
        _users_ldif="$OUTDIR/ldap_users.ldif"
        queue_phase_cmd "ldapsearch -x -H $_LDAP_URI $_ldap_auth_args -b '$_BASE_DN' '(objectClass=user)'"
        LDAPTLS_REQCERT=never ldapsearch -x -H "$_LDAP_URI" \
            ${_ldap_bind_dn:+-D "$_ldap_bind_dn"} \
            ${_ldap_bind_pw:+-w "$_ldap_bind_pw"} \
            -b "$_BASE_DN" \
            '(objectClass=user)' \
            sAMAccountName cn description info comment \
            memberOf adminCount userAccountControl \
            servicePrincipalName mail pwdLastSet logonCount \
            2>/dev/null | tee "$_users_ldif" > /dev/null
        ldap_show_results "$_users_ldif" "Users"

        # ── Query 2: All computers ──────────────────────────────────────
        echo -e "\n${_CYAN}[*] Querying computers...${_NC}"
        _comp_ldif="$OUTDIR/ldap_computers.ldif"
        queue_phase_cmd "ldapsearch -x -H $_LDAP_URI $_ldap_auth_args -b '$_BASE_DN' '(objectClass=computer)'"
        LDAPTLS_REQCERT=never ldapsearch -x -H "$_LDAP_URI" \
            ${_ldap_bind_dn:+-D "$_ldap_bind_dn"} \
            ${_ldap_bind_pw:+-w "$_ldap_bind_pw"} \
            -b "$_BASE_DN" \
            '(objectClass=computer)' \
            cn dNSHostName operatingSystem description info \
            2>/dev/null | tee "$_comp_ldif" > /dev/null
        ldap_show_results "$_comp_ldif" "Computers"

        # ── Query 3: Groups ─────────────────────────────────────────────
        echo -e "\n${_CYAN}[*] Querying groups...${_NC}"
        _groups_ldif="$OUTDIR/ldap_groups.ldif"
        queue_phase_cmd "ldapsearch -x -H $_LDAP_URI $_ldap_auth_args -b '$_BASE_DN' '(objectClass=group)'"
        LDAPTLS_REQCERT=never ldapsearch -x -H "$_LDAP_URI" \
            ${_ldap_bind_dn:+-D "$_ldap_bind_dn"} \
            ${_ldap_bind_pw:+-w "$_ldap_bind_pw"} \
            -b "$_BASE_DN" \
            '(objectClass=group)' \
            cn description member info \
            2>/dev/null | tee "$_groups_ldif" > /dev/null
        ldap_show_results "$_groups_ldif" "Groups"

        # ── Combined info:/description highlight summary ─────────────────
        echo -e "\n${ORANGE}╔═══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${ORANGE}║  LDAP INTERESTING FIELDS - info: / description: / creds   ║${NC}"
        echo -e "${ORANGE}╚═══════════════════════════════════════════════════════════╝${NC}"

        # info: fields
        _info_lines=$(grep -h -i "^info:\|^comment:" \
            "$OUTDIR/ldap_users.ldif" \
            "$OUTDIR/ldap_computers.ldif" \
            "$OUTDIR/ldap_groups.ldif" 2>/dev/null | sort -u)
        if [[ -n "$_info_lines" ]]; then
            echo -e "${ORANGE}[!] info:/comment: attribute values:${_NC}"
            while IFS= read -r _il; do
                echo -e "    ${ORANGE}${_il}${_NC}"
            done <<< "$_info_lines"
        else
            echo -e "${_GRAY}[-] No info: or comment: attributes found${_NC}"
        fi

        # description: fields
        _desc_lines=$(grep -h -i "^description:" \
            "$OUTDIR/ldap_users.ldif" \
            "$OUTDIR/ldap_computers.ldif" \
            "$OUTDIR/ldap_groups.ldif" 2>/dev/null | sort -u)
        if [[ -n "$_desc_lines" ]]; then
            echo -e "${ORANGE}[!] description: attribute values:${_NC}"
            while IFS= read -r _dl; do
                # Tightened regex — same as ldap_highlight: require credential keyword
                # adjacent to an assignment character or a (default|temp|initial|welcome) prefix.
                # Avoids boilerplate: "Key Distribution Center", "passwords replicated",
                # "tokenGroups", "logon remotely", "key objects", etc.
                if echo "$_dl" | grep -qiE \
                   '\b(pass(w(or)?d)?|pwd|passwd)[[:space:]]*[:=]|\bsecret[[:space:]]*[:=]|\bcred(ential)?[[:space:]]*[:=]|\b(default|temp|initial|welcome)[[:space:]]+(pass|pwd|cred|password)\b|password[[:space:]]+is[[:space:]]+\S{4}'; then
                    echo -e "    ${_RED}${_dl}  ◄ POSSIBLE CREDENTIAL${_NC}"
                else
                    echo -e "    ${ORANGE}${_dl}${_NC}"
                fi
            done <<< "$_desc_lines"
        else
            echo -e "${_GRAY}[-] No description: attributes found${_NC}"
        fi

        # Users with SPN (Kerberoastable) — exclude machine accounts ($) and disabled accounts
        # Kerberoasting: request a service ticket for the account, offline-crack its password hash.
        # OSCP-safe: collecting the hash is passive. Cracking happens locally.
        # Only ENABLED user accounts are realistic targets.

        # Parse LDIF entries with awk to correctly correlate SPN + UAC + sAMAccountName
        # (UAC comes BEFORE sAMAccountName in LDIF, so grep -A/B won't work reliably)
        _spn_parse_result=$(awk '
            /^$/ { if (spn && !machine && sam) {
                    if (uac+0 != 0 && (uac+0) % 4 >= 2) { print "DISABLED " sam }
                    else { print "ENABLED " sam }
                }
                spn=0; machine=0; sam=""; uac=0
            }
            /^sAMAccountName:/ { sam=$2; if (sam ~ /\$$/) machine=1 }
            /^servicePrincipalName:/ { spn=1 }
            /^userAccountControl:/ { uac=$2 }
            END { if (spn && !machine && sam) {
                    if (uac+0 != 0 && (uac+0) % 4 >= 2) { print "DISABLED " sam }
                    else { print "ENABLED " sam }
                }
            }
        ' "$OUTDIR/ldap_users.ldif" 2>/dev/null)

        _spn_users=""
        _spn_disabled=""
        while IFS= read -r _spr; do
            _spr_state=$(echo "$_spr" | awk '{print $1}')
            _spr_name=$(echo "$_spr" | awk '{print $2}')
            if [[ "$_spr_state" == "DISABLED" ]]; then
                _spn_disabled="${_spn_disabled}sAMAccountName: ${_spr_name} [DISABLED — not exploitable]\n"
            else
                _spn_users="${_spn_users}sAMAccountName: ${_spr_name}\n"
            fi
        done <<< "$_spn_parse_result"

        if [[ -n "$_spn_users" ]]; then
            echo -e "${_RED}[!] User accounts with SPN (Kerberoastable — ENABLED):${_NC}"
            echo -e "${_GRAY}    What: request a service ticket → get a crackable hash → crack offline${_NC}"
            echo -e "${_GRAY}    How:  impacket-GetUserSPNs DOMAIN/user:pass -dc-ip DC -request -outputfile kerb.txt${_NC}"
            echo -e "${_GRAY}    Crack: hashcat -m 13100 kerb.txt /usr/share/wordlists/rockyou.txt${_NC}"
            printf "${_RED}"
            printf "%b" "$_spn_users" | while IFS= read -r _su; do
                [[ -n "$_su" ]] && echo -e "    ${_RED}${_su}${_NC}"
            done
        fi
        if [[ -n "$_spn_disabled" ]]; then
            echo -e "${_GRAY}[○] Disabled accounts with SPN (not exploitable — disabled accounts cannot get service tickets):${_NC}"
            printf "%b" "$_spn_disabled" | while IFS= read -r _su; do
                [[ -n "$_su" ]] && echo -e "    ${_GRAY}${_su}${_NC}"
            done
        fi
        # Machine accounts with SPNs — informational only
        _spn_machines=$(grep -B5 "^servicePrincipalName:" "$OUTDIR/ldap_users.ldif" 2>/dev/null \
            | grep "^sAMAccountName:" | grep '\$$' | sort -u)
        if [[ -n "$_spn_machines" ]]; then
            echo -e "${ORANGE}[○] Machine accounts with SPN (normal — not user kerberoast targets):${_NC}"
            while IFS= read -r _sm; do
                echo -e "    ${ORANGE}${_sm}${_NC}"
            done <<< "$_spn_machines"
        fi

        # adminCount=1 users — awk-based: sAMAccountName comes AFTER adminCount in LDIF
        # grep -Bxx would miss it; parse entry-by-entry with awk
        _admin_parse_result=$(awk '
            /^$/ { if (admin && sam && !machine) {
                    if (uac+0 != 0 && (uac+0) % 4 >= 2) { print "DISABLED " sam }
                    else { print "ENABLED " sam }
                }
                admin=0; machine=0; sam=""; uac=0
            }
            /^sAMAccountName:/ { sam=$2; if (sam ~ /\$$/) machine=1 }
            /^adminCount:/ && $2=="1" { admin=1 }
            /^userAccountControl:/ { uac=$2 }
            END { if (admin && sam && !machine) {
                    if (uac+0 != 0 && (uac+0) % 4 >= 2) { print "DISABLED " sam }
                    else { print "ENABLED " sam }
                }
            }
        ' "$OUTDIR/ldap_users.ldif" 2>/dev/null)

        _admin_active=""; _admin_disabled=""
        while IFS= read -r _apr; do
            _apr_state=$(echo "$_apr" | awk '{print $1}')
            _apr_name=$(echo "$_apr" | awk '{print $2}')
            if [[ "$_apr_state" == "DISABLED" ]]; then
                _admin_disabled="${_admin_disabled}sAMAccountName: ${_apr_name} [DISABLED]\n"
            else
                _admin_active="${_admin_active}sAMAccountName: ${_apr_name}\n"
            fi
        done <<< "$_admin_parse_result"
        if [[ -n "$_admin_active" || -n "$_admin_disabled" ]]; then
            echo -e "${_RED}[!] Users with adminCount=1 (privileged / AdminSDHolder protected):${_NC}"
            echo -e "${_GRAY}    adminCount=1 means the account is in (or was in) a privileged group.${_NC}"
            echo -e "${_GRAY}    These accounts have stronger ACL protections via AdminSDHolder.${_NC}"
            echo -e "${_GRAY}    Target these for privilege escalation — if you compromise one, you may get DA.${_NC}"
        fi
        if [[ -n "$_admin_active" ]]; then
            printf "%b" "$_admin_active" | while IFS= read -r _au; do
                [[ -n "$_au" ]] && echo -e "    ${_RED}${_au}${_NC}"
            done
        fi
        if [[ -n "$_admin_disabled" ]]; then
            printf "%b" "$_admin_disabled" | while IFS= read -r _au; do
                [[ -n "$_au" ]] && echo -e "    ${_GRAY}${_au}${_NC}"
            done
        fi

        echo -e "\n${_GREEN}[+] LDAP raw dumps saved:${_NC}"
        echo -e "    ${_GRAY}$OUTDIR/ldap_users.ldif${_NC}"
        echo -e "    ${_GRAY}$OUTDIR/ldap_computers.ldif${_NC}"
        echo -e "    ${_GRAY}$OUTDIR/ldap_groups.ldif${_NC}"
        _LDAP_DUMP_DONE=true
    fi
fi

# --ldap mode: exit after LDAP dump, skip all spraying/post-enum
if [[ "$LDAP_ONLY" == true ]]; then
    echo -e "\n${GREEN}[+] --ldap mode: LDAP dump complete. Skipping spray/post-enum.${NC}"
    echo -e "${GRAY}    Output: $OUTDIR/${NC}"
    exit 0
fi

# ═══════════════════════════════════════════════════════════════════════════
}

ldap_dump_retry() {
# ─── LDAP dump retry (Phase 4.2 re-run using spray results) ───────────────
# Phase 4.2 runs before Phase 6, so found_creds.txt was empty. Re-run now.
# Only skip retry if explicit -f (FAST_MODE). Credential-based SKIP_ENUM should NOT block this.
if [[ "$FAST_MODE" != true ]] && [[ "$_LDAP_DUMP_DONE" != true ]] && [[ -n "$DOMAIN" ]] && [[ "$STANDALONE" != true ]] && \
   { [[ -s "$OUTDIR/targets_ldap.txt" ]] || [[ -s "$OUTDIR/targets_ldaps.txt" ]]; } && \
   command -v ldapsearch &>/dev/null && [[ -s "$CREDS_FILE" ]]; then
    echo -e "\n${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║  PHASE 4.2 (RETRY): LDAPSEARCH - FULL DOMAIN DUMP         ║${NC}"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo -e "${CYAN}[*] Retrying LDAP dump using freshly discovered credentials...${NC}"
    # Temporarily force Phase 4.2 re-run by resetting the skip guards
    _ldap_retry_user=""; _ldap_retry_pass=""
    while IFS='|' read -r _ _ _ _rt_user _rt_secret _ _rt_type _; do
        [[ "$_rt_type" == "hash" ]] && continue
        [[ -z "$_rt_user" || -z "$_rt_secret" ]] && continue
        _rt_base_dn=$(echo "$DOMAIN" | awk -F'.' '{for(i=1;i<=NF;i++) printf "DC=%s%s",$i,(i<NF?",":""); print ""}')
        _rt_out=$(LDAPTLS_REQCERT=never ldapsearch -x -H "ldap://${DC_IP:-$TARGET_ARG}" \
            -D "${_rt_user}@${DOMAIN}" -w "$_rt_secret" \
            -b "$_rt_base_dn" -s base "(objectClass=*)" 2>&1 | head -5)
        if echo "$_rt_out" | grep -qE "^dn:|numEntries:|result: 0 Success"; then
            _ldap_retry_user="$_rt_user"
            _ldap_retry_pass="$_rt_secret"
            break
        fi
    done < "$CREDS_FILE"
    if [[ -n "$_ldap_retry_user" ]]; then
        _BASE_DN=$(echo "$DOMAIN" | awk -F'.' '{for(i=1;i<=NF;i++) printf "DC=%s%s",$i,(i<NF?",":""); print ""}')
        _LDAP_URI="ldap://${DC_IP:-$TARGET_ARG}"
        echo -e "${GREEN}[+] Using: ${_ldap_retry_user}@${DOMAIN}${NC}"
        echo -e "\n${CYAN}[*] Querying all users...${NC}"
        LDAPTLS_REQCERT=never ldapsearch -x -H "$_LDAP_URI" -D "${_ldap_retry_user}@${DOMAIN}" -w "$_ldap_retry_pass" \
            -b "$_BASE_DN" '(objectClass=user)' \
            sAMAccountName cn description info comment memberOf adminCount \
            userAccountControl servicePrincipalName mail pwdLastSet \
            2>/dev/null | tee "$OUTDIR/ldap_users.ldif" > /dev/null
        ldap_show_results "$OUTDIR/ldap_users.ldif" "Users"
        echo -e "\n${CYAN}[*] Querying computers...${NC}"
        LDAPTLS_REQCERT=never ldapsearch -x -H "$_LDAP_URI" -D "${_ldap_retry_user}@${DOMAIN}" -w "$_ldap_retry_pass" \
            -b "$_BASE_DN" '(objectClass=computer)' \
            cn dNSHostName operatingSystem description info \
            2>/dev/null | tee "$OUTDIR/ldap_computers.ldif" > /dev/null
        ldap_show_results "$OUTDIR/ldap_computers.ldif" "Computers"
        echo -e "\n${CYAN}[*] Querying groups...${NC}"
        LDAPTLS_REQCERT=never ldapsearch -x -H "$_LDAP_URI" -D "${_ldap_retry_user}@${DOMAIN}" -w "$_ldap_retry_pass" \
            -b "$_BASE_DN" '(objectClass=group)' \
            cn description member info \
            2>/dev/null | tee "$OUTDIR/ldap_groups.ldif" > /dev/null
        ldap_show_results "$OUTDIR/ldap_groups.ldif" "Groups"
        _LDAP_DUMP_DONE=true
        echo -e "\n${GREEN}[+] LDAP raw dumps saved:${NC}"
        echo -e "    ${GRAY}$OUTDIR/ldap_users.ldif${NC}"
        echo -e "    ${GRAY}$OUTDIR/ldap_computers.ldif${NC}"
        echo -e "    ${GRAY}$OUTDIR/ldap_groups.ldif${NC}"
    else
        echo -e "${YELLOW}[!] LDAP dump retry: still could not authenticate${NC}"
    fi
fi
}
