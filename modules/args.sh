#!/bin/bash
# MODULE: args.sh - CLI argument parsing, temp file helpers, cleanup

# Argumenten parsen
GENERATE_USERS=false
GENERATE_ONLY=false            # --generateonly : alleen usernames genereren/exporteren, geen scans
SINGLE_TARGET=""
SINGLE_USER=""
SINGLE_PASS=""
SINGLE_HASH=""
SINGLE_DOMAIN=""
NO_CACHE=false
STANDALONE=false
COMBO_CRED=""   # -c user:pass or file
COMBO_HASH=""   # -ch user:hash or file

# New control flags
FORCE_ANON_SCAN=false        # --anonymous-scan : run anonymous/RID enum even if creds are provided
SKIP_DOMAIN_SIDS=false       # --skip-domain-sids : omit impacket-lookupsid -domain-sids (can be slow)
SKIP_DESC_USERS=false        # --skip-desc-users : skip LDAP get-desc-users (user description harvesting)
SKIP_SID_ENUM=false         # internal: skip SID/domain-sid enumeration (lookupsid/get-sid)
RUN_EXTRAS=true               # run advanced/vuln modules unless skipped by -f
EXTRAS_ONLY=false             # --extras-only : only run advanced/vuln modules
CHECK_SMB_SHARE_WRITE=false   # deprecated; share enum handled by SHARE_ENUM
OSCP_MODE=true                # --oscp / default=true : skip active coercion modules (petitpotam, coerce_plus) for exam compliance

# Custom port overrides
CUSTOM_SMB_PORT=""
CUSTOM_FTP_PORT=""
CUSTOM_SSH_PORT=""
CUSTOM_MSSQL_PORT=""
CUSTOM_WINRM_PORT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        -g|--generate)
            GENERATE_USERS=true
            shift
            ;;
        --generateonly)
            GENERATE_ONLY=true
            GENERATE_USERS=true
            shift
            ;;
        -f|--fast)
            SKIP_ENUM=true
            FAST_MODE=true
            RUN_EXTRAS=false
            SKIP_DOMAIN_SIDS=true    # fast mode auto-skips slow SID enumeration
            SKIP_DESC_USERS=true     # fast mode auto-skips LDAP description harvest
            SKIP_SID_ENUM=true
            shift
            ;;

        --ldap)
            LDAP_ONLY=true
            shift
            ;;

        -w|--workers)
            WORKERS="$2"
            shift 2
            ;;
        --smb-only)
            SMB_ONLY=true
            shift
            ;;

        --extras-only)
            EXTRAS_ONLY=true
            SKIP_ENUM=true
            RUN_EXTRAS=true
            shift
            ;;

        --oscp)
            OSCP_MODE=true
            shift
            ;;

        --resume)
            if [[ -z "$2" || "$2" == -* ]]; then
                echo -e "${RED}[X] --resume requires a phase number (0-8) or name${NC}"
                echo -e "${YELLOW}    Phases: 0=ports, 1=usergen, 2=spray, 3=shares, 4=asrep_kerb, 5=userenum, 6=mail, 7=adattacks, 8=slow${NC}"
                exit 1
            fi
            RESUME_PHASE="$2"
            shift 2
            ;;

        -s|--standalone)
            STANDALONE=true
            shift
            ;;
        --no-cache)
            NO_CACHE=true
            shift
            ;;
        --anonymous-scan)
            FORCE_ANON_SCAN=true
            shift
            ;;
        --skip-domain-sids)
            SKIP_DOMAIN_SIDS=true
            shift
            ;;
        --skip-desc-users)
            SKIP_DESC_USERS=true
            SKIP_SID_ENUM=true
            shift
            ;;
        --no-share-enum)
            SHARE_ENUM=false
            CHECK_SMB_SHARE_WRITE=false
            shift
            ;;
        --smb-port)
            CUSTOM_SMB_PORT="$2"
            PROTO_PORTS[smb]="$2"
            shift 2
            ;;
        --ftp-port)
            CUSTOM_FTP_PORT="$2"
            PROTO_PORTS[ftp]="$2"
            shift 2
            ;;
        --ssh-port)
            CUSTOM_SSH_PORT="$2"
            PROTO_PORTS[ssh]="$2"
            shift 2
            ;;
        --mssql-port)
            CUSTOM_MSSQL_PORT="$2"
            PROTO_PORTS[mssql]="$2"
            shift 2
            ;;
        --winrm-port)
            CUSTOM_WINRM_PORT="$2"
            PROTO_PORTS[winrm]="$2"
            shift 2
            ;;
        -T)
            SINGLE_TARGET="$2"
            shift 2
            ;;
        -U)
            SINGLE_USER="$2"
            shift 2
            ;;
        -P)
            SINGLE_PASS="$2"
            shift 2
            ;;
        -H)
            SINGLE_HASH="$2"
            shift 2
            ;;
        -D)
            SINGLE_DOMAIN="$2"
            shift 2
            ;;
        -c|--cred)
            # gebruikersnaam:password OR bestand met one user:pass per line
            if [[ -z "$2" ]]; then
                echo -e "${RED}[X] -c requires an argument: username:password OR file path${NC}"
                exit 1
            fi
            if [[ "$2" != *:* ]] && [[ ! -f "$2" ]]; then
                echo -e "${RED}[X] -c argument is neither a username:password pair nor an existing file: $2${NC}"
                exit 1
            fi
            COMBO_CRED="$2"
            shift 2
            ;;
        -ch|--cred-hash)
            # gebruikersnaam:hash OR bestand met one user:hash per line
            if [[ -z "$2" ]]; then
                echo -e "${RED}[X] -ch requires an argument: username:hash OR file path${NC}"
                exit 1
            fi
            if [[ "$2" != *:* ]] && [[ ! -f "$2" ]]; then
                echo -e "${RED}[X] -ch argument is neither a username:hash pair nor an existing file: $2${NC}"
                exit 1
            fi
            COMBO_HASH="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

# Standaarden
SKIP_ENUM="${SKIP_ENUM:-false}"
FAST_MODE="${FAST_MODE:-false}"   # set ONLY by -f; unlike SKIP_ENUM, never auto-set by credential detection
LDAP_ONLY="${LDAP_ONLY:-false}"   # --ldap flag: run only the Phase 4.2 LDAP dump and exit
init_workers

# NXC port flags - alleen set if custom port was specified
# These are appended to nxc commandoo's when non-standard ports are used
NXC_SMB_PORT=""
NXC_FTP_PORT=""
NXC_SSH_PORT=""
NXC_MSSQL_PORT=""
NXC_WINRM_PORT=""
[[ -n "$CUSTOM_SMB_PORT" ]] && NXC_SMB_PORT="--port $CUSTOM_SMB_PORT"
[[ -n "$CUSTOM_FTP_PORT" ]] && NXC_FTP_PORT="--port $CUSTOM_FTP_PORT"
[[ -n "$CUSTOM_SSH_PORT" ]] && NXC_SSH_PORT="--port $CUSTOM_SSH_PORT"
[[ -n "$CUSTOM_MSSQL_PORT" ]] && NXC_MSSQL_PORT="--port $CUSTOM_MSSQL_PORT"
[[ -n "$CUSTOM_WINRM_PORT" ]] && NXC_WINRM_PORT="--port $CUSTOM_WINRM_PORT"

# Handle enkele waarden - create temp files or use directly

# -----------------------------------------------------------------------------
# COMBO CREDS (-c / -ch): gebruikersnaam:password or gebruikersnaam:hash (waarde or file)
# If set, we DO NOT auto-use gebruikers.txt/wachtwoorden.txt/hashes.txt standaards.
# If a file is provided, format is one pair per line: user:secret (secret may contain ':')
# -----------------------------------------------------------------------------
COMBO_MODE=""            # "pass" or "hash"
COMBO_PAIRS_FILE=""      # normalized pairs file
COMBO_USERS_FILE=""      # extracted users (for display / reuse)

make_pairs_from_value_or_file() {
    local arg="$1"
    local outfile="$2"
    if [[ -f "$arg" ]]; then
        grep -vE '^[[:space:]]*#' "$arg" 2>/dev/null | sed 's/\r$//' | sed '/^[[:space:]]*$/d' > "$outfile"
    else
        echo "$arg" > "$outfile"
    fi
}

extract_users_from_pairs() {
    local infile="$1"
    local outfile="$2"
    > "$outfile"
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        local user="${line%%:*}"
        user="$(echo "$user" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [[ -n "$user" ]] && echo "$user" >> "$outfile"
    done < "$infile"
    sort -u "$outfile" -o "$outfile" 2>/dev/null
}

validate_pairs_file() {
    local infile="$1"
    local mode="$2"  # pass|hash

    # Find eerst non-empty, non-comment line
    local first=""
    first="$(grep -vE '^[[:space:]]*(#|$)' "$infile" 2>/dev/null | head -n 1)"

    if [[ -z "$first" ]]; then
        echo -e "${RED}[X] Empty credentials file provided for -${mode}.${NC}"
        exit 1
    fi

    if ! echo "$first" | grep -q ":"; then
        if [[ "$mode" == "hash" ]]; then
            echo -e "${RED}[X] -ch expects username:hash pairs (one per line).${NC}"
            echo -e "${YELLOW}    Your input looks like hash-only. Use -H <hash|file> for hash-only, or format as user:hash.${NC}"
        else
            echo -e "${RED}[X] -c expects username:password pairs (one per line).${NC}"
        fi
        exit 1
    fi

    # Geldigeate every pair line
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

        if ! echo "$line" | grep -q ":"; then
            echo -e "${RED}[X] Bad pair (missing ':'): $line${NC}"
            exit 1
        fi

        local user="${line%%:*}"
        local secret="${line#*:}"
        user="$(echo "$user" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        secret="$(echo "$secret" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"

        if [[ -z "$user" || -z "$secret" ]]; then
            echo -e "${RED}[X] Bad pair (empty user or secret): $line${NC}"
            exit 1
        fi
    done < "$infile"
}


if [[ -n "$COMBO_CRED" && -n "$COMBO_HASH" ]]; then
    echo -e "${RED}[X] Use either -c (user:pass) OR -ch (user:hash), not both.${NC}"
    exit 1
fi

if [[ -n "$COMBO_CRED" ]]; then
    COMBO_MODE="pass"
    COMBO_PAIRS_FILE="/tmp/nxc_combo_pass_$$.txt"
    COMBO_USERS_FILE="/tmp/nxc_combo_users_$$.txt"
    make_pairs_from_value_or_file "$COMBO_CRED" "$COMBO_PAIRS_FILE"
    validate_pairs_file "$COMBO_PAIRS_FILE" "pass"
    extract_users_from_pairs "$COMBO_PAIRS_FILE" "$COMBO_USERS_FILE"

    USERS="$COMBO_USERS_FILE"
    PASSWORDS="/tmp/nxc_combo_passwords_$$.txt"
    > "$PASSWORDS"
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        echo "${line#*:}" >> "$PASSWORDS"
    done < "$COMBO_PAIRS_FILE"

    HASHES=""
    SINGLE_USER=""; SINGLE_PASS=""; SINGLE_HASH=""
fi

if [[ -n "$COMBO_HASH" ]]; then
    COMBO_MODE="hash"
    COMBO_PAIRS_FILE="/tmp/nxc_combo_hash_$$.txt"
    COMBO_USERS_FILE="/tmp/nxc_combo_users_$$.txt"
    make_pairs_from_value_or_file "$COMBO_HASH" "$COMBO_PAIRS_FILE"
    validate_pairs_file "$COMBO_PAIRS_FILE" "hash"
    extract_users_from_pairs "$COMBO_PAIRS_FILE" "$COMBO_USERS_FILE"

    USERS="$COMBO_USERS_FILE"
    HASHES="/tmp/nxc_combo_hashes_$$.txt"
    > "$HASHES"
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
        echo "${line#*:}" >> "$HASHES"
    done < "$COMBO_PAIRS_FILE"

    PASSWORDS=""
    SINGLE_USER=""; SINGLE_PASS=""; SINGLE_HASH=""
fi

if [[ -n "$SINGLE_TARGET" ]]; then
    TARGETS="$SINGLE_TARGET"
elif [[ -f "targets.txt" ]]; then
    TARGETS="targets.txt"
else
    TARGETS=""
fi

if [[ -z "$COMBO_MODE" && -n "$SINGLE_USER" ]]; then
    # Check if SINGLE_USER is a bestandspad or an actual gebruikersnaam
    if [[ -f "$SINGLE_USER" ]]; then
        # It's a file - use it directly
        USERS="$SINGLE_USER"
    else
        # It's a gebruikersnaam - create temp file
        USERS_TEMP="/tmp/nxc_single_user_$$.txt"
        echo "$SINGLE_USER" > "$USERS_TEMP"
        USERS="$USERS_TEMP"
    fi
elif [[ -z "$COMBO_MODE" && -f "users.txt" ]]; then
    USERS="users.txt"
else
    USERS=""
fi

if [[ -z "$COMBO_MODE" && -n "$SINGLE_PASS" ]]; then
    # Check if SINGLE_PASS is a bestandspad or an actual password
    if [[ -f "$SINGLE_PASS" ]]; then
        # It's a file - use it directly
        PASSWORDS="$SINGLE_PASS"
    else
        # It's a password - create temp file
        PASSWORDS_TEMP="/tmp/nxc_single_pass_$$.txt"
        echo "$SINGLE_PASS" > "$PASSWORDS_TEMP"
        PASSWORDS="$PASSWORDS_TEMP"
    fi
elif [[ -z "$COMBO_MODE" && -f "passwords.txt" ]]; then
    PASSWORDS="passwords.txt"
else
    PASSWORDS=""
fi

if [[ -z "$COMBO_MODE" && -n "$SINGLE_HASH" ]]; then
    # Check if SINGLE_HASH is a bestandspad or an actual hash waarde
    if [[ -f "$SINGLE_HASH" ]]; then
        # It's a file - use it directly
        HASHES="$SINGLE_HASH"
    else
        # It's a hash waarde - create temp file
        HASHES_TEMP="/tmp/nxc_single_hash_$$.txt"
        echo "$SINGLE_HASH" > "$HASHES_TEMP"
        HASHES="$HASHES_TEMP"
    fi
elif [[ -z "$COMBO_MODE" && -z "$SINGLE_PASS" && -f "hashes.txt" ]]; then
    HASHES="hashes.txt"
else
    HASHES=""
fi

if [[ -n "$SINGLE_DOMAIN" ]]; then
    DOMAIN="$SINGLE_DOMAIN"
elif [[ -f "domain.txt" ]]; then
    DOMAIN="$(cat domain.txt | tr -d '\n\r')"
else
    DOMAIN=""
fi

# dc.txt / --dc flag pin the Domain Controller IP at parse time
SINGLE_DC="${SINGLE_DC:-}"
if [[ -n "$SINGLE_DC" ]]; then
    DC_IP="$SINGLE_DC"
elif [[ -f "dc.txt" ]]; then
    DC_IP="$(head -1 dc.txt | tr -d '\n\r[:space:]')"
    [[ -n "$DC_IP" ]] && echo -e "${GREEN}[+] DC IP:     $DC_IP (from dc.txt)${NC}"
fi

# Opschonen voor tijdelijke bestanden
cleanup_temp_files() {
    [[ -n "$USERS_TEMP" && -f "$USERS_TEMP" ]] && rm -f "$USERS_TEMP"
    [[ -n "$PASSWORDS_TEMP" && -f "$PASSWORDS_TEMP" ]] && rm -f "$PASSWORDS_TEMP"
    [[ -n "$HASHES_TEMP" && -f "$HASHES_TEMP" ]] && rm -f "$HASHES_TEMP"
    [[ -n "$COMBO_PAIRS_FILE" && -f "$COMBO_PAIRS_FILE" ]] && rm -f "$COMBO_PAIRS_FILE"
    [[ -n "$COMBO_USERS_FILE" && -f "$COMBO_USERS_FILE" ]] && rm -f "$COMBO_USERS_FILE"
    [[ "$PASSWORDS" == /tmp/nxc_combo_passwords_* && -f "$PASSWORDS" ]] && rm -f "$PASSWORDS"
    [[ "$HASHES" == /tmp/nxc_combo_hashes_* && -f "$HASHES" ]] && rm -f "$HASHES"

}
