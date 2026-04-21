#!/bin/bash
# =============================================================================
# MODULE: utils.sh
# Core utilities: colors, command runner, ANSI stripping, output formatting,
# phase command queue, connection error tracking, worker init.
# All functions here are pure helpers - no side effects, no global state writes
# except for the phase command buffer and connection error counter.
# =============================================================================

trap 'echo -e "\n\033[0;31m[!] Interrupted!\033[0m"; exit 130' INT TERM

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;96m'; MAGENTA='\033[0;35m'
GRAY='\033[0;90m'; WHITE='\033[1;37m'; NC='\033[0m'
ORANGE='\033[38;5;208m'

# ── Worker / thread flags ─────────────────────────────────────────────────────
WORKERS=20
NXC_WORKERS_FLAG=""
KERBRUTE_THREADS=20
HYDRA_THREADS=4

init_workers() {
    if [[ "$WORKERS" =~ ^[0-9]+$ ]] && (( WORKERS > 0 )); then :; else WORKERS=20; fi
    NXC_WORKERS_FLAG="--threads $WORKERS"
    KERBRUTE_THREADS="$WORKERS"
    HYDRA_THREADS="$WORKERS"
}

# ── Phase command queue ───────────────────────────────────────────────────────
# Buffers only shell/admin follow-up commands; printed at phase end.
PHASE_CMD_BUFFER=()
declare -A PHASE_CMD_SEEN 2>/dev/null

queue_phase_cmd() {
    local line="$1"
    local keep=false
    local dedupe_key="$line"

    if [[ "$line" == \#* ]]; then
        if [[ "$line" == *"QUICK SHELL COMMANDS"* ]] || [[ "$line" == *"SMB SHARES"* ]] || [[ "$line" == *"BLOODHOUND"* ]]; then
            keep=true
            dedupe_key="$(printf '%s' "$line" | sed -E 's/\(from [^)]+ success\)//g; s/[[:space:]]+/ /g; s/[[:space:]]+$//')"
        fi
    else
        case "$line" in
            *evil-winrm*|*impacket-psexec*|*impacket-wmiexec*|*impacket-smbexec*|*impacket-secretsdump*|*impacket-getTGT*|*impacket-mssqlclient*|*ssh*|*smbclient.py*|*impacket-smbclient*|*bloodhound-python*|*--bloodhound*|*nxc\ smb*--sam*|*nxc\ smb*--lsa*|*nxc\ smb*--ntds*|*nxc\ smb*lsassy*|*hydra*)
                keep=true ;;
        esac
    fi

    [[ "$keep" != true ]] && return 1
    [[ -n "${PHASE_CMD_SEEN[$dedupe_key]}" ]] && return 1
    PHASE_CMD_SEEN["$dedupe_key"]=1
    PHASE_CMD_BUFFER+=("$line")
    return 0
}

flush_phase_cmds() {
    local title="$1"
    [[ ${#PHASE_CMD_BUFFER[@]} -eq 0 ]] && return 0
    title="${title#after }"

    echo -e "${MAGENTA}╔═══════════════════════════════════════════════════════════╗${NC}"
    printf "${MAGENTA}║  QUICK COMMANDS FOR   %-36s║${NC}\n" "${title}:"
    echo -e "${MAGENTA}╚═══════════════════════════════════════════════════════════╝${NC}"

    for c in "${PHASE_CMD_BUFFER[@]}"; do
        if [[ "$c" == \#* ]]; then
            printf "%b%s%b\n" "$GRAY" "$c" "$NC"
        else
            printf "%b>> %s%b\n" "$GRAY" "$c" "$NC"
        fi
    done
    echo
    PHASE_CMD_BUFFER=()
    PHASE_CMD_SEEN=()
}

# ── Phase state / resume ──────────────────────────────────────────────────────
declare -A PHASE_NAMES=(
    [0]="PORTS" [1]="USERGEN" [2]="SPRAY" [3]="SHARES"
    [4]="ASREP_KERB" [5]="USERENUM" [6]="MAIL" [7]="ADATTACKS" [8]="SLOW"
)
declare -A PHASE_DESCRIPTIONS=(
    [0]="Port scanning"
    [1]="Username generation & kerbrute"
    [2]="Credential spraying"
    [3]="SMB share enumeration"
    [4]="AS-REP roasting & Kerberoasting"
    [5]="User enumeration (RID, LDAP)"
    [6]="Mail enumeration (SMTP/POP3/IMAP)"
    [7]="AD attacks (descriptions, GPP, users, cred dump)"
    [8]="Slow operations (spider, enum4linux, vuln modules)"
)
RESUME_PHASE=""
PHASE_STATE_FILE=""

init_phase_state() {
    PHASE_STATE_FILE="$OUTDIR/.phase_state"
    [[ ! -f "$PHASE_STATE_FILE" ]] && echo "0" > "$PHASE_STATE_FILE"
}

save_phase_state() {
    local phase_num="$1"
    echo "$phase_num" > "$PHASE_STATE_FILE"
    echo -e "${GREEN}[✓] Phase $phase_num (${PHASE_NAMES[$phase_num]}) completed${NC}"
}

should_run_phase() {
    local phase_num="$1"
    [[ -z "$RESUME_PHASE" ]] && return 0
    local resume_num="$RESUME_PHASE"
    if [[ ! "$RESUME_PHASE" =~ ^[0-9]+$ ]]; then
        for num in "${!PHASE_NAMES[@]}"; do
            [[ "${PHASE_NAMES[$num],,}" == "${RESUME_PHASE,,}" ]] && { resume_num="$num"; break; }
        done
    fi
    [[ "$phase_num" -ge "$resume_num" ]]
}

show_resume_status() {
    [[ -z "$RESUME_PHASE" ]] && return
    echo -e "${YELLOW}╔═══════════════════════════════════════════════════════════╗${NC}"
    printf "${YELLOW}║  RESUME MODE: Starting from phase %-23s║${NC}\n" "${RESUME_PHASE}"
    echo -e "${YELLOW}╚═══════════════════════════════════════════════════════════╝${NC}"
    for num in $(seq 0 8); do
        if should_run_phase "$num"; then
            echo -e "    ${GREEN}[$num] ${PHASE_NAMES[$num]} - ${PHASE_DESCRIPTIONS[$num]}${NC}"
        else
            echo -e "    ${GRAY}[$num] ${PHASE_NAMES[$num]} - SKIPPED${NC}"
        fi
    done
    echo ""
}

# ── AD connection error tracking ─────────────────────────────────────────────
AD_CONN_ERR_LIMIT=8    # raised: nxc ldap --asreproast internal KDC errors are not fatal
AD_CONN_ERR_COUNT=0
AD_CONN_ERR_ABORT=false
CURRENT_PHASE=""

ad_connection_error_line() {
    local _l="$1"
    [[ "$CURRENT_PHASE" == "PHASE7" ]] || return 1
    [[ "$AD_CONN_ERR_ABORT" == true ]] && return 0

    # ── Do NOT count nxc's internal Kerberos port-88 errors as fatal ─────────
    # When nxc ldap --asreproast resolves the wrong KDC host (a common nxc bug),
    # it generates "Connection error (HOST:88)" lines. These are expected and should
    # not trigger the abort that would skip Kerberoasting / LDAP attacks.
    if [[ "$_l" == *":88)"* && "$_l" == *"Connection error"* ]]; then
        return 0   # silently ignore — impacket-GetNPUsers with -dc-ip is the reliable fallback
    fi
    # Also ignore "Connection error (HOST:389)" when it's a non-DC host — those are
    # LDAP connection attempts to workstations (expected failure, not a fatal event)
    if [[ "$_l" == *":389)"* && "$_l" == *"Connection error"* ]]; then
        return 0
    fi

    if [[ "$_l" == *"Connection timed out"* || "$_l" == *"Connection refused"* || \
          "$_l" == *"Errno 110"* || "$_l" == *"Errno 111"* || "$_l" == *"Connection error ("* ]]; then
        AD_CONN_ERR_COUNT=$((AD_CONN_ERR_COUNT + 1))
        if (( AD_CONN_ERR_COUNT >= AD_CONN_ERR_LIMIT )); then
            AD_CONN_ERR_ABORT=true
            echo -e "${YELLOW}[!] Reached ${AD_CONN_ERR_LIMIT} AD connection errors — skipping remaining AD attacks${NC}"
            echo -e "${YELLOW}    (DC unreachable or credentials rejected by all protocols)${NC}"
        fi
        return 0
    fi
    return 1
}

# Call this before each major Phase 7 section to prevent one failed AS-REP
# method from blocking Kerberoasting / LDAP enumeration.
ad_reset_err_count() {
    AD_CONN_ERR_COUNT=0
    AD_CONN_ERR_ABORT=false
}

# ── Misc small helpers ────────────────────────────────────────────────────────
count_lines() { grep -c '' "$1" 2>/dev/null || echo 0; }

show_cmd() {
    printf "%b>> %s%b\n" "$GRAY" "$1" "$NC"
}

show_skipped_extra() {
    local label="$1"
    local cmd_hint="${2:-}"
    [[ -n "$cmd_hint" ]] && printf "%b>> %s%b\n" "$GRAY" "$cmd_hint" "$NC"
    echo -e "${GRAY}>> SKIPPED (fast mode): ${label}${NC}"
}

# ── User color rotation ───────────────────────────────────────────────────────
declare -A USER_COLOR_MAP=()
USER_COLOR_IDX=0
USER_COLOR_PALETTE=("$GREEN" "$CYAN" "$MAGENTA" "$BLUE" "$ORANGE" "$YELLOW" "$WHITE")

get_user_banner_color() {
    local u="$1"
    [[ -z "$u" ]] && echo "$GREEN" && return
    if [[ -n "${USER_COLOR_MAP[$u]}" ]]; then echo "${USER_COLOR_MAP[$u]}"; return; fi
    local c="${USER_COLOR_PALETTE[$USER_COLOR_IDX]}"
    USER_COLOR_MAP[$u]="$c"
    USER_COLOR_IDX=$(( (USER_COLOR_IDX + 1) % ${#USER_COLOR_PALETTE[@]} ))
    echo "$c"
}

build_user_variants() {
    local u="$1"
    USER_VARIANTS=()
    if [[ "$u" == *""* || "$u" == *"@"* ]]; then USER_VARIANTS+=("$u"); return; fi
    USER_VARIANTS+=("$u")
    [[ -n "$DOMAIN" ]] && USER_VARIANTS+=("${DOMAIN}\\${u}" "${u}@${DOMAIN}")
    USER_VARIANTS+=(".\\${u}")
}

# ── ANSI stripping ────────────────────────────────────────────────────────────
strip_literal_ansi() {
    local _l="$1"
    if command -v perl >/dev/null 2>&1; then
        printf '%s' "$_l" | perl -pe '
            s/\r//g;
            s/\e\[[0-9;?]*[ -\/]*[@-~]//g;
            s/\\033\[[0-9;?]*[ -\/]*[@-~]//g;
            s/\\x1[bB]\[[0-9;?]*[ -\/]*[@-~]//g;
        '
    else
        printf '%s' "$_l" | sed -E \
            -e 's/\r//g' \
            -e 's/\x1B\[[0-9;?]*[ -/]*[@-~]//g' \
            -e 's/\\033\[[0-9;?]*[ -/]*[@-~]//g' \
            -e 's/\\x1[bB]\[[0-9;?]*[ -/]*[@-~]//g'
    fi
}

# ── SMB share colorization ────────────────────────────────────────────────────
colorize_smb_share_line() {
    local raw="$1"
    local clean out tmp
    clean="$(strip_literal_ansi "$raw")"
    out="$clean"
    tmp="__NXC_RW__"
    out="${out//READ,WRITE/$tmp}"
    out="${out// READ / ${ORANGE}READ${NC} }"
    if [[ "$out" =~ [[:space:]]READ$ ]]; then
        out="${out%READ}${ORANGE}READ${NC}"
    fi
    out="${out//$tmp/${RED}READ,WRITE${NC}}"
    printf '%s' "$out"
}

fmt_smb_access_color() {
    local a="$1"
    case "$a" in
        RW|READ,WRITE) printf "%b%s%b" "$RED" "$a" "$NC" ;;
        R|READ)        printf "%b%s%b" "$ORANGE" "$a" "$NC" ;;
        *)             printf "%s" "$a" ;;
    esac
}

highlight_rid() {
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*[0-9]+:[[:space:]] ]]; then
            echo -e "${WHITE}${line}${NC}"
        else
            echo "$line"
        fi
        ad_connection_error_line "$line" >/dev/null 2>&1 || true
    done
}

# ── Command runner ────────────────────────────────────────────────────────────
render_cmd_line() {
    local raw_line="$1"
    local outfile="${2:-}"
    local line
    line="$(strip_literal_ansi "$raw_line")"
    line="${line//$'\r'/}"
    line="${line//$'\n'/}"

    [[ -n "$outfile" ]] && printf '%s\n' "$line" >> "$outfile"

    if [[ "$line" == \$krb5* ]]; then
        # Kerberoast ($krb5tgs$) and AS-REP ($krb5asrep$) hashes — always bright white so they are never missed
        printf "%b%s%b\n" "$WHITE" "$line" "$NC"
    elif [[ "$line" =~ ^[[:space:]]*[0-9]+:[[:space:]] ]]; then
        printf "%b%s%b\n" "$WHITE" "$line" "$NC"
    elif [[ "$line" == *"User:"*"description:"* ]]; then
        printf "%b%s%b\n" "$WHITE" "$line" "$NC"
    elif [[ "$line" == POWERSHE* ]]; then
        # NXC powershell_history output has two line types:
        #   Path header:    POWERSHE...  IP  PORT  HOST             C:\path\file.txt  (13 spaces)
        #   History entry:  POWERSHE...  IP  PORT  HOST                actual command  (16 spaces)
        # After stripping fields 1-4, path headers have 13 leading spaces; history
        # entries have 16 (3 extra). Check for 16+ spaces (">= 14" handles slight variance).
        local _psh_tail
        _psh_tail=$(printf '%s' "$line" | sed -E 's/^[A-Z.]+[[:space:]]+[0-9.]+[[:space:]]+[0-9]+[[:space:]]+[A-Za-z0-9._-]+//')
        if [[ "$line" == *"[ PASSWORD"* || "$line" == *"[ PASSW"* ]]; then
            printf "%b%s%b\n" "$RED" "$line" "$NC"
        elif [[ "${#_psh_tail}" -gt 0 ]] && [[ "${_psh_tail:0:14}" == "              " ]]; then
            # 14+ leading spaces = history content entry → WHITE for visibility
            printf "%b%s%b\n" "$WHITE" "$line" "$NC"
        else
            # Path header or module status line → CYAN
            printf "%b%s%b\n" "$CYAN" "$line" "$NC"
        fi
    elif [[ "$line" == SMB* ]] && { [[ "$line" == *"READ,WRITE"* ]] || [[ "$line" =~ [[:space:]]READ([[:space:]]|$) ]] || [[ "$raw_line" == *'\\033['* ]] || [[ "$raw_line" == *'\\x1b['* ]]; }; then
        local colored
        colored="$(colorize_smb_share_line "$raw_line")"
        printf "%b\n" "$colored"
    else
        printf '%s\n' "$line"
    fi

    ad_connection_error_line "$line" >/dev/null 2>&1 || true
}

run_cmd() {
    local cmd="$1"
    local outfile="${2:-}"

    if [[ "$CURRENT_PHASE" == "PHASE7" && "$AD_CONN_ERR_ABORT" == true ]]; then
        echo -e "${YELLOW}[!] Skipping AD attack command after connection error threshold: $cmd${NC}"
        return 0
    fi

    show_cmd "$cmd"

    if [[ -n "$outfile" ]]; then
        : > "$outfile"
        while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
            render_cmd_line "$raw_line" "$outfile"
        done < <(eval "$cmd" 2>/dev/null)
    else
        while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
            render_cmd_line "$raw_line"
        done < <(eval "$cmd" 2>/dev/null)
    fi
}

run_cmd_process() {
    local cmd="$1"
    local cred_type="${2:-password}"

    if [[ "$CURRENT_PHASE" == "PHASE7" && "$AD_CONN_ERR_ABORT" == true ]]; then
        echo -e "${YELLOW}[!] Skipping AD attack command after connection error threshold: $cmd${NC}"
        return 0
    fi

    show_cmd "$cmd"
    process_output "$cred_type" < <(eval "$cmd" 2>/dev/null)
}
