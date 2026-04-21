#!/bin/bash
# =============================================================================
# MODULE: ports.sh
# Port scanning, protocol target file building, port cache management,
# kerbrute binary discovery.
# =============================================================================

# ── Protocol port map (edit here for non-standard ports) ─────────────────────
declare -A PROTO_PORTS=(
    [smb]=445   [winrm]=5985 [rdp]=3389  [ssh]=22
    [ldap]=389  [ldaps]=636  [ftp]=21    [mssql]=1433
    [wmi]=135   [vnc]=5900   [smtp]=25   [pop3]=110
    [imap]=143  [nfs]=2049
    [mysql]=3306 [http]=80   [https]=443
    [postgres]=5432 [redis]=6379 [oracle]=1521
)
# PROTO_ORDER controls spray order AND display order in port summary
# http/https/mysql/postgres/redis/oracle are scan-only (no nxc spray) — listed last
PROTO_ORDER=("smb" "winrm" "rdp" "ssh" "ldap" "ldaps" "ftp" "mssql" "wmi" "smtp" "pop3" "imap" "vnc" "nfs" "mysql" "http" "https" "postgres" "redis" "oracle")
# Protocols that have nxc spray support (used in spray.sh)
SPRAY_PROTOS=("smb" "winrm" "rdp" "ssh" "ldap" "ftp" "mssql" "wmi" "mysql")
# Protocols that are scan-only (no nxc spray, but we check them and suggest tools)
SCAN_ONLY_PROTOS=("http" "https" "postgres" "redis" "oracle")

# Runtime LDAP state
LDAPS_AVAILABLE=false
LDAP_PORT_FLAG="--port 389"

# ── Scan-only ports — checked in port scan but not sprayed via nxc ────────────
# Shown in summary with tool suggestions when open
_show_scan_only_hints() {
    local _target="${1:-$TARGET_ARG}"
    # Use the first confirmed-open host from each protocol's target file
    # This avoids showing hints with an unreachable first-line-of-targets IP
    local _http_ip;  _http_ip=$(head -1  "$OUTDIR/targets_http.txt"  2>/dev/null)
    local _https_ip; _https_ip=$(head -1 "$OUTDIR/targets_https.txt" 2>/dev/null)
    local _pg_ip;    _pg_ip=$(head -1    "$OUTDIR/targets_postgres.txt" 2>/dev/null)
    local _redis_ip; _redis_ip=$(head -1 "$OUTDIR/targets_redis.txt"  2>/dev/null)
    local _ora_ip;   _ora_ip=$(head -1   "$OUTDIR/targets_oracle.txt" 2>/dev/null)
    # Fallback to first SMB target (likely the most reachable host)
    local _fallback; _fallback=$(head -1 "$OUTDIR/targets_smb.txt" 2>/dev/null || \
                                 head -1 "$TARGET_ARG"              2>/dev/null || \
                                 echo    "$TARGET_ARG")
    _http_ip="${_http_ip:-$_fallback}"
    _https_ip="${_https_ip:-$_fallback}"
    _pg_ip="${_pg_ip:-$_fallback}"
    _redis_ip="${_redis_ip:-$_fallback}"
    _ora_ip="${_ora_ip:-$_fallback}"
    local _ip="$_fallback"  # keep for any legacy references below
    local _hints_shown=false

    # Check if any scan-only ports are open first
    local _any_open=false
    for _so_p in http https postgres redis oracle; do
        [[ -s "$OUTDIR/targets_${_so_p}.txt" ]] && { _any_open=true; break; }
    done
    if [[ "$_any_open" == true ]]; then
        echo -e "${CYAN}[*] Web/DB ports detected — tool suggestions:${NC}"
    fi

    [[ -s "$OUTDIR/targets_http.txt" ]] && {
        echo -e "${CYAN}[*] HTTP (port 80) is open — web enumeration:${NC}"
        echo -e "${GRAY}    >> whatweb http://${_http_ip} && curl -sk http://${_http_ip} | head -50${NC}"
        echo -e "${GRAY}    >> gobuster dir -u http://${_http_ip} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt${NC}"
        echo -e "${GRAY}    >> nikto -h http://${_http_ip}${NC}"
        _hints_shown=true
    }
    [[ -s "$OUTDIR/targets_https.txt" ]] && {
        echo -e "${CYAN}[*] HTTPS (port 443) is open — web enumeration:${NC}"
        echo -e "${GRAY}    >> whatweb https://${_https_ip} && curl -sk https://${_https_ip} | head -50${NC}"
        echo -e "${GRAY}    >> gobuster dir -u https://${_https_ip} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k${NC}"
        echo -e "${GRAY}    >> nikto -h https://${_https_ip} -ssl${NC}"
        _hints_shown=true
    }
    # mysql handled in Phase 6 spray (default cred check + user cred spray)
    [[ -s "$OUTDIR/targets_postgres.txt" ]] && {
        echo -e "${RED}[!] PostgreSQL (port 5432) is open — default credential check runs in Phase 6${NC}"
        echo -e "${GRAY}    >> psql -h ${_pg_ip} -U postgres -c '\\l'${NC}"
        echo -e "${GRAY}    >> psql -h ${_pg_ip} -U postgres -c 'SELECT usename, passwd FROM pg_shadow;'${NC}"
        _hints_shown=true
    }
    [[ -s "$OUTDIR/targets_redis.txt" ]] && {
        echo -e "${RED}[!] Redis (port 6379) is open — default (unauthenticated) check runs in Phase 6${NC}"
        echo -e "${GRAY}    >> redis-cli -h ${_redis_ip} info server${NC}"
        echo -e "${GRAY}    >> redis-cli -h ${_redis_ip} keys '*'${NC}"
        echo -e "${GRAY}    >> redis-cli -h ${_redis_ip} config get requirepass${NC}"
        _hints_shown=true
    }
    [[ -s "$OUTDIR/targets_oracle.txt" ]] && {
        echo -e "${ORANGE}[○] Oracle DB (port 1521) is open — manual enumeration required:${NC}"
        echo -e "${GRAY}    >> odat.py all -s ${_ora_ip} -p 1521${NC}"
        echo -e "${GRAY}    >> nmap -sV -p 1521 --script oracle-enum-sid ${_ora_ip}${NC}"
        echo -e "${GRAY}    >> sqlplus sys/change_on_install@${_ora_ip}:1521/XE as sysdba${NC}"
        _hints_shown=true
    }
    [[ "$_hints_shown" == true ]] && echo ""
}

# ── Kerbrute discovery ────────────────────────────────────────────────────────
find_kerbrute() {
    [[ -n "${KERBRUTE:-}" && -x "${KERBRUTE:-}" ]] && { echo "$KERBRUTE"; return 0; }
    command -v kerbrute &>/dev/null && { echo "kerbrute"; return 0; }
    local locations=(
        "/home/$USER/Desktop/OSCP/Tools/kerbrute_linux_amd64"
        "/home/$USER/Desktop/OSCP/Tools/kerbrute"
        "/home/$USER/tools/kerbrute_linux_amd64"
        "/home/$USER/tools/kerbrute"
        "/home/$USER/kerbrute_linux_amd64"
        "/opt/kerbrute/kerbrute_linux_amd64"
        "/opt/kerbrute_linux_amd64"
        "/usr/local/bin/kerbrute_linux_amd64"
        "/usr/local/bin/kerbrute"
        "$HOME/go/bin/kerbrute"
        "./kerbrute_linux_amd64"
        "./kerbrute"
    )
    for loc in "${locations[@]}"; do
        [[ -x "$loc" ]] && { echo "$loc"; return 0; }
    done
    return 1
}

# ── Low-level port check ──────────────────────────────────────────────────────
port_open() {
    # 2s timeout: fast enough for LAN/VPN, still reliable for open ports
    # "filtered" ports (no-response) take the full timeout — this is unavoidable
    nc -z -w2 "$1" "$2" 2>/dev/null
}

proto_available() {
    [[ -s "$OUTDIR/targets_${1}.txt" ]]
}

get_proto_targets() {
    local f="$OUTDIR/targets_${1}.txt"
    [[ -s "$f" ]] && echo "$f" && return 0
    return 1
}

# ── Port scan + cache ─────────────────────────────────────────────────────────
build_proto_targets() {
    # Narrow protocol list if --smb-only was requested
    # Done here (not at source time) because args.sh is sourced after ports.sh
    if [[ "${SMB_ONLY:-false}" == true ]]; then
        PROTO_ORDER=("smb")
    fi

    local CACHE_FILE=".nxc_ports_cache"
    local targets_hash=""

    if [[ -f "$TARGET_ARG" ]]; then
        targets_hash=$(md5sum "$TARGET_ARG" 2>/dev/null | cut -d' ' -f1)
    else
        targets_hash=$(echo "$TARGET_ARG" | md5sum | cut -d' ' -f1)
    fi

    # ── Cache hit ────────────────────────────────────────────────────────────
    if [[ -f "$CACHE_FILE" ]] && [[ "$NO_CACHE" != "true" ]]; then
        local cached_hash
        cached_hash=$(head -1 "$CACHE_FILE" 2>/dev/null)
        if [[ "$cached_hash" == "$targets_hash" ]]; then
            echo -e "\n${GREEN}[+] Using cached port scan results from $CACHE_FILE${NC}"
            echo -e "${YELLOW}[!] Cache mode: port availability below is CACHED and may be stale if targets/services changed${NC}"
            echo -e "${GRAY}    (use --no-cache to force rescan)${NC}"

            for proto in "${PROTO_ORDER[@]}"; do > "$OUTDIR/targets_${proto}.txt"; done

            local in_results=false
            while IFS= read -r line; do
                [[ "$line" == "---RESULTS---" ]] && { in_results=true; continue; }
                [[ "$in_results" != "true" ]] && continue
                local proto="${line%%:*}"
                local ip="${line#*:}"
                [[ -n "$proto" && -n "$ip" ]] && echo "$ip" >> "$OUTDIR/targets_${proto}.txt"
            done < "$CACHE_FILE"

            echo -e "${CYAN}[*] Port availability (cached):${NC}"
            local port_num=1
            for proto in "${PROTO_ORDER[@]}"; do
                local count
                count=$(wc -l < "$OUTDIR/targets_${proto}.txt" 2>/dev/null || echo 0)
                local port="${PROTO_PORTS[$proto]}"
                local _so=false; for _p in "${SCAN_ONLY_PROTOS[@]:-}"; do [[ "$_p" == "$proto" ]] && _so=true; done
                if [[ $count -gt 0 ]]; then
                    if [[ "$_so" == true ]]; then
                        printf "${GRAY}[%02d]${NC} ${CYAN}%s(%s): %s targets [web/db]${NC}\n" "$port_num" "$proto" "$port" "$count"
                    else
                        printf "${GRAY}[%02d]${NC} ${GREEN}%s(%s): %s targets${NC}\n" "$port_num" "$proto" "$port" "$count"
                    fi
                else
                    printf "${GRAY}[%02d]${NC} ${GRAY}%s(%s): 0 targets${NC}\n" "$port_num" "$proto" "$port"
                fi
                ((port_num++))
            done
            echo ""

            # ── Stale cache detection: warn if ALL ports show 0 targets ──────
            local _total_open=0
            for proto in "${PROTO_ORDER[@]}"; do
                local _c; _c=$(wc -l < "$OUTDIR/targets_${proto}.txt" 2>/dev/null || echo 0)
                (( _total_open += _c ))
            done
            if [[ $_total_open -eq 0 ]]; then
                echo -e "${RED}╔═══════════════════════════════════════════════════════════╗${NC}"
                echo -e "${RED}║  WARNING: CACHED SCAN SHOWS 0 OPEN PORTS                 ║${NC}"
                echo -e "${RED}╠═══════════════════════════════════════════════════════════╣${NC}"
                echo -e "${RED}║  This cache may be from a different target or old run.    ║${NC}"
                echo -e "${RED}║  If ports should be open, run with --no-cache             ║${NC}"
                echo -e "${RED}╚═══════════════════════════════════════════════════════════╝${NC}"
                echo -e "${YELLOW}  >> bash $0 $@ --no-cache${NC}"
                echo ""
            fi

            if [[ -s "$OUTDIR/targets_ldaps.txt" ]]; then
                LDAPS_AVAILABLE=true; LDAP_PORT_FLAG=""
            else
                LDAPS_AVAILABLE=false; LDAP_PORT_FLAG="--port 389"
                echo -e "${YELLOW}[!] LDAPS (636) not available - using plain LDAP (389) to avoid timeouts${NC}"
            fi
            return 0
        fi
    fi

    # ── Full scan ────────────────────────────────────────────────────────────
    echo -e "\n${CYAN}[*] Scanning ports on all targets...${NC}"

    local targets=()
    if [[ -f "$TARGET_ARG" ]]; then
        mapfile -t targets < "$TARGET_ARG"
    else
        targets+=("$TARGET_ARG")
    fi
    local total=${#targets[@]}

    for proto in "${!PROTO_PORTS[@]}"; do > "$OUTDIR/targets_${proto}.txt"; done

    # Invalidate user-enum cache when targets change (fresh port scan = stale user data)
    [[ -f ".nxc_users_cache" ]] && rm -f ".nxc_users_cache" && echo -e "${GRAY}[*] Cleared .nxc_users_cache (fresh scan)${NC}"
    echo "$targets_hash" > "$CACHE_FILE"
    echo "---RESULTS---" >> "$CACHE_FILE"

    local i=0
    for ip in "${targets[@]}"; do
        [[ -z "$ip" ]] && continue
        ((i++))
        printf "\r${CYAN}[*] Scanning $i/$total: $ip ${NC}\n"

        # Build space-separated port:proto map for Python scanner
        local _port_map=""
        for _bp in "${!PROTO_PORTS[@]}"; do
            _port_map="$_port_map ${_bp}:${PROTO_PORTS[$_bp]}"
        done

        # ── Python scanner (ncscanner approach): RTT-calibrated, threaded ──
        # Inject the proto:port map as a Python dict literal into the script.
        # (Using env var avoids the stdin/heredoc conflict when running python3 -)
        local _pairs_py="{"
        for _bp in "${!PROTO_PORTS[@]}"; do
            _pairs_py="${_pairs_py}'${_bp}':${PROTO_PORTS[$_bp]},"
        done
        _pairs_py="${_pairs_py}}"

        local _py_results
        _py_results=$(NXC_PAIRS="$_pairs_py" python3 - "$ip" << 'PYSCAN'
import sys, socket, struct, time, threading, errno, os, ast

target = sys.argv[1]
pairs = ast.literal_eval(os.environ.get("NXC_PAIRS", "{}"))

WORKERS = 200
ECONNREFUSED = getattr(errno, "ECONNREFUSED", 111)

def measure_rtt(host, probe_ports):
    samples = []
    for p in probe_ports:
        if len(samples) >= 3: break
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            t0 = time.perf_counter()
            rc = s.connect_ex((host, p))
            t1 = time.perf_counter()
            s.close()
            if rc in (0, ECONNREFUSED):
                samples.append(t1 - t0)
        except: pass
    if not samples: return 0.0
    samples.sort()
    return samples[len(samples) // 2]

probe_ports = list(pairs.values()) or [80, 443, 22]
rtt = measure_rtt(target, probe_ports[:5])
timeout = max(0.5, min(3.0, rtt * 4.0)) if rtt > 0 else 0.8
sys.stderr.write(f"RTT={rtt*1000:.0f}ms timeout={timeout:.2f}s\n")

open_protos = []
lock = threading.Lock()
sem = threading.Semaphore(WORKERS)
threads = []

def tcp_probe(host, port, timeout, retry=True):
    for attempt in range(2 if retry else 1):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            s.settimeout(timeout if attempt == 0 else timeout * 1.6)
            rc = s.connect_ex((host, port))
            s.close()
            if rc == 0: return "OPEN"
            if rc == ECONNREFUSED: return "CLOSED"
        except: pass
        if attempt == 0 and retry: time.sleep(0.04)
    return "TIMEOUT"

def scan_one(proto, port):
    state = tcp_probe(target, port, timeout)
    if state == "OPEN":
        with lock:
            open_protos.append(proto)
    sem.release()

for proto, port in pairs.items():
    sem.acquire()
    t = threading.Thread(target=scan_one, args=(proto, port), daemon=True)
    threads.append(t); t.start()
for t in threads: t.join()
for p in open_protos: print(p)
PYSCAN
        ) 2>&1

        # Parse results: lines starting with RTT go to stderr, open protos to stdout
        local _rtt_line
        _rtt_line=$(echo "$_py_results" | grep "^RTT=" | head -1)
        [[ -n "$_rtt_line" ]] && echo -e "${GRAY}  $_rtt_line${NC}"

        local _open_protos
        _open_protos=$(echo "$_py_results" | grep -v "^RTT=")

        if [[ -z "$_open_protos" ]]; then
            # Python failed or not available — fall back to nmap then nc
            if command -v nmap >/dev/null 2>&1; then
                local _port_list
                _port_list=$(printf '%s,' "${PROTO_PORTS[@]}" | sed 's/,$//')
                local _nmap_out
                _nmap_out=$(nmap -Pn -T4 -p "$_port_list" --open "$ip" 2>/dev/null)
                for proto in "${!PROTO_PORTS[@]}"; do
                    local port="${PROTO_PORTS[$proto]}"
                    if echo "$_nmap_out" | grep -qE "^${port}/tcp.*open"; then
                        _open_protos="$_open_protos"$'
'"$proto"
                    fi
                done
            else
                for proto in "${!PROTO_PORTS[@]}"; do
                    local port="${PROTO_PORTS[$proto]}"
                    port_open "$ip" "$port" && _open_protos="$_open_protos"$'
'"$proto"
                done
            fi
        fi

        # Write results to target files and cache
        while IFS= read -r _op; do
            _op=$(echo "$_op" | tr -d '[:space:]')
            [[ -z "$_op" ]] && continue
            [[ -n "${PROTO_PORTS[$_op]+_}" ]] || continue
            echo "$ip" >> "$OUTDIR/targets_${_op}.txt"
            echo "${_op}:${ip}" >> "$CACHE_FILE"
        done <<< "$_open_protos"
    done

    echo -e "${GREEN}[+] Port scan cached to $CACHE_FILE${NC}"
    echo -e "${CYAN}[*] Port availability:${NC}"
    for proto in "${PROTO_ORDER[@]}"; do
        local count
        count=$(wc -l < "$OUTDIR/targets_${proto}.txt" 2>/dev/null || echo 0)
        local port="${PROTO_PORTS[$proto]}"
        local _so=false; for _p in "${SCAN_ONLY_PROTOS[@]:-}"; do [[ "$_p" == "$proto" ]] && _so=true; done
        if [[ $count -gt 0 ]]; then
            if [[ "$_so" == true ]]; then
                echo -e "    ${CYAN}$proto($port): $count/$total targets${NC} ${GRAY}[web/db]${NC}"
            else
                echo -e "    ${GREEN}$proto($port): $count/$total targets${NC}"
            fi
        else
            echo -e "    ${GRAY}$proto($port): 0/$total targets${NC}"
        fi
    done
    echo ""

    if [[ -s "$OUTDIR/targets_ldaps.txt" ]]; then
        LDAPS_AVAILABLE=true; LDAP_PORT_FLAG=""
    else
        LDAPS_AVAILABLE=false; LDAP_PORT_FLAG="--port 389"
        echo -e "${YELLOW}[!] LDAPS (636) not available - using plain LDAP (389) to avoid timeouts${NC}"
    fi
}

# ── Runtime init — runs at source time ───────────────────────────────────────
# Must be after find_kerbrute() is defined above.
KERBRUTE_BIN=$(find_kerbrute)
