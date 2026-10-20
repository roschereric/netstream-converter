#!/bin/bash
# nsconv test kit: collect end-to-end evidence (nsconv + FlowLink) into one .tgz.
# Run as root on the nsconv host; with FlowLink on another host, also run it there with --flowlink-only.
# For --secs seconds it captures NetStream input (switch -> nsconv) and nsconv output (nsconv -> collector) with
# tcpdump (bounded size), and collects status, logs, config, service, sandbox, network, SELinux and FlowLink
# facts. FlowLink secrets are redacted; the FlowLink API key file is never read. A missing tool or file is
# recorded in MANIFEST.tsv and never stops the run. Nothing is changed on the host.
#
#   sudo ./nsconv-collect-evidence.sh                         # 300 s window, then start your replay
#   sudo ./nsconv-collect-evidence.sh --secs 600 --sample sample-v9.pcap --note "test 3: v9 IPv6"
#   sudo ./nsconv-collect-evidence.sh --flowlink-only         # on a separate FlowLink host
#   ./nsconv-collect-evidence.sh --dry-run                    # print what would run
set -u
export LC_ALL=C PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

SECS=300
MAX_MB=100
OUTDIR=.
IN_IFACE=any
DRY=0
FL_ONLY=0
NOTE=""
SAMPLES=()
NSCONF=/etc/nsconv/nsconv.toml
FLCONF=/etc/illumio-flowlink/config.yaml
FLLOG=/var/log/illumio-flowlink/flowlink.log

usage() {
    cat <<'EOT'
Usage: nsconv-collect-evidence.sh [options]
  --secs N          capture window in seconds (default 300)
  --max-mb N        size cap per capture file in MB (default 100)
  --in-iface IF     interface for the input capture (default any; use the NIC name on bonded hosts)
  --sample FILE     add the sample pcap you replayed (repeatable)
  --note TEXT       free text stored in NOTE.txt (what you tested)
  --config FILE     nsconv config (default /etc/nsconv/nsconv.toml)
  --flowlink-only   FlowLink host without nsconv: capture traffic to FlowLink's ports, collect FlowLink only
  --out DIR         where to write the .tgz (default current directory)
  --dry-run         print the commands and change nothing
EOT
}

while [ $# -gt 0 ]; do
    case $1 in
        --secs) SECS=$2; shift ;;
        --max-mb) MAX_MB=$2; shift ;;
        --in-iface) IN_IFACE=$2; shift ;;
        --sample) SAMPLES+=("$2"); shift ;;
        --note) NOTE=$2; shift ;;
        --config) NSCONF=$2; shift ;;
        --flowlink-only) FL_ONLY=1 ;;
        --out) OUTDIR=$2; shift ;;
        --dry-run) DRY=1 ;;
        -h | --help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done
case $SECS$MAX_MB in *[!0-9]*) echo "--secs and --max-mb take whole numbers" >&2; exit 2 ;; esac
if [ "$DRY" = 0 ] && [ "$(id -u)" != 0 ]; then
    echo "run as root (sudo): tcpdump, journal, audit log and FlowLink files need it; or use --dry-run" >&2
    exit 2
fi

HOST=$(hostname -s 2>/dev/null || hostname)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
NAME=nsconv-evidence-$HOST-$STAMP
W=$(mktemp -d "${TMPDIR:-/tmp}/nsconv-evidence.XXXXXX") || exit 1
D=$W/$NAME
mkdir -p "$D/cmd" "$D/pcap" "$D/files"
printf 'item\texit\tfile\tcommand\n' >"$D/MANIFEST.tsv"
[ "$DRY" = 1 ] && echo "dry run: nothing is captured or written; commands that would run:"

# item NAME[.json] command... : stdout to cmd/NAME.txt (or NAME.json), stderr to cmd/NAME.err when not empty, exit
# code to MANIFEST; never fails the run
item() {
    local n=${1%.json} f=$1
    [ "$f" = "$n" ] && f=$n.txt
    shift
    if [ "$DRY" = 1 ]; then echo "  [$f] $*"; return 0; fi
    local rc=0
    if command -v "$1" >/dev/null 2>&1; then
        timeout 60 "$@" >"$D/cmd/$f" 2>"$D/cmd/$n.err" || rc=$?
        [ -s "$D/cmd/$n.err" ] || rm -f "$D/cmd/$n.err"
    else
        echo "not available: $1" >"$D/cmd/$f"
        rc=127
    fi
    printf '%s\t%s\tcmd/%s\t%s\n' "$n" "$rc" "$f" "$*" >>"$D/MANIFEST.tsv"
}
# sh NAME 'shell text' : same for a pipeline
sh_item() {
    if [ "$DRY" = 1 ]; then echo "  [$1] $2"; return 0; fi
    local rc=0
    timeout 60 bash -c "$2" >"$D/cmd/$1.txt" 2>&1 || rc=$?
    printf '%s\t%s\tcmd/%s.txt\t%s\n' "$1" "$rc" "$1" "$2" >>"$D/MANIFEST.tsv"
}
# copy SRC [DESTNAME] : a file into files/
copy() {
    local dst=${2:-$(basename "$1")}
    if [ "$DRY" = 1 ]; then echo "  [copy] $1 -> files/$dst"; return 0; fi
    local rc=1
    [ -r "$1" ] && cp -p "$1" "$D/files/$dst" && rc=0
    printf 'copy\t%s\tfiles/%s\t%s\n' "$rc" "$dst" "$1" >>"$D/MANIFEST.tsv"
}
redact() { # FlowLink YAML: blank the value of any key that looks like a secret, and user:password@ in URLs
    sed -E -e 's/^([[:space:]-]*[A-Za-z0-9_]*(api_?key|secret|token|password|passwd|credential)[A-Za-z0-9_]*[[:space:]]*:).*/\1 <REDACTED>/I' \
        -e 's#(://)[^/@[:space:]]+@#\1<REDACTED>@#g' "$1"
}

NSCONVCTL=${NSCONVCTL:-$(command -v nsconvctl || echo /usr/bin/nsconvctl)} # env override for a non-RPM binary
HAVE_NS=0
[ "$FL_ONLY" = 0 ] && [ -x "$NSCONVCTL" ] && HAVE_NS=1
HAVE_FL=0
{ [ -e "$FLCONF" ] || systemctl cat illumio-flowlink >/dev/null 2>&1; } && HAVE_FL=1
[ "$DRY" = 1 ] && HAVE_FL=1 && { [ "$FL_ONLY" = 1 ] || HAVE_NS=1; }

# ---- what to capture --------------------------------------------------------------------------------------
IN_PORTS=""
OUT_TARGETS=""
if [ "$HAVE_NS" = 1 ]; then
    CFG=$("$NSCONVCTL" --config "$NSCONF" config show 2>/dev/null)
    IN_PORTS=$(echo "$CFG" | sed -n 's/^input\..*\.listen = "\(.*\)"$/\1/p' | sed 's/.*://' | sort -u | tr '\n' ' ')
    OUT_TARGETS=$(echo "$CFG" | sed -n 's/^output\.\(.*\)\.target = "\(.*\)"$/\1=\2/p' | tr '\n' ' ')
    # dry run without read access to the config: show the shape
    [ "$DRY" = 1 ] && [ -z "$IN_PORTS" ] && IN_PORTS="<listen-port>" && OUT_TARGETS="<output>=<target-ip>:<port>"
fi
FL_PORTS=""
if [ "$FL_ONLY" = 1 ] && [ -r "$FLCONF" ]; then
    FL_PORTS=$(sed -n "s/^[[:space:]]*ports:[[:space:]]*['\"]\{0,1\}\([0-9][0-9, ]*\).*/\1/p" "$FLCONF" | tr -s ', ' '\n' | grep . | sort -u | tr '\n' ' ')
fi
port_filter() { # "9996 2055" -> "udp and (dst port 9996 or dst port 2055)"
    local f="" p
    for p in $1; do f="$f${f:+ or }dst port $p"; done
    echo "udp and ($f)"
}
COUNT=$((MAX_MB * 1024 * 1024 / 1500))
PIDS=()
CAPS=()
capture() { # capture NAME IFACE FILTER
    if [ "$DRY" = 1 ]; then echo "  [pcap/$1.pcap] timeout -s INT $((SECS + 5)) tcpdump -i $2 -nn -s 0 -U -c $COUNT -w pcap/$1.pcap '$3'"; return; fi
    if ! command -v tcpdump >/dev/null 2>&1; then
        printf 'pcap/%s\t127\t-\ttcpdump not installed (dnf install tcpdump)\n' "$1" >>"$D/MANIFEST.tsv"
        return
    fi
    timeout -s INT $((SECS + 5)) tcpdump -i "$2" -nn -s 0 -U -c "$COUNT" -w "$D/pcap/$1.pcap" "$3" >"$D/cmd/tcpdump-$1.txt" 2>&1 &
    PIDS+=($!)
    CAPS+=("pcap/$1	pcap/$1.pcap	tcpdump -i $2 -c $COUNT '$3' (log: cmd/tcpdump-$1.txt)")
}
local_iface() { # interface the kernel uses to reach IP (lo for this host's own addresses)
    ip route get "$1" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -1
}

# ---- before the window ------------------------------------------------------------------------------------
T0=$(date +%s)
sh_item host 'date -u; hostname -f; uname -a; cat /etc/os-release; uptime'
sh_item clock 'timedatectl 2>&1; chronyc tracking 2>&1'
if [ "$HAVE_NS" = 1 ]; then
    item nsconv-version "$NSCONVCTL" version
    item nsconv-status-before.json "$NSCONVCTL" --config "$NSCONF" --json status --detail
    sh_item udp-snmp-before 'grep ^Udp: /proc/net/snmp; grep ^Udp6 /proc/net/snmp6'
fi

if [ "$FL_ONLY" = 0 ] && [ -n "$IN_PORTS" ]; then
    capture input "$IN_IFACE" "$(port_filter "$IN_PORTS")"
fi
for t in $OUT_TARGETS; do
    n=${t%%=*}
    hp=${t#*=}
    h=${hp%:*}
    h=${h#[}
    h=${h%]}
    ifc=$(local_iface "$h")
    capture "output-$n" "${ifc:-any}" "udp and dst host $h and dst port ${hp##*:}"
done
if [ "$FL_ONLY" = 1 ]; then
    if [ -n "$FL_PORTS" ] || [ "$DRY" = 1 ]; then
        capture flowlink-input "$IN_IFACE" "$(port_filter "${FL_PORTS:-<flowlink-port>}")"
    else
        printf 'pcap/flowlink-input\t1\t-\tno ports found in %s\n' "$FLCONF" >>"$D/MANIFEST.tsv"
    fi
fi
FLSIZE0=0
[ -r "$FLLOG" ] && FLSIZE0=$(stat -c %s "$FLLOG" 2>/dev/null || echo 0)

# ---- the window -------------------------------------------------------------------------------------------
if [ "$DRY" = 1 ]; then
    echo "  [wait] $SECS s: replay the sample pcap now (tcpreplay or nsconvctl replay)"
else
    echo "capturing for $SECS s into $D (start your replay now; Ctrl+C stops early and still writes the .tgz)"
    trap 'echo "stopping early"' INT
    sleep "$SECS" || true
    trap - INT
fi

# ---- after the window -------------------------------------------------------------------------------------
if [ "$HAVE_NS" = 1 ]; then
    item nsconv-status-after.json "$NSCONVCTL" --config "$NSCONF" --json status --detail
    item nsconv-status-text "$NSCONVCTL" --config "$NSCONF" status --detail
    sh_item udp-snmp-after 'grep ^Udp: /proc/net/snmp; grep ^Udp6 /proc/net/snmp6'
fi
if [ "$DRY" = 0 ]; then
    sleep 2 # let the last output datagrams (flush_ms) reach the capture
    # TERM to timeout is passed on to tcpdump, which flushes and closes the file (exit 0 or 124 = stopped by us)
    for p in "${PIDS[@]+"${PIDS[@]}"}"; do kill -TERM "$p" 2>/dev/null; done
    i=0
    for p in "${PIDS[@]+"${PIDS[@]}"}"; do
        rc=0
        wait "$p" 2>/dev/null || rc=$?
        c=${CAPS[$i]}
        printf '%s\t%s\t%s\n' "${c%%	*}" "$rc" "${c#*	}" >>"$D/MANIFEST.tsv"
        i=$((i + 1))
    done
fi
SINCE=$(date -d "@$((T0 - 600))" '+%Y-%m-%d %H:%M:%S' 2>/dev/null || echo "-15min")

if [ "$HAVE_NS" = 1 ]; then
    item nsconv-logs "$NSCONVCTL" --config "$NSCONF" logs --since "$SINCE"
    item nsconv-journal-json journalctl -u nsconv --since "$SINCE" -o json --no-pager
    item nsconv-config-show "$NSCONVCTL" --config "$NSCONF" config show
    item nsconv-config-check "$NSCONVCTL" --config "$NSCONF" config check
    copy "$NSCONF" nsconv.toml
    item nsconv-unit-status systemctl status nsconv --no-pager -l
    item nsconv-unit-cat systemctl cat nsconv
    item nsconv-unit-show systemctl show nsconv -p MainPID -p ActiveState -p NRestarts -p ExecMainStartTimestamp
    item nsconv-security systemd-analyze security nsconv --no-pager
    item nsconv-rpm rpm -q nsconv
    item nsconv-rpm-verify rpm -V nsconv
    # shellcheck disable=SC2016 # expanded by the inner bash
    sh_item nsconv-process 'p=$(systemctl show -p MainPID --value nsconv); [ "${p:-0}" != 0 ] && { ps -o user,pid,nlwp,rss,etime,args -p "$p"; ps -Z -p "$p"; grep -E "^(Cap|NoNewPrivs|Threads|VmRSS|VmHWM)" /proc/$p/status; }'
    # decode the captures here, so the evidence holds flows as nsconv itself reads them
    if [ "$DRY" = 1 ]; then
        echo "  [decode] nsconvctl --json decode pcap/<each>.pcap > pcap/<each>.flows.jsonl"
    else
        for f in "$D"/pcap/*.pcap; do
            [ -s "$f" ] || continue
            b=${f%.pcap}
            "$NSCONVCTL" --json decode "$f" >"$b.flows.jsonl" 2>"$b.decode-summary.txt"
            printf 'decode\t%s\tpcap/%s\tnsconvctl --json decode %s\n' "$?" "$(basename "$b").flows.jsonl" "$(basename "$f")" >>"$D/MANIFEST.tsv"
        done
    fi
fi

sh_item sysctl 'sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter; sysctl -a 2>/dev/null | grep -E "\.rp_filter|net.core.rmem|net.core.netdev_max_backlog|ip_nonlocal_bind|udp_mem"'
sh_item firewalld 'firewall-cmd --state && firewall-cmd --get-active-zones && firewall-cmd --list-all-zones'
sh_item nft 'nft list ruleset 2>&1 | head -400'
sh_item selinux 'getenforce; sestatus'
sh_item avc-recent 'ausearch -m avc,user_avc -ts recent -i 2>&1 | tail -200'
# the whole window from the raw log (ausearch -ts today can take minutes on a large audit.log)
sh_item avc-window "grep -h 'avc: .*denied' /var/log/audit/audit.log | awk -F'[(.]' -v t=$((T0 - 600)) '\$2 >= t' | tail -200"
item ss-udp ss -lunp
item ss-udp-mem ss -uanmp
sh_item ip 'ip -s addr; ip route; ip -6 route; ip neigh'

if [ "$HAVE_FL" = 1 ]; then
    sh_item flowlink-version 'rpm -q illumio-flowlink; ls -l /usr/local/bin/flowlink /usr/local/bin/illumio-flowlink-ctl'
    item flowlink-unit-status systemctl status illumio-flowlink --no-pager -l
    sh_item flowlink-ctl-status 'sudo -u ilo-flowlink /usr/local/bin/illumio-flowlink-ctl status'
    if [ "$DRY" = 1 ]; then
        echo "  [copy] $FLCONF -> files/flowlink-config.redacted.yaml (secrets replaced by <REDACTED>; api_info is never read)"
        echo "  [copy] lines appended to $FLLOG during the window -> files/flowlink-window.log"
    else
        rc=1
        [ -r "$FLCONF" ] && redact "$FLCONF" >"$D/files/flowlink-config.redacted.yaml" && rc=0
        printf 'copy\t%s\tfiles/flowlink-config.redacted.yaml\t%s (secrets redacted)\n' "$rc" "$FLCONF" >>"$D/MANIFEST.tsv"
        rc=1
        if [ -r "$FLLOG" ]; then
            size=$(stat -c %s "$FLLOG")
            # a rotated log restarts at 0: then take the whole new file
            if [ "$size" -ge "$FLSIZE0" ]; then tail -c +$((FLSIZE0 + 1)) "$FLLOG"; else cat "$FLLOG"; fi \
                | head -c $((MAX_MB * 1024 * 1024)) >"$D/files/flowlink-window.log" && rc=0
            tail -n 500 "$FLLOG" >"$D/files/flowlink-tail500.log"
        fi
        printf 'copy\t%s\tfiles/flowlink-window.log\t%s from byte %s\n' "$rc" "$FLLOG" "$FLSIZE0" >>"$D/MANIFEST.tsv"
    fi
    item flowlink-journal journalctl -u illumio-flowlink --since "$SINCE" --no-pager
    sh_item flowlink-files 'ls -la /var/log/illumio-flowlink/ /var/lib/illumio-flowlink/data 2>&1 | head -100; ls -l /usr/local/illumio/ 2>&1'
    copy /usr/local/illumio/flowlink_config_schema.json
fi

for s in "${SAMPLES[@]+"${SAMPLES[@]}"}"; do copy "$s" "sample-$(basename "$s")"; done
if [ "$DRY" = 1 ]; then
    echo "  [write] NOTE.txt, SHA256SUMS, $OUTDIR/$NAME.tgz"
    rm -rf "$W"
    exit 0
fi
{
    echo "host: $HOST  window: $(date -u -d "@$T0" '+%Y-%m-%d %H:%M:%S') UTC + ${SECS} s  flowlink-only: $FL_ONLY"
    echo "input ports: ${IN_PORTS:-none}  outputs: ${OUT_TARGETS:-none}  flowlink ports: ${FL_PORTS:-n/a}"
    echo "note: $NOTE"
} >"$D/NOTE.txt"
{ # quick look for the tester; the full check is in the guide (section "How the evidence is validated")
    for f in "$D"/pcap/*.decode-summary.txt; do
        [ -e "$f" ] && echo "$(basename "${f%.decode-summary.txt}").pcap: $(grep -o 'datagrams=[0-9]* flows=[0-9]*' "$f")"
    done
    [ -s "$D/cmd/nsconv-status-after.json" ] &&
        echo "status after: $(grep -o '"unaccounted": *[0-9]*' "$D/cmd/nsconv-status-after.json" | head -1), health $(grep -o '"health": *"[a-z]*"' "$D/cmd/nsconv-status-after.json" | head -1)"
} >"$D/SUMMARY.txt" 2>/dev/null
cat "$D/SUMMARY.txt"
# MANIFEST.tsv: item, exit code, file, sha256 of the file, command. SHA256SUMS: for `sha256sum -c`.
{
    printf 'item\texit\tfile\tsha256\tcommand\n'
    tail -n +2 "$D/MANIFEST.tsv" | while IFS="$(printf '\t')" read -r n rc f c; do
        h=-
        [ -f "$D/$f" ] && h=$(sha256sum "$D/$f" | cut -d' ' -f1)
        printf '%s\t%s\t%s\t%s\t%s\n' "$n" "$rc" "$f" "$h" "$c"
    done
} >"$D/MANIFEST.new" && mv "$D/MANIFEST.new" "$D/MANIFEST.tsv"
# shellcheck disable=SC2094 # find skips SHA256SUMS itself
(cd "$D" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum >SHA256SUMS)
echo "items that failed or are missing (exit code not 0; 124 on a capture = stopped at the end of the window):"
awk -F'\t' 'NR > 1 && $2 != "0" {print "  " $1 " (exit " $2 "): " $5}' "$D/MANIFEST.tsv"
mkdir -p "$OUTDIR"
if tar -C "$W" -czf "$OUTDIR/$NAME.tgz" "$NAME"; then
    rm -rf "$W"
    echo "wrote $OUTDIR/$NAME.tgz ($(du -h "$OUTDIR/$NAME.tgz" | cut -f1)), sha256 $(sha256sum "$OUTDIR/$NAME.tgz" | cut -d' ' -f1)"
else
    echo "tar failed; the evidence is still in $D" >&2
    exit 1
fi
