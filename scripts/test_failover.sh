#!/usr/bin/env bash
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SENTINEL="$ROOT/bin/sentinel"
BLACKLIST="$ROOT/config/blacklist.txt"
PORT=$(awk '/#define PKT_PORT/ {print $3}' "$ROOT/src/protocol.h")
AUTOBAN_X=$(awk '/#define AUTOBAN_MAX_PKTS/ {print $3}' "$ROOT/src/protocol.h")
CKPT_MS=$(awk '/#define CHECKPOINT_INTERVAL_MS/ {print $3}' "$ROOT/src/protocol.h")
SETTLE=$(python3 -I -c "print(($CKPT_MS * 4) / 1000.0)") # long enough for at least two checkpoints

PASS=0
FAIL=0
PIDS=()
DIRS=()

# prints PASS or FAIL for one check
check() {
    local name="$1"
    shift
    if "$@"; then
        echo "  PASS $name"
        PASS=$((PASS + 1))
    else
        echo "  FAIL $name"
        FAIL=$((FAIL + 1))
    fi
}

# kills every sentinel this script started and removes the temp directories
cleanup() {
    for p in "${PIDS[@]:-}"; do
        [ -n "$p" ] && kill -9 "$p" 2>/dev/null
    done
    for d in "${DIRS[@]:-}"; do
        [ -n "$d" ] && rm -rf "$d"
    done
}
trap cleanup EXIT

# sends one UDP message and prints the reply, or <none> after half a second
# usage: req 'MESSAGE (python escapes allowed)' [source ip]
req() {
    python3 -I -c '
import socket, sys
msg = sys.argv[1].encode().decode("unicode_escape").encode("latin-1")
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[2], 0))
s.settimeout(0.5)
s.sendto(msg, ("127.0.0.1", int(sys.argv[3])))
try:
    print(s.recvfrom(4096)[0].decode(errors="replace"))
except socket.timeout:
    print("<none>")
' "$1" "${2:-127.0.0.1}" "$PORT"
}

# sends count PKT datagrams from source ip as fast as possible, without waiting for replies
flood() {
    python3 -I -c '
import socket, sys
src, count = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, 0))
for i in range(count):
    s.sendto(("PKT|src=%s|dst_port=80|seq=%d|payload=x" % (src, i)).encode(), ("127.0.0.1", int(sys.argv[3])))
' "$1" "$2" "$PORT"
}

# starts a sentinel in directory $1 with the extra arguments; sets SPID and logs to $1/sentinel.log
start_sentinel() {
    local d="$1"
    shift
    ( cd "$d" && exec "$SENTINEL" --no-crash --blacklist "$BLACKLIST" "$@" ) >"$d/sentinel.log" 2>&1 &
    SPID=$!
    PIDS+=("$SPID")
}

# waits until the sentinel in SPID answers a QUERY; returns 1 if it never does
wait_ready() {
    for _ in 1 2 3 4 5 6; do
        kill -0 "$SPID" 2>/dev/null || return 1
        if [ "$(req 'QUERY|ip=127.0.0.1')" != "<none>" ]; then
            return 0
        fi
    done
    return 1
}

# kills the sentinel in SPID with SIGKILL and waits until it is gone and the port is free
kill_hard() {
    kill -9 "$SPID" 2>/dev/null
    wait "$SPID" 2>/dev/null
    sleep 0.3
}

# makes a new temp directory and leaves its path in NEWDIR (not a subshell, so cleanup sees it)
new_dir() {
    NEWDIR="$(mktemp -d /tmp/sentinel_test_XXXXXX)"
    DIRS+=("$NEWDIR")
}

# starts a primary in a new directory, blocks three IPs, waits for checkpoints, then kill -9s it;
# sets WORKDIR to the directory
crashed_primary() {
    new_dir
    WORKDIR="$NEWDIR"
    start_sentinel "$WORKDIR"
    wait_ready || { echo "  primary did not start"; return 1; }
    req 'BLOCK|ip=10.30.0.1' >/dev/null
    req 'BLOCK|ip=10.30.0.2' >/dev/null
    req 'BLOCK|ip=10.30.0.3' >/dev/null
    sleep "$SETTLE"
    kill_hard
}

# QUERY answers for a fixed set of ips, joined on one line
snapshot() {
    local out=""
    for ip in 10.30.0.1 10.30.0.2 10.30.0.3 10.31.0.1 127.0.0.50 10.0.0.66 10.32.0.9; do
        out="$out $ip=$(req "QUERY|ip=$ip")"
    done
    echo "$out"
}

contains() { grep -q -- "$2" <<<"$1"; }
starts_with() { [[ "$1" == "$2"* ]]; }
file_has() { grep -q -- "$2" "$1"; }
file_has_i() { grep -qiE -- "$2" "$1"; }
alive() { kill -0 "$1" 2>/dev/null; }

if [ ! -x "$SENTINEL" ]; then
    echo "bin/sentinel not found; run make first"
    exit 2
fi
if [ "$(req 'QUERY|ip=127.0.0.1')" != "<none>" ]; then
    echo "something is already answering on UDP port $PORT; stop it first"
    exit 2
fi

echo "== tests 2-4: block/unblock/query, auto-ban, failover"
new_dir
D1="$NEWDIR"
start_sentinel "$D1"
P1=$SPID
check "primary starts and answers" wait_ready

echo "-- test 2: BLOCK / UNBLOCK / QUERY"
check "BLOCK reply" test "$(req 'BLOCK|ip=10.20.0.1')" = "OK BLOCKED 10.20.0.1"
check "QUERY blocked ip" starts_with "$(req 'QUERY|ip=10.20.0.1')" "BLOCKED hits="
check "UNBLOCK reply" test "$(req 'UNBLOCK|ip=10.20.0.1')" = "OK UNBLOCKED 10.20.0.1"
check "QUERY unblocked ip" starts_with "$(req 'QUERY|ip=10.20.0.1')" "ALLOWED hits="
check "QUERY base blacklist entry" starts_with "$(req 'QUERY|ip=10.0.0.66')" "BLOCKED hits="
check "QUERY unknown ip" starts_with "$(req 'QUERY|ip=10.20.9.9')" "ALLOWED hits=0"

echo "-- test 3: flood one ip"
check "flood source not blocked before" starts_with "$(req 'QUERY|ip=127.0.0.50')" "ALLOWED"
flood 127.0.0.50 $((AUTOBAN_X + 10))
sleep 0.3
check "flooded ip is blocked" starts_with "$(req 'QUERY|ip=127.0.0.50')" "BLOCKED hits="
check "AUTO-BAN logged" file_has "$D1/sentinel.log" "AUTO-BAN 127.0.0.50"

echo "-- test 4: kill -9 the primary, start the standby"
req 'BLOCK|ip=10.30.0.1' >/dev/null
req 'BLOCK|ip=10.30.0.2' >/dev/null
req 'BLOCK|ip=10.30.0.3' >/dev/null
sleep "$SETTLE"
BEFORE="$(snapshot)"
check "snapshot before the crash shows the blocked ips" bash -c '[[ "$1" == *"10.30.0.1=BLOCKED"*"10.30.0.2=BLOCKED"*"10.30.0.3=BLOCKED"*"127.0.0.50=BLOCKED"* ]]' _ "$BEFORE"
check "checkpoint file exists before the crash" test -s "$D1/state/checkpoint.dat"
SPID=$P1
kill_hard
start_sentinel "$D1" --standby
check "standby starts and answers" wait_ready
AFTER="$(snapshot)"
check "QUERY answers identical after failover" test "$BEFORE" = "$AFTER"
check "[Service Restored] logged" file_has "$D1/sentinel.log" "\[Service Restored\]"
check "standby alive" alive "$SPID"
if [ "$BEFORE" != "$AFTER" ]; then
    echo "    before:$BEFORE"
    echo "    after: $AFTER"
fi
kill_hard

echo "== test 5: flipped bytes in checkpoint.dat"
if crashed_primary; then
    python3 -I -c '
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
for off in (20, 30, len(b) - 6):
    b[off] ^= 0xFF
open(p, "wb").write(b)
' "$WORKDIR/state/checkpoint.dat"
    check "checkpoint.prev exists" test -s "$WORKDIR/state/checkpoint.prev"
    start_sentinel "$WORKDIR" --standby
    check "standby starts despite a tampered checkpoint" wait_ready
    check "rejection logged" file_has "$WORKDIR/sentinel.log" "checkpoint rejected"
    check "fell back to checkpoint.prev" file_has "$WORKDIR/sentinel.log" "using checkpoint.prev"
    check "blocked ips restored from checkpoint.prev" starts_with "$(req 'QUERY|ip=10.30.0.2')" "BLOCKED"
    check "[Service Restored] logged" file_has "$WORKDIR/sentinel.log" "\[Service Restored\]"
    check "standby alive" alive "$SPID"
    kill_hard
else
    FAIL=$((FAIL + 1))
fi

echo "== test 6: truncated checkpoint.dat"
if crashed_primary; then
    SIZE=$(stat -c %s "$WORKDIR/state/checkpoint.dat")
    truncate -s $((SIZE / 2)) "$WORKDIR/state/checkpoint.dat"
    check "checkpoint.prev exists" test -s "$WORKDIR/state/checkpoint.prev"
    start_sentinel "$WORKDIR" --standby
    check "standby starts despite a truncated checkpoint" wait_ready
    check "rejection logged" file_has "$WORKDIR/sentinel.log" "checkpoint rejected"
    check "fell back to checkpoint.prev" file_has "$WORKDIR/sentinel.log" "using checkpoint.prev"
    check "blocked ips restored from checkpoint.prev" starts_with "$(req 'QUERY|ip=10.30.0.3')" "BLOCKED"
    check "standby alive" alive "$SPID"
    kill_hard
else
    FAIL=$((FAIL + 1))
fi

echo "== test 7: oversized and malformed input"
new_dir
D7="$NEWDIR"
start_sentinel "$D7"
P7=$SPID
check "primary starts and answers" wait_ready

BIG="$(python3 -I -c 'print("A" * 900)')"
HUGE_IP="$(python3 -I -c 'print("1" * 700)')"

check "oversized PKT gets no OK" test "$(req "PKT|src=10.40.0.1|dst_port=80|seq=1|payload=$BIG")" = "<none>"
check "oversized PKT logged" file_has_i "$D7/sentinel.log" "dropped|rejected|larger"
R="$(req "BLOCK|ip=$HUGE_IP")"
check "oversized BLOCK reply is not OK" bash -c '! [[ "$1" == OK* ]]' _ "$R"

for bad in 'BLOCK|ip=999.1.1.1' 'BLOCK|ip=' 'UNBLOCK|ip=1.2.3' 'QUERY|ip=10.40.0.1x' 'QUERY|ip=10.40.0.1|extra' 'BLOCK|ip=10.40.0.1\r\nBLOCK|ip=10.40.0.2'; do
    check "malformed '$bad' gets ERR" starts_with "$(req "$bad")" "ERR"
done

for bad in 'BLOCK' 'FOO|x' 'PKT|garbage' 'PKT|src=999.9.9.9|dst_port=80|seq=1|payload=x' 'PKT|src=10.40.0.1|dst_port=0|seq=1|payload=x' 'QUERY|ip=10.40.0.1\x00' 'BLOCK|ip=10.40.0.5\x00junk'; do
    R="$(req "$bad")"
    check "malformed '$bad' is not accepted" bash -c '! [[ "$1" == OK* || "$1" == BLOCKED* ]]' _ "$R"
done

check "nothing was blocked by bad input" starts_with "$(req 'QUERY|ip=10.40.0.1')" "ALLOWED hits=0"
check "10.40.0.5 not blocked by NUL-injected message" starts_with "$(req 'QUERY|ip=10.40.0.5')" "ALLOWED"
check "sentinel still alive after bad input" alive "$P7"
check "sentinel still answers" starts_with "$(req 'BLOCK|ip=10.40.0.9')" "OK BLOCKED"
SPID=$P7
kill_hard

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
