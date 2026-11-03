#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SENTINEL="$ROOT/bin/sentinel"
BLACKLIST="$ROOT/config/blacklist.txt"
HB_PORT=$(awk '/#define HEARTBEAT_PORT/ {print $3}' "$ROOT/src/protocol.h")
PKT_PORT=$(awk '/#define PKT_PORT/ {print $3}' "$ROOT/src/protocol.h")
T_MS=$(awk '/#define T_MS/ {print $3}' "$ROOT/src/protocol.h")
CKPT_MS=$(awk '/#define CHECKPOINT_INTERVAL_MS/ {print $3}' "$ROOT/src/protocol.h")
SETTLE=$(python3 -I -c "print($CKPT_MS * 2.2 / 1000.0)")

PASS=0
FAIL=0
PIDS=()
DIRS=()
SPID=""
NEWDIR=""
LISTENER=""
BEATS=""

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

# kills the listener and every sentinel this script started, and removes the temp directories
cleanup() {
    [ -n "$LISTENER" ] && kill "$LISTENER" 2>/dev/null
    for p in "${PIDS[@]:-}"; do
        [ -n "$p" ] && kill -9 "$p" 2>/dev/null
    done
    for d in "${DIRS[@]:-}"; do
        [ -n "$d" ] && rm -rf "$d"
    done
}
trap cleanup EXIT

# makes a temp directory and leaves its path in NEWDIR
new_dir() {
    NEWDIR="$(mktemp -d /tmp/sentinel_hb_XXXXXX)"
    DIRS+=("$NEWDIR")
}

# starts a sentinel in directory $1 with extra arguments and sets SPID to its pid
start_sentinel() {
    local d="$1"
    shift
    ( cd "$d" && exec "$SENTINEL" --no-crash --blacklist "$BLACKLIST" "$@" ) >>"$d/sentinel.log" 2>&1 &
    SPID=$!
    PIDS+=("$SPID")
}

# kills the sentinel in SPID with SIGKILL and waits until it is gone
kill_hard() {
    kill -9 "$SPID" 2>/dev/null
    wait "$SPID" 2>/dev/null
    sleep 0.3
}

# waits up to 4 seconds for a heartbeat from pid $1 to be received
wait_beat() {
    for _ in $(seq 1 40); do
        grep -qF "pid=$1|" "$BEATS" && return 0
        sleep 0.1
    done
    return 1
}

# prints the heartbeat payloads received from pid $1
beats_of() { grep -F "pid=$1|" "$BEATS" | cut -d' ' -f2-; }

# prints the value of field $2 (pid, epoch, seq, ts) from every heartbeat of pid $1
values_of() { beats_of "$1" | sed -n "s/.*|$2=\([0-9][0-9]*\).*/\1/p"; }

# true if pid $1 sent at least one heartbeat and every one of them has epoch $2
all_epoch() {
    local vals
    vals="$(values_of "$1" epoch)"
    [ -n "$vals" ] && [ "$(sort -u <<<"$vals")" = "$2" ]
}

# true if every heartbeat of pid $1 matches the wire format the monitor parses
well_formed() {
    local re='^HEARTBEAT\|pid=[0-9]+\|epoch=[0-9]+\|seq=[0-9]+\|ts=[0-9]+$'
    local line seen=0
    while IFS= read -r line; do
        seen=1
        [[ "$line" =~ $re ]] || return 1
    done < <(beats_of "$1")
    [ "$seen" -eq 1 ]
}

# true if the seq values of pid $1 go up by exactly one each time
seq_consecutive() {
    local prev="" cur
    local count=0
    while read -r cur; do
        if [ -n "$prev" ] && [ "$cur" -ne $((prev + 1)) ]; then
            return 1
        fi
        prev=$cur
        count=$((count + 1))
    done < <(values_of "$1" seq)
    [ "$count" -ge 3 ]
}

if [ ! -x "$SENTINEL" ]; then
    echo "bin/sentinel not found; run make first"
    exit 2
fi
for port in "$HB_PORT" "$PKT_PORT"; do
    if ! python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))' "$port" 2>/dev/null; then
        echo "UDP port $port is already in use; stop whatever holds it first (a running monitor?)"
        exit 2
    fi
done

new_dir
BEATS="$NEWDIR/beats.log"
: >"$BEATS"
python3 -I -c '
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
f = open(sys.argv[2], "a", buffering=1)
while True:
    data, _ = s.recvfrom(2048)
    f.write("%d %s\n" % (int(time.time() * 1000), data.decode(errors="replace")))
' "$HB_PORT" "$BEATS" &
LISTENER=$!
sleep 0.3

echo "-- A: primary"
new_dir
D="$NEWDIR"
start_sentinel "$D"
P1=$SPID
check "primary sends heartbeats" wait_beat "$P1"
START_MS=$(date +%s%3N)
sleep 2.5
END_MS=$(date +%s%3N)
check "heartbeats carry the sentinel's own pid" test -n "$(beats_of "$P1")"
check "wire format matches HEARTBEAT|pid|epoch|seq|ts" well_formed "$P1"
check "epoch is 0 for the primary" all_epoch "$P1" 0
check "seq goes up by one each beat" seq_consecutive "$P1"
IN_WINDOW=$(awk -v s="$START_MS" -v e="$END_MS" -v p="pid=$P1|" '$1 >= s && $1 <= e && index($0, p)' "$BEATS" | wc -l)
EXPECT=$(python3 -I -c "print(int(2500 / $T_MS))")
check "about one heartbeat per $T_MS ms ($IN_WINDOW in 2.5 s, expected near $EXPECT)" \
    bash -c '[ "$1" -ge $(($2 - 1)) ] && [ "$1" -le $(($2 + 1)) ]' _ "$IN_WINDOW" "$EXPECT"

echo "-- B: first takeover"
sleep "$SETTLE"
kill_hard
start_sentinel "$D" --standby
P2=$SPID
check "standby sends heartbeats" wait_beat "$P2"
sleep 1
check "standby has a different pid" test "$P2" != "$P1"
check "epoch is 1 after the first takeover" all_epoch "$P2" 1
check "standby wire format" well_formed "$P2"
check "primary sent no heartbeat after it was killed" bash -c '
    last_p1=$(grep -nF "pid=$1|" "$3" | tail -1 | cut -d: -f1)
    first_p2=$(grep -nF "pid=$2|" "$3" | head -1 | cut -d: -f1)
    [ -n "$last_p1" ] && [ -n "$first_p2" ] && [ "$last_p1" -lt "$first_p2" ]' _ "$P1" "$P2" "$BEATS"

echo "-- C: second takeover"
sleep "$SETTLE"
kill_hard
start_sentinel "$D" --standby
P3=$SPID
check "second standby sends heartbeats" wait_beat "$P3"
sleep 1
check "epoch is 2 after the second takeover" all_epoch "$P3" 2
kill_hard

echo "-- D: standby with no checkpoint"
new_dir
start_sentinel "$NEWDIR" --standby
P4=$SPID
check "standby with no checkpoint sends heartbeats" wait_beat "$P4"
sleep 1
check "epoch is 1 even without a checkpoint" all_epoch "$P4" 1
kill_hard

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
