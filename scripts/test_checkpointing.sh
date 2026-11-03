#!/usr/bin/env bash
# test_checkpointing.sh - the sentinel's checkpoint thread (primary and standby):
#   A. state/checkpoint.dat appears, is valid, and holds the base blacklist
#   B. BLOCK, UNBLOCK and PKT hits reach the file within a couple of checkpoint intervals
#   C. checkpoint.prev appears, and saves happen about every CHECKPOINT_INTERVAL_MS
#   D. SIGTERM stops the thread promptly and leaves a valid file and no .tmp
#   E. a standby keeps checkpointing: epoch + 1, and the restored state is carried forward
#   F. repeated kill -9 at random moments never leaves an invalid checkpoint.dat
# Every sentinel runs in its own temp directory. Needs python3 and the built bin/sentinel;
# UDP port PKT_PORT must be free.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SENTINEL="$ROOT/bin/sentinel"
BLACKLIST="$ROOT/config/blacklist.txt"
PORT=$(awk '/#define PKT_PORT/ {print $3}' "$ROOT/src/protocol.h")
AUTOBAN_X=$(awk '/#define AUTOBAN_MAX_PKTS/ {print $3}' "$ROOT/src/protocol.h")
CKPT_MS=$(awk '/#define CHECKPOINT_INTERVAL_MS/ {print $3}' "$ROOT/src/protocol.h")
MAX_TRACKED=$(awk '/#define MAX_TRACKED_IPS/ {print $3}' "$ROOT/src/protocol.h")
SETTLE=$(python3 -I -c "print($CKPT_MS * 2.2 / 1000.0)")
FIRST_SAVE_S=$(python3 -I -c "print($CKPT_MS * 3 / 1000.0)")

PASS=0
FAIL=0
PIDS=()
DIRS=()
SPID=""
NEWDIR=""

# reads a checkpoint file; prints VALID plus epoch=, bl= and tracked= lines, or INVALID <reason>
INFO_PY='
import struct, sys, zlib
p, ring = sys.argv[1], int(sys.argv[2])
try:
    b = open(p, "rb").read()
except OSError:
    print("INVALID unreadable"); sys.exit(0)
if len(b) < 20:
    print("INVALID short"); sys.exit(0)
if b[:4] != b"SNTL":
    print("INVALID magic"); sys.exit(0)
ver, epoch, n = struct.unpack_from("<III", b, 4)
if ver != 1:
    print("INVALID version"); sys.exit(0)
if 16 + n + 4 != len(b):
    print("INVALID length"); sys.exit(0)
if zlib.crc32(b[:-4]) & 0xFFFFFFFF != struct.unpack_from("<I", b, len(b) - 4)[0]:
    print("INVALID crc"); sys.exit(0)
d = b[16:-4]
pos = 0
blc = struct.unpack_from("<I", d, pos)[0]; pos += 4
ips = []
for _ in range(blc):
    ips.append(d[pos:pos + 16].split(b"\0")[0].decode()); pos += 16
trc = struct.unpack_from("<I", d, pos)[0]; pos += 4
tr = []
for _ in range(trc):
    ip = d[pos:pos + 16].split(b"\0")[0].decode(); pos += 16
    hits = struct.unpack_from("<I", d, pos)[0]; pos += 12 + 8 * ring
    tr.append("%s:%d" % (ip, hits))
if pos + 24 != len(d):
    print("INVALID layout"); sys.exit(0)
print("VALID")
print("epoch=%d" % epoch)
print("bl=" + ",".join(ips))
print("tracked=" + ",".join(tr))
'

# counts how many different modification times the file shows over $2 seconds
MTIME_PY='
import os, sys, time
seen = set()
end = time.time() + float(sys.argv[2])
while time.time() < end:
    try:
        seen.add(os.stat(sys.argv[1]).st_mtime_ns)
    except OSError:
        pass
    time.sleep(0.02)
print(len(seen))
'

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

# sends one message and prints the reply, or <none> after half a second
req() {
    python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
s.settimeout(0.5)
s.sendto(sys.argv[1].encode(), ("127.0.0.1", int(sys.argv[2])))
try:
    print(s.recvfrom(4096)[0].decode(errors="replace"))
except socket.timeout:
    print("<none>")
' "$1" "$PORT"
}

# sends count valid PKT datagrams from source ip $1
send_pkts() {
    python3 -I -c '
import socket, sys
src, count = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, 0))
for i in range(count):
    s.sendto(("PKT|src=%s|dst_port=80|seq=%d|payload=x" % (src, i)).encode(), ("127.0.0.1", int(sys.argv[3])))
' "$1" "$2" "$PORT"
}

# sends one PKT from each of count different source addresses 127.2.x.y
spray() {
    python3 -I -c '
import socket, sys
for i in range(int(sys.argv[1])):
    ip = "127.2.%d.%d" % (i // 250, i % 250 + 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, 0))
    s.sendto(("PKT|src=%s|dst_port=80|seq=1|payload=x" % ip).encode(), ("127.0.0.1", int(sys.argv[2])))
    s.close()
' "$1" "$PORT"
}

# makes a temp directory and leaves its path in NEWDIR
new_dir() {
    NEWDIR="$(mktemp -d /tmp/sentinel_ckpt_XXXXXX)"
    DIRS+=("$NEWDIR")
}

# starts a sentinel in directory $1 with extra arguments; appends to $1/sentinel.log and sets SPID
start_sentinel() {
    local d="$1"
    shift
    ( cd "$d" && exec "$SENTINEL" --no-crash --blacklist "$BLACKLIST" "$@" ) >>"$d/sentinel.log" 2>&1 &
    SPID=$!
    PIDS+=("$SPID")
}

# waits up to $2 seconds for the sentinel in $1 to print "listening on" more than $3 times
wait_listening() {
    local tries=$(( $(python3 -I -c "print(int($2 * 10))") ))
    for _ in $(seq 1 "$tries"); do
        [ "$(grep -c "listening on" "$1/sentinel.log")" -gt "$3" ] && return 0
        sleep 0.1
    done
    return 1
}

# waits up to $2 seconds for file $1 to exist
wait_file() {
    local tries=$(( $(python3 -I -c "print(int($2 * 10))") ))
    for _ in $(seq 1 "$tries"); do
        [ -s "$1" ] && return 0
        sleep 0.1
    done
    return 1
}

# kills the sentinel in SPID with SIGKILL and waits until it is gone
kill_hard() {
    kill -9 "$SPID" 2>/dev/null
    wait "$SPID" 2>/dev/null
    sleep 0.3
}

info() { python3 -I -c "$INFO_PY" "$1" "$((AUTOBAN_X + 1))"; }
field() { grep "^$2=" <<<"$1" | cut -d= -f2-; }
valid_file() { [ "$(info "$1" | head -1)" = "VALID" ]; }
bl_has() { [[ ",$(field "$(info "$1")" bl)," == *",$2,"* ]]; }
bl_lacks() { valid_file "$1" && ! bl_has "$1" "$2"; }
tracked_has() { [[ ",$(field "$(info "$1")" tracked)," == *",$2,"* ]]; }
epoch_is() { [ "$(field "$(info "$1")" epoch)" = "$2" ]; }
log_has() { grep -qF -- "$2" "$1/sentinel.log"; }

if [ ! -x "$SENTINEL" ]; then
    echo "bin/sentinel not found; run make first"
    exit 2
fi
if ! python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", int(sys.argv[1])))' "$PORT" 2>/dev/null; then
    echo "UDP port $PORT is already in use; stop whatever holds it first"
    exit 2
fi

new_dir
D="$NEWDIR"
DAT="$D/state/checkpoint.dat"
PREV="$D/state/checkpoint.prev"
start_sentinel "$D"
PRIMARY=$SPID
wait_listening "$D" 3 0

echo "-- A: first checkpoint"
check "checkpoint.dat appears within 3 intervals" wait_file "$DAT" "$FIRST_SAVE_S"
check "checkpoint.dat is valid" valid_file "$DAT"
check "epoch 0 for the primary" epoch_is "$DAT" 0
check "base blacklist is saved (10.0.0.66)" bl_has "$DAT" 10.0.0.66
check "base blacklist is saved (127.0.0.67)" bl_has "$DAT" 127.0.0.67

echo "-- B: state changes reach the file"
check "BLOCK reply" test "$(req 'BLOCK|ip=10.70.0.1')" = "OK BLOCKED 10.70.0.1"
sleep "$SETTLE"
check "blocked ip is in the checkpoint" bl_has "$DAT" 10.70.0.1
req 'UNBLOCK|ip=10.70.0.1' >/dev/null
sleep "$SETTLE"
check "unblocked ip is gone from the checkpoint" bl_lacks "$DAT" 10.70.0.1
req 'BLOCK|ip=10.70.0.9' >/dev/null
send_pkts 127.0.0.60 3
sleep "$SETTLE"
check "persistent block is in the checkpoint" bl_has "$DAT" 10.70.0.9
check "PKT hit count is in the checkpoint" tracked_has "$DAT" 127.0.0.60:3

echo "-- C: rotation and interval"
check "checkpoint.prev exists" wait_file "$PREV" 1
check "checkpoint.prev is valid" valid_file "$PREV"
SAVES="$(python3 -I -c "$MTIME_PY" "$DAT" 2.4)"
check "saves happen repeatedly (>= 3 in 2.4 s, got $SAVES)" test "$SAVES" -ge 3
check "saves are not a busy loop (1 to 8 in 2.4 s, got $SAVES)" bash -c '[ "$1" -ge 1 ] && [ "$1" -le 8 ]' _ "$SAVES"

echo "-- D: clean shutdown"
kill -TERM "$PRIMARY"
START=$(date +%s.%N)
wait "$PRIMARY"
CODE=$?
ELAPSED=$(python3 -I -c "print(round($(date +%s.%N) - $START, 2))")
check "exit code 0 after SIGTERM" test "$CODE" -eq 0
check "stopped within 2 s (took $ELAPSED s)" python3 -I -c "import sys; sys.exit(0 if $ELAPSED < 2.0 else 1)"
check "no checkpoint.tmp left behind" test ! -e "$D/state/checkpoint.tmp"
check "checkpoint.dat still valid" valid_file "$DAT"

echo "-- E: standby keeps checkpointing"
rm -f "$DAT" "$PREV"
start_sentinel "$D" --standby
wait_listening "$D" 3 1
check "standby logs the takeover" log_has "$D" "[Service Restored]"
check "standby writes its own checkpoint.dat" wait_file "$DAT" "$FIRST_SAVE_S"
check "standby checkpoint is valid" valid_file "$DAT"
kill_hard

echo "-- E2: standby carries the restored state forward"
new_dir
D="$NEWDIR"
DAT="$D/state/checkpoint.dat"
start_sentinel "$D"
wait_listening "$D" 3 0
req 'BLOCK|ip=10.70.0.9' >/dev/null
send_pkts 127.0.0.60 3
sleep "$SETTLE"
kill_hard
start_sentinel "$D" --standby
wait_listening "$D" 3 1
sleep "$SETTLE"
check "epoch is 1 after takeover" epoch_is "$DAT" 1
check "blocked ip carried into the standby's checkpoint" bl_has "$DAT" 10.70.0.9
check "hit counts carried into the standby's checkpoint" tracked_has "$DAT" 127.0.0.60:3
check "standby answers from the restored state" test "$(req 'QUERY|ip=10.70.0.9')" = "BLOCKED hits=0"
kill_hard

echo "-- F: repeated kill -9 at random moments"
new_dir
D="$NEWDIR"
DAT="$D/state/checkpoint.dat"
PREV="$D/state/checkpoint.prev"
start_sentinel "$D"
wait_listening "$D" 3 0
spray $((MAX_TRACKED + 10))
for n in 1 2 3; do
    req "BLOCK|ip=10.71.0.$n" >/dev/null
done
sleep "$SETTLE"
BAD=""
BAD_PREV=""
PREV_SEEN=0
RUNS=12
for i in $(seq 1 "$RUNS"); do
    sleep "$(python3 -I -c "import random; print(round(random.uniform(0.1, 0.9), 2))")"
    kill_hard
    valid_file "$DAT" || BAD="$BAD $i"
    if [ -e "$PREV" ]; then
        PREV_SEEN=$((PREV_SEEN + 1))
        valid_file "$PREV" || BAD_PREV="$BAD_PREV $i"
    fi
    start_sentinel "$D" --standby
    wait_listening "$D" 3 "$i"
done
check "checkpoint.dat valid after each of $RUNS kills (bad runs:${BAD:- none})" test -z "$BAD"
check "checkpoint.prev existed after the kills ($PREV_SEEN of $RUNS)" test "$PREV_SEEN" -gt 0
check "checkpoint.prev valid after each of $RUNS kills (bad runs:${BAD_PREV:- none})" test -z "$BAD_PREV"
sleep "$SETTLE"
check "state survived every takeover (10.71.0.1)" test "$(req 'QUERY|ip=10.71.0.1')" = "BLOCKED hits=0"
check "state survived every takeover (10.71.0.3)" test "$(req 'QUERY|ip=10.71.0.3')" = "BLOCKED hits=0"
kill_hard

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
