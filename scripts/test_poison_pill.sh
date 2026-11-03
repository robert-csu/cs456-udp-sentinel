#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SENTINEL="$ROOT/bin/sentinel"
BLACKLIST="$ROOT/config/blacklist.txt"
PORT=$(awk '/#define PKT_PORT/ {print $3}' "$ROOT/src/protocol.h")
CKPT_MS=$(awk '/#define CHECKPOINT_INTERVAL_MS/ {print $3}' "$ROOT/src/protocol.h")
SETTLE=$(python3 -I -c "print($CKPT_MS * 2.2 / 1000.0)")
STALL_MS=5000
WARN="WARN skipped suspected poison-pill packet"

PASS=0
FAIL=0
PIDS=()
DIRS=()
SPID=""
NEWDIR=""

# FNV-1a (32 bit) of the datagram bytes given as $1, printed as 8 hex digits
FNV_PY='
import sys
h = 0x811C9DC5
for x in sys.argv[1].encode():
    h = ((h ^ x) * 0x01000193) & 0xFFFFFFFF
print("%08x" % h)
'

# prints "<inflight_valid>:<inflight_hash as 8 hex digits>" from a checkpoint file, or INVALID
INFLIGHT_PY='
import struct, sys, zlib
p, ring = sys.argv[1], int(sys.argv[2])
try:
    b = open(p, "rb").read()
except OSError:
    print("INVALID"); sys.exit(0)
if len(b) < 20 or b[:4] != b"SNTL" or zlib.crc32(b[:-4]) & 0xFFFFFFFF != struct.unpack_from("<I", b, len(b) - 4)[0]:
    print("INVALID"); sys.exit(0)
d = b[16:-4]
pos = 0
blc = struct.unpack_from("<I", d, pos)[0]; pos += 4 + 16 * blc
trc = struct.unpack_from("<I", d, pos)[0]; pos += 4 + trc * (16 + 12 + 8 * ring)
pos += 16
valid, h = struct.unpack_from("<II", d, pos)
print("%d:%08x" % (valid, h))
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

# sends a QUERY and prints the reply, or <none> after half a second
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

# sends datagram $2 from source ip $1 and does not wait for a reply
send_from() {
    python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], 0))
s.sendto(sys.argv[2].encode(), ("127.0.0.1", int(sys.argv[3])))
' "$1" "$2" "$PORT"
}

# makes a temp directory and leaves its path in NEWDIR
new_dir() {
    NEWDIR="$(mktemp -d /tmp/sentinel_poison_XXXXXX)"
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

# waits up to 3 seconds for the sentinel log in $1 to show "listening on" more than $2 times
wait_listening() {
    for _ in $(seq 1 30); do
        [ "$(grep -c "listening on" "$1/sentinel.log")" -gt "$2" ] && return 0
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

# hit count a QUERY reports for ip $1, or -1
hits_of() { req "QUERY|ip=$1" | sed -n 's/.*hits=\([0-9][0-9]*\).*/\1/p' | grep . || echo -1; }
inflight_of() { python3 -I -c "$INFLIGHT_PY" "$1" "$((20 + 1))"; }
warn_count() { grep -cF -- "$WARN" "$1/sentinel.log"; }
eq() { [ "$1" = "$2" ]; }

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

POISON='PKT|src=127.0.0.80|dst_port=80|seq=7|payload=STALL'
POISON_HASH="$(python3 -I -c "$FNV_PY" "$POISON")"
OTHER='PKT|src=127.0.0.80|dst_port=80|seq=8|payload=hello'

echo "-- A: checkpoint records the in-flight packet"
new_dir
D="$NEWDIR"
DAT="$D/state/checkpoint.dat"
start_sentinel "$D" --test-stall-ms "$STALL_MS"
check "sentinel accepts --test-stall-ms and starts" wait_listening "$D" 0
send_from 127.0.0.80 "$POISON"
sleep "$SETTLE"
check "checkpoint records valid=1 and the datagram's hash ($POISON_HASH)" eq "$(inflight_of "$DAT")" "1:$POISON_HASH"
kill_hard

echo "-- B: the standby skips that packet once"
start_sentinel "$D" --standby
check "standby starts" wait_listening "$D" 1
H0="$(hits_of 127.0.0.80)"
check "no warning before the packet is replayed" eq "$(warn_count "$D")" 0
send_from 127.0.0.80 "$POISON"
sleep 0.3
check "replayed packet is skipped and logged" eq "$(warn_count "$D")" 1
check "skipped packet is not counted" eq "$(hits_of 127.0.0.80)" "$H0"
send_from 127.0.0.80 "$POISON"
sleep 0.3
check "the same datagram is processed normally the second time" eq "$(hits_of 127.0.0.80)" "$((H0 + 1))"
check "only one warning in total" eq "$(warn_count "$D")" 1
send_from 127.0.0.80 "$OTHER"
sleep 0.3
check "a different packet is processed normally" eq "$(hits_of 127.0.0.80)" "$((H0 + 2))"
kill_hard

echo "-- C: other traffic does not use up the suspect"
new_dir
D="$NEWDIR"
DAT="$D/state/checkpoint.dat"
start_sentinel "$D" --test-stall-ms "$STALL_MS"
wait_listening "$D" 0
send_from 127.0.0.80 "$POISON"
sleep "$SETTLE"
kill_hard
start_sentinel "$D" --standby
wait_listening "$D" 1
send_from 127.0.0.81 'PKT|src=127.0.0.81|dst_port=80|seq=1|payload=x'
sleep 0.3
check "unrelated packet is processed" eq "$(hits_of 127.0.0.81)" 1
check "no warning for the unrelated packet" eq "$(warn_count "$D")" 0
H0="$(hits_of 127.0.0.80)"
send_from 127.0.0.80 "$POISON"
sleep 0.3
check "the suspect is still skipped afterwards" eq "$(warn_count "$D")" 1
check "and it is not counted" eq "$(hits_of 127.0.0.80)" "$H0"
kill_hard

echo "-- D: nothing in flight, nothing skipped"
new_dir
D="$NEWDIR"
DAT="$D/state/checkpoint.dat"
start_sentinel "$D"
wait_listening "$D" 0
send_from 127.0.0.82 'PKT|src=127.0.0.82|dst_port=80|seq=1|payload=x'
sleep "$SETTLE"
check "finished packet is not saved as in flight" eq "$(inflight_of "$DAT")" "0:00000000"
kill_hard
start_sentinel "$D" --standby
wait_listening "$D" 1
send_from 127.0.0.82 'PKT|src=127.0.0.82|dst_port=80|seq=1|payload=x'
sleep 0.3
check "the same packet is processed after takeover" eq "$(hits_of 127.0.0.82)" 2
check "no poison-pill warning" eq "$(warn_count "$D")" 0
kill_hard

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
