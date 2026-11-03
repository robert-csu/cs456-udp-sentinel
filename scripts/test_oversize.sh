#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SENTINEL="$ROOT/bin/sentinel"
BLACKLIST="$ROOT/config/blacklist.txt"
PORT=$(awk '/#define PKT_PORT/ {print $3}' "$ROOT/src/protocol.h")
LIMIT=$(awk '/#define MAX_PKT_SIZE/ {print $3}' "$ROOT/src/protocol.h")

PASS=0
FAIL=0
WORKDIR=""
SPID=""

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

# kills the sentinel and removes the temp directory
cleanup() {
    [ -n "$SPID" ] && kill -9 "$SPID" 2>/dev/null
    [ -n "$WORKDIR" ] && rm -rf "$WORKDIR"
}
trap cleanup EXIT

# sends one datagram of exactly $2 bytes ("PKT|" followed by filler) from source ip $1
send_sized() {
    python3 -I -c '
import socket, sys
src, size = sys.argv[1], int(sys.argv[2])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, 0))
s.sendto((b"PKT|" + b"A" * size)[:size], ("127.0.0.1", int(sys.argv[3])))
' "$1" "$2" "$PORT"
}

# prints the log lines that mention source ip $1
log_for() { grep -F "from $1:" "$WORKDIR/sentinel.log"; }

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

WORKDIR="$(mktemp -d /tmp/sentinel_oversize_XXXXXX)"
( cd "$WORKDIR" && exec "$SENTINEL" --no-crash --blacklist "$BLACKLIST" ) >"$WORKDIR/sentinel.log" 2>&1 &
SPID=$!

for _ in $(seq 1 30); do
    grep -q "listening on" "$WORKDIR/sentinel.log" && break
    sleep 0.1
done
check "sentinel started" grep -q "listening on" "$WORKDIR/sentinel.log"

send_sized 127.0.0.101 "$LIMIT"
send_sized 127.0.0.102 $((LIMIT + 1))
send_sized 127.0.0.103 2000
send_sized 127.0.0.104 65000
send_sized 127.0.0.105 100
sleep 0.5

echo "-- datagram of exactly $LIMIT bytes is not oversized"
check "limit-sized datagram was seen" test -n "$(log_for 127.0.0.101)"
check "limit-sized datagram not reported as oversized" bash -c '! grep -F "from 127.0.0.101:" "$1" | grep -q "exceeds"' _ "$WORKDIR/sentinel.log"

echo "-- oversized datagrams are rejected with their real length"
check "$((LIMIT + 1)) bytes" bash -c 'grep -F "from 127.0.0.102:" "$1" | grep -q "datagram of $2 bytes exceeds"' _ "$WORKDIR/sentinel.log" $((LIMIT + 1))
check "2000 bytes" bash -c 'grep -F "from 127.0.0.103:" "$1" | grep -q "datagram of 2000 bytes exceeds"' _ "$WORKDIR/sentinel.log"
check "65000 bytes" bash -c 'grep -F "from 127.0.0.104:" "$1" | grep -q "datagram of 65000 bytes exceeds"' _ "$WORKDIR/sentinel.log"
check "limit named in the message" bash -c 'grep -F "from 127.0.0.103:" "$1" | grep -q "the $2 byte limit"' _ "$WORKDIR/sentinel.log" "$LIMIT"

echo "-- sentinel keeps running"
check "datagram after the oversized ones was handled" test -n "$(log_for 127.0.0.105)"
check "sentinel still alive" kill -0 "$SPID"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
