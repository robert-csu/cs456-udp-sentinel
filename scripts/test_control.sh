#!/usr/bin/env bash

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SENTINEL="$ROOT/bin/sentinel"
BLACKLIST="$ROOT/config/blacklist.txt"
PORT=$(awk '/#define PKT_PORT/ {print $3}' "$ROOT/src/protocol.h")
AUTOBAN_X=$(awk '/#define AUTOBAN_MAX_PKTS/ {print $3}' "$ROOT/src/protocol.h")
BL_MAX=$(awk '/#define BL_MAX/ {print $3}' "$ROOT/src/protocol.h")
MAX_TRACKED=$(awk '/#define MAX_TRACKED_IPS/ {print $3}' "$ROOT/src/protocol.h")

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

# sends one message (python escapes allowed) and prints the reply, or <none> after half a second
# usage: req 'MESSAGE' [source ip]
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

# like req, but prints the address the reply came from as ip:port
req_from() {
    python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[2], 0))
s.settimeout(0.5)
s.sendto(sys.argv[1].encode(), ("127.0.0.1", int(sys.argv[3])))
try:
    print("%s:%d" % s.recvfrom(4096)[1])
except socket.timeout:
    print("<none>")
' "$1" "${2:-127.0.0.1}" "$PORT"
}

# sends count valid PKT datagrams from source ip $1; the src= field claims $3 (default: the real ip)
send_pkts() {
    python3 -I -c '
import socket, sys
src, count, claim = sys.argv[1], int(sys.argv[2]), sys.argv[3] or sys.argv[1]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((src, 0))
for i in range(count):
    s.sendto(("PKT|src=%s|dst_port=80|seq=%d|payload=x" % (claim, i)).encode(), ("127.0.0.1", int(sys.argv[4])))
' "$1" "$2" "${3:-}" "$PORT"
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

# BLOCKs new addresses until a reply is not OK; prints "<number accepted> <first non-OK reply>"
fill_blacklist() {
    python3 -I -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
s.settimeout(0.5)
ok = 0
for i in range(int(sys.argv[1])):
    ip = "10.60.%d.%d" % (i // 200, i % 200 + 1)
    s.sendto(("BLOCK|ip=" + ip).encode(), ("127.0.0.1", int(sys.argv[2])))
    try:
        r = s.recvfrom(4096)[0].decode(errors="replace")
    except socket.timeout:
        r = "<none>"
    if not r.startswith("OK BLOCKED"):
        print(ok, r)
        sys.exit(0)
    ok += 1
print(ok, "<never full>")
' "$((BL_MAX + 50))" "$PORT"
}

# hits=<n> from a QUERY reply, or -1
hits_of() { sed -n 's/.*hits=\([0-9][0-9]*\).*/\1/p' <<<"$1" | grep . || echo -1; }

eq() { [ "$1" = "$2" ]; }
starts_with() { [[ "$1" == "$2"* ]]; }
log_has() { grep -qF -- "$1" "$WORKDIR/sentinel.log"; }

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

WORKDIR="$(mktemp -d /tmp/sentinel_control_XXXXXX)"
( cd "$WORKDIR" && exec "$SENTINEL" --no-crash --blacklist "$BLACKLIST" ) >"$WORKDIR/sentinel.log" 2>&1 &
SPID=$!
for _ in $(seq 1 30); do
    grep -q "listening on" "$WORKDIR/sentinel.log" && break
    sleep 0.1
done
check "sentinel started" log_has "listening on"

echo "-- BLOCK / UNBLOCK / QUERY replies"
check "BLOCK" eq "$(req 'BLOCK|ip=10.20.0.1')" "OK BLOCKED 10.20.0.1"
check "BLOCK again is idempotent" eq "$(req 'BLOCK|ip=10.20.0.1')" "OK BLOCKED 10.20.0.1"
check "QUERY blocked" eq "$(req 'QUERY|ip=10.20.0.1')" "BLOCKED hits=0"
check "UNBLOCK" eq "$(req 'UNBLOCK|ip=10.20.0.1')" "OK UNBLOCKED 10.20.0.1"
check "QUERY unblocked" eq "$(req 'QUERY|ip=10.20.0.1')" "ALLOWED hits=0"
check "UNBLOCK again is idempotent" eq "$(req 'UNBLOCK|ip=10.20.0.1')" "OK UNBLOCKED 10.20.0.1"
check "QUERY base blacklist entry" eq "$(req 'QUERY|ip=10.0.0.66')" "BLOCKED hits=0"
check "UNBLOCK base blacklist entry" eq "$(req 'UNBLOCK|ip=10.0.0.66')" "OK UNBLOCKED 10.0.0.66"
check "base entry allowed after UNBLOCK" eq "$(req 'QUERY|ip=10.0.0.66')" "ALLOWED hits=0"
check "trailing CRLF accepted" eq "$(req 'QUERY|ip=10.20.0.1\r\n')" "ALLOWED hits=0"
check "reply comes from the listening port" eq "$(req_from 'QUERY|ip=10.20.0.1' 127.0.0.77)" "127.0.0.1:$PORT"

echo "-- rejected control messages"
for bad in 'BLOCK|ip=999.1.1.1' 'BLOCK|ip=10.0.0' 'BLOCK|ip=' 'UNBLOCK|ip=1.2.3' 'QUERY|ip=10.40.0.1x' 'BLOCK|ip=not.an.ip'; do
    check "'$bad' -> ERR bad ip" eq "$(req "$bad")" "ERR bad ip"
done
for bad in 'BLOCK|ip' 'BLOCK|' 'BLOCK|foo=1' 'QUERY|ip=10.40.0.1|extra' 'UNBLOCK|ip=10.40.0.1|ip=10.40.0.2'; do
    check "'$bad' -> ERR bad format" eq "$(req "$bad")" "ERR bad format"
done
for bad in 'FOO|x' 'BLOCK' 'block|ip=10.40.0.1' 'QUERY'; do
    check "'$bad' -> ERR unknown type" eq "$(req "$bad")" "ERR unknown type"
done
check "NUL byte gets no reply" eq "$(req 'QUERY|ip=10.40.0.1\x00')" "<none>"
check "NUL byte cannot smuggle a second ip" eq "$(req 'BLOCK|ip=10.40.0.5\x00junk')" "<none>"
check "oversized BLOCK gets no reply" eq "$(req "BLOCK|ip=$(python3 -I -c 'print("1" * 700)')")" "<none>"
check "malformed PKT gets no reply" eq "$(req 'PKT|garbage')" "<none>"
check "valid PKT gets no reply" eq "$(req 'PKT|src=10.40.0.1|dst_port=80|seq=1|payload=x')" "<none>"
check "bad input blocked nothing" eq "$(req 'QUERY|ip=10.40.0.5')" "ALLOWED hits=0"

echo "-- PKT handling"
send_pkts 127.0.0.60 3
sleep 0.2
check "3 PKTs counted for the sender" eq "$(req 'QUERY|ip=127.0.0.60')" "ALLOWED hits=3"
send_pkts 127.0.0.62 2 9.9.9.9
sleep 0.2
check "hits go to the real sender, not the src= claim" eq "$(req 'QUERY|ip=127.0.0.62')" "ALLOWED hits=2"
check "claimed src= address is not counted" eq "$(req 'QUERY|ip=9.9.9.9')" "ALLOWED hits=0"
req 'PKT|src=127.0.0.63|dst_port=0|seq=1|payload=x' 127.0.0.63 >/dev/null
check "malformed PKT is not counted" eq "$(req 'QUERY|ip=127.0.0.63')" "ALLOWED hits=0"
req 'BLOCK|ip=127.0.0.61' >/dev/null
send_pkts 127.0.0.61 2
sleep 0.2
check "blocked sender's PKTs are still counted" eq "$(req 'QUERY|ip=127.0.0.61')" "BLOCKED hits=2"
check "blocked PKT logged as blocked" log_has "blocked 127.0.0.61:"
send_pkts 127.0.0.66 1
sleep 0.2
check "base blacklist sender counted and blocked" eq "$(req 'QUERY|ip=127.0.0.66')" "BLOCKED hits=1"

echo "-- auto-ban"
check "flood source starts allowed" starts_with "$(req 'QUERY|ip=127.0.0.50')" "ALLOWED"
send_pkts 127.0.0.50 $((AUTOBAN_X + 10))
sleep 0.3
R="$(req 'QUERY|ip=127.0.0.50')"
check "flooded ip is blocked" starts_with "$R" "BLOCKED hits="
check "all flood hits counted" bash -c '[ "$1" -ge "$2" ]' _ "$(hits_of "$R")" $((AUTOBAN_X + 1))
check "AUTO-BAN logged" log_has "AUTO-BAN 127.0.0.50"
check "auto-banned ip can be unblocked" eq "$(req 'UNBLOCK|ip=127.0.0.50')" "OK UNBLOCKED 127.0.0.50"
check "unblocked flood source allowed again" starts_with "$(req 'QUERY|ip=127.0.0.50')" "ALLOWED hits="

echo "-- bounds"
read -r OK_COUNT FULL_REPLY <<<"$(fill_blacklist)"
check "blacklist fills up" bash -c '[ "$1" -ge "$2" ] && [ "$1" -le "$3" ]' _ "$OK_COUNT" $((BL_MAX - 20)) "$BL_MAX"
check "BLOCK on a full blacklist -> ERR blacklist full" eq "$FULL_REPLY" "ERR blacklist full"
check "QUERY works while full" starts_with "$(req 'QUERY|ip=10.60.0.1')" "BLOCKED"
check "UNBLOCK frees a slot" eq "$(req 'UNBLOCK|ip=10.60.0.1')" "OK UNBLOCKED 10.60.0.1"
check "BLOCK works again" eq "$(req 'BLOCK|ip=10.61.0.1')" "OK BLOCKED 10.61.0.1"
spray $((MAX_TRACKED + 20))
sleep 0.5
check "tracking table full is logged" log_has "tracking table full"
check "sentinel survives a full tracking table" kill -0 "$SPID"
check "sentinel still answers" starts_with "$(req 'QUERY|ip=10.60.0.2')" "BLOCKED"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]
