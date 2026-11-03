"""
spoofer.py - Heartbeat spoofer against the monitor.

Forges datagrams and sends to the monitor on the heartbeat port.
The monitor accepts any beat formed correctly, so it cannot tell the forged beat
apart.
While the real sentinel is dead, the monitor will report the service is healthy.

python3 spoofer.py						# beat forever at the 500ms interval
python3 spoofer.py --interval 0.25		# beat twice as fast
python3 spoofer.py --pid 1234			# pretend to be a different pid
"""

import time
import socket
import argparse

HOST = "127.0.0.1"
HEARTBEAT_PORT = 9100
T_MS = 500
HB_FMT = "HEARTBEAT|pid={pid}|seq={seq}|ts={ts}"

def now_ms():
	return int(time.time() * 1000)

def main():
	parser = argparse.ArgumentParser(description="Spoof heartbeats to the monitor.")
	parser.add_argument("--interval", type=float, default=T_MS / 1000.0, help="seconds between forged beats (default = 500ms)")
	parser.add_argument("--pid", type=int, default=99999, help="fake pid (99999)")
	parser.add_argument("--host", default=HOST)
	parser.add_argument("--port", type=int, default=HEARTBEAT_PORT)

	args = parser.parse_args()
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	print(f"spoofing heartbeats -> {args.host}:{args.port} every {args.interval}s as pid={args.pid}")

	seq = 0
	try:
		while True:
			msg = HB_FMT.format(pid = args.pid, seq=seq, ts=now_ms())
			sock.sendto(msg.encode(), (args.host, args.port))
			print(f"send: {msg}")
			seq += 1
			time.sleep(args.interval)
	except KeyboardInterrupt:
		print("\nstopped")
	finally:
		sock.close()

if __name__ == "__main__":
	main()
