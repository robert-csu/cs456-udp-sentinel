#!/usr/bin/env python3
"""Send three heartbeat-validation probes to the running CS456 monitor.
 
The monitor runs in a separate terminal. This script does not capture monitor
stdout or save logs, so it reports sent probes and *expected* rejection output,
not independently verified PASS/FAIL results.
"""
import socket
import time
 
HOST = "127.0.0.1"
HEARTBEAT_PORT = 9100
 
 
def send_heartbeat(pid, epoch, seq):
    payload = f"HEARTBEAT|pid={pid}|epoch={epoch}|seq={seq}|ts={int(time.time() * 1000)}"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(payload.encode("ascii"), (HOST, HEARTBEAT_PORT))
    print(f"Sent: {payload}", flush=True)
 
 
def probe(title, description, pid, epoch, seq, expected):
    print("\n" + "=" * 62)
    print(title)
    print(description)
    send_heartbeat(pid, epoch, seq)
    print(f"Expected in MONITOR terminal: {expected}")
    print("Result: Probe sent. Check the monitor terminal for rejection.")
    time.sleep(2)
 
 
def main():
    print("CS456 SENTINEL — HEARTBEAT VALIDATION DEMO")
    print("Run ./bin/monitor and ./bin/sentinel --no-crash in separate terminals.")
    print("This script requires NO log file. Watch the monitor's live console.\n")
    try:
        pid = int(input("Enter the real Sentinel PID from the monitor: ").strip())
        if pid <= 0:
            raise ValueError
    except (ValueError, EOFError):
        print("ERROR: Enter a positive numeric PID.")
        return 2
 
    print("\nConfirm the monitor is already receiving heartbeats from this PID.")
    input("Press ENTER to begin the three tests...")
 
    probe("TEST 1 — REPLAYED SEQUENCE",
          "Send the correct PID and epoch 0, but reuse old sequence 0.",
          pid, 0, 0, "Rejected stale sequence: 0")
    probe("TEST 2 — SPOOFED PID",
          "Send a heartbeat with a different PID but the same epoch 0.",
          pid + 100000, 0, 999999, "Rejected unexpected PID")
    probe("TEST 3 — UNAUTHORIZED EPOCH",
          "Send a heartbeat claiming a new epoch without a failover.",
          pid + 100000, 99, 999999, "rejected unauthorized epoch change")
 
    print("\n" + "=" * 62)
    print("DEMO COMPLETE — Three probes sent; inspect monitor output for results.")
    print("These checks reject basic replay/identity mismatches, not all spoofing.")
    return 0
 
 
if __name__ == "__main__":
    raise SystemExit(main())