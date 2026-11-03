"""
Induced Failover / Split-Brain

What this script does
---------------------
1. Confirms the primary is alive (PID) and serving (QUERY).
2. Optionally BLOCKs a test IP so we can later detect a stale standby.
3. Drops heartbeats to the monitor (HEARTBEAT_PORT 9100) for the miss window,
   while the primary stays up.
4. Watches for the symptoms of a (false) failover:
     - monitor.log gaining a FAILURE line (detector declared death),
     - a second sentinel process appearing (standby launched),
     - the standby log showing "[Service Restored]" (bind succeeded ->
       hijack) vs "gave up" (bind safeguard held),
     - the test IP's QUERY verdict flipping BLOCKED->ALLOWED (a stale server
       is now answering).
5. Emits timestamped markers and a PASS/FAIL/PARTIAL verdict for the audit summary.

Run the sentinel with --no-crash so a real random crash cannot be
mistaken for an induced false failover.
"""

import argparse
import logging
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime

HOST_DEFAULT = "127.0.0.1"
PKT_PORT = 9000
HEARTBEAT_PORT = 9100
TIMEOUT_MS = 500 * 3

log = logging.getLogger("scenario1")


def _setup_logging(logfile):
    fmt = logging.Formatter("%(asctime)s.%(msecs)03d  %(message)s", "%H:%M:%S")
    h = logging.StreamHandler(sys.stdout)
    h.setFormatter(fmt)
    log.addHandler(h)

    if logfile:
        fh = logging.FileHandler(logfile)
        fh.setFormatter(fmt)
        log.addHandler(fh)
    log.setLevel(logging.INFO)


def mark(tag, msg=""):
    log.info("[%s] %s", tag, msg)

def pid_alive(pid):
    if pid <= 0:
        return None

    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True

def count_processes(pattern):
    if not pattern:
        return -1

    try:
        out = subprocess.run(["pgrep", "-af", pattern],
                             capture_output=True, text=True)
        return len([ln for ln in out.stdout.splitlines() if ln.strip()])
    except FileNotFoundError:
        return -1

def _send_recv(host, port, payload, timeout=2.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload.encode(), (host, port))
            data, _ = s.recvfrom(4096)
            return data.decode(errors="replace").strip()
    except (socket.timeout, OSError):
        return None

def query_ip(host, port, ip):
    return _send_recv(host, port, f"QUERY|ip={ip}")


def block_ip(host, port, ip):
	return _send_recv(host, port, f"BLOCK|ip={ip}")


def query_verdict(resp):
    if not resp:
        return None

    m = re.match(r"(BLOCKED|ALLOWED)\b", resp)
    return m.group(1) if m else None

def count_failure_lines(path):
    try:
        with open(path, "r", errors="replace") as f:
            return sum(1 for ln in f if " FAILURE " in ln)
    except FileNotFoundError:
        return 0


def scan_standby_log(path):
    if not path:
        return None

    try:
        with open(path, "r", errors="replace") as f:
            text = f.read()
    except FileNotFoundError:
        return None

    if "[Service Restored]" in text:
        return "restored"

    if "gave up after" in text:
        return "gaveup"
    return None

class Suppressor:
    def setup(self): ...
    def teardown(self): ...


class ManualSuppressor(Suppressor):
    def setup(self):
        mark("SUPPRESS", "MANUAL: block heartbeats to the monitor now.")

    def teardown(self):
        mark("RESTORE", "MANUAL: restore heartbeat flow now.")


class IptablesDropSuppressor(Suppressor):
    def __init__(self, port):
        self.port = port

    def _rule(self, action):
        subprocess.run(["iptables", action, "INPUT", "-p", "udp",
                        "--dport", str(self.port), "-j", "DROP"], check=True)

    def setup(self):
        self._rule("-I")
        mark("SUPPRESS", f"iptables INPUT DROP udp --dport {self.port}")

    def teardown(self):
        try:
            self._rule("-D")
            mark("RESTORE", "iptables rule removed")
        except subprocess.CalledProcessError:
            mark("RESTORE", "WARNING: could not remove rule - run "
                            f"`sudo iptables -D INPUT -p udp --dport "
                            f"{self.port} -j DROP` by hand")


def build_suppressor(args):
    if args.strategy == "manual":
        return ManualSuppressor()
    if args.strategy == "iptables-drop":
        return IptablesDropSuppressor(args.heartbeat_port)
    raise ValueError(args.strategy)


def run(args):
    if args.sentinel_pid <= 0 and not args.proc_pattern:
        mark("ABORT", "need --sentinel-pid or --proc-pattern to prove the "
                      "sentinel stays alive during the attack")
        return 2

    suppressor = build_suppressor(args)

    if pid_alive(args.sentinel_pid) is False:
        mark("ABORT", f"sentinel PID {args.sentinel_pid} not alive at baseline")
        return 2

    base_failures = count_failure_lines(args.monitor_log)
    base_procs = count_processes(args.proc_pattern)
    serving = query_ip(args.service_host, args.service_port, args.test_ip)

    if serving is None:
        mark("ABORT", "primary not answering QUERY at baseline")
        return 2

    mark("BASELINE", f"sentinel alive; serving (QUERY->{serving!r}); "
                     f"prior FAILURE lines={base_failures}; procs={base_procs}")

    if args.inject_block:
        r = block_ip(args.service_host, args.service_port, args.test_ip)
        v = query_verdict(query_ip(args.service_host, args.service_port,
                                   args.test_ip))
        mark("INJECT", f"BLOCK {args.test_ip} -> {r!r}; QUERY now {v!r} ")

    window = args.timeout_ms / 1000.0 + args.margin
    mark("ATTACK-START", f"dropping heartbeats on {args.heartbeat_port} for "
                         f"{window:.1f}s (timeout {args.timeout_ms}ms + "
                         f"margin {args.margin}s)")
    alive_samples = []
    max_procs = base_procs
    stale_answer_seen = False
    split_brain_seen = False

    try:
        suppressor.setup()
        deadline = time.time() + window
        while time.time() < deadline:
            alive = pid_alive(args.sentinel_pid)
            if alive is not None:
                alive_samples.append(alive)
            nproc = count_processes(args.proc_pattern)
            max_procs = max(max_procs, nproc)
            if args.inject_block:
                v = query_verdict(query_ip(args.service_host,
                                           args.service_port, args.test_ip))
                if v == "ALLOWED":
                    stale_answer_seen = True
            if alive and ((base_procs >= 0 and nproc > base_procs)
                          or stale_answer_seen):
                if not split_brain_seen:
                    mark("SPLIT-BRAIN", f"primary alive while procs={nproc} "
                                        f"(base {base_procs}), "
                                        f"stale_answer={stale_answer_seen}")
                split_brain_seen = True
            time.sleep(args.poll_interval)
    finally:
        suppressor.teardown()

    time.sleep(args.margin)
    new_failures = count_failure_lines(args.monitor_log) - base_failures
    standby = scan_standby_log(args.standby_log)
    final_procs = count_processes(args.proc_pattern)
    sentinel_still_alive = pid_alive(args.sentinel_pid)
    stayed_alive = bool(alive_samples) and all(alive_samples) \
        and sentinel_still_alive is not False
    mark("POST-ATTACK", f"new FAILURE lines={new_failures}; "
                        f"alive_throughout={stayed_alive}; "
                        f"max_procs={max_procs}; final_procs={final_procs}; "
                        f"standby_log={standby}; stale_answer={stale_answer_seen}")

    if not stayed_alive:
        mark("VERDICT", "INCONCLUSIVE - sentinel did not stay alive the whole "
                        "window. Re-run with --no-crash.")
        return 3
    hijack = split_brain_seen or stale_answer_seen or standby == "restored" \
        or (base_procs >= 0 and max_procs > base_procs)
    if hijack:
        mark("VERDICT", "FAIL - SPLIT-BRAIN: a standby came up and bound the"
                        "service port while the original primary never died.")
        return 1
    if new_failures > 0:
        mark("VERDICT", "PARTIAL - induced FALSE POSITIVE in the detector "
                        "(monitor logged FAILURE while the primary was alive), "
                        "but no standby took over.")
        return 1
    mark("VERDICT", "PASS - monitor did not declare the live sentinel dead "
                    "within the window.")
    return 0

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--service-host", default=HOST_DEFAULT)
    p.add_argument("--service-port", type=int, default=PKT_PORT)
    p.add_argument("--heartbeat-port", type=int, default=HEARTBEAT_PORT)
    p.add_argument("--timeout-ms", type=int, default=TIMEOUT_MS)
    p.add_argument("--sentinel-pid", type=int, default=0,
                   help="PID of the primary sentinel (--no-crash).")
    p.add_argument("--proc-pattern", default="sentinel",
                   help="pgrep pattern to count live sentinels.")
    p.add_argument("--monitor-log", default="monitor.log")
    p.add_argument("--standby-log", default=None,
                   help="Optional log where the standby writes "
                        "'[Service Restored]' or 'gave up after'.")
    p.add_argument("--inject-block", action="store_true",
                   help="BLOCK a test IP at baseline and watch for a stale "
                        "standby answering ALLOWED.")
    p.add_argument("--test-ip", default="203.0.113.7",
                   help="TEST-NET-3 IP used for the BLOCK/QUERY probe.")
    p.add_argument("--strategy", choices=["iptables-drop", "manual"],
                   default="manual")
    p.add_argument("--margin", type=float, default=1.0)
    p.add_argument("--poll-interval", type=float, default=0.2)
    p.add_argument("--logfile", default=None)
    return p.parse_args(argv)


def main():
    args = parse_args()
    _setup_logging(args.logfile)
    mark("RUN", f"false-failover audit @ {datetime.now().isoformat()}")
    try:
        sys.exit(run(args))
    except KeyboardInterrupt:
        mark("ABORT", "interrupted - suppressor teardown ran in finally")
        sys.exit(130)


if __name__ == "__main__":
    main()
