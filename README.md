# cs456-udp-sentinel

## Build and run

```sh
make              # build sentinel, monitor, client into bin/
make tests        # build the C unit tests in tests/ into bin/tests/
make test         # build everything, run the C unit tests, then scripts/test_*.sh
make clean        # remove build/ and bin/
make distclean    # clean, plus delete everything in logs/
```

## Sentinel

The sentinel is the critical service. It listens for UDP packets, drops the ones that come from a
blacklisted address, sends a heartbeat to the monitor on a fixed interval, and (unless told not to)
crashes itself at a random time so the monitor has something to detect.

```sh
bin/sentinel [--blacklist <path>] [--no-crash] [--seed <n>] [--crash-min-ms <n>] [--crash-max-ms <n>] [--help]
```

| Option | Default | Meaning |
|---|---|---|
| `--blacklist <path>` | `config/blacklist.txt` | File of blocked IPv4 addresses |
| `--no-crash` | off | Disable the random crash; run until Ctrl-C or SIGTERM |
| `--seed <n>` | time and pid | Seed for the crash timing. The seed in use is printed at startup, so a crash can be reproduced |
| `--crash-min-ms <n>` | 5000 | Earliest the crash can happen, in milliseconds after startup |
| `--crash-max-ms <n>` | 20000 | Latest the crash can happen |

A bad or missing option value prints a message and exits with code 2. `--crash-min-ms` must not exceed `--crash-max-ms`.

### Trying it by hand

Listen for heartbeats in one terminal:

```sh
python3 -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',9100));[print(s.recvfrom(200)[0].decode(),flush=True) for _ in iter(int,1)]"
```

Run the sentinel in a second one. A short crash window makes the demo quick, and a fixed seed repeats it:

```sh
bin/sentinel --seed 1 --crash-min-ms 3000 --crash-max-ms 6000
```

Send a packet from a blacklisted address in a third:

```sh
python3 -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.66',0));s.sendto(b'PKT|src=8.8.8.8|dst_port=80|seq=1|payload=hi',('127.0.0.1',9000))"
```
