# Protocol

All messages are single UDP datagrams of at most `MAX_PKT_SIZE` (576) bytes, text, `|`-separated.
Constants live in `src/protocol.h`.

## Client -> sentinel (UDP 9000)

| Message | Format |
|---|---|
| Packet | `PKT\|src=<ip>\|dst_port=<n>\|seq=<n>\|payload=<text>` |
| Block | `BLOCK\|ip=<ip>` |
| Unblock | `UNBLOCK\|ip=<ip>` |
| Query | `QUERY\|ip=<ip>` |

The blacklist check on a `PKT` uses the real sender address from `recvfrom()`, not the `src=` field.
Oversized, malformed, bad-IP and NUL-containing datagrams are rejected and logged.

## Sentinel -> requester (reply to the sender's address)

| Request | Reply |
|---|---|
| `BLOCK` | `OK BLOCKED <ip>` |
| `UNBLOCK` | `OK UNBLOCKED <ip>` |
| `QUERY` (blocked) | `BLOCKED hits=<n>` |
| `QUERY` (not blocked) | `ALLOWED hits=<n>` |
| any rejected request | `ERR <reason>` |

`PKT` gets no reply.

## Sentinel -> monitor (UDP 9100)

`HEARTBEAT|pid=<pid>|epoch=<n>|seq=<n>|ts=<ms>`, sent every `T_MS` (500 ms). `epoch` is 0 for the first
primary and increases by one each time a standby takes over.

## Constants

| Name | Value | Meaning |
|---|---|---|
| `AUTOBAN_MAX_PKTS` (X) | 20 | packets from one IP within the window before it is auto-banned |
| `AUTOBAN_WINDOW_MS` (Y) | 1000 | auto-ban window |
| `CHECKPOINT_INTERVAL_MS` (K) | 500 | time between checkpoints |
| `MAX_TRACKED_IPS` | 256 | size of the per-IP hit table |
| `CHECKPOINT_PATH` / `_TMP` / `_PREV` | `state/checkpoint.{dat,tmp,prev}` | checkpoint files |
