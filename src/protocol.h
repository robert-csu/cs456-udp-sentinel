#ifndef PROTOCOL_H
#define PROTOCOL_H

#define HOST "127.0.0.1"
#define PKT_PORT 9000 // client -> sentinel
#define HEARTBEAT_PORT 9100 // sentinel -> monitor
#define T_MS 500
#define MAX_MISSED_HEARTBEAT 3
#define MAX_PKT_SIZE 576

#define MSG_PKT "PKT"
#define MSG_HEARTBEAT "HEARTBEAT"

#define SRC_IP_LEN 16
#define PAYLOAD_LEN 256

// client -> sentinel (UDP PKT_PORT)
// PKT|src=<ip>|dst_port=<n>|seq=<n>|payload=<text>
#define PKT_FMT_OUT "PKT|src=%s|dst_port=%d|seq=%d|payload=%s"
#define PKT_FMT_IN "PKT|src=%15[^|]|dst_port=%d|seq=%d|payload=%255s"

// sentinel -> monitor (UDP HEARTBEAT_PORT)
// HEARTBEAT|pid=<n>|seq=<n>|ts=<ms>
#define HB_FMT_OUT "HEARTBEAT|pid=%d|seq=%d|ts=%lld"
#define HB_FMT_IN "HEARTBEAT|pid=%d|seq=%d|ts=%lld"

#endif