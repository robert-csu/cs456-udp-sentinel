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
// HEARTBEAT|pid=<n>|epoch=<n>|seq=<n>|ts=<ms>
#define HB_FMT_OUT "HEARTBEAT|pid=%d|epoch=%d|seq=%d|ts=%lld"
#define HB_FMT_IN  "HEARTBEAT|pid=%d|epoch=%d|seq=%d|ts=%lld"

#define BL_MAX 256
#define BL_FILE_MAX 65536
#define MAX_TRACKED_IPS 256

// sentinel -> requester (reply to the address the request came from)
#define REPLY_BLOCKED_FMT "OK BLOCKED %s"
#define REPLY_UNBLOCKED_FMT "OK UNBLOCKED %s"
#define REPLY_QUERY_BLOCKED_FMT "BLOCKED hits=%d"
#define REPLY_QUERY_ALLOWED_FMT "ALLOWED hits=%d"
#define REPLY_ERR_FMT "ERR %s"

// client -> sentinel control messages
#define BL_FMT_IN    "BLOCK|ip=%15[^|]"
#define UNBL_FMT_IN  "UNBLOCK|ip=%15[^|]"
#define QUERY_FMT_IN "QUERY|ip=%15[^|]"

#define BL_FMT_OUT    "BLOCK|ip=%s"
#define UNBL_FMT_OUT  "UNBLOCK|ip=%s"
#define QUERY_FMT_OUT "QUERY|ip=%s"


// auto-ban: an IP sending more than X packets within Y ms is blocked
#define AUTOBAN_MAX_PKTS 20 // X
#define AUTOBAN_WINDOW_MS 1000 // Y: one second

// checkpointing
#define CHECKPOINT_INTERVAL_MS 500 // K: same as T_MS
#define CHECKPOINT_PATH "state/checkpoint.dat"
#define CHECKPOINT_TMP "state/checkpoint.tmp"
#define CHECKPOINT_PREV "state/checkpoint.prev"

#define BIND_RETRY_MS 2000
#define BIND_RETRY_STEP_MS 100

#endif