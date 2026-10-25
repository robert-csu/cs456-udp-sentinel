#ifndef PROTOCOL_H
#define PROTOCOL_H

#define HOST "127.0.0.1"
#define PKT_PORT 9000 // client -> sentinel
#define HEARTBEAT_PORT 9100 // sentinel -> monitor
#define T_MS 500
#define MAX_MISSED_HEARTBEAT 3
#define MAX_PKT_SIZE 576

#endif