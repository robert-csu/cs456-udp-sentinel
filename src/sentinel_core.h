#ifndef SENTINEL_CORE_H
#define SENTINEL_CORE_H

#include "protocol.h"

// parse_pkt error codes
typedef enum {
    PKT_OK = 0,
    PKT_ERR_NULL = -1, // buf or out is NULL
    PKT_ERR_FORMAT = -2, // sscanf did not match all 4 fields
    PKT_ERR_TRAILING = -3, // all fields matched but bytes were left over
    PKT_ERR_SRC = -4, // src is not a valid IPv4 address
    PKT_ERR_PORT = -5, // dst_port outside 1..65535
    PKT_ERR_SEQ = -6, // seq is negative
    PKT_ERR_CHAR = -7 // illegal '|' in payload
} pkt_err_t;

typedef struct {
    char src[SRC_IP_LEN];
    int dst_port;
    int seq;
    char payload[PAYLOAD_LEN];
} pkt_t;


pkt_err_t parse_pkt(const char *buf, pkt_t *out);

#endif
