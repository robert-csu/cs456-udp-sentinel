#ifndef SENTINEL_CORE_H
#define SENTINEL_CORE_H

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
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


static inline pkt_err_t parse_pkt(const char *buf, pkt_t *out){
    if(!buf || !out) {
        return PKT_ERR_NULL;
    }
    
    char src[SRC_IP_LEN] = {0};
    int dst_port = 0;
    int seq = 0;
    char payload[PAYLOAD_LEN] = {0};

    int consumed = 0;
    int matched = sscanf(buf, PKT_FMT_IN "%n", src, &dst_port, &seq, payload, &consumed);
    if(matched != 4) {
        return PKT_ERR_FORMAT;
    }
    size_t buf_len = strlen(buf);
    if(buf_len > 0 && buf[buf_len - 1] == '\n') {
        buf_len--; // Exclude the newline character from the length
        if(buf_len > 0 && buf[buf_len - 1] == '\r') {
            buf_len--; // Exclude the carriage return character from the length
        }
    }
    if((size_t)consumed != buf_len) {
        return PKT_ERR_TRAILING;
    }

    struct in_addr addr;
    int result = inet_pton(AF_INET, src, &addr);
    if(result != 1) {
        return PKT_ERR_SRC;
    }

    if(dst_port < 1 || dst_port > 65535) {
        return PKT_ERR_PORT;
    }

    if(seq < 0) {
        return PKT_ERR_SEQ;
    }

    if(strchr(payload, '|')) {
        return PKT_ERR_CHAR;
    }


    strcpy(out->src, src);
    out->dst_port = dst_port;
    out->seq = seq;
    strcpy(out->payload, payload);

    return PKT_OK;
}

#endif
