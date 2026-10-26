#ifndef SENTINEL_CORE_H
#define SENTINEL_CORE_H

#include <arpa/inet.h>
#include <stdio.h>
#include <stdbool.h>
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

// blacklist_parse / blacklist_load error codes
typedef enum {
    BL_OK = 0,
    BL_ERR_NULL = -1, // text, path or bl is NULL
    BL_ERR_BAD_ENTRY = -2, // a non-blank, non-comment line is not a valid IPv4 address
    BL_ERR_FULL = -3, // more than BL_MAX unique entries
    BL_ERR_IO = -4 // file could not be opened or read
} bl_err_t;

typedef struct {
    char src[SRC_IP_LEN];
    int dst_port;
    int seq;
    char payload[PAYLOAD_LEN];
} pkt_t;

typedef struct{
    char ips[BL_MAX][SRC_IP_LEN];
    int count;
}blacklist_t;


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

// 1 = blocked, 0 = not blocked, -1 = NULL argument
static inline int is_blacklisted(const blacklist_t *bl, const char *ip) {
    if(!bl || !ip) {
        return -1;
    }
    for(int i = 0; i < bl->count; i++) {
        if(strcmp(bl->ips[i], ip) == 0) {
            return 1;
        }
    }
    return 0;
}

// text is the file contents; fills bl only on success
static inline bl_err_t blacklist_parse(const char *text, blacklist_t *bl) {
    if (text == NULL || bl == NULL){
        return BL_ERR_NULL;
    }

    blacklist_t tmp;
    memset(&tmp, 0, sizeof(blacklist_t));

    const char *line = text;
    while(*line != '\0') {
        size_t line_len = strcspn(line, "\n");
        char buf[64];
        if (line_len >= sizeof(buf)) {
            return BL_ERR_BAD_ENTRY;
        }

        memcpy(buf, line, line_len);
        buf[line_len] = '\0';

        int tail = (int)line_len - 1;
        while (tail >= 0 && (buf[tail] == ' ' || buf[tail] == '\t' || buf[tail] == '\r')) {
            buf[tail] = '\0';
            tail--;
        }

        char *entry = buf;
        while (*entry == ' ' || *entry == '\t') {
            entry++;
        }
        if (*entry == '\0') {
            line += line_len;
            if (*line == '\n') line++;
            continue;
        }
        if (*entry == '#') {
            line += line_len;
            if (*line == '\n') line++;
            continue;
        }

        struct in_addr addr;
        if (inet_pton(AF_INET, entry, &addr) != 1) {
            return BL_ERR_BAD_ENTRY;
        }

        if (strlen(entry) >= SRC_IP_LEN) {
            return BL_ERR_BAD_ENTRY;
        }

        bool is_duplicate = false;
        for (int i = 0; i < tmp.count; i++) {
            if (strcmp(tmp.ips[i], entry) == 0) {
                is_duplicate = true;
                break;
            }
        }

        if (is_duplicate) {
            line += line_len;
            if (*line == '\n') line++;
            continue;
        }

        if (tmp.count >= BL_MAX) {
            return BL_ERR_FULL;
        }

        strncpy(tmp.ips[tmp.count], entry, SRC_IP_LEN - 1);
        tmp.ips[tmp.count][SRC_IP_LEN - 1] = '\0';
        tmp.count++;

        line += line_len;
        if (*line == '\n') {
            line++;
        }

    }

    memcpy(bl, &tmp, sizeof(blacklist_t));
    return BL_OK;
}

// reads the file at path and passes its contents to blacklist_parse
static inline bl_err_t blacklist_load(const char *path, blacklist_t *bl) {
    (void)path;
    (void)bl;
    return (bl_err_t)-99;
}

#endif
