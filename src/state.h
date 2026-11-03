
#ifndef STATE_H
#define STATE_H

#include <stdint.h>
#include <pthread.h>
#include "protocol.h"
#include "sentinel_core.h"

typedef enum {
    STATE_OK = 0, // the blacklist changed
    STATE_NOOP = 1, // no change to the blacklist
    STATE_FULL = 2, // block only: BL_MAX entries already blocked
    STATE_BAD_ARG = 3 // NULL argument or ip is not a valid IPv4 address
} state_result_t;
#define HIT_RING (AUTOBAN_MAX_PKTS + 1)

typedef struct {
    char ip[SRC_IP_LEN];
    int hits;
    long long ring[HIT_RING];
    int ring_next;
    int ring_count;
} ip_track_t;

struct sentinel_state {
    pthread_mutex_t lock; // mutual exclusion

    blacklist_t blacklist;
    ip_track_t tracked[MAX_TRACKED_IPS];
    int tracked_count;

    long long total_alerts; // hits from addresses that were already blocked
    long long dropped_packets; // datagrams rejected as malformed or oversized
    int epoch; // 0 for the first primary, +1 for each standby takeover

    int inflight_valid;
    uint32_t inflight_hash;

    int full_warned; // not saved in checkpoints
    long long full_warn_ms; // time of the last tracking-table-full warning

    int suspect_valid; // not saved in checkpoint
    unsigned suspect_hash; // hash of the packet that was in flight when the previous primary died
};
typedef struct sentinel_state sentinel_state_t;

int state_init(sentinel_state_t *s, const blacklist_t *base);

state_result_t state_block(sentinel_state_t *s, const char *ip);

state_result_t state_unblock(sentinel_state_t *s, const char *ip);

int state_query(sentinel_state_t *s, const char *ip, int *hits);

int state_record_hit(sentinel_state_t *s, const char *ip, long long now_ms);

int state_begin_packet(sentinel_state_t *s, unsigned hash);

int state_end_packet(sentinel_state_t *s);

int state_adopt_suspect(sentinel_state_t *s);

int state_is_suspect(sentinel_state_t *s, unsigned hash);

#endif
