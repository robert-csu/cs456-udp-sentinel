
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "state.h"

#define FULL_WARN_INTERVAL_MS 1000 // at most one tracking-table-full warning per second

// returns 1 if ip is a NUL-terminated dotted IPv4 address that fits in SRC_IP_LEN
static int valid_ip(const char *ip) {
    if (!ip || strlen(ip) >= SRC_IP_LEN) {
        return 0;
    }
    struct in_addr addr;
    return inet_pton(AF_INET, ip, &addr) == 1;
}

// returns index of blocked ip
static int find_blocked(const sentinel_state_t *s, const char *ip) {
    if (!s || !ip) {
        return -1;
    }
    for (int i = 0; i < s->blacklist.count; i++) {
        if (strcmp(s->blacklist.ips[i], ip) == 0) {
            return i;
        }
    }
    return -1;
}

// returns index of tracked ip
static int find_tracked(const sentinel_state_t *s, const char *ip) {
    if (!s || !ip) {
        return -1;
    }
    for (int i = 0; i < s->tracked_count; i++) {
        if (strcmp(s->tracked[i].ip, ip) == 0) {
            return i;
        }
    }
    return -1;
}

// appends ip to the blacklist; the caller holds the lock
static state_result_t block_locked(sentinel_state_t *s, const char *ip) {
    if (!s || !ip) {
        return STATE_BAD_ARG;
    }
    if(find_blocked(s, ip) >= 0) {
        return STATE_NOOP;
    }
    if(s->blacklist.count >= BL_MAX){
        return STATE_FULL;
    }
    memcpy(s->blacklist.ips[s->blacklist.count], ip, strlen(ip) + 1);
    s->blacklist.count++;
    return STATE_OK;
}

// zeroes s, copies base (may be NULL) and sets epoch 0; returns 0, or -1 if s is NULL
int state_init(sentinel_state_t *s, const blacklist_t *base) {
    if (!s) {
        return -1;
    }
    memset(s, 0, sizeof(*s));
    if(pthread_mutex_init(&s->lock, NULL) != 0) {
        return -1;
    }
    if(base) {
        s->blacklist = *base;
    }
    return 0;
}

state_result_t state_block(sentinel_state_t *s, const char *ip) {
    if(!s || !valid_ip(ip)) {
        return STATE_BAD_ARG;
    }
    pthread_mutex_lock(&s->lock);
    state_result_t result = block_locked(s, ip);
    pthread_mutex_unlock(&s->lock);
    return result;
}

state_result_t state_unblock(sentinel_state_t *s, const char *ip) {
    if(!s || !valid_ip(ip)) {
        return STATE_BAD_ARG;
    }
    pthread_mutex_lock(&s->lock);
    int idx = find_blocked(s, ip);
    state_result_t result = STATE_NOOP;
    if(idx >= 0) {
        int last = s->blacklist.count - 1;
        memcpy(s->blacklist.ips[idx], s->blacklist.ips[last], SRC_IP_LEN);
        memset(s->blacklist.ips[last], 0, SRC_IP_LEN);
        s->blacklist.count--;
        result = STATE_OK;
    }
    pthread_mutex_unlock(&s->lock);
    return result;
}

int state_query(sentinel_state_t *s, const char *ip, int *hits) {
    if(!s || !valid_ip(ip)) {
        return -1;
    }
    pthread_mutex_lock(&s->lock);
    int blocked = find_blocked(s, ip) >= 0;
    if(hits){
        int t = find_tracked(s, ip);
        *hits = t >= 0 ? s->tracked[t].hits : 0;
    }
    pthread_mutex_unlock(&s->lock);
    return blocked;
}

int state_record_hit(sentinel_state_t *s, const char *ip, long long now_ms) {
    if(!s || !valid_ip(ip) || now_ms < 0) {
        return -1;
    }
    pthread_mutex_lock(&s->lock);
    int t_idx = find_tracked(s, ip);
    if(t_idx < 0){
        if(s->tracked_count >= MAX_TRACKED_IPS){
            if(!s->full_warned || now_ms - s->full_warn_ms >= FULL_WARN_INTERVAL_MS) {
                fprintf(stderr, "[%lld] WARN tracking table full, not counting %s\n", now_ms, ip);
                s->full_warned = 1;
                s->full_warn_ms = now_ms;
            }
            pthread_mutex_unlock(&s->lock);
            return -2;
        }
        t_idx = s->tracked_count++;
        memset(&s->tracked[t_idx], 0, sizeof(s->tracked[t_idx]));
        memcpy(s->tracked[t_idx].ip, ip, strlen(ip) + 1);
    }
    ip_track_t *track = &s->tracked[t_idx];

    int was_blocked = find_blocked(s, ip) >= 0;
    if(was_blocked) {
        s->total_alerts++;
    }

    track->hits++;
    track->ring[track->ring_next] = now_ms;
    track->ring_next = (track->ring_next + 1) % HIT_RING;
    if(track->ring_count < HIT_RING) {
        track->ring_count++;
    }

    int banned = 0;
    // once the ring is full, ring_next points at the oldest of the newest X+1 hits
    if(!was_blocked && track->ring_count == HIT_RING) {
        long long span = now_ms - track->ring[track->ring_next];
        if(span < AUTOBAN_WINDOW_MS) {
            if(block_locked(s, ip) == STATE_OK) {
                printf("[%lld] AUTO-BAN %s (%d pkts in %lld ms)\n", now_ms, ip, track->ring_count, span);
                banned = 1;
            }
            else{
                fprintf(stderr, "[%lld] WARN blacklist full, cannot auto-ban %s\n", now_ms, ip);
            }
        }
    }

    pthread_mutex_unlock(&s->lock);
    return banned;
}

int state_begin_packet(sentinel_state_t *s, unsigned hash) {
    if(!s) {
        return -1;
    }
    pthread_mutex_lock(&s->lock);
    s->inflight_valid = 1;
    s->inflight_hash = hash;
    pthread_mutex_unlock(&s->lock);
    return 0;
}

int state_end_packet(sentinel_state_t *s) {
    if(!s) {
        return -1;
    }
    pthread_mutex_lock(&s->lock);
    s->inflight_valid = 0;
    s->inflight_hash = 0;
    pthread_mutex_unlock(&s->lock);
    return 0;
}

int state_adopt_suspect(sentinel_state_t *s) {
    if(!s) {
        return -1;
    }
    pthread_mutex_lock(&s->lock);
    int adopted = s->inflight_valid != 0;
    if(adopted) {
        s->suspect_valid = 1;
        s->suspect_hash = s->inflight_hash;
        s->inflight_valid = 0;
        s->inflight_hash = 0;
    }
    pthread_mutex_unlock(&s->lock);
    return adopted;
}

int state_is_suspect(sentinel_state_t *s, unsigned hash) {
    if(!s) {
        return -1;
    }
    pthread_mutex_lock(&s->lock);
    int match = s->suspect_valid && s->suspect_hash == hash;
    if(match){
        s->suspect_valid = 0;
    }
    pthread_mutex_unlock(&s->lock);
    return match;
}
