#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "protocol.h"
#include "sentinel_core.h"
#include "state.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); failures++; } \
} while (0)

// writes the n-th distinct test address (10.0.<n/250>.<n%250+1>) into ip
static void nth_ip(int n, char *ip, size_t len)
{
    snprintf(ip, len, "10.0.%d.%d", n / 250, n % 250 + 1);
}

// builds a base blacklist from text
static void make_base(blacklist_t *bl, const char *text)
{
    bl_err_t err = blacklist_parse(text, bl);
    CHECK(err == BL_OK, "test setup: blacklist_parse failed");
}

static void test_init(void)
{
    sentinel_state_t s;
    int hits = -1;

    CHECK(state_init(NULL, NULL) == -1, "state_init(NULL) should return -1");

    CHECK(state_init(&s, NULL) == 0, "state_init with NULL base should succeed");
    CHECK(s.epoch == 0, "epoch should start at 0");
    CHECK(state_query(&s, "10.0.0.66", &hits) == 0, "empty state should allow everything");
    CHECK(hits == 0, "empty state should have 0 hits");

    blacklist_t base;
    make_base(&base, "10.0.0.66\n192.168.1.100\n");
    CHECK(state_init(&s, &base) == 0, "state_init with base should succeed");
    CHECK(state_query(&s, "10.0.0.66", NULL) == 1, "base entry should be blocked");
    CHECK(state_query(&s, "192.168.1.100", NULL) == 1, "second base entry should be blocked");
    CHECK(state_query(&s, "10.0.0.67", NULL) == 0, "non-base entry should be allowed");
}

static void test_block_unblock_query(void)
{
    sentinel_state_t s;
    state_init(&s, NULL);

    CHECK(state_block(&s, "10.1.1.1") == STATE_OK, "first block should be STATE_OK");
    CHECK(state_query(&s, "10.1.1.1", NULL) == 1, "blocked ip should query as blocked");
    CHECK(state_block(&s, "10.1.1.1") == STATE_NOOP, "duplicate block should be STATE_NOOP");
    CHECK(state_query(&s, "10.1.1.2", NULL) == 0, "other ip should be unaffected");

    CHECK(state_unblock(&s, "10.1.1.1") == STATE_OK, "unblock of blocked ip should be STATE_OK");
    CHECK(state_query(&s, "10.1.1.1", NULL) == 0, "unblocked ip should query as allowed");
    CHECK(state_unblock(&s, "10.1.1.1") == STATE_NOOP, "unblock of unblocked ip should be STATE_NOOP");
    CHECK(state_unblock(&s, "10.9.9.9") == STATE_NOOP, "unblock of unknown ip should be STATE_NOOP");

    CHECK(state_block(&s, "10.1.1.1") == STATE_OK, "re-block after unblock should be STATE_OK");
    CHECK(state_query(&s, "10.1.1.1", NULL) == 1, "re-blocked ip should query as blocked");
}

static void test_base_entry_can_be_unblocked(void)
{
    sentinel_state_t s;
    blacklist_t base;
    make_base(&base, "10.0.0.66\n10.0.0.67\n");
    state_init(&s, &base);

    CHECK(state_unblock(&s, "10.0.0.66") == STATE_OK, "base entry should be unblockable");
    CHECK(state_query(&s, "10.0.0.66", NULL) == 0, "unblocked base entry should be allowed");
    CHECK(state_query(&s, "10.0.0.67", NULL) == 1, "other base entry should stay blocked");
}

static void test_bad_arguments(void)
{
    sentinel_state_t s;
    state_init(&s, NULL);
    int hits = 7;

    CHECK(state_block(NULL, "10.0.0.1") == STATE_BAD_ARG, "block with NULL state");
    CHECK(state_block(&s, NULL) == STATE_BAD_ARG, "block with NULL ip");
    CHECK(state_block(&s, "") == STATE_BAD_ARG, "block with empty ip");
    CHECK(state_block(&s, "999.1.1.1") == STATE_BAD_ARG, "block with out-of-range octet");
    CHECK(state_block(&s, "10.0.0") == STATE_BAD_ARG, "block with short ip");
    CHECK(state_block(&s, "10.0.0.1x") == STATE_BAD_ARG, "block with trailing junk");
    CHECK(state_block(&s, "not an ip") == STATE_BAD_ARG, "block with text");
    CHECK(state_block(&s, "10.0.0.1|10.0.0.2") == STATE_BAD_ARG, "block with delimiter");

    CHECK(state_unblock(NULL, "10.0.0.1") == STATE_BAD_ARG, "unblock with NULL state");
    CHECK(state_unblock(&s, NULL) == STATE_BAD_ARG, "unblock with NULL ip");
    CHECK(state_unblock(&s, "999.1.1.1") == STATE_BAD_ARG, "unblock with bad ip");

    CHECK(state_query(NULL, "10.0.0.1", &hits) == -1, "query with NULL state");
    CHECK(state_query(&s, NULL, &hits) == -1, "query with NULL ip");
    CHECK(state_query(&s, "999.1.1.1", &hits) == -1, "query with bad ip");

    CHECK(state_record_hit(NULL, "10.0.0.1", 0) == -1, "record_hit with NULL state");
    CHECK(state_record_hit(&s, NULL, 0) == -1, "record_hit with NULL ip");
    CHECK(state_record_hit(&s, "999.1.1.1", 0) == -1, "record_hit with bad ip");
    CHECK(state_record_hit(&s, "10.0.0.1", -1) == -1, "record_hit with negative time");

    // none of the above may have changed anything
    CHECK(state_query(&s, "10.0.0.1", &hits) == 0 && hits == 0, "bad calls must not change state");
}

static void test_blacklist_full(void)
{
    sentinel_state_t s;
    state_init(&s, NULL);
    char ip[SRC_IP_LEN];

    for(int i = 0; i < BL_MAX; i++) {
        nth_ip(i, ip, sizeof ip);
        if(state_block(&s, ip) != STATE_OK) {
            CHECK(0, "block should succeed until BL_MAX entries");
            return;
        }
    }
    nth_ip(BL_MAX, ip, sizeof ip);
    CHECK(state_block(&s, ip) == STATE_FULL, "block past BL_MAX should be STATE_FULL");
    CHECK(state_query(&s, ip, NULL) == 0, "ip that did not fit must not be blocked");

    nth_ip(0, ip, sizeof ip);
    CHECK(state_block(&s, ip) == STATE_NOOP, "duplicate block on a full list should be STATE_NOOP, not FULL");

    CHECK(state_unblock(&s, ip) == STATE_OK, "unblock on a full list should work");
    nth_ip(BL_MAX, ip, sizeof ip);
    CHECK(state_block(&s, ip) == STATE_OK, "block should succeed again once a slot is free");
}

static void test_hit_counting(void)
{
    sentinel_state_t s;
    state_init(&s, NULL);
    int hits = -1;

    for(int i = 1; i <= 5; i++) {
        CHECK(state_record_hit(&s, "10.2.2.2", i * 10) == 0, "hits below the limit should return 0");
    }
    CHECK(state_query(&s, "10.2.2.2", &hits) == 0, "ip below the limit should be allowed");
    CHECK(hits == 5, "query should report 5 hits");

    CHECK(state_query(&s, "10.2.2.3", &hits) == 0 && hits == 0, "untouched ip should have 0 hits");

    // blocked ips still accumulate hits
    state_block(&s, "10.2.2.4");
    state_record_hit(&s, "10.2.2.4", 0);
    state_record_hit(&s, "10.2.2.4", 1);
    CHECK(state_query(&s, "10.2.2.4", &hits) == 1 && hits == 2, "blocked ip should still count hits");
}

static void test_autoban_threshold(void)
{
    sentinel_state_t s;
    state_init(&s, NULL);
    int hits = 0;

    // exactly X packets in the window: not banned yet
    for(int i = 0; i < AUTOBAN_MAX_PKTS; i++) {
        CHECK(state_record_hit(&s, "10.3.3.3", i) == 0, "first X hits should not ban");
    }
    CHECK(state_query(&s, "10.3.3.3", NULL) == 0, "X hits in the window should still be allowed");

    // the X+1th hit inside the window bans
    CHECK(state_record_hit(&s, "10.3.3.3", AUTOBAN_MAX_PKTS) == 1, "X+1th hit should auto-ban");
    CHECK(state_query(&s, "10.3.3.3", &hits) == 1, "auto-banned ip should query as blocked");
    CHECK(hits == AUTOBAN_MAX_PKTS + 1, "hits should include the banning packet");

    // further hits do not report a new ban
    CHECK(state_record_hit(&s, "10.3.3.3", AUTOBAN_MAX_PKTS + 1) == 0, "hit on an already-banned ip should return 0");
    CHECK(state_query(&s, "10.3.3.3", &hits) == 1 && hits == AUTOBAN_MAX_PKTS + 2, "hits keep counting after a ban");

    // other ips are unaffected
    CHECK(state_query(&s, "10.3.3.4", NULL) == 0, "auto-ban must not touch other ips");
}

static void test_autoban_window(void)
{
    sentinel_state_t s;
    state_init(&s, NULL);

    // X packets, then one more exactly Y ms after the first: the first has aged out, so no ban
    for(int i = 0; i < AUTOBAN_MAX_PKTS; i++) {
        state_record_hit(&s, "10.4.4.4", 0);
    }
    CHECK(state_record_hit(&s, "10.4.4.4", AUTOBAN_WINDOW_MS) == 0, "hits exactly Y ms apart are not in the same window");
    CHECK(state_query(&s, "10.4.4.4", NULL) == 0, "ip should still be allowed after the window passed");

    // one ms earlier it would have been inside the window
    sentinel_state_t t;
    state_init(&t, NULL);
    for(int i = 0; i < AUTOBAN_MAX_PKTS; i++) {
        state_record_hit(&t, "10.4.4.5", 0);
    }
    CHECK(state_record_hit(&t, "10.4.4.5", AUTOBAN_WINDOW_MS - 1) == 1, "hit Y-1 ms after the first is in the window");

    // a slow sender never trips it: one packet every Y ms, far more than X packets in total
    sentinel_state_t u;
    state_init(&u, NULL);
    for(int i = 0; i < AUTOBAN_MAX_PKTS * 3; i++) {
        CHECK(state_record_hit(&u, "10.4.4.6", (long long)i * AUTOBAN_WINDOW_MS) == 0, "slow sender must not be banned");
    }
    CHECK(state_query(&u, "10.4.4.6", NULL) == 0, "slow sender should stay allowed");
}

static void test_autoban_after_unblock(void)
{
    sentinel_state_t s;
    state_init(&s, NULL);

    for(int i = 0; i <= AUTOBAN_MAX_PKTS; i++) {
        state_record_hit(&s, "10.5.5.5", i);
    }
    CHECK(state_query(&s, "10.5.5.5", NULL) == 1, "setup: ip should be auto-banned");
    CHECK(state_unblock(&s, "10.5.5.5") == STATE_OK, "auto-banned ip should be unblockable");
    CHECK(state_query(&s, "10.5.5.5", NULL) == 0, "unblocked ip should be allowed");
}

static void test_tracking_table_full(void)
{
    sentinel_state_t s;
    state_init(&s, NULL);
    char ip[SRC_IP_LEN];

    for(int i = 0; i < MAX_TRACKED_IPS; i++) {
        nth_ip(i, ip, sizeof ip);
        if(state_record_hit(&s, ip, 0) != 0) {
            CHECK(0, "hits should be tracked until MAX_TRACKED_IPS distinct ips");
            return;
        }
    }
    nth_ip(MAX_TRACKED_IPS, ip, sizeof ip);
    CHECK(state_record_hit(&s, ip, 0) == -2, "a new ip past MAX_TRACKED_IPS should return -2");

    nth_ip(0, ip, sizeof ip);
    CHECK(state_record_hit(&s, ip, 1) == 0, "an already-tracked ip should still be counted when the table is full");
    int hits = 0;
    state_query(&s, ip, &hits);
    CHECK(hits == 2, "already-tracked ip should have 2 hits");
}

// each thread blocks its own range of ips while also querying and recording hits
#define THREADS 4
#define PER_THREAD 50

static sentinel_state_t shared;

static void *worker(void *arg)
{
    int id = (int)(long)arg;
    char ip[SRC_IP_LEN];
    for(int i = 0; i < PER_THREAD; i++) {
        nth_ip(id * PER_THREAD + i, ip, sizeof ip);
        state_block(&shared, ip);
        state_query(&shared, ip, NULL);
        state_record_hit(&shared, ip, i);
    }
    return NULL;
}

static void test_concurrent_access(void)
{
    pthread_t th[THREADS];
    state_init(&shared, NULL);

    for(long i = 0; i < THREADS; i++) {
        pthread_create(&th[i], NULL, worker, (void *)i);
    }
    for(int i = 0; i < THREADS; i++) {
        pthread_join(th[i], NULL);
    }

    int bad = 0;
    char ip[SRC_IP_LEN];
    for(int i = 0; i < THREADS * PER_THREAD; i++) {
        nth_ip(i, ip, sizeof ip);
        int hits = 0;
        if(state_query(&shared, ip, &hits) != 1 || hits != 1) {
            bad++;
        }
    }
    CHECK(bad == 0, "every ip blocked by a worker should be blocked with exactly 1 hit");
}

int main(void)
{
    test_init();
    test_block_unblock_query();
    test_base_entry_can_be_unblocked();
    test_bad_arguments();
    test_blacklist_full();
    test_hit_counting();
    test_autoban_threshold();
    test_autoban_window();
    test_autoban_after_unblock();
    test_tracking_table_full();
    test_concurrent_access();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    return 0;
}
