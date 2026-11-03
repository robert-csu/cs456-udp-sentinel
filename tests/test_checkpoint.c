
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include "protocol.h"
#include "sentinel_core.h"
#include "state.h"
#include "checkpoint.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); failures++; } \
} while (0)

static char dir[64];
static char path[128], tmp[128], prev[128];

// makes a fresh temp directory and the three checkpoint paths inside it
static void setup(void)
{
    snprintf(dir, sizeof dir, "/tmp/ckpt_test_XXXXXX");
    if(!mkdtemp(dir)) {
        perror("mkdtemp");
        exit(2);
    }
    snprintf(path, sizeof path, "%s/checkpoint.dat", dir);
    snprintf(tmp, sizeof tmp, "%s/checkpoint.tmp", dir);
    snprintf(prev, sizeof prev, "%s/checkpoint.prev", dir);
}

// removes every file a test can leave behind, then the directory itself
static void cleanup(void)
{
    char p[160];
    const char *names[] = {"checkpoint.dat", "checkpoint.tmp", "checkpoint.prev", "sub/checkpoint.dat", "sub/checkpoint.tmp", "sub/checkpoint.prev"};
    for(size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        snprintf(p, sizeof p, "%s/%s", dir, names[i]);
        unlink(p);
    }
    snprintf(p, sizeof p, "%s/sub", dir);
    rmdir(p);
    rmdir(dir);
}

// removes the three checkpoint files so the next test starts empty
static void reset_files(void)
{
    unlink(path);
    unlink(tmp);
    unlink(prev);
}

// fills s with a recognisable state; variant changes every value
static void populate(sentinel_state_t *s, int variant)
{
    char ip[32];
    state_init(s, NULL);
    for(int i = 0; i < 3 + variant; i++) {
        snprintf(ip, sizeof ip, "10.9.%d.%d", variant, i + 1);
        state_block(s, ip);
    }
    for(int i = 0; i < 5 + variant; i++) {
        state_record_hit(s, "10.8.8.8", 100 + i);
    }
    state_record_hit(s, "10.9.0.1", 7); // a hit from a blocked ip (variant 0), bumps total_alerts
    s->dropped_packets = 7 + variant;
    s->epoch = 3 + variant;
    s->inflight_valid = 1;
    s->inflight_hash = 0xDEADBEEFu + (unsigned)variant;
}

// returns 1 if every persisted field of a and b is identical
static int same_state(const sentinel_state_t *a, const sentinel_state_t *b)
{
    if(a->blacklist.count != b->blacklist.count || a->tracked_count != b->tracked_count) {
        return 0;
    }
    for(int i = 0; i < a->blacklist.count; i++) {
        if(strcmp(a->blacklist.ips[i], b->blacklist.ips[i]) != 0) {
            return 0;
        }
    }
    for(int i = 0; i < a->tracked_count; i++) {
        const ip_track_t *x = &a->tracked[i], *y = &b->tracked[i];
        if(strcmp(x->ip, y->ip) != 0 || x->hits != y->hits || x->ring_next != y->ring_next || x->ring_count != y->ring_count) {
            return 0;
        }
        for(int r = 0; r < HIT_RING; r++) {
            if(x->ring[r] != y->ring[r]) {
                return 0;
            }
        }
    }
    return a->total_alerts == b->total_alerts && a->dropped_packets == b->dropped_packets && a->epoch == b->epoch && a->inflight_valid == b->inflight_valid && a->inflight_hash == b->inflight_hash;
}

// reads the whole file into a malloc'd buffer; returns its size or -1
static long read_file(const char *p, unsigned char **out)
{
    FILE *f = fopen(p, "rb");
    if(!f) {
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    *out = malloc((n > 0 ? (size_t)n : 1) + 16); // slack so a test can append bytes
    if(!*out || fread(*out, 1, (size_t)n, f) != (size_t)n) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return n;
}

// overwrites the file with buf
static void write_file(const char *p, const unsigned char *buf, long n)
{
    FILE *f = fopen(p, "wb");
    if(f) {
        fwrite(buf, 1, (size_t)n, f);
        fclose(f);
    }
}

// reads a little-endian u32 at offset off
static uint32_t get_u32(const unsigned char *b, long off)
{
    return (uint32_t)b[off] | (uint32_t)b[off + 1] << 8 | (uint32_t)b[off + 2] << 16 | (uint32_t)b[off + 3] << 24;
}

// writes a little-endian u32 at offset off
static void put_u32(unsigned char *b, long off, uint32_t v)
{
    b[off] = v & 0xFF;
    b[off + 1] = (v >> 8) & 0xFF;
    b[off + 2] = (v >> 16) & 0xFF;
    b[off + 3] = (v >> 24) & 0xFF;
}

// saves a populated state to path and returns it in want; the files are fresh
static void save_good(sentinel_state_t *want, int variant)
{
    populate(want, variant);
    ckpt_err_t err = checkpoint_save(want, path, tmp, prev);
    CHECK(err == CKPT_OK, "test setup: checkpoint_save failed");
}

// applies edit to the saved file and expects checkpoint_load_file to fail with want_err and leave s alone
typedef void (*edit_fn)(unsigned char *buf, long *n);

static void expect_corruption(const char *what, edit_fn edit, ckpt_err_t want_err)
{
    reset_files();
    sentinel_state_t saved;
    save_good(&saved, 0);

    unsigned char *buf = NULL;
    long n = read_file(path, &buf);
    CHECK(n > CKPT_HEADER_SIZE + CKPT_CRC_SIZE, "test setup: checkpoint file too small");
    if(n <= 0) {
        return;
    }
    edit(buf, &n);
    write_file(path, buf, n);
    free(buf);

    sentinel_state_t target, before;
    populate(&target, 2);
    populate(&before, 2);
    ckpt_err_t err = checkpoint_load_file(&target, path);
    if(err != want_err) {
        fprintf(stderr, "FAIL: %s: got error %d, want %d\n", what, (int)err, (int)want_err);
        failures++;
    }
    CHECK(same_state(&target, &before), "a rejected checkpoint must leave the state unchanged");
}

static void flip_magic(unsigned char *b, long *n) { (void)n; b[0] ^= 0xFF; }
static void bad_version(unsigned char *b, long *n) { (void)n; put_u32(b, 4, CKPT_VERSION + 1); }
static void huge_length(unsigned char *b, long *n) { (void)n; put_u32(b, 12, 0xFFFFFFFFu); }
static void length_off_by_one(unsigned char *b, long *n) { put_u32(b, 12, get_u32(b, 12) + 1); (void)n; }
static void flip_data(unsigned char *b, long *n) { b[CKPT_HEADER_SIZE + (get_u32(b, 12) / 2)] ^= 0x01; (void)n; }
static void flip_first_data(unsigned char *b, long *n) { b[CKPT_HEADER_SIZE] ^= 0x80; (void)n; }
static void flip_last_data(unsigned char *b, long *n) { b[CKPT_HEADER_SIZE + get_u32(b, 12) - 1] ^= 0x01; (void)n; }
static void flip_epoch(unsigned char *b, long *n) { b[8] ^= 0x01; (void)n; }
static void flip_crc(unsigned char *b, long *n) { b[*n - 1] ^= 0x01; }
static void drop_last_byte(unsigned char *b, long *n) { (void)b; *n -= 1; }
static void drop_half(unsigned char *b, long *n) { (void)b; *n /= 2; }
static void keep_header_only(unsigned char *b, long *n) { (void)b; *n = CKPT_HEADER_SIZE; }
static void keep_three_bytes(unsigned char *b, long *n) { (void)b; *n = 3; }
static void empty_file(unsigned char *b, long *n) { (void)b; *n = 0; }
static void trailing_garbage(unsigned char *b, long *n) { b[*n] = 0xAA; *n += 1; }

static void test_crc32(void)
{
    CHECK(checkpoint_crc32("123456789", 9) == 0xCBF43926u, "CRC-32 of \"123456789\" should be 0xCBF43926");
    CHECK(checkpoint_crc32("", 0) == 0u, "CRC-32 of nothing should be 0");
    CHECK(checkpoint_crc32("a", 1) == 0xE8B7BE43u, "CRC-32 of \"a\" should be 0xE8B7BE43");
}

static void test_roundtrip(void)
{
    reset_files();
    sentinel_state_t want, got;
    save_good(&want, 0);

    state_init(&got, NULL);
    CHECK(checkpoint_load_file(&got, path) == CKPT_OK, "load of a fresh checkpoint should succeed");
    CHECK(same_state(&want, &got), "loaded state should equal the saved state");
    CHECK(got.epoch == 3, "loaded epoch should be the saved epoch, not incremented");

    // the loaded state must still work: lock usable, queries and updates behave
    CHECK(state_query(&got, "10.9.0.1", NULL) == 1, "restored blocked ip should still be blocked");
    CHECK(state_block(&got, "10.77.0.1") == STATE_OK, "restored state should accept new blocks");

    // the temp file must not be left behind
    CHECK(access(tmp, F_OK) != 0, "checkpoint.tmp should not exist after a successful save");
}

static void test_file_layout(void)
{
    reset_files();
    sentinel_state_t want;
    save_good(&want, 1);

    unsigned char *b = NULL;
    long n = read_file(path, &b);
    CHECK(n > CKPT_HEADER_SIZE + CKPT_CRC_SIZE, "checkpoint file should be larger than header + crc");
    if(n <= 0) {
        return;
    }
    CHECK(memcmp(b, CKPT_MAGIC, 4) == 0, "file should start with the magic");
    CHECK(get_u32(b, 4) == CKPT_VERSION, "version field should be CKPT_VERSION");
    CHECK(get_u32(b, 8) == (uint32_t)want.epoch, "epoch field should hold the saved epoch");
    CHECK((long)get_u32(b, 12) == n - CKPT_HEADER_SIZE - CKPT_CRC_SIZE, "length field should match the file size");
    CHECK(get_u32(b, n - 4) == checkpoint_crc32(b, (size_t)n - CKPT_CRC_SIZE), "trailing u32 should be the CRC of everything before it");
    free(b);
}

static void test_ring_survives(void)
{
    reset_files();
    sentinel_state_t s;
    state_init(&s, NULL);
    for(int i = 0; i < AUTOBAN_MAX_PKTS; i++) {
        state_record_hit(&s, "10.6.6.6", i);
    }
    CHECK(checkpoint_save(&s, path, tmp, prev) == CKPT_OK, "save should succeed");

    sentinel_state_t got;
    state_init(&got, NULL);
    CHECK(checkpoint_load_file(&got, path) == CKPT_OK, "load should succeed");
    CHECK(state_query(&got, "10.6.6.6", NULL) == 0, "ip should not be banned yet after the restore");
    CHECK(state_record_hit(&got, "10.6.6.6", AUTOBAN_MAX_PKTS) == 1, "the X+1th hit after a restore should still auto-ban");
}

static void test_save_creates_directory(void)
{
    reset_files();
    char sub_path[160], sub_tmp[160], sub_prev[160];
    snprintf(sub_path, sizeof sub_path, "%s/sub/checkpoint.dat", dir);
    snprintf(sub_tmp, sizeof sub_tmp, "%s/sub/checkpoint.tmp", dir);
    snprintf(sub_prev, sizeof sub_prev, "%s/sub/checkpoint.prev", dir);

    sentinel_state_t s, got;
    populate(&s, 0);
    CHECK(checkpoint_save(&s, sub_path, sub_tmp, sub_prev) == CKPT_OK, "save should create a missing directory");
    state_init(&got, NULL);
    CHECK(checkpoint_load_file(&got, sub_path) == CKPT_OK && same_state(&s, &got), "state saved into a new directory should load");
}

static void test_prev_rotation(void)
{
    reset_files();
    sentinel_state_t a, b, got;
    populate(&a, 0);
    populate(&b, 1);

    CHECK(checkpoint_save(&a, path, tmp, prev) == CKPT_OK, "first save");
    CHECK(access(prev, F_OK) != 0, "no checkpoint.prev after the very first save");
    CHECK(checkpoint_save(&b, path, tmp, prev) == CKPT_OK, "second save");

    state_init(&got, NULL);
    CHECK(checkpoint_load_file(&got, path) == CKPT_OK && same_state(&b, &got), ".dat should hold the newest state");
    state_init(&got, NULL);
    CHECK(checkpoint_load_file(&got, prev) == CKPT_OK && same_state(&a, &got), ".prev should hold the previous state");
}

static void test_corrupt_dat_does_not_replace_prev(void)
{
    reset_files();
    sentinel_state_t a, b, c, got;
    populate(&a, 0);
    populate(&b, 1);
    populate(&c, 2);
    checkpoint_save(&a, path, tmp, prev);
    checkpoint_save(&b, path, tmp, prev); // .prev = a, .dat = b

    unsigned char *buf = NULL;
    long n = read_file(path, &buf);
    if(n > 0) {
        buf[CKPT_HEADER_SIZE] ^= 0x55;
        write_file(path, buf, n);
        free(buf);
    }
    CHECK(checkpoint_save(&c, path, tmp, prev) == CKPT_OK, "save over a corrupt .dat should still succeed");

    state_init(&got, NULL);
    CHECK(checkpoint_load_file(&got, path) == CKPT_OK && same_state(&c, &got), ".dat should hold the new state");
    state_init(&got, NULL);
    CHECK(checkpoint_load_file(&got, prev) == CKPT_OK, ".prev must stay valid; a corrupt .dat must not be rotated into it");
}

static void test_failed_save_keeps_old_dat(void)
{
    reset_files();
    sentinel_state_t a, b, got;
    populate(&a, 0);
    populate(&b, 1);
    checkpoint_save(&a, path, tmp, prev);

    // a directory as the temp path makes the write fail
    CHECK(checkpoint_save(&b, path, dir, prev) == CKPT_ERR_IO, "save with an unwritable temp path should return CKPT_ERR_IO");
    state_init(&got, NULL);
    CHECK(checkpoint_load_file(&got, path) == CKPT_OK && same_state(&a, &got), "a failed save must leave the previous .dat intact");
}

static void test_corruption(void)
{
    expect_corruption("flipped magic", flip_magic, CKPT_ERR_MAGIC);
    expect_corruption("wrong version", bad_version, CKPT_ERR_VERSION);
    expect_corruption("length 0xFFFFFFFF", huge_length, CKPT_ERR_LENGTH);
    expect_corruption("length off by one", length_off_by_one, CKPT_ERR_LENGTH);
    expect_corruption("flipped data byte (middle)", flip_data, CKPT_ERR_CRC);
    expect_corruption("flipped first data byte", flip_first_data, CKPT_ERR_CRC);
    expect_corruption("flipped last data byte", flip_last_data, CKPT_ERR_CRC);
    expect_corruption("flipped epoch byte", flip_epoch, CKPT_ERR_CRC);
    expect_corruption("flipped crc byte", flip_crc, CKPT_ERR_CRC);
    expect_corruption("truncated by one byte", drop_last_byte, CKPT_ERR_LENGTH);
    expect_corruption("truncated to half", drop_half, CKPT_ERR_LENGTH);
    expect_corruption("truncated to the header", keep_header_only, CKPT_ERR_LENGTH);
    expect_corruption("truncated to 3 bytes", keep_three_bytes, CKPT_ERR_LENGTH);
    expect_corruption("empty file", empty_file, CKPT_ERR_LENGTH);
    expect_corruption("trailing garbage", trailing_garbage, CKPT_ERR_LENGTH);
}

static void test_load_bad_arguments(void)
{
    sentinel_state_t s;
    state_init(&s, NULL);
    CHECK(checkpoint_load_file(NULL, path) == CKPT_ERR_ARG, "load_file with NULL state");
    CHECK(checkpoint_load_file(&s, NULL) == CKPT_ERR_ARG, "load_file with NULL path");
    reset_files();
    CHECK(checkpoint_load_file(&s, path) == CKPT_ERR_IO, "load_file of a missing file should be CKPT_ERR_IO");
    CHECK(checkpoint_save(NULL, path, tmp, prev) == CKPT_ERR_ARG, "save with NULL state");
    CHECK(checkpoint_save(&s, NULL, tmp, prev) == CKPT_ERR_ARG, "save with NULL path");
    CHECK(checkpoint_save(&s, path, NULL, prev) == CKPT_ERR_ARG, "save with NULL tmp");
    CHECK(checkpoint_save(&s, path, tmp, NULL) == CKPT_ERR_ARG, "save with NULL prev");
    CHECK(checkpoint_load(NULL, NULL, path, prev) == CKPT_SRC_ERR, "load with NULL state");
    CHECK(checkpoint_load(&s, NULL, NULL, prev) == CKPT_SRC_ERR, "load with NULL path");
    CHECK(checkpoint_load(&s, NULL, path, NULL) == CKPT_SRC_ERR, "load with NULL prev");
}

// corrupts one byte of the file at p
static void corrupt(const char *p)
{
    unsigned char *b = NULL;
    long n = read_file(p, &b);
    if(n > CKPT_HEADER_SIZE) {
        b[CKPT_HEADER_SIZE] ^= 0x5A;
        write_file(p, b, n);
    }
    free(b);
}

static void test_fallback_order(void)
{
    sentinel_state_t a, b, got;
    blacklist_t base;
    CHECK(blacklist_parse("10.0.0.66\n192.168.1.100\n", &base) == BL_OK, "test setup: base blacklist");
    populate(&a, 0);
    populate(&b, 1);

    // both good: the current checkpoint wins
    reset_files();
    checkpoint_save(&a, path, tmp, prev);
    checkpoint_save(&b, path, tmp, prev);
    CHECK(checkpoint_load(&got, &base, path, prev) == CKPT_SRC_CURRENT, "good .dat should be used first");
    CHECK(same_state(&b, &got), "state should come from .dat");

    // current corrupt, prev good
    corrupt(path);
    CHECK(checkpoint_load(&got, &base, path, prev) == CKPT_SRC_PREV, "corrupt .dat should fall back to .prev");
    CHECK(same_state(&a, &got), "state should come from .prev");
    CHECK(state_block(&got, "10.55.0.1") == STATE_OK, "fallback state should be usable (lock initialised)");

    // current missing, prev good
    unlink(path);
    CHECK(checkpoint_load(&got, &base, path, prev) == CKPT_SRC_PREV, "missing .dat should fall back to .prev");
    CHECK(same_state(&a, &got), "state should come from .prev when .dat is missing");

    // both corrupt: base blacklist only
    checkpoint_save(&b, path, tmp, prev);
    corrupt(path);
    corrupt(prev);
    CHECK(checkpoint_load(&got, &base, path, prev) == CKPT_SRC_BASE, "both corrupt should fall back to the base blacklist");
    CHECK(state_query(&got, "10.0.0.66", NULL) == 1 && state_query(&got, "192.168.1.100", NULL) == 1, "base entries should be blocked");
    CHECK(got.blacklist.count == 2 && got.tracked_count == 0 && got.epoch == 0, "base fallback should start from empty state");
    CHECK(got.total_alerts == 0 && got.dropped_packets == 0 && got.inflight_valid == 0, "base fallback should clear counters");

    // nothing on disk at all: first start
    reset_files();
    CHECK(checkpoint_load(&got, &base, path, prev) == CKPT_SRC_BASE, "no files should use the base blacklist");
    CHECK(got.blacklist.count == 2, "first start should load the base blacklist");
    CHECK(checkpoint_load(&got, NULL, path, prev) == CKPT_SRC_BASE, "NULL base with no files should still work");
    CHECK(got.blacklist.count == 0, "NULL base should give an empty blacklist");
}

// writer thread keeps changing the state while the main thread checkpoints it
static sentinel_state_t shared;
static volatile int writer_stop = 0;

static void *writer(void *arg)
{
    (void)arg;
    char ip[SRC_IP_LEN];
    for(int i = 0; !writer_stop; i++) {
        snprintf(ip, sizeof ip, "10.4.%d.%d", (i / 250) % 200, i % 250 + 1);
        state_block(&shared, ip);
        state_record_hit(&shared, ip, i);
        if(i % 7 == 0) {
            state_unblock(&shared, ip);
        }
    }
    return NULL;
}

static void test_save_while_state_changes(void)
{
    reset_files();
    state_init(&shared, NULL);
    writer_stop = 0;
    pthread_t th;
    pthread_create(&th, NULL, writer, NULL);

    int bad = 0;
    for(int i = 0; i < 200; i++) {
        if(checkpoint_save(&shared, path, tmp, prev) != CKPT_OK) {
            bad++;
            continue;
        }
        sentinel_state_t got;
        state_init(&got, NULL);
        if(checkpoint_load_file(&got, path) != CKPT_OK) {
            bad++;
        }
    }
    writer_stop = 1;
    pthread_join(th, NULL);
    CHECK(bad == 0, "every checkpoint taken while the state was changing should be saved and valid");
}

int main(void)
{
    setup();
    test_crc32();
    test_roundtrip();
    test_file_layout();
    test_ring_survives();
    test_save_creates_directory();
    test_prev_rotation();
    test_corrupt_dat_does_not_replace_prev();
    test_failed_save_keeps_old_dat();
    test_corruption();
    test_load_bad_arguments();
    test_fallback_order();
    test_save_while_state_changes();
    cleanup();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    return 0;
}
