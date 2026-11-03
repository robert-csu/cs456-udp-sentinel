
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
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
    snprintf(dir, sizeof dir, "/tmp/poison_test_XXXXXX");
    if(!mkdtemp(dir)) {
        perror("mkdtemp");
        exit(2);
    }
    snprintf(path, sizeof path, "%s/checkpoint.dat", dir);
    snprintf(tmp, sizeof tmp, "%s/checkpoint.tmp", dir);
    snprintf(prev, sizeof prev, "%s/checkpoint.prev", dir);
}

// removes the checkpoint files and the temp directory
static void cleanup(void)
{
    unlink(path);
    unlink(tmp);
    unlink(prev);
    rmdir(dir);
}

static void test_hash_vectors(void)
{
    CHECK(packet_hash("", 0) == 0x811C9DC5u, "hash of nothing is the offset basis");
    CHECK(packet_hash("a", 1) == 0xE40C292Cu, "FNV-1a of \"a\"");
    CHECK(packet_hash("foobar", 6) == 0xBF9CF968u, "FNV-1a of \"foobar\"");
    CHECK(packet_hash("hello", 5) == 0x4F9F2CABu, "FNV-1a of \"hello\"");
    CHECK(packet_hash("PKT|src=127.0.0.80|dst_port=80|seq=7|payload=STALL", 50) == 0x6C99B4A7u,
          "FNV-1a of the poison test datagram");
}

static void test_hash_properties(void)
{
    CHECK(packet_hash(NULL, 5) == 0x811C9DC5u, "NULL buffer gives the offset basis");
    CHECK(packet_hash("abc", 0) == 0x811C9DC5u, "length 0 gives the offset basis");
    CHECK(packet_hash("ab", 2) != packet_hash("ba", 2), "order matters");
    CHECK(packet_hash("ab", 2) == 0x4D2505CAu, "FNV-1a of \"ab\"");
    CHECK(packet_hash("a\0", 2) == 0x2B24D044u, "an embedded NUL byte is hashed, not treated as the end");
    CHECK(packet_hash("a\0", 2) != packet_hash("a\0", 1), "only the first len bytes are hashed");
    CHECK(packet_hash("abc", 3) == packet_hash("abcdef", 3), "bytes past len are ignored");

    char big[MAX_PKT_SIZE];
    memset(big, 'A', sizeof big);
    uint32_t h1 = packet_hash(big, sizeof big);
    CHECK(h1 == packet_hash(big, sizeof big), "hash is deterministic");
    big[sizeof big - 1] = 'B';
    CHECK(h1 != packet_hash(big, sizeof big), "changing the last byte changes the hash");
    big[sizeof big - 1] = 'A';
    big[0] ^= 0x01;
    CHECK(h1 != packet_hash(big, sizeof big), "flipping one bit changes the hash");
}

static void test_begin_end(void)
{
    sentinel_state_t s;
    state_init(&s, NULL);
    CHECK(s.inflight_valid == 0 && s.inflight_hash == 0, "a new state has nothing in flight");

    CHECK(state_begin_packet(&s, 0x1234ABCDu) == 0, "begin_packet should return 0");
    CHECK(s.inflight_valid == 1 && s.inflight_hash == 0x1234ABCDu, "begin_packet should record the hash");

    CHECK(state_begin_packet(&s, 0x0BADF00Du) == 0, "a second begin_packet should return 0");
    CHECK(s.inflight_valid == 1 && s.inflight_hash == 0x0BADF00Du, "begin_packet should overwrite the previous mark");

    CHECK(state_end_packet(&s) == 0, "end_packet should return 0");
    CHECK(s.inflight_valid == 0 && s.inflight_hash == 0, "end_packet should clear the mark");
    CHECK(state_end_packet(&s) == 0, "end_packet with nothing in flight should still return 0");
    CHECK(s.inflight_valid == 0 && s.inflight_hash == 0, "end_packet with nothing in flight changes nothing");
}

static void test_suspect_skipped_once(void)
{
    sentinel_state_t s;
    state_init(&s, NULL);
    state_begin_packet(&s, 0xCAFEBABEu);

    CHECK(state_adopt_suspect(&s) == 1, "adopting an in-flight packet should return 1");
    CHECK(s.inflight_valid == 0 && s.inflight_hash == 0, "adopting should clear the in-flight mark");
    CHECK(state_is_suspect(&s, 0xCAFEBABEu) == 1, "the suspect packet should be recognised");
    CHECK(state_is_suspect(&s, 0xCAFEBABEu) == 0, "a suspect is skipped only once");
}

static void test_other_hash_keeps_suspect(void)
{
    sentinel_state_t s;
    state_init(&s, NULL);
    state_begin_packet(&s, 0xCAFEBABEu);
    state_adopt_suspect(&s);

    CHECK(state_is_suspect(&s, 0x11111111u) == 0, "a different packet is not the suspect");
    CHECK(state_is_suspect(&s, 0x22222222u) == 0, "another different packet is not the suspect");
    CHECK(state_is_suspect(&s, 0xCAFEBABEu) == 1, "other packets must not consume the suspect");
}

static void test_adopt_without_inflight(void)
{
    sentinel_state_t s;
    state_init(&s, NULL);
    CHECK(state_adopt_suspect(&s) == 0, "adopting with nothing in flight should return 0");
    CHECK(state_is_suspect(&s, 0) == 0, "no suspect after adopting nothing (hash 0)");
    CHECK(state_is_suspect(&s, 0x811C9DC5u) == 0, "no suspect after adopting nothing (any hash)");
}

static void test_adopt_twice(void)
{
    sentinel_state_t s;
    state_init(&s, NULL);
    state_begin_packet(&s, 0xCAFEBABEu);
    CHECK(state_adopt_suspect(&s) == 1, "first adopt");
    CHECK(state_adopt_suspect(&s) == 0, "second adopt has nothing to adopt");
    CHECK(state_is_suspect(&s, 0xCAFEBABEu) == 1, "a second adopt must not lose the suspect");
}

static void test_bad_arguments(void)
{
    CHECK(state_begin_packet(NULL, 1) == -1, "begin_packet(NULL)");
    CHECK(state_end_packet(NULL) == -1, "end_packet(NULL)");
    CHECK(state_adopt_suspect(NULL) == -1, "adopt_suspect(NULL)");
    CHECK(state_is_suspect(NULL, 1) == -1, "is_suspect(NULL)");
}

static void test_inflight_survives_checkpoint(void)
{
    sentinel_state_t s, got;
    state_init(&s, NULL);
    state_begin_packet(&s, 0xCAFEBABEu);
    CHECK(checkpoint_save(&s, path, tmp, prev) == CKPT_OK, "save with a packet in flight");

    state_init(&got, NULL);
    CHECK(checkpoint_load_file(&got, path) == CKPT_OK, "load the checkpoint");
    CHECK(got.inflight_valid == 1 && got.inflight_hash == 0xCAFEBABEu, "the in-flight packet should be restored");
    CHECK(state_adopt_suspect(&got) == 1, "the standby should adopt the restored in-flight packet");
    CHECK(state_is_suspect(&got, 0xCAFEBABEu) == 1, "the restored packet should be recognised as the suspect");
}

static void test_standby_start_with_checkpoint_load(void)
{
    sentinel_state_t s, standby;
    state_init(&s, NULL);
    state_begin_packet(&s, 0xFEEDF00Du);
    checkpoint_save(&s, path, tmp, prev);

    CHECK(checkpoint_load(&standby, NULL, path, prev) == CKPT_SRC_CURRENT, "standby loads the current checkpoint");
    CHECK(state_adopt_suspect(&standby) == 1, "standby adopts the suspect");
    CHECK(state_is_suspect(&standby, 0xFEEDF00Du) == 1, "standby skips that packet");
    CHECK(state_is_suspect(&standby, 0xFEEDF00Du) == 0, "standby skips it only once");
}

static void test_finished_packet_not_in_checkpoint(void)
{
    sentinel_state_t s, got;
    state_init(&s, NULL);
    state_begin_packet(&s, 0xCAFEBABEu);
    state_end_packet(&s);
    checkpoint_save(&s, path, tmp, prev);

    state_init(&got, NULL);
    CHECK(checkpoint_load_file(&got, path) == CKPT_OK, "load the checkpoint");
    CHECK(got.inflight_valid == 0 && got.inflight_hash == 0, "a finished packet must not be saved as in flight");
    CHECK(state_adopt_suspect(&got) == 0, "nothing to adopt from a clean checkpoint");
}

static void test_suspect_not_saved(void)
{
    sentinel_state_t s, got;
    state_init(&s, NULL);
    state_begin_packet(&s, 0xCAFEBABEu);
    state_adopt_suspect(&s);
    checkpoint_save(&s, path, tmp, prev);

    state_init(&got, NULL);
    CHECK(checkpoint_load_file(&got, path) == CKPT_OK, "load the checkpoint");
    CHECK(got.inflight_valid == 0, "the suspect must not come back as an in-flight packet");
    CHECK(state_adopt_suspect(&got) == 0, "the suspect must not be inherited by the next standby");
    CHECK(state_is_suspect(&got, 0xCAFEBABEu) == 0, "the suspect must not be saved");
}

int main(void)
{
    setup();
    test_hash_vectors();
    test_hash_properties();
    test_begin_end();
    test_suspect_skipped_once();
    test_other_hash_keeps_suspect();
    test_adopt_without_inflight();
    test_adopt_twice();
    test_bad_arguments();
    test_inflight_survives_checkpoint();
    test_standby_start_with_checkpoint_load();
    test_finished_packet_not_in_checkpoint();
    test_suspect_not_saved();
    cleanup();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    return 0;
}
