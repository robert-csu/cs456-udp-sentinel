#include <stdio.h>
#include <string.h>
#include "protocol.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); failures++; } \
} while (0)

static void test_constants(void)
{
    CHECK(PKT_PORT > 0 && PKT_PORT <= 65535, "PKT_PORT out of range");
    CHECK(HEARTBEAT_PORT > 0 && HEARTBEAT_PORT <= 65535, "HEARTBEAT_PORT out of range");
    CHECK(T_MS > 0, "T_MS must be positive");
    CHECK(MAX_MISSED_HEARTBEAT > 0, "MAX_MISSED_HEARTBEAT must be positive");
}

static void test_pkt_roundtrip(void)
{
    char buf[MAX_PKT_SIZE];
    char ip[SRC_IP_LEN], payload[PAYLOAD_LEN];
    int dst_port = 0, seq = 0;

    int len = snprintf(buf, sizeof buf, PKT_FMT_OUT, "192.168.100.12", 80, 7, "hello");
    CHECK(len > 0 && len < MAX_PKT_SIZE, "PKT message does not fit MAX_PKT_SIZE");
    CHECK(strncmp(buf, MSG_PKT "|", sizeof(MSG_PKT)) == 0, "PKT message has wrong prefix");

    int n = sscanf(buf, PKT_FMT_IN, ip, &dst_port, &seq, payload);
    CHECK(n == 4, "PKT parse did not return 4 fields");
    CHECK(strcmp(ip, "192.168.100.12") == 0, "PKT src mismatch");
    CHECK(dst_port == 80, "PKT dst_port mismatch");
    CHECK(seq == 7, "PKT seq mismatch");
    CHECK(strcmp(payload, "hello") == 0, "PKT payload mismatch");
}

static void test_heartbeat_roundtrip(void)
{
    char buf[MAX_PKT_SIZE];
    int pid = 0, epoch = 0, seq = 0;
    long long ts = 0;

    int len = snprintf(buf, sizeof buf, HB_FMT_OUT, 4321, 2, 9, 1730000000000LL);
    CHECK(len > 0 && len < MAX_PKT_SIZE, "HEARTBEAT message does not fit MAX_PKT_SIZE");
    CHECK(strncmp(buf, MSG_HEARTBEAT "|", sizeof(MSG_HEARTBEAT)) == 0, "HEARTBEAT message has wrong prefix");

    int n = sscanf(buf, HB_FMT_IN, &pid, &epoch, &seq, &ts);
    CHECK(n == 4, "HEARTBEAT parse did not return 4 fields");
    CHECK(pid == 4321, "HEARTBEAT pid mismatch");
    CHECK(epoch == 2, "HEARTBEAT epoch mismatch");
    CHECK(seq == 9, "HEARTBEAT seq mismatch");
    CHECK(ts == 1730000000000LL, "HEARTBEAT ts mismatch");
}

static void test_malformed_rejected(void)
{
    char ip[SRC_IP_LEN], payload[PAYLOAD_LEN];
    int dst_port, seq, pid, hb_epoch, hb_seq;
    long long ts;

    CHECK(sscanf("PKT|src=1.2.3.4|dst_port=80", PKT_FMT_IN, ip, &dst_port, &seq, payload) != 4,"truncated PKT should not parse fully");
    CHECK(sscanf("HEARTBEAT|pid=1|epoch=0|seq=2", HB_FMT_IN, &pid, &hb_epoch, &hb_seq, &ts) != 4,"truncated HEARTBEAT should not parse fully");
    CHECK(sscanf("HEARTBEAT|pid=1|seq=2|ts=3", HB_FMT_IN, &pid, &hb_epoch, &hb_seq, &ts) != 4,"old HEARTBEAT without epoch must not parse");
    CHECK(sscanf("PKT|src=1.2.3.4|dst_port=80|seq=1|payload=x", HB_FMT_IN, &pid, &hb_epoch, &hb_seq, &ts) != 4,"PKT must not parse as HEARTBEAT");
}

// BLOCK / UNBLOCK / QUERY each write and read back the same ip
static void test_ctl_roundtrip(void)
{
    static const struct { const char *out_fmt, *in_fmt, *prefix; } kinds[] = {
        {BL_FMT_OUT, BL_FMT_IN, "BLOCK|ip="},
        {UNBL_FMT_OUT, UNBL_FMT_IN, "UNBLOCK|ip="},
        {QUERY_FMT_OUT, QUERY_FMT_IN, "QUERY|ip="},
    };

    for (size_t i = 0; i < sizeof kinds / sizeof kinds[0]; i++) {
        char buf[MAX_PKT_SIZE], ip[SRC_IP_LEN];
        int len = snprintf(buf, sizeof buf, kinds[i].out_fmt, "255.255.255.255");
        CHECK(len > 0 && len < MAX_PKT_SIZE, "control message does not fit MAX_PKT_SIZE");
        CHECK(strncmp(buf, kinds[i].prefix, strlen(kinds[i].prefix)) == 0, "control message has wrong prefix");

        int n = sscanf(buf, kinds[i].in_fmt, ip);
        CHECK(n == 1, "control parse did not return 1 field");
        CHECK(strcmp(ip, "255.255.255.255") == 0, "control ip mismatch");
    }
}

static void test_part2_constants(void)
{
    CHECK(AUTOBAN_MAX_PKTS > 0, "AUTOBAN_MAX_PKTS must be positive");
    CHECK(AUTOBAN_WINDOW_MS > 0, "AUTOBAN_WINDOW_MS must be positive");
    CHECK(CHECKPOINT_INTERVAL_MS > 0, "CHECKPOINT_INTERVAL_MS must be positive");
    CHECK(MAX_TRACKED_IPS > 0, "MAX_TRACKED_IPS must be positive");
    CHECK(strlen(CHECKPOINT_PATH) > 0, "CHECKPOINT_PATH empty");
    CHECK(strcmp(CHECKPOINT_PATH, CHECKPOINT_TMP) != 0, "CHECKPOINT_TMP must differ from CHECKPOINT_PATH");
    CHECK(strcmp(CHECKPOINT_PATH, CHECKPOINT_PREV) != 0, "CHECKPOINT_PREV must differ from CHECKPOINT_PATH");
    CHECK(strcmp(CHECKPOINT_TMP, CHECKPOINT_PREV) != 0, "CHECKPOINT_TMP must differ from CHECKPOINT_PREV");
}

static void test_replies(void)
{
    char buf[MAX_PKT_SIZE];

    snprintf(buf, sizeof buf, REPLY_BLOCKED_FMT, "10.0.0.5");
    CHECK(strcmp(buf, "OK BLOCKED 10.0.0.5") == 0, "OK BLOCKED reply wrong");
    snprintf(buf, sizeof buf, REPLY_UNBLOCKED_FMT, "10.0.0.5");
    CHECK(strcmp(buf, "OK UNBLOCKED 10.0.0.5") == 0, "OK UNBLOCKED reply wrong");
    snprintf(buf, sizeof buf, REPLY_QUERY_BLOCKED_FMT, 3);
    CHECK(strcmp(buf, "BLOCKED hits=3") == 0, "BLOCKED reply wrong");
    snprintf(buf, sizeof buf, REPLY_QUERY_ALLOWED_FMT, 0);
    CHECK(strcmp(buf, "ALLOWED hits=0") == 0, "ALLOWED reply wrong");
    snprintf(buf, sizeof buf, REPLY_ERR_FMT, "bad ip");
    CHECK(strcmp(buf, "ERR bad ip") == 0, "ERR reply wrong");
}

int main(void)
{
    test_part2_constants();
    test_replies();
    test_constants();
    test_pkt_roundtrip();
    test_heartbeat_roundtrip();
    test_malformed_rejected();
    test_ctl_roundtrip();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    return 0;
}
