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
    int pid = 0, seq = 0;
    long long ts = 0;

    int len = snprintf(buf, sizeof buf, HB_FMT_OUT, 4321, 9, 1730000000000LL);
    CHECK(len > 0 && len < MAX_PKT_SIZE, "HEARTBEAT message does not fit MAX_PKT_SIZE");
    CHECK(strncmp(buf, MSG_HEARTBEAT "|", sizeof(MSG_HEARTBEAT)) == 0, "HEARTBEAT message has wrong prefix");

    int n = sscanf(buf, HB_FMT_IN, &pid, &seq, &ts);
    CHECK(n == 3, "HEARTBEAT parse did not return 3 fields");
    CHECK(pid == 4321, "HEARTBEAT pid mismatch");
    CHECK(seq == 9, "HEARTBEAT seq mismatch");
    CHECK(ts == 1730000000000LL, "HEARTBEAT ts mismatch");
}

static void test_malformed_rejected(void)
{
    char ip[SRC_IP_LEN], payload[PAYLOAD_LEN];
    int dst_port, seq, pid, hb_seq;
    long long ts;

    CHECK(sscanf("PKT|src=1.2.3.4|dst_port=80", PKT_FMT_IN, ip, &dst_port, &seq, payload) != 4,"truncated PKT should not parse fully");
    CHECK(sscanf("HEARTBEAT|pid=1|seq=2", HB_FMT_IN, &pid, &hb_seq, &ts) != 3,"truncated HEARTBEAT should not parse fully");
    CHECK(sscanf("PKT|src=1.2.3.4|dst_port=80|seq=1|payload=x", HB_FMT_IN, &pid, &hb_seq, &ts) != 3,"PKT must not parse as HEARTBEAT");
}

int main(void)
{
    test_constants();
    test_pkt_roundtrip();
    test_heartbeat_roundtrip();
    test_malformed_rejected();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    return 0;
}
