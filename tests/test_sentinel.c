#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "protocol.h"
#include "sentinel_core.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); failures++; } \
} while (0)

typedef struct {
    const char *name;
    const char *input;
    int output_code;
} test_packet_parse_input_t;


// A parameterized test with both valid and invalid input, reference the output_code to sentinel_core.h
static const test_packet_parse_input_t test_packet_parse_inputs[] = {
    {.name = "base_valid_packet", .input = "PKT|src=10.0.0.5|dst_port=8080|seq=7|payload=hello", .output_code = PKT_OK,},
    {.name = "heartbeat_prefix", .input = "HEARTBEAT|pid=1|seq=2|ts=3", .output_code = PKT_ERR_FORMAT},
    {.name = "empty_string", .input = "", .output_code = PKT_ERR_FORMAT},
    {.name = "lowercase_prefix", .input = "pkt|src=10.0.0.5|dst_port=8080|seq=7|payload=hello", .output_code = PKT_ERR_FORMAT},
    {.name = "src_out_of_range", .input = "PKT|src=999.1.1.1|dst_port=8080|seq=7|payload=hello", .output_code = PKT_ERR_SRC},
    {.name = "src_not_an_ip", .input = "PKT|src=not.an.ip|dst_port=8080|seq=7|payload=hello", .output_code = PKT_ERR_SRC},
    {.name = "src_empty", .input = "PKT|src=|dst_port=8080|seq=7|payload=hello", .output_code = PKT_ERR_FORMAT},
    {.name = "src_too_long", .input = "PKT|src=1234567890123456|dst_port=8080|seq=7|payload=hello", .output_code = PKT_ERR_FORMAT},
    {.name = "port_zero", .input = "PKT|src=10.0.0.5|dst_port=0|seq=7|payload=hello", .output_code = PKT_ERR_PORT},
    {.name = "port_too_large", .input = "PKT|src=10.0.0.5|dst_port=70000|seq=7|payload=hello", .output_code = PKT_ERR_PORT},
    {.name = "port_negative", .input = "PKT|src=10.0.0.5|dst_port=-5|seq=7|payload=hello", .output_code = PKT_ERR_PORT},
    {.name = "port_non_numeric", .input = "PKT|src=10.0.0.5|dst_port=abc|seq=7|payload=hello", .output_code = PKT_ERR_FORMAT},
    {.name = "port_min_valid", .input = "PKT|src=10.0.0.5|dst_port=1|seq=7|payload=hello", .output_code = PKT_OK},
    {.name = "port_max_valid", .input = "PKT|src=10.0.0.5|dst_port=65535|seq=7|payload=hello", .output_code = PKT_OK},
    {.name = "port_max_plus_one", .input = "PKT|src=10.0.0.5|dst_port=65536|seq=7|payload=hello", .output_code = PKT_ERR_PORT},
    {.name = "seq_negative", .input = "PKT|src=10.0.0.5|dst_port=8080|seq=-1|payload=hello", .output_code = PKT_ERR_SEQ},
    {.name = "seq_non_numeric", .input = "PKT|src=10.0.0.5|dst_port=8080|seq=abc|payload=hello", .output_code = PKT_ERR_FORMAT},
    {.name = "payload_empty", .input = "PKT|src=10.0.0.5|dst_port=8080|seq=7|payload=", .output_code = PKT_ERR_FORMAT},
    {.name = "payload_whitespace", .input = "PKT|src=10.0.0.5|dst_port=8080|seq=7|payload=hi there", .output_code = PKT_ERR_TRAILING},
    {.name = "payload_missing", .input = "PKT|src=10.0.0.5|dst_port=8080|seq=7", .output_code = PKT_ERR_FORMAT},
    {.name = "fields_reordered", .input = "PKT|seq=7|src=10.0.0.5|dst_port=8080|payload=hello", .output_code = PKT_ERR_FORMAT},
    {.name = "extra_field", .input = "PKT|src=10.0.0.5|dst_port=8080|seq=7|payload=hello|extra=1", .output_code = PKT_ERR_CHAR},
    {.name = "spaces_as_delims", .input = "PKT src=10.0.0.5 dst_port=8080 seq=7 payload=hello", .output_code = PKT_ERR_FORMAT},
    {.name = "trailing_lf", .input = "PKT|src=10.0.0.5|dst_port=8080|seq=7|payload=hello\n", .output_code = PKT_OK},
    {.name = "trailing_crlf", .input = "PKT|src=10.0.0.5|dst_port=8080|seq=7|payload=hello\r\n", .output_code = PKT_OK },
    {.name = "double_newline", .input = "PKT|src=10.0.0.5|dst_port=8080|seq=7|payload=hello\n\n", .output_code = PKT_ERR_TRAILING},
    {.name = "pipe_in_payload", .input = "PKT|src=10.0.0.5|dst_port=8080|seq=7|payload=a|b", .output_code = PKT_ERR_CHAR}
};

static void test_packet_inputs(void){
    size_t num_tests = sizeof(test_packet_parse_inputs) / sizeof(test_packet_parse_inputs[0]);

    for (size_t i = 0; i < num_tests; i++) {
        const test_packet_parse_input_t tmp = test_packet_parse_inputs[i];
        pkt_t pkt;
        pkt_t untouched;
        memset(&pkt, 0xAA, sizeof pkt);
        memset(&untouched, 0xAA, sizeof untouched);
        pkt_err_t return_code = parse_pkt(tmp.input, &pkt);
        if (return_code != tmp.output_code) {
            fprintf(stderr, "Test failed: %s\n", tmp.name);
            failures++;
        }
        else{
            printf("[PASS] '%s'\n", tmp.name);
        }
        if (tmp.output_code != PKT_OK && memcmp(&pkt, &untouched, sizeof pkt) != 0) {
            fprintf(stderr, "Test failed: out modified on failure: %s\n", tmp.name);
            failures++;
        }
    }
}

static void fill_random_string(char *buffer, size_t length) {
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    size_t charset_size = sizeof(charset) - 1;

    for (size_t i = 0; i < length; i++) {
        buffer[i] = charset[rand() % charset_size];
    }
    buffer[length] = '\0';
}
// Tests the valid payload length: <256, else return invalid code
static void test_long_payloads(void){
    int payload_length[] = {128, 255, 256, 512};
    pkt_err_t expected_codes[] = {PKT_OK, PKT_OK, PKT_ERR_TRAILING, PKT_ERR_TRAILING};
    const char base_payload[] = "PKT|src=10.0.0.5|dst_port=8080|seq=7|payload=";

    size_t base_len = strlen(base_payload);
    size_t num_tests = sizeof(payload_length) / sizeof(payload_length[0]);

    for (size_t i = 0; i < num_tests; i++) {
        int p_len = payload_length[i];
        pkt_err_t expected_code = expected_codes[i];
        size_t total_buf_size = base_len + p_len + 1;
        char full_packet[total_buf_size];
        strcpy(full_packet, base_payload);
        fill_random_string(&full_packet[base_len], p_len);
        pkt_t pkt;
        pkt_t untouched;
        memset(&pkt, 0xAA, sizeof pkt);
        memset(&untouched, 0xAA, sizeof untouched);
        pkt_err_t return_code = parse_pkt(full_packet, &pkt);
        if(return_code != expected_code) {
            fprintf(stderr, "Test failed: Long payload of length %d\n", p_len);
            failures++;
        }
        else{
            printf("[PASS] Long payload of length %d\n", p_len);
        }
        if (expected_code != PKT_OK && memcmp(&pkt, &untouched, sizeof pkt) != 0) {
            fprintf(stderr, "Test failed: out modified on failure, payload length %d\n", p_len);
            failures++;
        }
    }
}


static void test_null_pointers(void){
    pkt_t pkt;
    pkt_err_t return_code = parse_pkt(NULL, &pkt);
    if(return_code != PKT_ERR_NULL) {
        fprintf(stderr, "Test failed: NULL pointer test\n");
        failures++;
    }
    else{
        printf("[PASS] NULL pointer test\n");
    }
    
    return_code = parse_pkt("PKT|src=10.0.0.5|dst_port=8080|seq=7|payload=hello", NULL);
    if(return_code != PKT_ERR_NULL) {
        fprintf(stderr, "Test failed: NULL pointer test\n");
        failures++;
    }
    else{
        printf("[PASS] NULL pointer test\n");
    }
}


typedef struct {
    const char *name;
    const char *entries[3];
    int n;
    const char *ip;
    int expected;
} test_is_blacklist_t;

static const test_is_blacklist_t test_is_blacklist_inputs[] = {
    {.name = "hit_first", .entries = {"10.0.0.66", "192.168.1.100"}, .n = 2, .ip = "10.0.0.66", .expected = 1},
    {.name = "ip_null", .entries = {"10.0.0.66", "192.168.1.100"}, .n = 2, .ip = NULL, .expected = -1},
    {.name = "hit_last", .entries = {"10.0.0.66", "192.168.1.100"}, .n = 2, .ip = "192.168.1.100", .expected = 1},
    {.name = "miss", .entries = {"10.0.0.66", "192.168.1.100"}, .n = 2, .ip = "8.8.8.8", .expected = 0},
    {.name = "shorter_near_miss", .entries = {"10.0.0.66", "192.168.1.100"}, .n = 2, .ip = "10.0.0.6", .expected = 0},
    {.name = "longer_near_miss", .entries = {"10.0.0.66", "192.168.1.100"}, .n = 2, .ip = "10.0.0.666", .expected = 0},
    {.name = "trailing_space", .entries = {"10.0.0.66", "192.168.1.100"}, .n = 2, .ip = "10.0.0.66 ", .expected = 0},
    {.name = "empty_ip", .entries = {"10.0.0.66", "192.168.1.100"}, .n = 2, .ip = "", .expected = 0},
    {.name = "empty_list", .entries = {NULL}, .n = 0, .ip = "10.0.0.66", .expected = 0}
};

static void test_is_blacklisted_table(void){
    size_t num_tests = sizeof(test_is_blacklist_inputs) / sizeof(test_is_blacklist_inputs[0]);

    for (size_t i = 0; i < num_tests; i++) {
        const test_is_blacklist_t tmp = test_is_blacklist_inputs[i];
        blacklist_t bl;
        memset(&bl, 0, sizeof bl);
        for (int j = 0; j < tmp.n; j++) {
            snprintf(bl.ips[j], sizeof bl.ips[j], "%s", tmp.entries[j]);
        }
        bl.count = tmp.n;
        int actual = is_blacklisted(&bl, tmp.ip);
        if (actual != tmp.expected) {
            fprintf(stderr, "Test failed: %s\n", tmp.name);
            failures++;
        }
        else{
            printf("[PASS] '%s'\n", tmp.name);
        }
    }
}

static void test_is_blacklisted_special(void){
    blacklist_t blk;
    int result = is_blacklisted(NULL, "10.0.0.66");
    if (result != -1) {
        fprintf(stderr, "Test failed: NULL blacklist test\n");
        failures++;
    }
    else{
        printf("[PASS] NULL blacklist test\n");
    }

    memset(&blk, 0, sizeof(blk));
    for(int i = 0; i < BL_MAX; i++){
        snprintf(blk.ips[i], sizeof blk.ips[i], "10.0.%d.%d", i / 250, i % 250 + 1);
    }
    blk.count = BL_MAX;
    result = is_blacklisted(&blk, blk.ips[BL_MAX - 1]);
    if(result != 1) {
        fprintf(stderr, "Test failed: Full blacklist test\n");
        failures++;
    }
    else{
        printf("[PASS] Full blacklist test\n");
    }

    memset(&blk, 0, sizeof(blk));
    snprintf(blk.ips[0], sizeof blk.ips[0], "10.0.0.66");
    snprintf(blk.ips[1], sizeof blk.ips[1], "192.168.1.100");
    blk.count = 1;
    result = is_blacklisted(&blk, "192.168.1.100");
    if(result != 0) {
        fprintf(stderr, "Test failed: Partial blacklist test\n");
        failures++;
    }
    else{
        printf("[PASS] Partial blacklist test\n");
    }
}



int main(void)
{
    test_packet_inputs();
    test_long_payloads();
    test_null_pointers();
    test_is_blacklisted_table();
    test_is_blacklisted_special();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    return 0;
}