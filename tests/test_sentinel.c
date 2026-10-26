#define _POSIX_C_SOURCE 200809L
#include <unistd.h>
#include <sys/stat.h>
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


typedef struct {
    const char *name;
    const char *text;
    int output_code;
    int expected_count;
    const char *first_ip;
} test_blacklist_parse_input_t;

static const test_blacklist_parse_input_t test_blacklist_parse_inputs[] = {
    {.name = "base_two_entries", .text = "10.0.0.66\n192.168.1.100\n", .output_code = BL_OK, .expected_count = 2, .first_ip = "10.0.0.66"},
    {.name = "empty_text", .text = "", .output_code = BL_OK, .expected_count = 0, .first_ip = NULL},
    {.name = "one_entry", .text = "10.0.0.66\n", .output_code = BL_OK, .expected_count = 1, .first_ip = "10.0.0.66"},
    {.name = "comment_line", .text = "# banned hosts\n10.0.0.66\n", .output_code = BL_OK, .expected_count = 1, .first_ip = "10.0.0.66"},
    {.name = "blank_lines", .text = "10.0.0.66\n\n192.168.1.100\n", .output_code = BL_OK, .expected_count = 2, .first_ip = "10.0.0.66"},
    {.name = "padded_entry", .text = "  10.0.0.66  \n192.168.1.100\n", .output_code = BL_OK, .expected_count = 2, .first_ip = "10.0.0.66"},
    {.name = "octet_out_of_range", .text = "999.9.9.9\n", .output_code = BL_ERR_BAD_ENTRY, .expected_count = 0, .first_ip = NULL},
    {.name = "non_ip_text", .text = "bogus\n", .output_code = BL_ERR_BAD_ENTRY, .expected_count = 0, .first_ip = NULL},
    {.name = "trailing_text", .text = "10.0.0.66 extra\n", .output_code = BL_ERR_BAD_ENTRY, .expected_count = 0, .first_ip = NULL},
    {.name = "inline_comment", .text = "10.0.0.66 # c\n", .output_code = BL_ERR_BAD_ENTRY, .expected_count = 0, .first_ip = NULL},
    {.name = "duplicate_entry", .text = "10.0.0.66\n10.0.0.66\n", .output_code = BL_OK, .expected_count = 1, .first_ip = "10.0.0.66"},
    {.name = "no_final_newline", .text = "10.0.0.66", .output_code = BL_OK, .expected_count = 1, .first_ip = "10.0.0.66"},
    {.name = "crlf_endings", .text = "10.0.0.66\r\n192.168.1.100\r\n", .output_code = BL_OK, .expected_count = 2, .first_ip = "10.0.0.66"},
    {.name = "ipv6_entry", .text = "::1\n", .output_code = BL_ERR_BAD_ENTRY, .expected_count = 0, .first_ip = NULL},
    {.name = "cidr_entry", .text = "10.0.0.0/8\n", .output_code = BL_ERR_BAD_ENTRY, .expected_count = 0, .first_ip = NULL},
    {.name = "over_15_chars", .text = "1234567890123456\n", .output_code = BL_ERR_BAD_ENTRY, .expected_count = 0, .first_ip = NULL},
    {.name = "leading_zero", .text = "010.0.0.1\n", .output_code = BL_ERR_BAD_ENTRY, .expected_count = 0, .first_ip = NULL},
    {.name = "valid_then_invalid", .text = "10.0.0.66\nbogus\n192.168.1.100\n", .output_code = BL_ERR_BAD_ENTRY, .expected_count = 0, .first_ip = NULL},
    {.name = "line_63_chars", .text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", .output_code = BL_ERR_BAD_ENTRY, .expected_count = 0, .first_ip = NULL},
    {.name = "line_64_chars", .text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", .output_code = BL_ERR_BAD_ENTRY, .expected_count = 0, .first_ip = NULL},
    {.name = "line_100_chars", .text = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n", .output_code = BL_ERR_BAD_ENTRY, .expected_count = 0, .first_ip = NULL},
    {.name = "indented_comment", .text = "   # note\n10.0.0.66\n", .output_code = BL_OK, .expected_count = 1, .first_ip = "10.0.0.66"},
    {.name = "crlf_blank_line", .text = "10.0.0.66\r\n\r\n1.2.3.4\r\n", .output_code = BL_OK, .expected_count = 2, .first_ip = "10.0.0.66"},
    {.name = "spaces_only_line", .text = "10.0.0.66\n    \n1.2.3.4\n", .output_code = BL_OK, .expected_count = 2, .first_ip = "10.0.0.66"},
    {.name = "only_comments", .text = "# a\n# b\n", .output_code = BL_OK, .expected_count = 0, .first_ip = NULL},
    {.name = "padded_duplicate", .text = "10.0.0.66\n  10.0.0.66  \n", .output_code = BL_OK, .expected_count = 1, .first_ip = "10.0.0.66"},
    {.name = "tab_inside_entry", .text = "10.0.0.66\t1.2.3.4\n", .output_code = BL_ERR_BAD_ENTRY, .expected_count = 0, .first_ip = NULL},
    {.name = "long_comment_line", .text = "# aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n10.0.0.66\n", .output_code = BL_OK, .expected_count = 1, .first_ip = "10.0.0.66"},
    {.name = "long_whitespace_line", .text = "                                                                      \n10.0.0.66\n", .output_code = BL_OK, .expected_count = 1, .first_ip = "10.0.0.66"}
};

static void test_blacklist_parse_table(void){
    size_t num_tests = sizeof(test_blacklist_parse_inputs) / sizeof(test_blacklist_parse_inputs[0]);
    for (size_t i = 0; i < num_tests; i++) {
        const test_blacklist_parse_input_t tmp = test_blacklist_parse_inputs[i];
        blacklist_t blk;
        blacklist_t untouched;
        memset(&blk, 0xAA, sizeof(blk));
        memset(&untouched, 0xAA, sizeof(untouched));
        bl_err_t result = blacklist_parse(tmp.text, &blk);
        if(result != tmp.output_code) {
            fprintf(stderr, "Test failed for input '%s': expected %d, got %d\n", tmp.name, tmp.output_code, (int)result);
            failures++;
        }
        else{
            printf("[PASS] '%s'\n", tmp.name);
            if(result == BL_OK) {
                if(blk.count != tmp.expected_count) {
                    fprintf(stderr, "Test failed for input '%s': expected count %d, got %d\n", tmp.name, tmp.expected_count, blk.count);
                    failures++;
                }
                else if(tmp.first_ip && strcmp(blk.ips[0], tmp.first_ip) != 0) {
                    fprintf(stderr, "Test failed for input '%s': expected first ip '%s', got '%s'\n", tmp.name, tmp.first_ip, blk.ips[0]);
                    failures++;
                }
            }
        }
        if(tmp.output_code != BL_OK && memcmp(&blk, &untouched, sizeof blk) != 0) {
            fprintf(stderr, "Test failed for input '%s': blacklist modified on failure\n", tmp.name);
            failures++;
        }
    }
}

// Writes n distinct "10.0.x.y" lines into buf
static void build_ip_lines(char *buf, size_t size, int n){
    size_t off = 0;
    for (int i = 0; i < n; i++) {
        off += (size_t)snprintf(buf + off, size - off, "10.0.%d.%d\n", i / 250, i % 250 + 1);
    }
}

static void test_blacklist_parse_special(void){
    static char text[4096];
    blacklist_t bl;
    blacklist_t untouched;
    bl_err_t result;

    memset(&bl, 0xAA, sizeof bl);
    memset(&untouched, 0xAA, sizeof untouched);
    result = blacklist_parse(NULL, &bl);
    if(result != BL_ERR_NULL) {
        fprintf(stderr, "Test failed: text NULL: expected %d, got %d\n", BL_ERR_NULL, (int)result);
        failures++;
    }
    else{
        printf("[PASS] text NULL\n");
    }
    if(memcmp(&bl, &untouched, sizeof bl) != 0) {
        fprintf(stderr, "Test failed: text NULL: blacklist modified\n");
        failures++;
    }

    result = blacklist_parse("10.0.0.66\n", NULL);
    if(result != BL_ERR_NULL) {
        fprintf(stderr, "Test failed: bl NULL: expected %d, got %d\n", BL_ERR_NULL, (int)result);
        failures++;
    }
    else{
        printf("[PASS] bl NULL\n");
    }

    memset(&bl, 0, sizeof bl);
    build_ip_lines(text, sizeof text, BL_MAX);
    result = blacklist_parse(text, &bl);
    if(result != BL_OK) {
        fprintf(stderr, "Test failed: exactly BL_MAX: expected %d, got %d\n", BL_OK, (int)result);
        failures++;
    }
    else if(bl.count != BL_MAX) {
        fprintf(stderr, "Test failed: exactly BL_MAX: expected count %d, got %d\n", BL_MAX, bl.count);
        failures++;
    }
    else if(strcmp(bl.ips[BL_MAX - 1], "10.0.1.6") != 0) {
        fprintf(stderr, "Test failed: exactly BL_MAX: last entry was '%s'\n", bl.ips[BL_MAX - 1]);
        failures++;
    }
    else{
        printf("[PASS] exactly BL_MAX\n");
    }


    memset(&bl, 0xAA, sizeof bl);
    memset(&untouched, 0xAA, sizeof untouched);
    build_ip_lines(text, sizeof text, BL_MAX + 1);
    result = blacklist_parse(text, &bl);
    if(result != BL_ERR_FULL) {
        fprintf(stderr, "Test failed: BL_MAX + 1: expected %d, got %d\n", BL_ERR_FULL, (int)result);
        failures++;
    }
    else{
        printf("[PASS] BL_MAX + 1\n");
    }
    if(memcmp(&bl, &untouched, sizeof bl) != 0) {
        fprintf(stderr, "Test failed: BL_MAX + 1: blacklist modified\n");
        failures++;
    }

    // BL_MAX entries followed by a repeat of an existing one is still OK
    memset(&bl, 0, sizeof bl);
    build_ip_lines(text, sizeof text, BL_MAX);
    snprintf(text + strlen(text), sizeof text - strlen(text), "10.0.0.1\n");
    result = blacklist_parse(text, &bl);
    if(result != BL_OK) {
        fprintf(stderr, "Test failed: full list plus repeat: expected %d, got %d\n", BL_OK, (int)result);
        failures++;
    }
    else if(bl.count != BL_MAX) {
        fprintf(stderr, "Test failed: full list plus repeat: expected count %d, got %d\n", BL_MAX, bl.count);
        failures++;
    }
    else{
        printf("[PASS] full list plus repeat\n");
    }
}

typedef struct{
    const char *name;
    const char *content;
    int output_code;
    int expected_count;
    const char *first_ip;
} test_blacklist_load_t;

static const test_blacklist_load_t test_blacklist_load_inputs[] = {
    {.name = "valid_file", .content = "10.0.0.66\n192.168.1.100\n", .output_code = BL_OK, .expected_count = 2, .first_ip = "10.0.0.66"},
    {.name = "empty_file", .content = "", .output_code = BL_OK, .expected_count = 0, .first_ip = NULL},
    {.name = "no_final_newline", .content = "10.0.0.66", .output_code = BL_OK, .expected_count = 1, .first_ip = "10.0.0.66"},
    {.name = "crlf_file", .content = "10.0.0.66\r\n192.168.1.100\r\n", .output_code = BL_OK, .expected_count = 2, .first_ip = "10.0.0.66"},
    {.name = "comments_only", .content = "# nothing here\n", .output_code = BL_OK, .expected_count = 0, .first_ip = NULL},
    {.name = "bad_entry_in_file", .content = "10.0.0.66\nbogus\n", .output_code = BL_ERR_BAD_ENTRY, .expected_count = 0, .first_ip = NULL},
    {.name = "long_comment_in_file", .content = "# aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n10.0.0.66\n", .output_code = BL_OK, .expected_count = 1, .first_ip = "10.0.0.66"}
};

static int write_temp_file(const char *content, size_t len, char *path_out){
    snprintf(path_out, 64, "%s", "/tmp/blacklist_test_XXXXXX"); // fixed size from char path[64]
    int fd = mkstemp(path_out);
    if(fd < 0){
        return -1;
    }
    ssize_t ret = write(fd, content, len);
    if(ret < 0 || (size_t)ret != len){
        close(fd);
        unlink(path_out);
        return -1;
    }
    close(fd);
    return 0;
}

static void test_blacklist_load_table(void){
    size_t num_tests = sizeof(test_blacklist_load_inputs) / sizeof(test_blacklist_load_inputs[0]);
    for(size_t i = 0; i < num_tests; i++){
        const test_blacklist_load_t tmp = test_blacklist_load_inputs[i];
        char path[64];
        blacklist_t blk;
        blacklist_t untouched;
        int setup_rc = write_temp_file(tmp.content, strlen(tmp.content), path);
        if(setup_rc != 0){
            fprintf(stderr, "Test failed for input '%s': unable to write temporary file\n", tmp.name);
            failures++;
            continue;
        }

        memset(&blk, 0xAA, sizeof blk);
        memset(&untouched, 0xAA, sizeof untouched);
        bl_err_t actual = blacklist_load(path, &blk);
        if(actual != tmp.output_code){
            fprintf(stderr, "Test failed for input '%s': expected %d, got %d\n", tmp.name, tmp.output_code, (int)actual);
            failures++;
        }
        else{
            printf("[PASS] '%s'\n", tmp.name);
            if(actual == BL_OK) {
                if(blk.count != tmp.expected_count) {
                    fprintf(stderr, "Test failed for input '%s': expected count %d, got %d\n", tmp.name, tmp.expected_count, blk.count);
                    failures++;
                }
                else if(tmp.first_ip && strcmp(blk.ips[0], tmp.first_ip) != 0) {
                    fprintf(stderr, "Test failed for input '%s': expected first ip '%s', got '%s'\n", tmp.name, tmp.first_ip, blk.ips[0]);
                    failures++;
                }
            }
        }
        if(tmp.output_code != BL_OK && memcmp(&blk, &untouched, sizeof blk) != 0) {
            fprintf(stderr, "Test failed for input '%s': blacklist modified on failure\n", tmp.name);
            failures++;
        }
        unlink(path);
    }
}

static void test_blacklist_load_special(void){
    static char big[BL_FILE_MAX + 2];
    const char valid_line[] = "10.0.0.66\n";
    const char nul_content[] = "10.0.0.66\n\0" "1.2.3.4\n";
    char path[64];
    blacklist_t bl;
    blacklist_t untouched;
    bl_err_t result;

    memset(&bl, 0xAA, sizeof bl);
    memset(&untouched, 0xAA, sizeof untouched);
    result = blacklist_load(NULL, &bl);
    if(result != BL_ERR_NULL) {
        fprintf(stderr, "Test failed: path NULL: expected %d, got %d\n", BL_ERR_NULL, (int)result);
        failures++;
    }
    else{
        printf("[PASS] path NULL\n");
    }
    if(memcmp(&bl, &untouched, sizeof bl) != 0) {
        fprintf(stderr, "Test failed: path NULL: blacklist modified\n");
        failures++;
    }

    if(write_temp_file(valid_line, strlen(valid_line), path) != 0) {
        fprintf(stderr, "Test failed: bl NULL: unable to write temporary file\n");
        failures++;
    }
    else{
        result = blacklist_load(path, NULL);
        if(result != BL_ERR_NULL) {
            fprintf(stderr, "Test failed: bl NULL: expected %d, got %d\n", BL_ERR_NULL, (int)result);
            failures++;
        }
        else{
            printf("[PASS] bl NULL\n");
        }
        unlink(path);
    }

    memset(&bl, 0xAA, sizeof bl);
    result = blacklist_load("/nonexistent/blacklist.txt", &bl);
    if(result != BL_ERR_IO) {
        fprintf(stderr, "Test failed: missing file: expected %d, got %d\n", BL_ERR_IO, (int)result);
        failures++;
    }
    else{
        printf("[PASS] missing file\n");
    }
    if(memcmp(&bl, &untouched, sizeof bl) != 0) {
        fprintf(stderr, "Test failed: missing file: blacklist modified\n");
        failures++;
    }

    memset(&bl, 0xAA, sizeof bl);
    result = blacklist_load("/tmp", &bl);
    if(result != BL_ERR_IO) {
        fprintf(stderr, "Test failed: directory: expected %d, got %d\n", BL_ERR_IO, (int)result);
        failures++;
    }
    else{
        printf("[PASS] directory\n");
    }
    if(memcmp(&bl, &untouched, sizeof bl) != 0) {
        fprintf(stderr, "Test failed: directory: blacklist modified\n");
        failures++;
    }

    memset(&bl, 0xAA, sizeof bl);
    if(write_temp_file(nul_content, sizeof nul_content - 1, path) != 0) {
        fprintf(stderr, "Test failed: NUL byte: unable to write temporary file\n");
        failures++;
    }
    else{
        result = blacklist_load(path, &bl);
        if(result != BL_ERR_BAD_ENTRY) {
            fprintf(stderr, "Test failed: NUL byte: expected %d, got %d\n", BL_ERR_BAD_ENTRY, (int)result);
            failures++;
        }
        else{
            printf("[PASS] NUL byte\n");
        }
        if(memcmp(&bl, &untouched, sizeof bl) != 0) {
            fprintf(stderr, "Test failed: NUL byte: blacklist modified\n");
            failures++;
        }
        unlink(path);
    }

    memset(&bl, 0xAA, sizeof bl);
    memset(big, 'a', BL_FILE_MAX);
    big[0] = '#';
    big[1] = ' ';
    big[BL_FILE_MAX - 1] = '\n';
    if(write_temp_file(big, BL_FILE_MAX, path) != 0) {
        fprintf(stderr, "Test failed: exactly BL_FILE_MAX: unable to write temporary file\n");
        failures++;
    }
    else{
        result = blacklist_load(path, &bl);
        if(result != BL_OK) {
            fprintf(stderr, "Test failed: exactly BL_FILE_MAX: expected %d, got %d\n", BL_OK, (int)result);
            failures++;
        }
        else if(bl.count != 0) {
            fprintf(stderr, "Test failed: exactly BL_FILE_MAX: expected count 0, got %d\n", bl.count);
            failures++;
        }
        else{
            printf("[PASS] exactly BL_FILE_MAX\n");
        }
        unlink(path);
    }

    memset(&bl, 0xAA, sizeof bl);
    memset(big, 'a', BL_FILE_MAX + 1);
    big[0] = '#';
    big[1] = ' ';
    big[BL_FILE_MAX] = '\n';
    if(write_temp_file(big, BL_FILE_MAX + 1, path) != 0) {
        fprintf(stderr, "Test failed: BL_FILE_MAX + 1: unable to write temporary file\n");
        failures++;
    }
    else{
        result = blacklist_load(path, &bl);
        if(result != BL_ERR_IO) {
            fprintf(stderr, "Test failed: BL_FILE_MAX + 1: expected %d, got %d\n", BL_ERR_IO, (int)result);
            failures++;
        }
        else{
            printf("[PASS] BL_FILE_MAX + 1\n");
        }
        if(memcmp(&bl, &untouched, sizeof bl) != 0) {
            fprintf(stderr, "Test failed: BL_FILE_MAX + 1: blacklist modified\n");
            failures++;
        }
        unlink(path);
    }

    if(geteuid() == 0) {
        printf("[SKIP] unreadable file (running as root)\n");
    }
    else if(write_temp_file(valid_line, strlen(valid_line), path) != 0) {
        fprintf(stderr, "Test failed: unreadable file: unable to write temporary file\n");
        failures++;
    }
    else{
        memset(&bl, 0xAA, sizeof bl);
        chmod(path, 0);
        result = blacklist_load(path, &bl);
        if(result != BL_ERR_IO) {
            fprintf(stderr, "Test failed: unreadable file: expected %d, got %d\n", BL_ERR_IO, (int)result);
            failures++;
        }
        else{
            printf("[PASS] unreadable file\n");
        }
        if(memcmp(&bl, &untouched, sizeof bl) != 0) {
            fprintf(stderr, "Test failed: unreadable file: blacklist modified\n");
            failures++;
        }
        chmod(path, 0600);
        unlink(path);
    }
}

int main(void)
{
    test_packet_inputs();
    test_long_payloads();
    test_null_pointers();
    test_blacklist_load_table();
    test_blacklist_load_special();
    test_is_blacklisted_table();
    test_is_blacklisted_special();
    test_blacklist_parse_table();
    test_blacklist_parse_special();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    return 0;
}