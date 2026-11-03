
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

/*
 * Include monitor.c so we can test its static functions.
 * Rename its main function to avoid a conflict with this test.
 */
#define main monitor_main
#include "../src/monitor.c"
#undef main

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s\n", msg); \
        failures++; \
    } \
} while (0)


/* reset monitor variables before each test */
static void reset_monitor(void)
{
    current_epoch = -1;
    last_seq = -1;
    current_pid = -1;
    expected_epoch = -1;
    replacement_pid = -1;
}


/* test heartbeat timeout configuration */
static void test_timeout(void)
{
    int before = failures;

    CHECK(T_MS > 0,
          "heartbeat interval must be positive");

    CHECK(MAX_MISSED_HEARTBEAT > 0,
          "missed heartbeat threshold must be positive");

    CHECK(TIMEOUT_VAL == T_MS * MAX_MISSED_HEARTBEAT,
          "timeout calculation is incorrect");

    if (failures == before)
        printf("[PASS] timeout configuration\n");
}


/* test first valid heartbeat initializes monitor */
static void test_first_heartbeat(void)
{
    int before = failures;
    reset_monitor();

    int result = validate_heartbeat(1234, 0, 1000, 0);

    CHECK(result == 1,
          "first heartbeat should be accepted");

    CHECK(current_pid == 1234,
          "PID not recorded");

    CHECK(current_epoch == 0,
          "epoch not recorded");

    CHECK(last_seq == 0,
          "sequence not recorded");

    if (failures == before)
        printf("[PASS] first heartbeat\n");
}


/* test increasing sequence numbers */
static void test_sequence_increment(void)
{
    int before = failures;
    reset_monitor();

    validate_heartbeat(1234, 0, 1000, 0);

    CHECK(validate_heartbeat(1234, 1, 1500, 0) == 1,
          "higher sequence should be accepted");

    CHECK(validate_heartbeat(1234, 2, 2000, 0) == 1,
          "next sequence should be accepted");

    CHECK(last_seq == 2,
          "last sequence not updated");

    if (failures == before)
        printf("[PASS] increasing sequence numbers\n");
}


/* test repeated heartbeat is rejected */
static void test_duplicate_heartbeat(void)
{
    int before = failures;
    reset_monitor();

    validate_heartbeat(1234, 5, 1000, 0);

    CHECK(validate_heartbeat(1234, 5, 1000, 0) == 0,
          "duplicate heartbeat should be rejected");

    CHECK(last_seq == 5,
          "duplicate heartbeat modified sequence");

    if (failures == before)
        printf("[PASS] duplicate heartbeat rejection\n");
}


/* test replay of an old sequence number */
static void test_old_sequence(void)
{
    int before = failures;
    reset_monitor();

    validate_heartbeat(1234, 10, 1000, 0);

    CHECK(validate_heartbeat(1234, 4, 500, 0) == 0,
          "old sequence should be rejected");

    CHECK(last_seq == 10,
          "old sequence changed monitor state");

    if (failures == before)
        printf("[PASS] old sequence rejection\n");
}


/* test a different PID using the same epoch */
static void test_pid_change(void)
{
    int before = failures;
    reset_monitor();

    validate_heartbeat(1234, 0, 1000, 0);

    CHECK(validate_heartbeat(9999, 1, 1500, 0) == 0,
          "unexpected PID should be rejected");

    CHECK(current_pid == 1234,
          "invalid PID replaced current PID");

    if (failures == before)
        printf("[PASS] unexpected PID rejection\n");
}


/* test heartbeat from an older sentinel generation */
static void test_old_epoch(void)
{
    int before = failures;
    reset_monitor();

    current_epoch = 3;
    current_pid = 1234;
    last_seq = 10;

    CHECK(validate_heartbeat(1234, 11, 2000, 2) == 0,
          "older epoch should be rejected");

    CHECK(current_epoch == 3,
          "older epoch changed current epoch");

    if (failures == before)
        printf("[PASS] old epoch rejection\n");
}


/* test unexpected newer epoch */
static void test_unauthorized_epoch(void)
{
    int before = failures;
    reset_monitor();

    validate_heartbeat(1234, 0, 1000, 0);

    CHECK(validate_heartbeat(5678, 0, 2000, 1) == 0,
          "unexpected new epoch should be rejected");

    CHECK(current_epoch == 0,
          "unauthorized epoch changed monitor state");

    if (failures == before)
        printf("[PASS] unauthorized epoch rejection\n");
}


/* test valid standby takeover */
static void test_valid_failover(void)
{
    int before = failures;
    reset_monitor();

    /* original sentinel is running */
    validate_heartbeat(1234, 10, 1000, 0);

    /* monitor has launched a replacement */
    expected_epoch = 1;
    replacement_pid = 5678;

    CHECK(validate_heartbeat(5678, 0, 2000, 1) == 1,
          "replacement heartbeat should be accepted");

    CHECK(current_epoch == 1,
          "epoch did not increase after failover");

    CHECK(current_pid == 5678,
          "replacement PID was not recorded");

    CHECK(last_seq == 0,
          "sequence should reset for new sentinel");

    if (failures == before)
        printf("[PASS] valid failover\n");
}


/* test wrong PID during recovery */
static void test_wrong_recovery_pid(void)
{
    int before = failures;
    reset_monitor();

    validate_heartbeat(1234, 5, 1000, 0);

    expected_epoch = 1;
    replacement_pid = 5678;

    CHECK(validate_heartbeat(9999, 0, 2000, 1) == 0,
          "wrong recovery PID should be rejected");

    CHECK(current_epoch == 0,
          "wrong recovery PID changed epoch");

    if (failures == before)
        printf("[PASS] wrong recovery PID rejection\n");
}


/* test wrong epoch during recovery */
static void test_wrong_recovery_epoch(void)
{
    int before = failures;
    reset_monitor();

    validate_heartbeat(1234, 5, 1000, 0);

    expected_epoch = 1;
    replacement_pid = 5678;

    CHECK(validate_heartbeat(5678, 0, 2000, 2) == 0,
          "unexpected recovery epoch should be rejected");

    CHECK(current_epoch == 0,
          "unexpected recovery epoch modified state");

    if (failures == before)
        printf("[PASS] wrong recovery epoch rejection\n");
}


/* test invalid heartbeat arguments */
static void test_invalid_heartbeat(void)
{
    int before = failures;
    reset_monitor();

    CHECK(validate_heartbeat(0, 0, 1000, 0) == 0,
          "zero PID should be rejected");

    CHECK(validate_heartbeat(-1, 0, 1000, 0) == 0,
          "negative PID should be rejected");

    CHECK(validate_heartbeat(1234, -1, 1000, 0) == 0,
          "negative sequence should be rejected");

    CHECK(validate_heartbeat(1234, 0, -1, 0) == 0,
          "negative timestamp should be rejected");

    CHECK(validate_heartbeat(1234, 0, 1000, -1) == 0,
          "negative epoch should be rejected");

    CHECK(current_epoch == -1,
          "invalid heartbeat changed monitor state");

    if (failures == before)
        printf("[PASS] invalid heartbeat arguments\n");
}


/* test event logging writes to a file */
static void test_logging(void)
{
    int before = failures;

    FILE *log = tmpfile();

    CHECK(log != NULL,
          "unable to create temporary log");

    if (!log)
        return;

    log_event(log, "Crash Detected");
    log_event(log, "Failover Triggered");
    log_event(log, "Service Restored");

    rewind(log);

    char buf[512] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, log);
    buf[n] = '\0';

    CHECK(strstr(buf, "Crash Detected") != NULL,
          "crash event not logged");

    CHECK(strstr(buf, "Failover Triggered") != NULL,
          "failover event not logged");

    CHECK(strstr(buf, "Service Restored") != NULL,
          "restoration event not logged");

    fclose(log);

    if (failures == before)
        printf("[PASS] event logging\n");
}


/*
 * Test restart_sentinel() using a temporary fake executable.
 *
 * The real monitor launches ./bin/sentinel.
 * This test creates a temporary bin/sentinel script to verify
 * that fork(), exec(), and standby arguments work correctly.
 *
 * The fake executable immediately exits, so this test does
 * not leave another Sentinel running.
 */
static void test_restart_sentinel(void)
{
    int before = failures;
    reset_monitor();

    char original_dir[PATH_MAX];

    if (!getcwd(original_dir, sizeof(original_dir))) {
        CHECK(0, "unable to get current directory");
        return;
    }

    char temp_dir[] = "/tmp/monitor_test_XXXXXX";

    if (!mkdtemp(temp_dir)) {
        CHECK(0, "unable to create temporary directory");
        return;
    }

    char bin_dir[PATH_MAX];
    char script[PATH_MAX];
    char output[PATH_MAX];

    snprintf(bin_dir, sizeof(bin_dir),
             "%s/bin", temp_dir);

    snprintf(script, sizeof(script),
             "%s/bin/sentinel", temp_dir);

    snprintf(output, sizeof(output),
             "%s/args.txt", temp_dir);

    /* create bin directory inside the temporary directory */
    if (mkdir(bin_dir, 0700) != 0) {
        CHECK(0, "unable to create temporary bin directory");
        rmdir(temp_dir);
        return;
    }

    /* create a fake Sentinel executable */
    FILE *f = fopen(script, "w");

    if (!f) {
        CHECK(0, "unable to create fake sentinel");
        rmdir(bin_dir);
        rmdir(temp_dir);
        return;
    }

    fprintf(f, "#!/bin/sh\n");
    fprintf(f, "printf '%%s\\n' \"$@\" > args.txt\n");
    fprintf(f, "exit 0\n");

    fclose(f);

    if (chmod(script, 0700) != 0) {
        CHECK(0, "unable to make fake sentinel executable");
        goto cleanup;
    }

    /* switch directory so ./bin/sentinel resolves to our fake */
    if (chdir(temp_dir) != 0) {
        CHECK(0, "unable to enter temporary directory");
        goto cleanup;
    }

    /* launch the fake replacement sentinel */
    pid_t pid = restart_sentinel(1);

    CHECK(pid > 0,
          "restart_sentinel failed to fork");

    if (pid > 0) {
        int status = 0;

        pid_t result = waitpid(pid, &status, 0);

        CHECK(result == pid,
              "failed to collect replacement process");

        if (result == pid) {
            CHECK(WIFEXITED(status) &&
                  WEXITSTATUS(status) == 0,
                  "replacement executable did not run successfully");
        }

        /* verify arguments passed to standby */
        FILE *args = fopen("args.txt", "r");

        CHECK(args != NULL,
              "replacement executable did not create output");

        if (args) {
            char contents[256] = {0};

            size_t n = fread(contents, 1,
                             sizeof(contents) - 1, args);

            contents[n] = '\0';

            CHECK(strstr(contents, "--standby") != NULL,
                  "replacement missing --standby argument");

            CHECK(strstr(contents, "--no-crash") != NULL,
                  "replacement missing --no-crash argument");

            fclose(args);
        }
    }

    /* return to the project directory */
    if (chdir(original_dir) != 0) {
        CHECK(0, "unable to return to project directory");
    }

cleanup:
    /* remove files created during the test */
    unlink(output);
    unlink(script);
    rmdir(bin_dir);
    rmdir(temp_dir);

    if (failures == before)
        printf("[PASS] standby process launch\n");
}


int main(void)
{
    test_timeout();
    test_first_heartbeat();
    test_sequence_increment();
    test_duplicate_heartbeat();
    test_old_sequence();
    test_pid_change();
    test_old_epoch();
    test_unauthorized_epoch();
    test_valid_failover();
    test_wrong_recovery_pid();
    test_wrong_recovery_epoch();
    test_invalid_heartbeat();
    test_logging();
    test_restart_sentinel();

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }

    printf("test_monitor: all checks passed\n");
    return 0;
}
