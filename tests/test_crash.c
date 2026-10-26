#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "protocol.h"
#include "sentinel_core.h"
#include "fault.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); failures++; } \
} while (0)

static long long mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}


static void test_crashes_within_window(void)
{
    long long start = mono_ms();
    pid_t pid = fork();
    CHECK(pid >= 0, "fork failed");
    if(pid < 0) {
        return;
    }
    if(pid == 0) {
        atomic_int stop = 0;
        fault_args_t args = {.min_ms = 100, .max_ms = 200, .pct = 100, .seed = 42, .stop = &stop};
        pthread_t tid;
        if(pthread_create(&tid, NULL, fault_thread, &args) != 0) {
            _exit(2);
        }
        pthread_join(tid, NULL);
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    long long elapsed = mono_ms() - start;

    CHECK(WIFSIGNALED(status), "Child did not exit due to a signal");
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT, "Child did not abort");
    CHECK(elapsed >= 100 && elapsed <= 200 + 500, "Child did not abort within the expected time window");
}

static void test_never_crashes_at_zero_percent(void)
{
    pid_t pid = fork();
    CHECK(pid >= 0, "fork failed");
    if(pid < 0) {
        return;
    }
    if(pid == 0) {
        atomic_int stop = 0;
        atomic_int rolls = 0;
        fault_args_t args = {.min_ms = 100, .max_ms = 200, .pct = 0, .seed = 42, .stop = &stop, .rolls = &rolls};
        pthread_t tid;
        if(pthread_create(&tid, NULL, fault_thread, &args) != 0) {
            _exit(2);
        }
        const struct timespec wait = {.tv_sec = 0, .tv_nsec = 600 * 1000000L};
        nanosleep(&wait, NULL);
        int n = atomic_load(&rolls);
        atomic_store(&stop, 1);
        pthread_join(tid, NULL);
        _exit(n >= 2 ? 0 : 3);
    }
    int status = 0;
    waitpid(pid, &status, 0);

    CHECK(!WIFSIGNALED(status), "Child crashed at pct = 0");
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0, "Child did not exit cleanly (exit code 3 means the thread stopped rolling)");
}

// forks a child running the fault thread with pct = 100 and returns the ms until it died from a signal,
// or -1 if the child did not crash (or fork failed), so a thread that never crashes cannot "agree" with itself
static long long crash_time_ms(unsigned seed)
{
    long long start = mono_ms();
    pid_t pid = fork();
    if(pid < 0) {
        return -1;
    }
    if(pid == 0) {
        atomic_int stop = 0;
        fault_args_t args = {.min_ms = 100, .max_ms = 600, .pct = 100, .seed = seed, .stop = &stop};
        pthread_t tid;
        if(pthread_create(&tid, NULL, fault_thread, &args) != 0) {
            _exit(2);
        }
        pthread_join(tid, NULL);
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    long long elapsed = mono_ms() - start;
    return WIFSIGNALED(status) ? elapsed : -1;
}

// tests that the same seed produces the same crash time
static void test_same_seed_same_crash_time(void)
{
    long long a = crash_time_ms(7);
    long long b = crash_time_ms(7);

    CHECK(a >= 100 && b >= 100, "Child did not crash after the minimum delay");
    CHECK(a >= 0 && b >= 0 && llabs(a - b) <= 100, "Same seed gave different crash times");

    unsigned s = 7;
    int expected = fault_next_sleep_ms(&s, 100, 600);
    CHECK(a >= expected && a <= expected + 100, "Crash did not happen at the seeded time");
}

// tests that the stop flag prevents a crash from occurring
static void test_stop_flag_prevents_crash(void)
{
    long long start = mono_ms();
    pid_t pid = fork();
    CHECK(pid >= 0, "fork failed");
    if(pid < 0) {
        return;
    }
    if(pid == 0) {
        atomic_int stop = 0;
        fault_args_t args = {.min_ms = 200, .max_ms = 300, .pct = 100, .seed = 42, .stop = &stop};
        pthread_t tid;
        if(pthread_create(&tid, NULL, fault_thread, &args) != 0) {
            _exit(2);
        }
        const struct timespec settle = {.tv_sec = 0, .tv_nsec = 50 * 1000000L}; // 100 ms
        nanosleep(&settle, NULL);
        atomic_store(&stop, 1);
        pthread_join(tid, NULL);
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    long long elapsed = mono_ms() - start;

    CHECK(elapsed >= 200, "Thread stopped before its sleep finished");
    CHECK(!WIFSIGNALED(status), "Child crashed even though stop was requested");
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0, "Child did not exit cleanly after stop");
}

int main(void)
{
    alarm(30);

    test_crashes_within_window();
    test_never_crashes_at_zero_percent();
    test_same_seed_same_crash_time();
    test_stop_flag_prevents_crash();

    if(failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_crash: all checks passed\n");
    return 0;
}
