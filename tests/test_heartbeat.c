#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "protocol.h"
#include "heartbeat.h"

static int failures = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); failures++; } \
} while (0)

#define RECV_TIMEOUT_MS 2000

static long long mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int open_test_listener(int *port)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    inet_pton(AF_INET, HOST, &addr.sin_addr);

    socklen_t len = sizeof addr;
    struct timeval tv = {.tv_sec = RECV_TIMEOUT_MS / 1000, .tv_usec = (RECV_TIMEOUT_MS % 1000) * 1000};
    if(bind(sock, (struct sockaddr *)&addr, sizeof addr) < 0 ||
       getsockname(sock, (struct sockaddr *)&addr, &len) < 0 ||
       setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0) {
        close(sock);
        return -1;
    }

    *port = ntohs(addr.sin_port);
    return sock;
}

static void test_sends_periodic_heartbeats(void)
{
    int port = 0;
    int sock = open_test_listener(&port);
    CHECK(sock >= 0, "could not open test listener");
    if(sock < 0) {
        return;
    }

    atomic_int stop = 0;
    hb_args_t args = {.port = port, .stop = &stop};
    pthread_t tid;
    int rc = pthread_create(&tid, NULL, heartbeat_thread, &args);
    CHECK(rc == 0, "could not create heartbeat thread");
    if(rc != 0) {
        close(sock);
        return;
    }

    int pid[3], seq[3];
    long long ts[3], arrived[3];
    int got = 0;

    for(int i = 0; i < 3; i++) {
        char buf[128];
        ssize_t n = recvfrom(sock, buf, sizeof(buf) - 1, 0, NULL, NULL);
        if(n < 0) {
            CHECK(0, "could not receive heartbeat");
            break;
        }
        arrived[i] = mono_ms();
        buf[n] = '\0';

        int matched = sscanf(buf, HB_FMT_IN, &pid[i], &seq[i], &ts[i]);
        if(matched != 3) {
            CHECK(0, "heartbeat did not parse");
            break;
        }
        got++;
    }
    
    atomic_store(&stop, 1);
    pthread_join(tid, NULL);
    close(sock);

    CHECK(got == 3, "did not receive 3 heartbeats");

    for(int i = 0; i < got; i++) {
        CHECK(pid[i] == (int)getpid(), "heartbeat pid is not the sender's pid");
        CHECK(ts[i] > 0, "heartbeat ts must be positive");
    }

    CHECK(got < 1 || seq[0] == 0, "first heartbeat seq must be 0");

    for(int i = 1; i < got; i++) {
        CHECK(seq[i] == seq[i - 1] + 1, "seq did not increase by exactly 1");
        CHECK(ts[i] >= ts[i - 1], "ts went backwards");
    }

    for(int i = 1; i < got; i++) {
        long long gap = arrived[i] - arrived[i - 1];
        CHECK(gap >= T_MS / 2 && gap <= T_MS * 2, "heartbeat gap not close to T_MS");
    }
}

// The join should return within about 2 * T_MS.
static void test_stops_on_request(void)
{
    int port = 0;
    int sock = open_test_listener(&port);
    CHECK(sock >= 0, "could not open test listener");
    if(sock < 0) {
        return;
    }

    atomic_int stop = 0;
    hb_args_t args = {.port = port, .stop = &stop};
    pthread_t tid;
    int rc = pthread_create(&tid, NULL, heartbeat_thread, &args);
    CHECK(rc == 0, "could not create heartbeat thread");
    if(rc != 0) {
        close(sock);
        return;
    }

    char buf[128];
    ssize_t n = recvfrom(sock, buf, sizeof(buf) - 1, 0, NULL, NULL);
    CHECK(n >= 0, "no heartbeat before stop was requested");

    long long start = mono_ms();
    atomic_store(&stop, 1);
    pthread_join(tid, NULL);
    long long elapsed = mono_ms() - start;
    close(sock);

    CHECK(elapsed <= T_MS * 2, "thread took too long to stop");
}

static void test_survives_no_listener(void)
{
    int port = 0;
    int sock = open_test_listener(&port);
    CHECK(sock >= 0, "could not open test listener");
    if(sock < 0) {
        return;
    }
    close(sock);

    atomic_int stop = 0;
    atomic_int sent = 0;
    hb_args_t args = {.port = port, .stop = &stop, .sent = &sent};
    pthread_t tid;
    int rc = pthread_create(&tid, NULL, heartbeat_thread, &args);
    CHECK(rc == 0, "could not create heartbeat thread");
    if(rc != 0) {
        return;
    }

    const struct timespec wait = {.tv_sec = (T_MS * 5 / 2) / 1000, .tv_nsec = ((T_MS * 5 / 2) % 1000) * 1000000L};
    nanosleep(&wait, NULL);
    int attempts = atomic_load(&sent);

    atomic_store(&stop, 1);
    pthread_join(tid, NULL);

    CHECK(attempts >= 2, "thread stopped sending after the monitor was missing");
}

int main(void)
{
    alarm(30); // a hung thread kills the test instead of blocking forever
    test_sends_periodic_heartbeats();
    test_stops_on_request();
    test_survives_no_listener();

    if(failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("test_heartbeat: all checks passed\n");
    return 0;
}
