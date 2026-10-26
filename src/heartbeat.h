#ifndef HEARTBEAT_H
#define HEARTBEAT_H

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "protocol.h"

typedef struct {
    int port;
    atomic_int *stop;
    atomic_int *sent;
} hb_args_t;


static inline long long hb_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}


static inline void *heartbeat_thread(void *arg) {
    hb_args_t args = *(hb_args_t *)arg;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        return NULL;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons(args.port);
    if(inet_pton(AF_INET, HOST, &addr.sin_addr) != 1) {
        close(sock);
        return NULL;
    }
    int pid = getpid();

    for(int seq = 0; !atomic_load(args.stop); seq++) {
        char buf[128];
        int n = snprintf(buf, sizeof(buf), HB_FMT_OUT, pid, seq, hb_now_ms());
        if(sendto(sock, buf, n, 0, (struct sockaddr *)&addr, sizeof addr) < 0) {
            // a missing monitor must not stop the sentinel, keep beating
        }
        if(args.sent) {
            atomic_fetch_add(args.sent, 1);
        }
        struct timespec wait = {.tv_sec = T_MS / 1000, .tv_nsec = (T_MS % 1000) * 1000000L};
        nanosleep(&wait, NULL);
    }
    close(sock);
    return NULL;
}

#endif
