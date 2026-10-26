#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <limits.h>

#include "protocol.h"
#include "sentinel_core.h"
#include "heartbeat.h"
#include "fault.h"

static atomic_int stop_request = 0;

static void on_signal(int sig) {
    (void)sig;
    atomic_store(&stop_request, 1);
}

static void usage(FILE *out) {
    fprintf(out, "usage: sentinel [--blacklist <path>] [--no-crash] [--seed <n>]\n"
            "                [--crash-min-ms <n>] [--crash-max-ms <n>] [--help]\n");
}

static int fill_addr(struct sockaddr_in *addr, int port) {
    memset(addr, 0, sizeof *addr);
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    return inet_pton(AF_INET, HOST, &addr->sin_addr) == 1 ? 0 : -1;
}

static int parse_uint(const char *s, unsigned long max, unsigned *out) {
    if(!s || *s == '\0' || *s == '-') {
        return -1;
    }
    char *end;
    errno = 0;
    unsigned long val = strtoul(s, &end, 10);
    if(errno != 0 || val > max || *end != '\0') {
        return -1;
    }
    *out = (unsigned)val;
    return 0;
}

static int open_listener(int port) {
    struct sockaddr_in addr;
    if(fill_addr(&addr, port) < 0) {
        fprintf(stderr, "invalid host address: %s\n", HOST);
        return -1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock < 0) {
        perror("socket");
        return -1;
    }
    if(bind(sock, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("bind");
        close(sock);
        return -1;
    }
    return sock;
}

static void handle_datagram(const blacklist_t *bl, char *buf, ssize_t len, const char *ip, const char *from) {
    if(len > MAX_PKT_SIZE) {
        printf("dropped from %s: datagram larger than %d bytes\n", from, MAX_PKT_SIZE);
        return;
    }

    buf[len] = '\0';
    if(strlen(buf) != (size_t)len) {
        printf("dropped from %s: NUL byte in datagram\n", from);
        return;
    }

    pkt_t pkt;
    pkt_err_t err = parse_pkt(buf, &pkt);
    if(err != PKT_OK) {
        printf("dropped from %s: %s\n", from, pkt_strerror(err));
        return;
    }


    // the blacklist is checked against the real sender address, not the src= field
    const char *verdict = is_blacklisted(bl, ip) != 0 ? "blocked" : "accepted";
    printf("%s %s (dst_port %d, seq %d)", verdict, from, pkt.dst_port, pkt.seq);
    if(strcmp(pkt.src, ip) != 0) {
        printf(" [claims src=%s]", pkt.src);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IOLBF, 0);

    const char *blacklist_path = "config/blacklist.txt";

    int no_crash = 0;
    int crash_min_ms = 5000; // 5 seconds
    int crash_max_ms = 20000; // 20 seconds
    int crash_pct = 100;
    unsigned seed = (unsigned)time(NULL) ^ (unsigned)getpid();

    // parse command-line options
    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "--no-crash") == 0) {
            no_crash = 1;
        } else if(strcmp(argv[i], "--blacklist") == 0) {
            if(++i >= argc) {
                fprintf(stderr, "--blacklist needs a path\n");
                return 2;
            }
            blacklist_path = argv[i];
        } else if(strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            return 0;
        } else if(strcmp(argv[i], "--crash-min-ms") == 0) {
            unsigned v;
            if(++i >= argc || parse_uint(argv[i], INT_MAX, &v) != 0) {
                fprintf(stderr, "--crash-min-ms needs a non-negative number\n");
                return 2;
            }
            crash_min_ms = (int)v;
        } else if(strcmp(argv[i], "--crash-max-ms") == 0) {
            unsigned v;
            if(++i >= argc || parse_uint(argv[i], INT_MAX, &v) != 0) {
                fprintf(stderr, "--crash-max-ms needs a non-negative number\n");
                return 2;
            }
            crash_max_ms = (int)v;
        } else if(strcmp(argv[i], "--seed") == 0) {
            unsigned v;
            if(++i >= argc || parse_uint(argv[i], UINT_MAX, &v) != 0) {
                fprintf(stderr, "--seed needs a non-negative number\n");
                return 2;
            }
            seed = v;
        } else {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            usage(stderr);
            return 2;
        }
    }

    if(crash_min_ms > crash_max_ms) {
        fprintf(stderr, "--crash-min-ms (%d) must not exceed --crash-max-ms (%d)\n", crash_min_ms, crash_max_ms);
        return 2;
    }

    // load blacklist before socket
    blacklist_t bl;
    bl_err_t err = blacklist_load(blacklist_path, &bl);
    if(err != BL_OK) {
        fprintf(stderr, "cannot load blacklist '%s' (error %d)\n", blacklist_path, (int)err);
        return 1;
    }
    printf("loaded %d blacklist entries from %s\n", bl.count, blacklist_path);

    int sock = open_listener(PKT_PORT);
    if(sock < 0) {
        return 1;
    }
    printf("listening on %s:%d\n", HOST, PKT_PORT);

    // heartbeat thread intialization
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    hb_args_t hb_args = {.port = HEARTBEAT_PORT, .stop = &stop_request, .sent = NULL};
    pthread_t hb;
    if(pthread_create(&hb, NULL, heartbeat_thread, &hb_args) != 0) {
        fprintf(stderr, "failed to create heartbeat thread\n");
        close(sock);
        return 1;
    }
    printf("heartbeat -> %s:%d every %d ms\n", HOST, HEARTBEAT_PORT, T_MS);

    // initialize fault thread
    fault_args_t fault_args = {.min_ms = crash_min_ms, .max_ms = crash_max_ms, .pct = crash_pct, .seed = seed, .stop = &stop_request, .rolls = NULL};
    pthread_t fault;
    int fault_started = 0;
    if(!no_crash) {
        if(pthread_create(&fault, NULL, fault_thread, &fault_args) != 0) {
            fprintf(stderr, "failed to create fault thread\n");
            atomic_store(&stop_request, 1);   // tell the heartbeat thread to stop
            pthread_join(hb, NULL);
            close(sock);
            return 1;
        }
        fault_started = 1;
        printf("crash injection on: seed %u, between %d and %d ms\n", seed, crash_min_ms, crash_max_ms);
    }

    // receive and handle datagrams
    char buf[MAX_PKT_SIZE + 1];
    while(!atomic_load(&stop_request)) {
        struct sockaddr_in sender;
        socklen_t sender_len = sizeof sender;
        ssize_t len = recvfrom(sock, buf, sizeof buf, 0, (struct sockaddr *)&sender, &sender_len);
        if(len < 0) {
            if(errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            perror("recvfrom");
            break;
        }

        char ip[INET_ADDRSTRLEN];
        char from[INET_ADDRSTRLEN + 8];
        inet_ntop(AF_INET, &sender.sin_addr, ip, sizeof ip);
        snprintf(from, sizeof from, "%s:%d", ip, ntohs(sender.sin_port));
        handle_datagram(&bl, buf, len, ip, from);
    }

    // closes everything
    atomic_store(&stop_request, 1);
    if(fault_started) {
        pthread_join(fault, NULL);
    }
    pthread_join(hb, NULL);
    close(sock);
    (void)no_crash;
    return 0;
}
