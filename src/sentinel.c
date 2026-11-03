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
#include <time.h>

#include "protocol.h"
#include "sentinel_core.h"
#include "heartbeat.h"
#include "fault.h"
#include "state.h"
#include "checkpoint.h"

static atomic_int stop_request = 0;

static void on_signal(int sig) {
    (void)sig;
    atomic_store(&stop_request, 1);
}

static void usage(FILE *out) {
    fprintf(out, "usage: sentinel [--blacklist <path>] [--no-crash] [--seed <n>] [--standby]\n"
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
    
    int yes = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) < 0) {
        perror("setsockopt SO_REUSEADDR");
        close(sock);
        return -1;
    }

    for(int waited = 0; ; waited += BIND_RETRY_STEP_MS) {
        if(bind(sock, (struct sockaddr *)&addr, sizeof addr) == 0) {
            return sock;
        }
        int bind_errno = errno;
        if(bind_errno != EADDRINUSE || waited >= BIND_RETRY_MS || atomic_load(&stop_request)) {
            fprintf(stderr, "cannot bind %s:%d: %s (gave up after %d ms)\n", HOST, port, strerror(bind_errno), waited);
            close(sock);
            return -1;
        }

        struct timespec pause =  {.tv_sec = 0, .tv_nsec = BIND_RETRY_STEP_MS * 1000000L};
        nanosleep(&pause, NULL);
    }
}

static void send_reply(int sock, const struct sockaddr_in *sender, const char *msg) {
    if(sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)sender, sizeof *sender) < 0) {
        perror("sendto");
    }
}

static const char *control_error(const char *buf) {
    const char *body = strchr(buf, '|');
    if(!body || strncmp(body + 1, "ip=", 3) != 0) {
        return "bad format";
    }
    return strchr(body + 4, '|') ? "bad format" : "bad ip";
}

static void handle_pkt(sentinel_state_t *state, char *buf, const char *ip, const char *from) {
    pkt_t pkt;
    pkt_err_t err = parse_pkt(buf, &pkt);
    if(err != PKT_OK) {
        printf("dropped from %s: %s\n", from, pkt_strerror(err));
        return;
    }
    state_record_hit(state, ip, hb_now_ms());
    const char *verdict = state_query(state, ip, NULL) == 1 ? "blocked" : "accepted";
    printf("%s %s (dst_port %d, seq %d)", verdict, from, pkt.dst_port, pkt.seq);
    if(strcmp(pkt.src, ip) != 0) {
        printf(" [claims src=%s]", pkt.src);
    }
    printf("\n");

}

static void handle_control(sentinel_state_t *state, int sock, const struct sockaddr_in *sender, msg_type_t type, char *buf, size_t len, const char *from) {
    char target[SRC_IP_LEN];
    int parsed = type == CTL_BLOCK ? block_parse(buf, len, target) :
                type == CTL_UNBLOCK ? unblock_parse(buf, len, target) :
                query_parse(buf, len, target);

    char reply[64];
    if(parsed != CTL_OK){
        snprintf(reply, sizeof reply, REPLY_ERR_FMT, control_error(buf));
        printf("rejected from %s: %s\n", from, reply);
        send_reply(sock, sender, reply);
        return;
    }

    if(type == CTL_QUERY) {
        int hits = 0;
        if(state_query(state, target, &hits) == 1) {
            snprintf(reply, sizeof reply, REPLY_QUERY_BLOCKED_FMT, hits);
        }
        else{
            snprintf(reply, sizeof reply, REPLY_QUERY_ALLOWED_FMT, hits);
        }
    }
    else if(type == CTL_BLOCK) {
        if(state_block(state, target) == STATE_FULL) {
            snprintf(reply, sizeof reply, REPLY_ERR_FMT, "blacklist full");
        }
        else {
            snprintf(reply, sizeof reply, REPLY_BLOCKED_FMT, target);
        }
    }
    else { // UNBLOCK
        state_unblock(state, target);
        snprintf(reply, sizeof reply, REPLY_UNBLOCKED_FMT, target);
    }

    printf("control message from %s: %s\n", from, reply);
    send_reply(sock, sender, reply);

}

static void handle_datagram(sentinel_state_t *state, int sock, const struct sockaddr_in *sender, char *buf, ssize_t len, const char *ip, const char *from) {
    if(len > MAX_PKT_SIZE) {
        printf("dropped from %s: datagram of %zd bytes exceeds the %d byte limit\n", from, len, MAX_PKT_SIZE);
        return;
    }

    buf[len] = '\0';
    if(strlen(buf) != (size_t)len) {
        printf("dropped from %s: NUL byte in datagram\n", from);
        return;
    }

    switch(dispatch(buf, (size_t)len)){
        case CTL_PKT:
            handle_pkt(state, buf, ip, from);
            break;
        case CTL_BLOCK:
            handle_control(state, sock, sender, CTL_BLOCK, buf, (size_t)len, from);
            break;
        case CTL_UNBLOCK:
            handle_control(state, sock, sender, CTL_UNBLOCK, buf, (size_t)len, from);
            break;
        case CTL_QUERY:
            handle_control(state, sock, sender, CTL_QUERY, buf, (size_t)len, from);
            break;
        default:
            printf("rejected from %s: unknown message type\n", from);
            send_reply(sock, sender, "ERR unknown type");
            break;
    }
}

typedef struct {
    sentinel_state_t *state;
    atomic_int *stop;
} checkpoint_args_t;

static void *checkpoint_thread(void *arg) {
    checkpoint_args_t args = *(checkpoint_args_t *)arg;

    while(!atomic_load(args.stop)) {
        ckpt_err_t err = checkpoint_save(args.state, CHECKPOINT_PATH, CHECKPOINT_TMP, CHECKPOINT_PREV);
        if(err != CKPT_OK) {
            fprintf(stderr, "[%lld] WARN checkpoint save failed: %s\n", hb_now_ms(), checkpoint_strerror(err));
        }
        fault_sleep_ms(CHECKPOINT_INTERVAL_MS, args.stop);
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, NULL, _IOLBF, 0);

    const char *blacklist_path = "config/blacklist.txt";

    int no_crash = 0;
    int crash_min_ms = 5000; // 5 seconds
    int crash_max_ms = 20000; // 20 seconds
    int crash_pct = 100;
    unsigned seed = (unsigned)time(NULL) ^ (unsigned)getpid();
    int standby = 0;

    // parse command-line options
    for(int i = 1; i < argc; i++) {
        if(strcmp(argv[i], "--no-crash") == 0) {
            no_crash = 1;
        } else if(strcmp(argv[i], "--standby") == 0) {
            standby = 1;
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

    sentinel_state_t state;
    if(!standby) {
        if(state_init(&state, &bl) != 0) {
            fprintf(stderr, "failed to initialize sentinel state\n");
            return 1;
        }
    }
    else{
        ckpt_source_t source = checkpoint_load(&state, &bl, CHECKPOINT_PATH, CHECKPOINT_PREV);
        if(source == CKPT_SRC_ERR) {
            fprintf(stderr, "cannot restore state\n");
            return 1;
        }
        state.epoch++;
        if(source == CKPT_SRC_BASE) {
            printf("[%lld] [Service Restored] standby active, no usable checkpoint, using base blacklist (%d blocked IPs, epoch %d)\n", hb_now_ms(), state.blacklist.count, state.epoch);
        }
        else {
            printf("[%lld] [Service Restored] standby active, loaded checkpoint v%d (%d blocked IPs, epoch %d)\n", hb_now_ms(), CKPT_VERSION, state.blacklist.count, state.epoch);
        }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    int sock = open_listener(PKT_PORT);
    if(sock < 0) {
        return 1;
    }
    printf("listening on %s:%d\n", HOST, PKT_PORT);

    // heartbeat thread intialization
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

    // initialize checkpoint thread
    checkpoint_args_t ckpt_args = {.state = &state, .stop = &stop_request};
    pthread_t ckpt;
    if(pthread_create(&ckpt, NULL, checkpoint_thread, &ckpt_args) != 0) {
        fprintf(stderr, "failed to create checkpoint thread\n");
        atomic_store(&stop_request, 1);
        if(fault_started) {
            pthread_join(fault, NULL);
        }
        pthread_join(hb, NULL);
        close(sock);
        return 1;
    }
    printf("checkpointing -> %s every %d ms\n", CHECKPOINT_PATH, CHECKPOINT_INTERVAL_MS);

    // receive and handle datagrams
    char buf[MAX_PKT_SIZE + 1];
    while(!atomic_load(&stop_request)) {
        struct sockaddr_in sender;
        socklen_t sender_len = sizeof sender;
        ssize_t len = recvfrom(sock, buf, sizeof buf, MSG_TRUNC, (struct sockaddr *)&sender, &sender_len);
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
        handle_datagram(&state, sock, &sender, buf, len, ip, from);
    }

    // closes everything
    atomic_store(&stop_request, 1);
    if(fault_started) {
        pthread_join(fault, NULL);
    }
    pthread_join(ckpt, NULL);
    pthread_join(hb, NULL);
    close(sock);
    (void)no_crash;
    return 0;
}
