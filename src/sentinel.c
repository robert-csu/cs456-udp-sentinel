#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "protocol.h"
#include "sentinel_core.h"

static void usage(FILE *out) {
    fprintf(out, "usage: sentinel [--blacklist <path>] [--no-crash] [--help]\n");
}

static int fill_addr(struct sockaddr_in *addr, int port) {
    memset(addr, 0, sizeof *addr);
    addr->sin_family = AF_INET;
    addr->sin_port = htons(port);
    return inet_pton(AF_INET, HOST, &addr->sin_addr) == 1 ? 0 : -1;
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

static void handle_datagram(const blacklist_t *bl, char *buf, ssize_t len, const char *from) {
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

    // is_blacklisted returns -1 on a bad argument, which also counts as blocked
    const char *verdict = is_blacklisted(bl, pkt.src) != 0 ? "blocked" : "accepted";
    printf("%s %s (dst_port %d, seq %d)\n", verdict, pkt.src, pkt.dst_port, pkt.seq);
}

int main(int argc, char *argv[]) {
    // line buffered, so log lines show up even when stdout is a file or pipe
    setvbuf(stdout, NULL, _IOLBF, 0);

    const char *blacklist_path = "config/blacklist.txt";
    int no_crash = 0;

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
        } else {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            usage(stderr);
            return 2;
        }
    }

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

    char buf[MAX_PKT_SIZE + 1];
    for(;;) {
        struct sockaddr_in sender;
        socklen_t sender_len = sizeof sender;
        ssize_t len = recvfrom(sock, buf, sizeof buf, 0, (struct sockaddr *)&sender, &sender_len);
        if(len < 0) {
            perror("recvfrom");
            break;
        }

        char ip[INET_ADDRSTRLEN];
        char from[INET_ADDRSTRLEN + 8];
        inet_ntop(AF_INET, &sender.sin_addr, ip, sizeof ip);
        snprintf(from, sizeof from, "%s:%d", ip, ntohs(sender.sin_port));
        handle_datagram(&bl, buf, len, from);
    }

    close(sock);
    (void)no_crash;
    return 0;
}
