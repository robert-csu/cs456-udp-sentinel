
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "protocol.h"
#include "sentinel_core.h"

/* timeout 1500ms */
#define TIMEOUT_VAL (T_MS * MAX_MISSED_HEARTBEAT)


int main(void)
{
    /* create UDP socket */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    /* valid? */ 
    if (sock < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    /* clear mem - prepare to connect */ 
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(HEARTBEAT_PORT);

    /* parse IP - exit if not good */
    if (inet_pton(AF_INET, HOST, &addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid IP address\n");
        close(sock);
        return EXIT_FAILURE;
    }

    /* attach socket monitor IP & port
      we're listening - or exiting w bad cc */
    if (bind(sock, (struct sockaddr *)&addr,
             sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        return EXIT_FAILURE;
    }

    /* struct to bail if recvfrom wait > 100 ms without heartbeat */
    struct timeval timeout = {
        .tv_sec = 0,
        .tv_usec = 100000
    };

    /* set socket options */
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                   &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt");
        close(sock);
        return EXIT_FAILURE;
    }

    
    /* open log */
    FILE *log = fopen("monitor.log", "a");

    /* no log - no point */
    if (!log) {
        perror("fopen");
        close(sock);
        return EXIT_FAILURE;
    }

    /* log presence */
    printf("Monitor listening on %s:%d\n",
           HOST, HEARTBEAT_PORT);
    printf("Heartbeat interval: %d ms\n", T_MS);
    printf("Failure timeout: %d ms\n", TIMEOUT_MS);

    /* last_heartbeat - time of last valid heartbeat
       received_first - heartbeat arrived flag 
       is_offline     - prevent repeated failure alerts */
    long long last_heartbeat = 0;
    int received_first = 0;
    int is_offline = 0;

    /* MAIN MONITOR LOOP - 
       ENSURE SENTINEL ONLINE OR TIMEOUT */
       while (1) {
        char buf[128];
    
    /* Waiting for UDP heartbeat to parse or alert & timeout */
        ssize_t len = recvfrom(
            sock,
            buf,
            sizeof(buf) - 1,
            0,
            NULL,
            NULL
        );

    /* got something? add null byte for safe read */
        if (len >= 0) {
            buf[len] = '\0';

            /* parse expected heartbeat format */
            int pid;
            int seq;
            long long timestamp;
            int consumed = 0;

        /* map to heartbeat */
            int matched = sscanf(
                buf,
                HB_FMT_IN "%n",
                &pid,
                &seq,
                &timestamp,
                &consumed
            );

        /* need all three fields present & valid */
            if (matched == 3 &&
                consumed == len &&
                pid > 0 &&
                seq >= 0 &&
                timestamp >= 0) {
        
            /* record this heartbeat time */
                last_heartbeat = now_ms();
                received_first = 1;

                printf("Heartbeat received: PID=%d SEQ=%d\n",
                       pid, seq);
            
            /* if heartbeat was offline - note restoration */
                if (service_offline) {
                    printf("Service heartbeat restored!\n");

                    time_t current = time(NULL);
                    fprintf(log, "%lld RECOVERED %s",
                            now_ms(), ctime(&current));
                    fflush(log);

                    service_offline = 0;
                }
            }
        }

        /* handle errors if something is wrong */
        else if (errno != EAGAIN &&
                 errno != EWOULDBLOCK &&
                 errno != EINTR) {
            perror("recvfrom");
            break;
        }

        /* did heartbeat expired?  */
        if (received_first && !service_offline) {
            long long elapsed = now_ms() - last_heartbeat;

            /* error log failure w timestamp */
            if (elapsed >= TIMEOUT_MS) {
                printf("\nALERT: Sentinel is OFFLINE!\n");
                printf("No heartbeat for %lld ms\n\n",
                       elapsed);

                time_t current = time(NULL);

                fprintf(log, "%lld FAILURE %s",
                        now_ms(), ctime(&current));
                fflush(log);

                service_offline = 1;
            }
        }
    }

    /* cleanup */
    fclose(log);
    close(sock);

    return EXIT_SUCCESS;
}