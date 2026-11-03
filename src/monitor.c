#define _POSIX_C_SOURCE 200809L

#include <sys/types.h>
#include <sys/wait.h>
#include <limits.h>
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

/* where sentinel should be executed from */
#define SENTINEL_PATH "./sentinel"

/* track the current sentinel and heatbeat generation */
static int current_epoch = -1;
static int last_seq = -1;
static int current_pid = -1;

static int expected_epoch = -1;
static pid_t replacement_pid = -1; 

/* restart sentinel after detecting a crash */
static pid_t restart_sentinel(int epoch) {
    pid_t pid = fork();

    if(pid < 0) {
        perror("fork");
        return -1;
    }

    /* child prrocess becomes the new sentinel */
    if(pid == 0) {
        char epoch_buf[32];

        snprintf(epoch_buf, sizeof(epoch_buf),
                "%d", epoch);
        
        /* pass the next epoch to sentinel */
        if (setenv("SENTINEL_EPOCH",
             epoch_buf, 1) != 0) {
            perror("setenv");
            _exit(EXIT_FAILURE);
        }

        /* replace child with tsentinel executable */
        execl(SENTINEL_PATH,
              SENTINEL_PATH,
            "--standby",
            "--no-crash",
            (char *)NULL);
        
            perror("execl");
            _exit(EXIT_FAILURE);
    }

    return pid;
}

/* print and log events with timestaps */
static void log_event(FILE *log, const char *event) {
    time_t current = time(NULL);
    struct tm local;

    localtime_r(&current, &local);

    char timestamp[64];

    strftime(timestamp, sizeof(timestamp),
             "%Y-%m-%d %H:%M:%S", &local);
    
    printf("[%s] %s\n", timestamp, event);

    fprintf(log, "[%s] %s\n", timestamp, event);
    fflush(log);
}

/* check heartbeat epoch and sequence to prevent old messages */
static int validate_heartbeat(int pid, int seq,
                              long long timestamp,
                              int epoch) {

    /* reject invalid heartbeat values */
    if(pid <= 0 || seq < 0 ||
        timestamp < 0 || epoch < 0) {
            return 0;
    }

    /* reject hearbeats from an older sentinel */
    if(epoch < current_epoch) {
        printf("Rejected olf epoch: %d\n", epoch);
        return 0;
    }

    /* when restarting - only accept the expected sentinel */
    if(expected_epoch >= 0) {
        if (epoch != expected_epoch ||
            pid != replacement_pid) {
            printf("Rejected unexected recovery heartbeat\n");
            return 0;
        }
    }

    if(epoch == current_epoch) {

        /* reject a different PID using the same epoch */
        if(current_pid != -1 && pid != current_pid) {
            printf("Rejected unexpected PID\n");
            return 0;
        }

        /* reject repeated or old sequenced numbers */
        if (seq <= last_seq) {
            printf("Rejected stale sequence: %d\n", seq);
            return 0;
        }
    }
    else {

        /* accept a newer epoch only during expected recovery */
        if (current_epoch != -1 &&
            expected_epoch != epoch) {
            printf("rejected unauthorized epoch change\n");
            return 0;
        }
    }

    /* done - update the last valid heartbeat information */
    current_epoch = epoch;
    current_pid = pid;
    last_seq = seq;

    return 1;
}

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
    printf("Failure timeout: %d ms\n", TIMEOUT_VAL);

    /* last_heartbeat - time of last valid heartbeat
       received_first - heartbeat arrived flag 
       is_offline     - prevent repeated failure alerts */
    long long last_heartbeat = 0;
    int received_first = 0;
    int is_offline = 0;

    /* failover_pending - waiting for replacement heartbeat */
    int failover_pending = 0;


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
            int epoch;
            int seq;
            long long timestamp;
            int consumed = 0;

        /* map to heartbeat */
            int matched = sscanf(
                buf,
                HB_FMT_IN "%n",
                &pid,
                &epoch,
                &seq,
                &timestamp,
                &consumed
            );

        /* need all three fields present & valid */
            if (matched == 4 &&
                consumed == len &&
                validate_heartbeat(pid, seq,
                                   timestamp, epoch)) {
        
            /* record this heartbeat time */
                last_heartbeat = now_ms();
                received_first = 1;

                printf("Heartbeat received: PID=%d SEQ=%d EPOCH=%d\n",
                       pid, seq, epoch);
            
            /* if heartbeat was offline - note restoration */
                if (is_offline && failover_pending) {
                    log_event(log, "Service Restored");

                    is_offline = 0;
                    failover_pending = 0;
                    expected_epoch = -1;
                    replacement_pid = -1;
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

        /* check whether replacement process has exited */
        if (replacement_pid > 0) {
            int status;

            pid_t result = waitpid(
                replacement_pid, &status, WNOHANG
            );

            if(result == replacement_pid) {
                replacement_pid = -1;
            }
        }
      

        /* did heartbeat expired?  */
        if (received_first && !is_offline) {
            long long elapsed = now_ms() - last_heartbeat;

            /* error log failure w timestamp */
            if (elapsed >= TIMEOUT_VAL) {
                log_event(log, "Crash Detected");

                printf("No heartbeat for %lld ms\n\n",
                       elapsed);
                
                is_offline = 1;

                /* start new sentinel w next epoch */
                if (current_epoch >= 0 &&
                    current_epoch < INT_MAX) {

                    expected_epoch = current_epoch + 1;

                    replacement_pid = restart_sentinel(expected_epoch);

                    if(replacement_pid > 0) {
                        failover_pending = -1;

                        /* log failover start */
                        log_event(log, "Failover Triggered");
                    }
                    else {
                        log_event(log, "Failover Event Failed");
                    }
                }
            }
        }
    }

    /* cleanup */
    fclose(log);
    close(sock);

    return EXIT_SUCCESS;
}