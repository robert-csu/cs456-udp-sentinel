#ifndef HEARTBEAT_H
#define HEARTBEAT_H

#include <stdatomic.h>

typedef struct {
    int port;
    atomic_int *stop;
    atomic_int *sent;
} hb_args_t;

// TDD stub: sends nothing yet
static inline void *heartbeat_thread(void *arg) {
    (void)arg;
    return NULL;
}

#endif
