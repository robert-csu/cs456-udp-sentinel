#ifndef FAULT_H
#define FAULT_H

#include <stdatomic.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "sentinel_core.h"

typedef struct {
    int min_ms;
    int max_ms;
    int pct;
    unsigned seed;
    atomic_int *stop;
    atomic_int *rolls;
} fault_args_t;

#define FAULT_SLICE_MS 50

// sleeps ms milliseconds in short slices so a stop request is noticed within one slice
static inline void fault_sleep_ms(int ms, atomic_int *stop) {
    while(ms > 0 && !atomic_load(stop)) {
        int slice = ms < FAULT_SLICE_MS ? ms : FAULT_SLICE_MS;
        struct timespec wait = {.tv_sec = slice / 1000, .tv_nsec = (slice % 1000) * 1000000L};
        nanosleep(&wait, NULL);
        ms -= slice;
    }
}

static inline void *fault_thread(void *arg){
    fault_args_t args = *(fault_args_t *)arg;

    while(!atomic_load(args.stop)) {
        int ms = fault_next_sleep_ms(&args.seed, args.min_ms, args.max_ms);
        if(ms == -1) {
            return NULL;
        }
        
        fault_sleep_ms(ms, args.stop);

        if(atomic_load(args.stop)) {
            break;
        }
        
        int crash = fault_should_crash(&args.seed, args.pct);
        if(args.rolls) {
            atomic_fetch_add(args.rolls, 1);
        }
        if(crash == 1) {
            fprintf(stderr, "sentinel: injecting crash\n");
            abort();
        }
    }
    return NULL;
}


#endif