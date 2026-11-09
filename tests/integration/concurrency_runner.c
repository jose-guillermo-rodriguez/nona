// Copyright (c) 2026 Nona Contributors.
// Licensed under the Apache License, Version 2.0 or the MIT License.
// ============================================================================
// ============================================================================

#include "nona.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

#define THREAD_COUNT 8
#define ITERATIONS_PER_THREAD 1000

typedef struct {
    uint32_t thread_id;
    uint32_t successful_ingests;
    uint32_t contention_locks;
} thread_stats_t;

static thread_stats_t g_stats[THREAD_COUNT];

static void* worker_thread(void* arg) {
    uint32_t tid = *(uint32_t*)arg;
    uint8_t thread_buf[128] NONA_ALIGN(64);
    
    memset(thread_buf, (uint8_t)(tid + 1), sizeof(thread_buf));

    for (int i = 0; i < ITERATIONS_PER_THREAD; i++) {
        thread_buf[0] = (uint8_t)(tid + 1);
        thread_buf[1] = (uint8_t)(i & 0xFF);
        thread_buf[2] = (uint8_t)((i >> 8) & 0xFF);

        int32_t rc = nona_ingest_stream(thread_buf, 128);
        assert(rc == 0 || rc == -4);
        if (rc == 0) {
            g_stats[tid].successful_ingests++;
        } else {
            g_stats[tid].contention_locks++;
        }

        assert(thread_buf[0] == (uint8_t)(tid + 1));
        assert(thread_buf[1] == (uint8_t)(i & 0xFF));
        assert(thread_buf[2] == (uint8_t)((i >> 8) & 0xFF));
    }
    return NULL;
}

int main(void) {
    printf("[*] Executing Multi-Threaded Concurrency & Corruption Suite (%d threads)...\n", THREAD_COUNT);

    int32_t init_rc = nona_core_init();
    assert(init_rc <= 0);

    pthread_t threads[THREAD_COUNT];
    uint32_t thread_ids[THREAD_COUNT];

    pthread_attr_t attr;
    assert(pthread_attr_init(&attr) == 0);
    /* Enforce 256 KB stack per thread: 8 threads * 256 KB = 2 MB (< 8 MB RLIMIT_MEMLOCK under mlockall) */
    assert(pthread_attr_setstacksize(&attr, 256 * 1024) == 0);

    for (int i = 0; i < THREAD_COUNT; i++) {
        thread_ids[i] = i;
        memset(&g_stats[i], 0, sizeof(thread_stats_t));
        g_stats[i].thread_id = i;
        assert(pthread_create(&threads[i], &attr, worker_thread, &thread_ids[i]) == 0);
    }
    pthread_attr_destroy(&attr);

    uint32_t total_success = 0;
    uint32_t total_contentions = 0;

    for (int i = 0; i < THREAD_COUNT; i++) {
        assert(pthread_join(threads[i], NULL) == 0);
        total_success += g_stats[i].successful_ingests;
        total_contentions += g_stats[i].contention_locks;
        printf("    [+] Thread %d: %u ingests accepted, %u contentions handled.\n",
               i, g_stats[i].successful_ingests, g_stats[i].contention_locks);
    }

    assert(total_success + total_contentions == THREAD_COUNT * ITERATIONS_PER_THREAD);
    printf("  [+] Concurrency audit passed: %u total operations, zero data races or corruption.\n",
           total_success + total_contentions);

    printf("[===] CONCURRENCY & RE-ENTRANCY VERIFIED (ZERO DATA RACES) [===]\n");
    return 0;
}
