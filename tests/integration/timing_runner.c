// Copyright (c) 2026 Jose Guillermo Rodriguez <jose-guillermo-rodriguez@users.noreply.github.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

// ============================================================================
// PROJECT: Nona Core Engine
// MODULE: timing_runner.c - Empirical Side-Channel Timing Neutrality Test
// ============================================================================

#include "../../include/nona.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "test_helpers.h"
#include <string.h>
#include <math.h>
#include <time.h>
#include <assert.h>

#define NUM_SAMPLES 100000

// PRNG provided by test_helpers.h

#if defined(__aarch64__) || defined(__arm64__)
static inline uint64_t rdtsc_serialized(void) {
    uint64_t val;
    __asm__ __volatile__ ("isb\n\tmrs %0, cntvct_el0" : "=r" (val) :: "memory");
    return val;
}
#elif defined(__x86_64__)
static inline uint64_t rdtsc_serialized(void) {
    uint32_t lo, hi;
    __asm__ __volatile__ (
        "lfence\n\t"
        "rdtsc\n\t"
        "lfence\n\t"
        : "=a" (lo), "=d" (hi)
        :: "memory"
    );
    return ((uint64_t)hi << 32) | lo;
}
#else
static inline uint64_t rdtsc_serialized(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
#endif

static int cmp_u64(const void* a, const void* b) {
    uint64_t arg1 = *(const uint64_t*)a;
    uint64_t arg2 = *(const uint64_t*)b;
    if (arg1 < arg2) return -1;
    if (arg1 > arg2) return 1;
    return 0;
}

static size_t filter_outliers(uint64_t* samples, size_t n) {
    if (n < 10) return n;
    uint64_t* tmp = malloc(n * sizeof(uint64_t));
    if (!tmp) return n;
    memcpy(tmp, samples, n * sizeof(uint64_t));
    qsort(tmp, n, sizeof(uint64_t), cmp_u64);

    uint64_t p80 = tmp[(size_t)(n * 0.80)];
    uint64_t cutoff = p80 * 4; // Drop context-switch spikes > 4x 80th percentile
    if (cutoff == 0) cutoff = 100000;
    free(tmp);

    size_t valid = 0;
    for (size_t i = 0; i < n; i++) {
        if (samples[i] <= cutoff) {
            samples[valid++] = samples[i];
        }
    }
    return valid;
}

static double compute_t_statistic(const uint64_t* class_a, size_t n_a, const uint64_t* class_b, size_t n_b, double* out_mean_a, double* out_mean_b) {
    if (n_a < 2 || n_b < 2) return 0.0;

    double sum_a = 0, sum_b = 0;
    for (size_t i = 0; i < n_a; i++) sum_a += class_a[i];
    for (size_t i = 0; i < n_b; i++) sum_b += class_b[i];

    *out_mean_a = sum_a / n_a;
    *out_mean_b = sum_b / n_b;

    double var_a = 0, var_b = 0;
    for (size_t i = 0; i < n_a; i++) var_a += (class_a[i] - *out_mean_a) * (class_a[i] - *out_mean_a);
    for (size_t i = 0; i < n_b; i++) var_b += (class_b[i] - *out_mean_b) * (class_b[i] - *out_mean_b);

    var_a /= (n_a - 1);
    var_b /= (n_b - 1);

    double denom = sqrt((var_a / n_a) + (var_b / n_b));
    if (denom == 0.0) {
        return (*out_mean_a == *out_mean_b) ? 0.0 : 999.0;
    }

    return (*out_mean_a - *out_mean_b) / denom;
}

int main(void) {
    printf("[*] Executing Empirical Timing Neutrality Suite (Cross-Platform dudect)...\n");
    fflush(stdout);

    uint64_t* class_a = malloc(NUM_SAMPLES * sizeof(uint64_t));
    uint64_t* class_b = malloc(NUM_SAMPLES * sizeof(uint64_t));
    assert(class_a && class_b);

    uint8_t buf_fixed[64] __attribute__((aligned(64)));
    uint8_t buf_rand[64] __attribute__((aligned(64)));
    uint8_t key[32] __attribute__((aligned(64)));
    uint8_t out[64] __attribute__((aligned(64)));

    for (int k = 0; k < 64; k++) buf_fixed[k] = (uint8_t)((k * 37 + 11) & 0xFF);
    for (int k = 0; k < 32; k++) key[k] = (uint8_t)((k * 19 + 5) & 0xFF);

    size_t count_a = 0, count_b = 0;

    for (int i = 0; i < 2000; i++) {
        nona_phase1_blind(buf_fixed, 64, 2, key, out, 64);
    }

    for (size_t i = 0; i < NUM_SAMPLES; i++) {
        uint8_t choice = (uint8_t)(next_u64() & 1);

        if (choice) {
            for (int k = 0; k < 64; k++) buf_rand[k] = (uint8_t)(next_u64() & 0xFF);
        }

        const uint8_t* in_ptr = choice ? buf_rand : buf_fixed;

        uint64_t t0 = rdtsc_serialized();
        nona_phase1_blind(in_ptr, 64, 2, key, out, 64);
        uint64_t t1 = rdtsc_serialized();

        uint64_t delta = t1 - t0;

        if (choice) {
            class_b[count_b++] = delta;
        } else {
            class_a[count_a++] = delta;
        }
    }

    count_a = filter_outliers(class_a, count_a);
    count_b = filter_outliers(class_b, count_b);

    double mean_a = 0, mean_b = 0;
    double t_nona = compute_t_statistic(class_a, count_a, class_b, count_b, &mean_a, &mean_b);

    printf("[+] Sample Counts -> Class A (Fixed): %zu | Class B (Random): %zu\n", count_a, count_b);
    printf("[+] Mean Ticks    -> Class A: %.2f | Class B: %.2f (Delta: %.2f)\n", mean_a, mean_b, fabs(mean_a - mean_b));
    printf("[+] Welch's t-statistic: %.2f\n", t_nona);
    fflush(stdout);

    assert(fabs(t_nona) < 4.5);
    printf("[===] TIMING NEUTRALITY VERIFIED (|t| < 4.5 CONSTANT-TIME BOUND) [===]\n");

    free(class_a);
    free(class_b);
    return 0;
}
