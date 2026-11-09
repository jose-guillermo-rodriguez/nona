// Copyright (c) 2026 Jose Guillermo Rodriguez <jose-guillermo-rodriguez@users.noreply.github.com>
// SPDX-License-Identifier: MIT OR Apache-2.0

// ============================================================================
// PROJECT: Nona Core Engine
// MODULE: remanence_runner.c - Volatile Memory Remanence Audit (H(R)=0)
// ============================================================================

#include "nona.h"
#include "nona_udf.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#define CANARY_BYTE_A 0xA5
#define CANARY_BYTE_B 0x5A
#define TEST_BUFFER_SIZE 128

int main(void) {
    printf("[*] Executing Memory Remanence & Volatile Decontamination Audit ($H(R)=0$)...\n");

    // ------------------------------------------------------------------------
    // SUB-TEST 1: Core Engine nona_ct_zeroize & DCE Resistance
    // ------------------------------------------------------------------------
    printf("  [1/2] Verifying engine nona_ct_zeroize volatile wipe...\n");

    uint8_t buffer[TEST_BUFFER_SIZE] __attribute__((aligned(64)));
    volatile uint8_t* v_buf = (volatile uint8_t*)buffer;

    // Populate with canary
    for (size_t i = 0; i < TEST_BUFFER_SIZE; ++i) {
        v_buf[i] = CANARY_BYTE_A;
    }

    // Verify negative control (canary confirmed in place)
    assert(v_buf[0] == CANARY_BYTE_A);
    assert(v_buf[TEST_BUFFER_SIZE - 1] == CANARY_BYTE_A);

    // Invoke actual engine C-ABI volatile zeroize routine
    int32_t ret = nona_ct_zeroize(buffer, TEST_BUFFER_SIZE);
    assert(ret == NONA_OK);

    // Read back via volatile pointer to prevent dead-code elimination (DCE)
    volatile uint8_t residual_a = 0;
    for (size_t i = 0; i < TEST_BUFFER_SIZE; ++i) {
        residual_a |= v_buf[i];
    }
    assert(residual_a == 0);

    // Boundary check: Null pointer handling
    int32_t null_ret = nona_ct_zeroize(NULL, TEST_BUFFER_SIZE);
    assert(null_ret == NONA_ERR_NULL_POINTER);

    printf("  [+] Core engine nona_ct_zeroize passed (entropy residual = 0).\n");

    // ------------------------------------------------------------------------
    // SUB-TEST 2: Database C-UDF Worker Context Frame Purge
    // ------------------------------------------------------------------------
    printf("  [2/2] Verifying nona_udf_worker_ctx_purge decontamination...\n");

    nona_udf_worker_ctx_t ctx __attribute__((aligned(64)));
    volatile uint8_t* v_ctx = (volatile uint8_t*)&ctx;

    // Fill entire context frame with canary pattern
    for (size_t i = 0; i < sizeof(nona_udf_worker_ctx_t); ++i) {
        v_ctx[i] = CANARY_BYTE_B;
    }

    // Confirm pre-purge canary
    assert(v_ctx[0] == CANARY_BYTE_B);
    assert(v_ctx[sizeof(nona_udf_worker_ctx_t) - 1] == CANARY_BYTE_B);

    // Invoke substrate database worker context purge
    nona_udf_worker_ctx_purge(&ctx);

    // Verify complete volatile entropy collapse across entire struct
    volatile uint8_t residual_b = 0;
    for (size_t i = 0; i < sizeof(nona_udf_worker_ctx_t); ++i) {
        residual_b |= v_ctx[i];
    }
    assert(residual_b == 0);
    assert(ctx.cardinality == 0);
    assert(ctx.payload_sum == 0);

    printf("  [+] Database C-UDF frame purged cleanly (%zu bytes decontaminated).\n",
           sizeof(nona_udf_worker_ctx_t));

    printf("[===] MEMORY REMANENCE VERIFIED ($H(R)=0$ ENTROPY COLLAPSE) [===]\n");
    return 0;
}
