// Copyright (c) 2026 Nona Contributors.
// Licensed under the Apache License, Version 2.0 or the MIT License.

// ============================================================================
// PROJECT: Nona Core Engine
// MODULE: c_runner.c - C-ABI Contract Permutations & Integration Runner
// ============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include "nona.h"

int main() {
    printf("[*] Executing HACVS-V2 Complete C-ABI Contract Permutation Suite...\n");

    uint8_t buf_a[64] __attribute__((aligned(64))) = {0};
    uint8_t buf_b[64] __attribute__((aligned(64))) = {0};
    uint8_t buf_out[64] __attribute__((aligned(64))) = {0};
    uint64_t payloads_b[2] __attribute__((aligned(64))) = {0};
    uint64_t payloads_out[2] __attribute__((aligned(64))) = {0};
    SanitizedCode code_out __attribute__((aligned(64)));
    ExceptionControlBlock ecb __attribute__((aligned(64))) = {0};
    uint64_t perm_idx = 0;
    uint64_t valid_card __attribute__((aligned(64))) = 0;

    // --- 1. Phase 1 & Phase 2 PSI Entry Points ---
    assert(nona_phase1_blind(buf_a, 64, 2, NULL, buf_out, 64) == NONA_ERR_NULL_POINTER);
    assert(nona_phase1_blind(buf_a, 64, 2, buf_b, buf_out + 1, 64) == NONA_ERR_UNALIGNED_POINTER);
    assert(nona_phase2_reblind(buf_a, 64, 2, NULL, buf_out, 64) == NONA_ERR_NULL_POINTER);
    assert(nona_phase2_reblind(buf_a, 64, 2, buf_b, buf_out + 1, 64) == NONA_ERR_UNALIGNED_POINTER);
    assert(nona_phase2_reblind(buf_a, 64, 2, buf_b, buf_a, 64) == NONA_ERR_BUFFER_ALIASING);
    assert(nona_phase2_reblind(buf_a, 64, 2, buf_b, buf_out, 64) == NONA_ERR_INVALID_CURVE_POINT);
    assert(nona_phase2_intersect(buf_a, 64, buf_b, 64, 2, buf_out, 64, 0, NULL) == NONA_ERR_NULL_POINTER);
    assert(nona_phase2_intersect(buf_a, 64, buf_b, 64, 2, buf_a, 64, 0, &valid_card) == NONA_ERR_BUFFER_ALIASING);
    assert(nona_phase2_intersect(buf_a, 64, buf_b, 64, 2, buf_out, 64, 0xDEADBEEF, &valid_card) == NONA_ERR_INVALID_FLAGS);
    assert(nona_phase2_intersect_payload(buf_a, 64, buf_b, 64, payloads_b, 2, buf_out, payloads_out, 64, 0x00000002, NULL, &valid_card) == NONA_ERR_NULL_POINTER);

    // --- 2. Adaptive VOLE Route Circuit ---
    assert(nona_adaptive_psi_route(100, 100, NULL) == NONA_ERR_NULL_POINTER);

    // --- 3. Stream Ingestion Perimeter ---
    assert(nona_ingest_stream(NULL, 128) == NONA_ERR_NULL_POINTER);
    assert(nona_ingest_stream(buf_a + 1, 128) == NONA_ERR_UNALIGNED_POINTER);
    assert(nona_ingest_stream(buf_a, 127) == NONA_ERR_LENGTH_BOUND_VIOLATION); // Must be multiple of 128
    assert(nona_ingest_stream(buf_a, 4224) == NONA_ERR_LENGTH_BOUND_VIOLATION); // > 4096 ceiling

    // --- 4. Normalization & Obfuscation ---
    assert(nona_normalize_and_obfuscate(NULL, 64, 21, 1, &code_out, &perm_idx) == NONA_ERR_NULL_POINTER);
    assert(nona_normalize_and_obfuscate(buf_a, 64, 21, 1, NULL, &perm_idx) == NONA_ERR_NULL_POINTER);
    assert(nona_normalize_and_obfuscate(buf_a, 64, 21, 1, &code_out, NULL) == NONA_ERR_NULL_POINTER);
    // Unaligned raw input bytes are valid (alignment 1), but output struct MUST be 64-byte aligned
    assert(nona_normalize_and_obfuscate(buf_a, 64, 21, 1, (SanitizedCode*)(buf_out + 1), &perm_idx) == NONA_ERR_UNALIGNED_POINTER);

    // --- 5. Gatekeeper & Manifest Validation ---
    assert(nona_gatekeeper_validate(NULL, 64, 2, buf_b) == NONA_ERR_NULL_POINTER);
    assert(nona_gatekeeper_validate(buf_a, 64, 2, NULL) == NONA_ERR_NULL_POINTER);
    assert(nona_gatekeeper_validate(buf_a, 64, 2, buf_a) == NONA_ERR_BUFFER_ALIASING); // Overlapping hash buffer

    // --- 6. Exception Control Processor ---
    assert(nona_process_exception_step(NULL, 1, buf_out) == NONA_ERR_NULL_POINTER);
    assert(nona_process_exception_step(&ecb, 1, NULL) == NONA_ERR_NULL_POINTER);

    printf("[===] HACVS-V2 C-ABI CONTRACT PERMUTATION MATRIX: 100%% COMPLIANT [===]\n");
    return 0;
}
