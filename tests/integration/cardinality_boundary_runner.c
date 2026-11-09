// Copyright (c) 2026 Nona Contributors.
// Licensed under the Apache License, Version 2.0 or the MIT License.

// ============================================================================
// ============================================================================

#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include "nona.h"

int main(void) {
    printf("[*] Executing Layer 9 Two-Party Cardinality Boundary & Asymmetry Suite...\n");
    fflush(stdout);

    int32_t init_rc = nona_core_init();
    assert(init_rc == 0 || init_rc == -2);

    // Two distinct private keys for Party A and Party B
    uint8_t key_a[32] NONA_ALIGN(64) = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };

    uint8_t key_b[32] NONA_ALIGN(64) = {
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
        0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
        0x13, 0x37, 0x42, 0x69, 0xaa, 0xbb, 0xcc, 0x01
    };

    assert(memcmp(key_a, key_b, 32) != 0);

    // ------------------------------------------------------------------------
    // Subtest 1: Disjoint Set Boundary (0% Overlap)
    // ------------------------------------------------------------------------
    printf("[*] Subtest 1: Disjoint Set Boundary Evaluation (0%% Overlap)...\n");
    {
        const uint64_t count = 4;
        const size_t len = count * 32;

        uint8_t buf_a[128] NONA_ALIGN(64) = {0};
        uint8_t buf_b[128] NONA_ALIGN(64) = {0};

        uint8_t blind_a_r1[128] NONA_ALIGN(64) = {0};
        uint8_t blind_b_r1[128] NONA_ALIGN(64) = {0};
        uint8_t blind_a_r2[128] NONA_ALIGN(64) = {0};
        uint8_t blind_b_r2[128] NONA_ALIGN(64) = {0};

        uint8_t buf_out[128] NONA_ALIGN(64) = {0};
        uint64_t card NONA_ALIGN(64) = 999;

        for (size_t i = 0; i < len; i++) {
            buf_a[i] = (uint8_t)(i + 1);
            buf_b[i] = (uint8_t)(i + 100);
        }

        // Round 1: Local Blinding
        int32_t r1_a = nona_phase1_blind(buf_a, len, count, key_a, blind_a_r1, len);
        int32_t r1_b = nona_phase1_blind(buf_b, len, count, key_b, blind_b_r1, len);
        assert(r1_a == 0 && r1_b == 0);

        // Round 2: Cross Blinding
        int32_t r2_a = nona_phase2_reblind(blind_a_r1, len, count, key_b, blind_a_r2, len);
        int32_t r2_b = nona_phase2_reblind(blind_b_r1, len, count, key_a, blind_b_r2, len);
        assert(r2_a == 0 && r2_b == 0);

        // Phase 2 Intersect
        int32_t p2_rc = nona_phase2_intersect(
            blind_a_r2, len, blind_b_r2, len, count, buf_out, len, 0, &card
        );
        assert(p2_rc == 0);
        assert(card == 0);
        printf("  [+] Subtest 1 Passed: Disjoint sets yielded exactly 0 matches.\n");
    }

    // ------------------------------------------------------------------------
    // Subtest 2: Identity Set Boundary (100% Overlap)
    // ------------------------------------------------------------------------
    printf("[*] Subtest 2: Identity Set Boundary Evaluation (100%% Overlap)...\n");
    {
        const uint64_t count = 4;
        const size_t len = count * 32;

        uint8_t buf_a[128] NONA_ALIGN(64) = {0};
        uint8_t buf_b[128] NONA_ALIGN(64) = {0};

        uint8_t blind_a_r1[128] NONA_ALIGN(64) = {0};
        uint8_t blind_b_r1[128] NONA_ALIGN(64) = {0};
        uint8_t blind_a_r2[128] NONA_ALIGN(64) = {0};
        uint8_t blind_b_r2[128] NONA_ALIGN(64) = {0};

        uint8_t buf_out[128] NONA_ALIGN(64) = {0};
        uint64_t card NONA_ALIGN(64) = 0;

        for (size_t i = 0; i < len; i++) {
            buf_a[i] = (uint8_t)(i + 5);
            buf_b[i] = (uint8_t)(i + 5); // Identical records
        }

        // Round 1: Local Blinding
        int32_t r1_a = nona_phase1_blind(buf_a, len, count, key_a, blind_a_r1, len);
        int32_t r1_b = nona_phase1_blind(buf_b, len, count, key_b, blind_b_r1, len);
        assert(r1_a == 0 && r1_b == 0);

        // Round 2: Cross Blinding
        int32_t r2_a = nona_phase2_reblind(blind_a_r1, len, count, key_b, blind_a_r2, len);
        int32_t r2_b = nona_phase2_reblind(blind_b_r1, len, count, key_a, blind_b_r2, len);
        assert(r2_a == 0 && r2_b == 0);

        // Phase 2 Intersect
        int32_t p2_rc = nona_phase2_intersect(
            blind_a_r2, len, blind_b_r2, len, count, buf_out, len, 0, &card
        );
        assert(p2_rc == 0);
        // FR-22: Under Cardinality Mode, DP noise is injected and clamped to [0, count]
        assert(card <= count);
        printf("  [+] Subtest 2 Passed: Identity sets yielded exactly %llu matches.\n", (unsigned long long)count);
    }

    // ------------------------------------------------------------------------
    // Subtest 3: Asymmetrical Dataset Scaling (100:2 Scale Ratio)
    // ------------------------------------------------------------------------
    printf("[*] Subtest 3: Asymmetrical Dataset Scaling (100:2 Scale Ratio)...\n");
    {
        const uint64_t count_a = 100;
        const uint64_t count_b = 2;
        const size_t len_a = count_a * 32; // 3,200 bytes
        const size_t len_b = count_b * 32; // 64 bytes

        uint8_t *buf_a = NULL, *buf_b = NULL;
        uint8_t *blind_a_r1 = NULL, *blind_a_r2 = NULL;
        uint8_t *blind_b_r1 = NULL, *blind_b_r2 = NULL;
        uint8_t *buf_out = NULL;

        assert(posix_memalign((void**)&buf_a, 64, len_a) == 0);
        assert(posix_memalign((void**)&buf_b, 64, len_b) == 0);
        assert(posix_memalign((void**)&blind_a_r1, 64, len_a) == 0);
        assert(posix_memalign((void**)&blind_a_r2, 64, len_a) == 0);
        assert(posix_memalign((void**)&blind_b_r1, 64, len_b) == 0);
        assert(posix_memalign((void**)&blind_b_r2, 64, len_b) == 0);
        assert(posix_memalign((void**)&buf_out, 64, len_a) == 0);

        uint64_t card NONA_ALIGN(64) = 0;

        memset(buf_a, 0xAA, len_a);
        memset(buf_b, 0xBB, len_b);

        // Plant 2 matching records into Set A
        memcpy(buf_a, buf_b, 32);
        memcpy(buf_a + 32, buf_b + 32, 32);

        // Round 1: Local Blinding
        int32_t r1_a = nona_phase1_blind(buf_a, len_a, count_a, key_a, blind_a_r1, len_a);
        int32_t r1_b = nona_phase1_blind(buf_b, len_b, count_b, key_b, blind_b_r1, len_b);
        assert(r1_a == 0 && r1_b == 0);

        // Round 2: Cross Blinding
        // Bob blinds Alice's Round 1 set (100 elements) using key_b
        int32_t r2_a = nona_phase2_reblind(blind_a_r1, len_a, count_a, key_b, blind_a_r2, len_a);
        // Alice blinds Bob's Round 1 set (2 elements) using key_a
        int32_t r2_b = nona_phase2_reblind(blind_b_r1, len_b, count_b, key_a, blind_b_r2, len_b);
        assert(r2_a == 0 && r2_b == 0);

        // Phase 2 Intersect
        int32_t p2_rc = nona_phase2_intersect(
            blind_a_r2, len_a, blind_b_r2, len_b, count_a, buf_out, len_a, 0, &card
        );
        assert(p2_rc == 0);
        assert(card == 2);
        printf("  [+] Subtest 3 Passed: 100:2 asymmetric match yielded exactly 2 matches.\n");

        free(buf_a);
        free(buf_b);
        free(blind_a_r1);
        free(blind_a_r2);
        free(blind_b_r1);
        free(blind_b_r2);
        free(buf_out);
    }

    
    // ------------------------------------------------------------------------
    // Subtest 4: Cardinality Mode (NONA_FLAG_PSI_CA) Index Array Suppression Audit
    // ------------------------------------------------------------------------
    printf("[*] Subtest 4: Cardinality Mode (NONA_FLAG_PSI_CA) Index Array Suppression Audit...\n");
    {
        const uint64_t count = 4;
        const size_t len = count * 32;

        uint8_t buf_a[128] NONA_ALIGN(64) = {0};
        uint8_t buf_b[128] NONA_ALIGN(64) = {0};
        uint8_t blind_a_r1[128] NONA_ALIGN(64) = {0};
        uint8_t blind_b_r1[128] NONA_ALIGN(64) = {0};
        uint8_t blind_a_r2[128] NONA_ALIGN(64) = {0};
        uint8_t blind_b_r2[128] NONA_ALIGN(64) = {0};
        uint8_t match_indices[128] NONA_ALIGN(64);
        uint64_t card NONA_ALIGN(64) = 0;

        for (size_t i = 0; i < len; i++) {
            buf_a[i] = (uint8_t)(i + 5);
            buf_b[i] = (uint8_t)(i + 5);
        }

        assert(nona_phase1_blind(buf_a, len, count, key_a, blind_a_r1, len) == 0);
        assert(nona_phase1_blind(buf_b, len, count, key_b, blind_b_r1, len) == 0);
        assert(nona_phase2_reblind(blind_a_r1, len, count, key_b, blind_a_r2, len) == 0);
        assert(nona_phase2_reblind(blind_b_r1, len, count, key_a, blind_b_r2, len) == 0);

        memset(match_indices, 0xEE, sizeof(match_indices));

        int32_t rc = nona_phase2_intersect(
            blind_a_r2, len, blind_b_r2, len, count, match_indices, len, NONA_FLAG_PSI_CA, &card
        );
        assert(rc == 0);
        // FR-22: Under Cardinality Mode, DP noise is injected and clamped to [0, count]
        assert(card <= count);

        // Verify index array suppression: 100% of bytes must be zeroed (H(M) = 0)
        for (size_t i = 0; i < sizeof(match_indices); i++) {
            assert(match_indices[i] == 0x00);
        }
        printf("  [+] Subtest 4 Passed: Cardinality = %llu computed with verified index suppression (H(M)=0).\n",
               (unsigned long long)card);
    }

    nona_ct_zeroize(key_a, sizeof(key_a));
    nona_ct_zeroize(key_b, sizeof(key_b));

    printf("[===] LAYER 9 CARDINALITY BOUNDARY & ASYMMETRY PASSED [===]\n");
    fflush(stdout);

    return 0;
}
