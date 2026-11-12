// Copyright (c) 2026 Nona Contributors.
// Licensed under the Apache License, Version 2.0 or the MIT License.

// ============================================================================
// ============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <sys/wait.h>
#include "nona.h"

int main(void) {
    printf("[*] Executing Layer 8 End-to-End Two-Party DH-PSI Determinism Suite...\n");
    fflush(stdout);

    int32_t init_rc = nona_core_init();
    assert(init_rc == 0 || init_rc == -2);

    // Ground-Truth Record Sets (3 Matching Pairs, 1 Disjoint Pair)
    // Party A[0] contains \r\n to verify perimeter wire-protocol normalization
    const char* party_a_raw[] = {
        "john.doe@domain.com\r\n",
        "alice@secure-network.org",
        "+15550192831",
        "alpha_unique_record_a@test.com"
    };

    const char* party_b_raw[] = {
        "john.doe@domain.com",
        "alice@secure-network.org",
        "+15550192831",
        "beta_unique_record_b@test.com"
    };

    const uint64_t count_a = 4;
    const uint64_t count_b = 4;
    const uint64_t expected_cardinality = 3;

    const size_t buf_len_a = count_a * 32; // 128 bytes
    const size_t buf_len_b = count_b * 32; // 128 bytes

    uint8_t buf_a[128] NONA_ALIGN(64) = {0};
    uint8_t buf_b[128] NONA_ALIGN(64) = {0};

    // Round 1 Buffers: A' = X^(k_A), B' = Y^(k_B)
    uint8_t blind_a_r1[128] NONA_ALIGN(64) = {0};
    uint8_t blind_b_r1[128] NONA_ALIGN(64) = {0};

    // Round 2 Buffers: A'' = (A')^(k_B) = X^(k_A * k_B), B'' = (B')^(k_A) = Y^(k_B * k_A)
    uint8_t blind_a_r2[128] NONA_ALIGN(64) = {0};
    uint8_t blind_b_r2[128] NONA_ALIGN(64) = {0};

    uint8_t match_indices_out[128] NONA_ALIGN(64) = {0};

    // Two distinct private scalar keys (Alice: k_A, Bob: k_B where k_A != k_B)
    uint8_t key_a[32] NONA_ALIGN(64) = {
        0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
        0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x11
    };

    uint8_t key_b[32] NONA_ALIGN(64) = {
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
        0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x02
    };

    // Assert that the two parties hold distinct keys
    assert(memcmp(key_a, key_b, 32) != 0);

    uint64_t calculated_cardinality NONA_ALIGN(64) = 0;
    uint64_t perm_idx NONA_ALIGN(64) = 0;

    // ------------------------------------------------------------------------
    // Step 1: Perimeter Normalization
    // ------------------------------------------------------------------------
    for (uint64_t i = 0; i < count_a; i++) {
        uint8_t align_slot[64] NONA_ALIGN(64) = {0};
        size_t len = strlen(party_a_raw[i]);
        if (len > 64) len = 64;
        memcpy(align_slot, party_a_raw[i], len);

        SanitizedCode code_out NONA_ALIGN(64) = {0};
        int32_t norm_rc = nona_normalize_and_obfuscate(
            align_slot, 64, 32, 1, &code_out, &perm_idx
        );
        assert(norm_rc == 0);
        memcpy(buf_a + (i * 32), code_out.data, 32);
    }

    for (uint64_t i = 0; i < count_b; i++) {
        uint8_t align_slot[64] NONA_ALIGN(64) = {0};
        size_t len = strlen(party_b_raw[i]);
        if (len > 64) len = 64;
        memcpy(align_slot, party_b_raw[i], len);

        SanitizedCode code_out NONA_ALIGN(64) = {0};
        int32_t norm_rc = nona_normalize_and_obfuscate(
            align_slot, 64, 32, 1, &code_out, &perm_idx
        );
        assert(norm_rc == 0);
        memcpy(buf_b + (i * 32), code_out.data, 32);
    }

    // ------------------------------------------------------------------------
    // Step 2: Round 1 Local Blinding (Alice: A' = X^(k_A), Bob: B' = Y^(k_B))
    // ------------------------------------------------------------------------
    printf("  [*] Round 1: Alice blinds with k_A; Bob blinds with k_B...\n");
    int32_t r1_a_rc = nona_phase1_blind(buf_a, buf_len_a, count_a, key_a, blind_a_r1, buf_len_a);
    int32_t r1_b_rc = nona_phase1_blind(buf_b, buf_len_b, count_b, key_b, blind_b_r1, buf_len_b);
    assert(r1_a_rc == 0 && r1_b_rc == 0);

    // Negative Control: Premature intersection of A' and B' MUST yield 0 matches
    // because elements are blinded under independent scalars (k_A != k_B)
    uint64_t premature_card NONA_ALIGN(64) = 999;
    int32_t pre_rc = nona_phase2_intersect(
        blind_a_r1, buf_len_a,
        blind_b_r1, buf_len_b,
        count_a,
        match_indices_out, buf_len_a,
        0,
        &premature_card
    );
    assert(pre_rc == 0);
    assert(premature_card == 0);
    printf("  [+] Negative Control Verified: Round 1 tokens are cryptographically orthogonal (0 matches).\n");

    // ------------------------------------------------------------------------
    // Step 3: Round 2 Cross-Blinding Exchange (Commutative Exponentiation)
    //   Alice receives B' and computes B'' = (B')^(k_A) = Y^(k_B * k_A)
    //   Bob receives A' and computes A'' = (A')^(k_B) = X^(k_A * k_B)
    // ------------------------------------------------------------------------
    printf("  [*] Round 2: Alice cross-blinds B' with k_A; Bob cross-blinds A' with k_B...\n");
    int32_t r2_b_rc = nona_phase2_reblind(blind_b_r1, buf_len_b, count_b, key_a, blind_b_r2, buf_len_b);
    int32_t r2_a_rc = nona_phase2_reblind(blind_a_r1, buf_len_a, count_a, key_b, blind_a_r2, buf_len_a);
    assert(r2_b_rc == 0 && r2_a_rc == 0);

    // ------------------------------------------------------------------------
    // Step 4: Phase 2 Private Set Intersection on Doubly-Blinded Sets
    // ------------------------------------------------------------------------
    printf("  [*] Matching Phase: Intersecting A'' and B''...\n");
    int32_t p2_rc = nona_phase2_intersect(
        blind_a_r2, buf_len_a,
        blind_b_r2, buf_len_b,
        count_a,
        match_indices_out, buf_len_a,
        0, // NONA_FLAG_FULL_PSI
        &calculated_cardinality
    );

    printf("  [*] Phase 2 Intersect Return Code: %d\n", p2_rc);
    printf("  [*] Calculated Cardinality: %llu (Expected: %llu)\n",
           (unsigned long long)calculated_cardinality, (unsigned long long)expected_cardinality);
    fflush(stdout);

    assert(p2_rc == 0);
    assert(calculated_cardinality == expected_cardinality);

    // ------------------------------------------------------------------------
    // Step 5: Test Cardinality-Only Mode (NONA_FLAG_PSI_CA = 1)
    // ------------------------------------------------------------------------
    uint64_t ca_cardinality NONA_ALIGN(64) = 0;
    if (access("/dev/nsm", R_OK | W_OK) == 0) {
        int32_t ca_rc = nona_phase2_intersect(
            blind_a_r2, buf_len_a,
            blind_b_r2, buf_len_b,
            count_a,
            match_indices_out, buf_len_a,
            NONA_FLAG_PSI_CA,
            &ca_cardinality
        );
        assert(ca_rc == 0);
        assert(ca_cardinality <= count_a);
    } else {
        pid_t pid = fork();
        assert(pid >= 0);
        if (pid == 0) {
            (void)nona_phase2_intersect(
                blind_a_r2, buf_len_a,
                blind_b_r2, buf_len_b,
                count_a,
                match_indices_out, buf_len_a,
                NONA_FLAG_PSI_CA,
                &ca_cardinality
            );
            _exit(0);
        }
        int wstatus = 0;
        assert(waitpid(pid, &wstatus, 0) == pid);
        assert(WIFSIGNALED(wstatus) || (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) != 0));
    }

    // Secure key zeroization
    nona_ct_zeroize(key_a, sizeof(key_a));
    nona_ct_zeroize(key_b, sizeof(key_b));

    printf("[===] LAYER 8 END-TO-END TWO-PARTY DH-PSI PASSED (%llu/%llu MATCHES VERIFIED) [===]\n",
           (unsigned long long)calculated_cardinality, (unsigned long long)expected_cardinality);
    fflush(stdout);

    return 0;
}
