// Copyright (c) 2026 Nona Contributors.
// Licensed under the Apache License, Version 2.0 or the MIT License.
// ============================================================================
// ============================================================================

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "nona.h"
#include "nona_udf.h"

int main(void) {
    printf("[*] Executing Database C-UDF Linkage & Stack Allocation Suite...\n");

    int32_t init_rc = nona_core_init();
    assert(init_rc <= 0);

    size_t ctx_size = sizeof(nona_udf_worker_ctx_t);
    printf("    [+] sizeof(nona_udf_worker_ctx_t) = %zu bytes (Ceiling: 2560 bytes)\n", ctx_size);
    assert(ctx_size < 2560);
    printf("  [+] Stack ceiling verified: sizeof(nona_udf_worker_ctx_t) < 2560 bytes.\n");

    nona_udf_worker_ctx_t ctx NONA_ALIGN(64);
    assert(((uintptr_t)&ctx % 64) == 0);

    nona_status_t status = nona_udf_worker_ctx_init(&ctx);
    assert(status == NONA_OK);
    assert(ctx.active_elements == 0);

    uint8_t raw_in[32 * 4] NONA_ALIGN(64);
    uint8_t key[32] NONA_ALIGN(64);
    uint8_t blinded_out[32 * 4] NONA_ALIGN(64);
    memset(raw_in, 0x42, sizeof(raw_in));
    memset(key, 0x07, sizeof(key));

    status = nona_udf_blind_batch(raw_in, 4, key, blinded_out);
    assert(status == NONA_OK);

    nona_udf_worker_ctx_purge(&ctx);
    for (size_t i = 0; i < sizeof(nona_udf_worker_ctx_t); i++) {
        assert(((volatile uint8_t*)&ctx)[i] == 0);
    }
    printf("  [+] Volatile frame purge verified: 100%% of context bytes zeroed.\n");

    printf("[===] DATABASE C-UDF LINKAGE SUITE PASSED [===]\n");
    return 0;
}
