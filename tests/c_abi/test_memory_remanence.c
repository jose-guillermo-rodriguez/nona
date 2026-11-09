#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "nona.h"
#include "nona_udf.h"

int main(void) {
    printf("[GATE 4] Running Memory Remanence Post-Purge Canary Assertion...\n");

    uint8_t raw_buffer[sizeof(nona_udf_worker_ctx_t) + 128];
    memset(raw_buffer, 0xA5, sizeof(raw_buffer));

    uintptr_t unaligned_addr = ((uintptr_t)raw_buffer + 64) & ~63;
    unaligned_addr += 8;
    nona_udf_worker_ctx_t* ctx = (nona_udf_worker_ctx_t*)unaligned_addr;

    assert(((uintptr_t)ctx % 64) != 0);

    nona_udf_worker_ctx_purge(ctx);

    const uint8_t* p = (const uint8_t*)ctx;
    size_t leak_count = 0;
    for (size_t i = 0; i < sizeof(nona_udf_worker_ctx_t); ++i) {
        if (p[i] != 0x00) {
            leak_count++;
        }
    }

    if (leak_count > 0) {
        fprintf(stderr, "[GATE 4 DEFECT] %zu bytes remained unzeroized after purge!\n", leak_count);
        return 1;
    }

    printf("  ✓ Memory scrub unconditionally zeroized all context bytes\n");
    return 0;
}
