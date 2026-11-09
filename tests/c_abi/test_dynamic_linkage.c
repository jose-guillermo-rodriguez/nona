#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <dlfcn.h>
#include <string.h>

#include "nona.h"
#include "nona_udf.h"

#define LOAD_SYMBOL(handle, var, sym_name) \
    var = dlsym(handle, sym_name); \
    if (!var) { \
        fprintf(stderr, "[ABI FAILURE] Missing export: %s: %s\n", sym_name, dlerror()); \
        exit(1); \
    }

typedef int32_t (*nona_core_init_fn)(void);
typedef int32_t (*nona_phase1_blind_fn)(const uint8_t*, size_t, size_t, const uint8_t*, uint8_t*, size_t);
typedef int32_t (*nona_phase2_intersect_payload_fn)(
    const uint8_t*, size_t, const uint8_t*, size_t, const uint64_t*, size_t,
    uint8_t*, uint64_t*, size_t, uint32_t, uint64_t*, uint64_t*
);

int main(int argc, char** argv) {
    const char* lib_path = (argc > 1) ? argv[1] : "target/release/libnona_core.dylib";
    
    printf("[GATE 1] Loading dynamic library: %s\n", lib_path);
    void* handle = dlopen(lib_path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        fprintf(stderr, "[GATE 1 FATAL] dlopen failed: %s\n", dlerror());
        return 1;
    }

    nona_core_init_fn nona_core_init;
    nona_phase1_blind_fn nona_phase1_blind;
    nona_phase2_intersect_payload_fn nona_phase2_intersect_payload;

    LOAD_SYMBOL(handle, nona_core_init, "nona_core_init");
    LOAD_SYMBOL(handle, nona_phase1_blind, "nona_phase1_blind");
    LOAD_SYMBOL(handle, nona_phase2_intersect_payload, "nona_phase2_intersect_payload");
    printf("  ✓ Dynamic export resolution passed (#[no_mangle] verified)\n");

    uint8_t dummy_token[64] __attribute__((aligned(64))) = {0};
    uint64_t dummy_payload[2] __attribute__((aligned(64))) = {0};
    uint8_t stack_indices[64] __attribute__((aligned(64))) = {0};
    uint64_t stack_payloads[16] __attribute__((aligned(64))) = {0};

    // Natural 8-byte scalar alignment on C stack (exercising alignment gate)
    uint64_t stack_cardinality = 0;
    uint64_t stack_payload_sum = 0;

    uintptr_t addr = (uintptr_t)&stack_cardinality;
    printf("  Stack scalar pointer: 0x%lx (modulo 64: %lu, modulo 8: %lu)\n", 
           addr, addr % 64, addr % sizeof(uint64_t));

    int32_t status = nona_phase2_intersect_payload(
        dummy_token, 64, dummy_token, 64, dummy_payload, 0,
        stack_indices, stack_payloads, 16, 0,
        &stack_cardinality, &stack_payload_sum
    );

    if (status == NONA_ERR_UNALIGNED_POINTER) {
        fprintf(stderr, "[GATE 1 DEFECT] Function rejected natural 8-byte aligned scalar pointer!\n");
        dlclose(handle);
        return 2;
    }

    printf("  ✓ Scalar alignment acceptance passed (Status: %d)\n", status);
    dlclose(handle);
    return 0;
}
