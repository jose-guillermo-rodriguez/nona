
#ifndef UNDEBUG_GUARD
#define UNDEBUG_GUARD
#ifdef NDEBUG
#error "[VACUOUS TEST DEFECT] NDEBUG is defined! C assertions would be compiled away to no-ops."
#endif
#endif

// ============================================================================
// ============================================================================

#ifndef NONA_TEST_HELPERS_H
#define NONA_TEST_HELPERS_H

#include <stdint.h>

static uint64_t g_prng_state = 0x123456789ABCDEF0ULL;

static inline void seed_prng(uint64_t seed) {
    g_prng_state = seed;
}

static inline uint64_t next_u64(void) {
    g_prng_state ^= (g_prng_state << 13);
    g_prng_state ^= (g_prng_state >> 7);
    g_prng_state ^= (g_prng_state << 17);
    return g_prng_state;
}

#endif // NONA_TEST_HELPERS_H
