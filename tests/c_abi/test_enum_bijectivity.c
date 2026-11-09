#include "nona.h"

// If duplicate error codes exist, clang/gcc fails with: "error: duplicate case value"
// If variants are unhandled, -Werror,-Wswitch fails with: "error: enumeration values not handled"
void verify_enum_uniqueness(nona_status_t code) {
    switch (code) {
        case NONA_OK: break;
        case NONA_ERR_NULL_POINTER: break;
        case NONA_ERR_UNALIGNED_POINTER: break;
        case NONA_ERR_LENGTH_BOUND_VIOLATION: break;
        case NONA_ERR_LOCK_BUSY: break;
        case NONA_ERR_BUFFER_ALIASING: break;
        case NONA_ERR_INVALID_FLAGS: break;
        case NONA_ERR_POINTER_WRAPAROUND: break;
        case NONA_ERR_OUT_OF_MEMORY: break;
        case NONA_ERR_STACK_CEILING_EXCEEDED: break;
        case NONA_ERR_ELEMENT_COUNT_BOUND_VIOLATION: break;
        case NONA_ERR_STACK_OVERFLOW: break;
        case NONA_ERR_INVALID_PARAM: break;
        case NONA_ERR_INVALID_CURVE_POINT: break;
        case NONA_ERR_INTERNAL_PANIC: break;
    }
}

int main(void) {
    return 0;
}
