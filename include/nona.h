// Copyright (c) 2026 Nona Contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0


// ============================================================================
// ============================================================================

#ifndef NONA_H
#define NONA_H

#include <stdint.h>
#include <stddef.h>

#if defined(_MSC_VER)
#define NONA_ALIGN(x) __declspec(align(x))
#define NONA_ALIGNED_STRUCT(name, x) __declspec(align(x)) struct name
#elif defined(__GNUC__) || defined(__clang__)
#define NONA_ALIGN(x) __attribute__((aligned(x)))
#define NONA_ALIGNED_STRUCT(name, x) struct __attribute__((aligned(x))) name
#else
#error "Unsupported compiler: 64-byte structural alignment macro required."
#endif

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// CANONICAL STATUS CODES & FEATURE FLAGS
// ============================================================================
/// Satisfies [FR-24-PANICMATRIX]
/// Canonical C-ABI status codes for type-safe error reporting.
typedef enum nona_status_t {
    NONA_OK                         =  0,
    NONA_ERR_NULL_POINTER           = -1,
    NONA_ERR_UNALIGNED_POINTER      = -2,
    NONA_ERR_LENGTH_BOUND_VIOLATION = -3,
    NONA_ERR_LOCK_BUSY              = -4,
    NONA_ERR_BUFFER_ALIASING        = -5,
    NONA_ERR_INVALID_FLAGS          = -6,
    NONA_ERR_POINTER_WRAPAROUND     = -7,
    NONA_ERR_OUT_OF_MEMORY          = -8,
    NONA_ERR_STACK_CEILING_EXCEEDED = -9,
    NONA_ERR_ELEMENT_COUNT_BOUND_VIOLATION = -10,
    NONA_ERR_STACK_OVERFLOW         = -11,
    NONA_ERR_INVALID_PARAM          = -12,
    NONA_ERR_INVALID_CURVE_POINT    = -13,
    NONA_ERR_INTERNAL_PANIC         = -14
} nona_status_t;

#define NONA_SUCCESS NONA_OK

// ============================================================================
// CANONICAL EXECUTION FLAGS
// ============================================================================
#define NONA_FLAG_FULL_PSI  0x00000000
#define NONA_FLAG_PSI_CA    0x00000001
#define NONA_FLAG_PSI_PR    0x00000002
#define NONA_FLAG_PSI_SUM   0x00000004

// ============================================================================
// CORE C-ABI STRUCTURES
// ============================================================================

/// Satisfies [FR-06-PSIMALG]
/// Satisfies [FR-02-STKBUFF]
/// 256-Bit Prime Field Element (secp256k1 field / p = 2^256 - 2^32 - 977)
NONA_ALIGNED_STRUCT(FieldElement, 64) {
    uint64_t limbs[4];
};
typedef struct FieldElement FieldElement;

/// Satisfies [FR-06-PSIMALG]
/// Satisfies [FR-14-DISCSTATE]
/// Private Set Intersection (PSI) Circuit Context Frame
NONA_ALIGNED_STRUCT(PsiCircuitState, 64) {
    FieldElement base_value;
    FieldElement exponent;
    FieldElement accumulator;
};
typedef struct PsiCircuitState PsiCircuitState;

#ifndef offsetof
#define offsetof(T, m) __builtin_offsetof(T, m)
#endif

_Static_assert(sizeof(FieldElement) == 64, "FieldElement size must be 64 bytes");
_Static_assert(_Alignof(FieldElement) == 64, "FieldElement alignment must be 64 bytes");
_Static_assert(sizeof(PsiCircuitState) == 192, "PsiCircuitState size must be 192 bytes");
_Static_assert(_Alignof(PsiCircuitState) == 64, "PsiCircuitState alignment must be 64 bytes");
_Static_assert(offsetof(PsiCircuitState, base_value) == 0, "base_value offset must be 0");
_Static_assert(offsetof(PsiCircuitState, exponent) == 64, "exponent offset must be 64");
_Static_assert(offsetof(PsiCircuitState, accumulator) == 128, "accumulator offset must be 128");


/// Secure, 64-byte aligned wrapper structure for cryptographic verification
NONA_ALIGNED_STRUCT(GatekeeperScratchpad, 64) {
    uint8_t computed[32];
    uint8_t expected[32];
};
typedef struct GatekeeperScratchpad GatekeeperScratchpad;
typedef GatekeeperScratchpad nona_gatekeeper_scratchpad_t;

/// Satisfies [FR-01-NORMBYTE]
/// Satisfies [FR-02-STKBUFF]
/// 64-Byte Cache-Aligned Normalized Output Payload
NONA_ALIGNED_STRUCT(SanitizedCode, 64) {
    uint8_t data[64];
};
typedef struct SanitizedCode SanitizedCode;

/// Satisfies [FR-09-IDXOBFC]
/// Format-Preserving Feistel Index Permutation Circuit
NONA_ALIGNED_STRUCT(IndexPermutationCircuit, 64) {
    uint64_t a;
    uint64_t c;
};
typedef struct IndexPermutationCircuit IndexPermutationCircuit;

/// Satisfies [FR-20-ABRTGATE]
/// 64-Byte Cache-Aligned Exception Control Block
NONA_ALIGNED_STRUCT(ExceptionControlBlock, 64) {
    uint64_t g_total;
    uint64_t g_err;
    uint64_t w_total;
    uint64_t w_err;
    uint64_t c_write;
    uint64_t c_read;
    uint8_t _padding[16];
};
typedef struct ExceptionControlBlock ExceptionControlBlock;


// ============================================================================
// PUBLIC C-ABI FUNCTION EXPORTS
// ============================================================================

/// Structural initialization and system memory locking (mlockall / rlimit)
int32_t nona_core_init(void);

/// Single-stage PSI matching circuit evaluation
int32_t nona_core_process(PsiCircuitState* state);

/// Satisfies [FR-18-ZEROREM]
/// Constant-time memory zeroization preventing dead-code elimination (DCE).
int32_t nona_ct_zeroize(uint8_t* ptr, size_t len);

/// Phase 1 Asymmetric Blinding Entry Point (FR-14 / FR-19)
int32_t nona_phase1_blind(
    const uint8_t* raw_in,
    size_t in_len,
    size_t n_elements,
    const uint8_t* key_bytes,
    uint8_t* blinded_out,
    size_t out_len
);

/// Phase 2 Asymmetric Re-Blinding Entry Point (Round 2 Peer Blinding)
int32_t nona_phase2_reblind(
    const uint8_t* in_elements,
    size_t in_len,
    size_t n_elements,
    const uint8_t* key_bytes,
    uint8_t* blinded_out,
    size_t out_len
);

/// Phase 2 Asymmetric Intersect Entry Point (FR-14 / FR-19)
int32_t nona_phase2_intersect(
    const uint8_t* blinded_a,
    size_t len_a,
    const uint8_t* blinded_b,
    size_t len_b,
    size_t n_elements,
    uint8_t* match_indices_out,
    size_t out_capacity,
    uint32_t flags,
    uint64_t* cardinality_out
);

/// Adaptive Route Decision Circuit
int32_t nona_adaptive_psi_route(
    uint64_t n_elements,
    uint64_t m_elements,
    uint32_t* out_route_id
);

/// Phase 2 PSI-PR Payload Intersect Entry Point
int32_t nona_phase2_intersect_payload(
    const uint8_t* blinded_a,
    size_t len_a,
    const uint8_t* blinded_b,
    size_t len_b,
    const uint64_t* payloads_b,
    size_t n_elements,
    uint8_t* match_indices_out,
    uint64_t* payloads_out,
    size_t out_capacity,
    uint32_t flags,
    uint64_t* cardinality_out,
    uint64_t* sum_out
);

/// Zero-copy stream ingestion into N=128 ring manifold
int32_t nona_ingest_stream(const uint8_t* stream_ptr, size_t len);

/// Branchless parameter and bounds validation (FR-08-GATEKEEPR)
int32_t nona_gatekeeper_validate(
    const uint8_t* payload_ptr,
    size_t payload_len,
    size_t cardinality,
    const uint8_t* expected_hash
);

/// Polymorphic 64-byte byte normalization and Feistel permutation
int32_t nona_normalize_and_obfuscate(
    const uint8_t* input_ptr,
    size_t input_len,
    uint64_t a,
    uint64_t c,
    SanitizedCode* output_code,
    uint64_t* out_permuted_index
);

/// Standalone Feistel index permutation
int32_t nona_permute_index(
    const IndexPermutationCircuit* circuit_ptr,
    uint64_t index,
    uint64_t* permuted_index_ptr
);

/// Exception control step processor
int32_t nona_process_exception_step(
    ExceptionControlBlock* ecb,
    uint8_t e_i,
    uint8_t* window_buffer
);

/// Multi-buffer FFI boundary validation
int32_t nona_validate_ffi_bounds(
    const uint8_t* in_ptr,
    size_t in_len,
    size_t n_elements,
    const uint8_t* key_ptr,
    size_t key_len,
    uint8_t* out_ptr,
    size_t out_len,
    size_t expected_out_len
);

#ifdef __cplusplus
}
#endif

#endif // NONA_H

