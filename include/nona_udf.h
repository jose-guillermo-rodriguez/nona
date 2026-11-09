// Copyright (c) 2026 Nona Contributors.
// SPDX-License-Identifier: MIT OR Apache-2.0


// ============================================================================
// ============================================================================

#ifndef NONA_UDF_H
#define NONA_UDF_H

#include "nona.h"

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// UDF EXECUTION CONSTANTS & MEMORY BOUNDS
// ============================================================================
#define NONA_UDF_MAX_BATCH_ELEMENTS 32
#define NONA_UDF_ELEMENT_SIZE       32
#define NONA_UDF_MAX_BUFFER_BYTES   (NONA_UDF_MAX_BATCH_ELEMENTS * NONA_UDF_ELEMENT_SIZE)

// ============================================================================
// 64-BYTE ALIGNED UDF WORKER CONTEXT FRAME
// ============================================================================

/// Satisfies [FR-32-UDFLINK]
/// Thread-local worker scratchpad allocated on the host execution stack.
/// Bounded to 0 heap allocations, suitable for Snowflake, DuckDB, or ClickHouse threads.
NONA_ALIGNED_STRUCT(nona_udf_worker_ctx, 64) {
    uint8_t scratch_in[NONA_UDF_MAX_BUFFER_BYTES];
    uint8_t scratch_out[NONA_UDF_MAX_BUFFER_BYTES];
    uint8_t match_indices[NONA_UDF_MAX_BATCH_ELEMENTS * sizeof(uint32_t)];
    uint64_t payload_scratch[NONA_UDF_MAX_BATCH_ELEMENTS];
    uint64_t cardinality;
    uint64_t payload_sum;
    uint32_t active_elements;
    uint8_t _reserved[44];
};
typedef struct nona_udf_worker_ctx nona_udf_worker_ctx;
typedef struct nona_udf_worker_ctx nona_udf_worker_ctx_t;

/// Satisfies [FR-32-UDFLINK]
/// Initialize and sanitize thread-local worker context frame.
static inline nona_status_t nona_udf_worker_ctx_init(nona_udf_worker_ctx_t* ctx) {
    if (!ctx) {
        return NONA_ERR_NULL_POINTER;
    }
    if (((uintptr_t)ctx % 64) != 0) {
        return NONA_ERR_UNALIGNED_POINTER;
    }
    volatile uint8_t* p = (volatile uint8_t*)ctx;
    for (size_t i = 0; i < sizeof(nona_udf_worker_ctx_t); ++i) {
        p[i] = 0;
    }
    return NONA_OK;
}

/// Satisfies [FR-32-UDFLINK]
/// Satisfies [FR-05-RAMCLR]
/// Volatile decontamination of the worker context frame.
static inline void nona_udf_worker_ctx_purge(nona_udf_worker_ctx_t* ctx) {
    if (ctx) {
        volatile uint8_t* p = (volatile uint8_t*)ctx;
        for (size_t i = 0; i < sizeof(nona_udf_worker_ctx_t); ++i) {
            p[i] = 0;
        }
    }
}

// ============================================================================
// INLINE C-UDF EXECUTION ADAPTERS
// ============================================================================

/// Satisfies [FR-32-UDFLINK]
/// Satisfies [FR-12-PHASE1BLIND]
/// Vectorized Phase 1 blinding wrapper for database column vectors.
static inline nona_status_t nona_udf_blind_batch(
    const uint8_t* raw_in,
    size_t n_elements,
    const uint8_t* key_bytes,
    uint8_t* blinded_out
) {
    if (!raw_in || !key_bytes || !blinded_out) {
        return NONA_ERR_NULL_POINTER;
    }
    if ((((uintptr_t)raw_in | (uintptr_t)key_bytes | (uintptr_t)blinded_out) % 64) != 0) {
        return NONA_ERR_UNALIGNED_POINTER;
    }
    if (n_elements == 0 || n_elements > NONA_UDF_MAX_BATCH_ELEMENTS) {
        return NONA_ERR_INVALID_PARAM;
    }

    size_t byte_len = n_elements * NONA_UDF_ELEMENT_SIZE;
    int32_t ret = nona_phase1_blind(
        raw_in,
        byte_len,
        n_elements,
        key_bytes,
        blinded_out,
        byte_len
    );
    return (nona_status_t)ret;
}

/// Satisfies [FR-32-UDFLINK]
/// Satisfies [FR-13-PHASE2INT]
/// Vectorized Phase 2 intersection wrapper for database joins.
static inline nona_status_t nona_udf_intersect_batch(
    const uint8_t* blinded_a,
    size_t n_elements_a,
    const uint8_t* blinded_b,
    size_t n_elements_b,
    uint32_t flags,
    nona_udf_worker_ctx_t* ctx,
    uint64_t* out_cardinality
) {
    if (!blinded_a || !blinded_b || !ctx || !out_cardinality) {
        return NONA_ERR_NULL_POINTER;
    }
    if ((((uintptr_t)blinded_a | (uintptr_t)blinded_b | (uintptr_t)ctx) % 64) != 0 ||
        ((uintptr_t)out_cardinality % sizeof(uint64_t)) != 0) {
        return NONA_ERR_UNALIGNED_POINTER;
    }
    if (n_elements_a == 0 || n_elements_a > NONA_UDF_MAX_BATCH_ELEMENTS ||
        n_elements_b == 0 || n_elements_b > NONA_UDF_MAX_BATCH_ELEMENTS) {
        return NONA_ERR_INVALID_PARAM;
    }

    size_t len_a = n_elements_a * NONA_UDF_ELEMENT_SIZE;
    size_t len_b = n_elements_b * NONA_UDF_ELEMENT_SIZE;
    size_t out_capacity = n_elements_a * sizeof(uint32_t);

    int32_t ret = nona_phase2_intersect(
        blinded_a,
        len_a,
        blinded_b,
        len_b,
        n_elements_a,
        ctx->match_indices,
        out_capacity,
        flags,
        &ctx->cardinality
    );

    *out_cardinality = ctx->cardinality;
    return (nona_status_t)ret;
}

/// Satisfies [FR-32-UDFLINK]
/// Satisfies [FR-29-PSIPR]
/// Vectorized Phase 2 Payload Retrieval (PSI-PR) and Aggregation wrapper.
static inline nona_status_t nona_udf_intersect_payload_batch(
    const uint8_t* blinded_a,
    size_t n_elements_a,
    const uint8_t* blinded_b,
    size_t n_elements_b,
    const uint64_t* payloads_b,
    uint32_t flags,
    nona_udf_worker_ctx_t* ctx,
    uint64_t* out_cardinality,
    uint64_t* out_sum
) {
    if (!blinded_a || !blinded_b || !ctx || !out_cardinality) {
        return NONA_ERR_NULL_POINTER;
    }
    if ((((uintptr_t)blinded_a | (uintptr_t)blinded_b | (uintptr_t)ctx | (uintptr_t)out_cardinality) % 64) != 0) {
        return NONA_ERR_UNALIGNED_POINTER;
    }
    if (n_elements_a == 0 || n_elements_a > NONA_UDF_MAX_BATCH_ELEMENTS ||
        n_elements_b == 0 || n_elements_b > NONA_UDF_MAX_BATCH_ELEMENTS) {
        return NONA_ERR_INVALID_PARAM;
    }

    size_t len_a = n_elements_a * NONA_UDF_ELEMENT_SIZE;
    size_t len_b = n_elements_b * NONA_UDF_ELEMENT_SIZE;
    size_t out_capacity = n_elements_a * sizeof(uint32_t);

    int32_t ret = nona_phase2_intersect_payload(
        blinded_a,
        len_a,
        blinded_b,
        len_b,
        payloads_b,
        n_elements_a,
        ctx->match_indices,
        ctx->payload_scratch,
        out_capacity,
        flags,
        &ctx->cardinality,
        &ctx->payload_sum
    );

    *out_cardinality = ctx->cardinality;
    if (out_sum) {
        *out_sum = ctx->payload_sum;
    }
    return (nona_status_t)ret;
}

#ifdef __cplusplus
}
#endif

// ============================================================================
// ZERO-HEAP CHUNKED STREAMING ITERATOR (FR-34)
// ============================================================================
#define NONA_UDF_STREAM_CHUNK_ELEMENTS 32
#define NONA_UDF_STREAM_CHUNK_BYTES    (NONA_UDF_STREAM_CHUNK_ELEMENTS * NONA_UDF_ELEMENT_SIZE)

NONA_ALIGNED_STRUCT(nona_udf_chunk_iter, 64) {
    uint8_t   chunk_data[NONA_UDF_STREAM_CHUNK_BYTES];
    uint64_t  current_chunk_idx;
    uint64_t  total_elements_processed;
    uint32_t  elements_in_chunk;
    uint32_t  is_last_chunk;
    uint8_t   reserved[48];
};
typedef struct nona_udf_chunk_iter nona_udf_chunk_iter;
typedef struct nona_udf_chunk_iter nona_udf_chunk_iter_t;

#ifdef __cplusplus
}
#endif

#endif // NONA_UDF_H
