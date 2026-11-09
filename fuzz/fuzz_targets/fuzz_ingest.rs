// Copyright (c) 2026 Nona Contributors.
// Licensed under the Apache License, Version 2.0 or the MIT License.

//! libFuzzer and Standalone Continuous Fuzzing Harness: Ingestion and Normalization
//!
//! Fuzzes normalize_to_buffer and zero-copy stream ingestion across arbitrary
//! mutated byte patterns, verifying panic-freedom, bounded outputs, and memory safety.

use nona_core::nona_ingest_stream;
use nona_core::normalization::normalize_to_buffer;

/// # Panics
/// Panics only if normalized output exceeds bounded scratch capacity.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
    if size == 0 {
        return 0;
    }
    let slice = unsafe { core::slice::from_raw_parts(data, size) };

    // Target A: normalize_to_buffer
    let mut out_buf = [0u8; 64];
    let test_slice = if size > 64 { &slice[..64] } else { slice };
    let rc = normalize_to_buffer(test_slice, &mut out_buf);
    if rc >= 0 {
        assert!(rc <= 64, "Normalized length must not exceed buffer size");
    }

    // Target B: nona_ingest_stream (requires 64-byte alignment and <= 4096 bytes)
    // Enforce Architectural Invariant §1: 4 KiB buffers must never touch the stack.
    #[repr(C, align(64))]
    struct AlignedStream {
        data: [u8; 4096],
    }
    struct StaticStream(core::cell::UnsafeCell<AlignedStream>);
    unsafe impl Sync for StaticStream {}
    static STREAM: StaticStream = StaticStream(core::cell::UnsafeCell::new(AlignedStream {
        data: [0u8; 4096],
    }));

    let aligned = unsafe { &mut *STREAM.0.get() };
    let ingest_len = size.min(4096);
    aligned.data[..ingest_len].copy_from_slice(&slice[..ingest_len]);

    unsafe {
        let _ = nona_ingest_stream(aligned.data.as_ptr(), ingest_len);
    }
    0
}

fn main() {
    println!("[*] Launching Ingestion and Normalization Mutational Fuzzing (100,000 cycles)...");

    let mut state: u64 = 0xda942042e4dd58b5;
    let mut next_u64 = || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545F4914F6CDD1D)
    };

    let mut corpus = vec![0u8; 4096];
    for cycle in 1..=100_000 {
        let size = (usize::try_from(next_u64()).unwrap_or(0) % corpus.len()).max(1);
        for chunk in corpus[..size].chunks_mut(8) {
            let rnd = next_u64().to_le_bytes();
            let copy_len = chunk.len().min(8);
            chunk[..copy_len].copy_from_slice(&rnd[..copy_len]);
        }

        LLVMFuzzerTestOneInput(corpus.as_ptr(), size);

        if cycle % 25_000 == 0 {
            println!("  [+] Ingestion harness completed {cycle} / 100,000 cycles (zero panics)");
        }
    }
    println!(
        "[*] Ingestion and Normalization continuous fuzzing PASSED (100,000/100,000 iterations)."
    );
}
