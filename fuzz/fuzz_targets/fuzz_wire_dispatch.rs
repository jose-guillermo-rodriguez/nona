// Copyright (c) 2026 Nona Contributors.
// Licensed under the Apache License, Version 2.0 or the MIT License.

//! libFuzzer and Standalone Continuous Fuzzing Harness: Enclave Wire Dispatch
//!
//! Fuzzes dispatch_frame, EnclaveRequestHeader parsing, MTU boundaries,
//! command routing, and payload limits against malformed adversarial inputs.

use nona_core::enclave_server::{dispatch_frame, EnclaveRequestHeader};

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
/// # Panics
/// Does not panic; invalid headers return early with code 0.
pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
    let header_size = core::mem::size_of::<EnclaveRequestHeader>();
    if size < header_size {
        return 0;
    }

    let slice = unsafe { core::slice::from_raw_parts(data, size) };
    let header_bytes = &slice[..header_size];
    let payload = &slice[header_size..];

    let mut reserved = [0u8; 16];
    reserved.copy_from_slice(&header_bytes[16..32]);

    let header = EnclaveRequestHeader {
        magic: u32::from_le_bytes([
            header_bytes[0],
            header_bytes[1],
            header_bytes[2],
            header_bytes[3],
        ]),
        version: u16::from_le_bytes([header_bytes[4], header_bytes[5]]),
        command: u16::from_le_bytes([header_bytes[6], header_bytes[7]]),
        payload_len: u32::from_le_bytes([
            header_bytes[8],
            header_bytes[9],
            header_bytes[10],
            header_bytes[11],
        ]),
        flags: u32::from_le_bytes([
            header_bytes[12],
            header_bytes[13],
            header_bytes[14],
            header_bytes[15],
        ]),
        reserved,
    };

    let mut resp_payload = vec![0u8; 8192];
    let _ = dispatch_frame(&header, payload, &mut resp_payload);
    0
}

fn main() {
    println!("[*] Launching Wire Dispatch Mutational Fuzzing (100,000 cycles)...");

    let mut state: u64 = 0x853c49e6748fea9b;
    let mut next_u64 = || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545F4914F6CDD1D)
    };

    let mut corpus = vec![0u8; 4096];
    for cycle in 1..=100_000 {
        let size = (usize::try_from(next_u64()).unwrap_or(0) % corpus.len()).max(32);
        for chunk in corpus[..size].chunks_mut(8) {
            let rnd = next_u64().to_le_bytes();
            let copy_len = chunk.len().min(8);
            chunk[..copy_len].copy_from_slice(&rnd[..copy_len]);
        }

        LLVMFuzzerTestOneInput(corpus.as_ptr(), size);

        if cycle % 25_000 == 0 {
            println!(
                "  [+] Wire dispatch harness completed {cycle} / 100,000 cycles (zero panics)"
            );
        }
    }
    println!("[*] Wire Dispatch continuous fuzzing PASSED (100,000/100,000 iterations).");
}
