// Copyright (c) 2026 Nona Contributors.
// Licensed under the Apache License, Version 2.0 or the MIT License.

use nona_core::enclave_server::{dispatch_frame, EnclaveRequestHeader};
use nona_core::nona_ingest_stream;
use nona_core::normalization::normalize_to_buffer;

#[test]
fn test_fuzz_wire_dispatch_smoke() {
    let mut state: u64 = 0x853c49e6748fea9b;
    let mut next_u64 = || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545F4914F6CDD1D)
    };

    let header_size = core::mem::size_of::<EnclaveRequestHeader>();
    let mut buffer = [0u8; 1024];

    for _ in 0..2_000 {
        for chunk in buffer.chunks_mut(8) {
            let rnd = next_u64().to_le_bytes();
            let len = chunk.len().min(8);
            chunk[..len].copy_from_slice(&rnd[..len]);
        }

        let header_bytes = &buffer[..header_size];
        let payload = &buffer[header_size..];

        let mut header = EnclaveRequestHeader {
            magic: u32::from_le_bytes(header_bytes[0..4].try_into().unwrap()),
            version: u16::from_le_bytes(header_bytes[4..6].try_into().unwrap()),
            command: u16::from_le_bytes(header_bytes[6..8].try_into().unwrap()),
            payload_len: u32::from_le_bytes(header_bytes[8..12].try_into().unwrap()),
            flags: u32::from_le_bytes(header_bytes[12..16].try_into().unwrap()),
            reserved: [0u8; 16],
        };
        header.reserved.copy_from_slice(&header_bytes[16..32]);

        let mut resp = [0u8; 4096];
        let _ = dispatch_frame(&header, payload, &mut resp);
    }
}

#[test]
fn test_fuzz_ingest_smoke() {
    let mut state: u64 = 0xda942042e4dd58b5;
    let mut next_u64 = || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545F4914F6CDD1D)
    };

    #[repr(C, align(64))]
    struct AlignedStream {
        data: [u8; 4096],
    }
    let mut stream = AlignedStream { data: [0u8; 4096] };

    for _ in 0..2_000 {
        for chunk in stream.data.chunks_mut(8) {
            let rnd = next_u64().to_le_bytes();
            let len = chunk.len().min(8);
            chunk[..len].copy_from_slice(&rnd[..len]);
        }

        let test_len = (usize::try_from(next_u64()).unwrap_or(0) % 4096) + 1;
        let mut out = [0u8; 64];
        let _ = normalize_to_buffer(&stream.data[..test_len.min(64)], &mut out);

        unsafe {
            let _ = nona_ingest_stream(stream.data.as_ptr(), test_len);
        }
    }
}
