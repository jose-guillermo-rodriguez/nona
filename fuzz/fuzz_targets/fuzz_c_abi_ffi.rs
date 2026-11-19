// Copyright (c) 2026 Nona Contributors.
// Licensed under the Apache License, Version 2.0 or the MIT License.

//! libFuzzer and Standalone Continuous Fuzzing Harness: C-ABI FFI Perimeter
//!
//! Fuzzes exported C-ABI entry points across arbitrary byte lengths, unaligned
//! pointers, zero/oversized counts, overlapping/aliased input-output buffers,
//! and random scalars/points, asserting deterministic error codes and zero panics/UB.

use core::cell::UnsafeCell;
use nona_core::exception::ExceptionControlBlock;
use nona_core::normalization::SanitizedCode;
use nona_core::obfuscation::IndexPermutationCircuit;
use nona_core::psi::{
    FieldElement, PsiCircuitState, NONA_FLAG_FULL_PSI, NONA_FLAG_PSI_CA, NONA_FLAG_PSI_PR,
    NONA_FLAG_PSI_SUM,
};
use nona_core::{
    nona_adaptive_psi_route, nona_core_process, nona_ct_zeroize, nona_gatekeeper_validate,
    nona_ingest_stream, nona_normalize_and_obfuscate, nona_permute_index, nona_phase1_blind,
    nona_phase2_intersect, nona_phase2_intersect_payload, nona_phase2_reblind,
    nona_process_exception_step, nona_validate_ffi_bounds,
};

#[repr(C, align(64))]
struct AlignedArena {
    in_a: [u8; 4096],
    in_b: [u8; 4096],
    out_a: [u8; 4096],
    out_b: [u8; 4096],
    key: [u8; 64],
    payloads_in: [u64; 128],
    payloads_out: [u64; 128],
    sanitized: SanitizedCode,
    ecb: ExceptionControlBlock,
    psi_state: PsiCircuitState,
    circuit: IndexPermutationCircuit,
    scalars_u64: [u64; 16],
}

struct StaticArena(UnsafeCell<AlignedArena>);
unsafe impl Sync for StaticArena {}

static ARENA: StaticArena = StaticArena(UnsafeCell::new(AlignedArena {
    in_a: [0u8; 4096],
    in_b: [0u8; 4096],
    out_a: [0u8; 4096],
    out_b: [0u8; 4096],
    key: [0u8; 64],
    payloads_in: [0u64; 128],
    payloads_out: [0u64; 128],
    sanitized: SanitizedCode { data: [0u8; 64] },
    ecb: ExceptionControlBlock {
        g_total: 0,
        g_err: 0,
        w_total: 0,
        w_err: 0,
        c_write: 0,
        c_read: 0,
        _padding: [0u8; 16],
    },
    psi_state: PsiCircuitState {
        base_value: FieldElement { limbs: [0; 4] },
        exponent: FieldElement { limbs: [0; 4] },
        accumulator: FieldElement { limbs: [0; 4] },
    },
    circuit: IndexPermutationCircuit { a: 1, c: 1 },
    scalars_u64: [0u64; 16],
}));

fn read_u64_le(slice: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    for (i, dst) in bytes.iter_mut().enumerate() {
        *dst = slice.get(offset + i).copied().unwrap_or(0);
    }
    u64::from_le_bytes(bytes)
}

fn read_u32_le(slice: &[u8], offset: usize) -> u32 {
    let mut bytes = [0u8; 4];
    for (i, dst) in bytes.iter_mut().enumerate() {
        *dst = slice.get(offset + i).copied().unwrap_or(0);
    }
    u32::from_le_bytes(bytes)
}

fn read_usize_le(slice: &[u8], offset: usize) -> usize {
    usize::try_from(read_u64_le(slice, offset)).unwrap_or(usize::MAX)
}

#[inline(never)]
fn fuzz_c_abi_blinding_stages(arena: &mut AlignedArena, slice: &[u8]) {
    let n_elements = (usize::from(slice[0]) % 16).max(1);
    let byte_len = n_elements * 32;
    let fuzz_in_len = read_usize_le(slice, 1) % 4200;
    let fuzz_out_len = read_usize_le(slice, 9) % 4200;
    let fuzz_count = read_usize_le(slice, 17) % 140;

    unsafe {
        assert!(
            nona_phase1_blind(
                core::ptr::null(),
                byte_len,
                n_elements,
                arena.key.as_ptr(),
                arena.out_a.as_mut_ptr(),
                byte_len,
            ) < 0
        );
        assert!(
            nona_phase1_blind(
                arena.in_a.as_ptr().wrapping_add(1),
                byte_len,
                n_elements,
                arena.key.as_ptr(),
                arena.out_a.as_mut_ptr(),
                byte_len,
            ) < 0
        );
        assert!(
            nona_phase1_blind(
                arena.in_a.as_ptr(),
                byte_len,
                n_elements,
                arena.key.as_ptr(),
                arena.in_a.as_mut_ptr(),
                byte_len,
            ) < 0
        );
        let _ = nona_phase1_blind(
            arena.in_a.as_ptr(),
            fuzz_in_len,
            fuzz_count,
            arena.key.as_ptr(),
            arena.out_a.as_mut_ptr(),
            fuzz_out_len,
        );
        let p1_rc = nona_phase1_blind(
            arena.in_a.as_ptr(),
            byte_len,
            n_elements,
            arena.key.as_ptr(),
            arena.out_a.as_mut_ptr(),
            byte_len,
        );
        assert!(p1_rc <= 0);

        assert!(
            nona_phase2_reblind(
                arena.out_a.as_ptr(),
                byte_len,
                n_elements,
                arena.key.as_ptr().wrapping_add(1),
                arena.out_b.as_mut_ptr(),
                byte_len,
            ) < 0
        );
        assert!(
            nona_phase2_reblind(
                arena.out_a.as_ptr(),
                byte_len,
                n_elements,
                arena.key.as_ptr(),
                arena.out_a.as_mut_ptr(),
                byte_len,
            ) < 0
        );
        let _ = nona_phase2_reblind(
            arena.in_a.as_ptr(),
            fuzz_in_len,
            fuzz_count,
            arena.key.as_ptr(),
            arena.out_b.as_mut_ptr(),
            fuzz_out_len,
        );
        if p1_rc == 0 {
            let rb_rc = nona_phase2_reblind(
                arena.out_a.as_ptr(),
                byte_len,
                n_elements,
                arena.key.as_ptr(),
                arena.out_b.as_mut_ptr(),
                byte_len,
            );
            assert_eq!(rb_rc, 0);
        }
    }
}

#[inline(never)]
fn fuzz_c_abi_intersect_stages(arena: &mut AlignedArena, slice: &[u8]) {
    let n_elements = (usize::from(slice[0]) % 16).max(1);
    let byte_len = n_elements * 32;
    let fuzz_flags = read_u32_le(slice, 25);
    let flag_choices = [
        NONA_FLAG_FULL_PSI,
        NONA_FLAG_PSI_CA,
        NONA_FLAG_PSI_PR,
        NONA_FLAG_PSI_SUM,
        fuzz_flags,
    ];
    let selected_flag = flag_choices[usize::from(slice[0]) % flag_choices.len()];

    arena.scalars_u64[0] = 0;
    arena.scalars_u64[1] = 0;
    arena.scalars_u64[2] = 0;

    unsafe {
        let card_ptr = arena.scalars_u64.as_mut_ptr();
        assert!(
            nona_phase2_intersect(
                arena.out_a.as_ptr(),
                byte_len,
                arena.out_a.as_ptr(),
                byte_len,
                n_elements,
                arena.in_b.as_mut_ptr(),
                n_elements * 4,
                NONA_FLAG_FULL_PSI,
                card_ptr,
            ) < 0
        );
        assert!(
            nona_phase2_intersect(
                arena.out_a.as_ptr(),
                byte_len,
                arena.out_b.as_ptr(),
                byte_len,
                n_elements,
                arena.in_b.as_mut_ptr().wrapping_add(1),
                n_elements * 4,
                NONA_FLAG_PSI_CA,
                card_ptr,
            ) < 0
        );
        let int_rc = nona_phase2_intersect(
            arena.out_a.as_ptr(),
            byte_len,
            arena.out_b.as_ptr(),
            byte_len,
            n_elements,
            arena.in_b.as_mut_ptr(),
            n_elements * 4,
            selected_flag,
            card_ptr,
        );
        if int_rc == 0 {
            assert!(arena.scalars_u64[0] <= u64::try_from(n_elements).unwrap_or(u64::MAX));
        }

        let _ = nona_phase2_intersect_payload(
            arena.out_a.as_ptr(),
            byte_len,
            arena.out_b.as_ptr(),
            byte_len,
            arena.payloads_in.as_ptr(),
            n_elements,
            arena.in_b.as_mut_ptr(),
            arena.payloads_out.as_mut_ptr(),
            n_elements * 4,
            selected_flag,
            &raw mut arena.scalars_u64[1],
            &raw mut arena.scalars_u64[2],
        );
    }
}

#[inline(never)]
fn fuzz_c_abi_bijection_and_routing(arena: &mut AlignedArena, slice: &[u8]) {
    arena.circuit =
        IndexPermutationCircuit::new(read_u64_le(slice, 0) | 1, read_u64_le(slice, 8));
    let idx_in = read_u64_le(slice, 16);
    let mut perm_a = 0u64;
    let mut perm_b = 0u64;

    unsafe {
        assert_eq!(
            nona_permute_index(&raw const arena.circuit, idx_in, &raw mut perm_a),
            0
        );
        assert_eq!(
            nona_permute_index(&raw const arena.circuit, idx_in, &raw mut perm_b),
            0
        );
        assert_eq!(perm_a, perm_b);
        assert!(
            nona_permute_index(
                (&raw const arena.circuit).cast::<u8>().wrapping_add(1).cast(),
                idx_in,
                &raw mut perm_a,
            ) < 0
        );

        let mut route_id = 0u32;
        let route_rc = nona_adaptive_psi_route(
            read_u64_le(slice, 0),
            read_u64_le(slice, 8),
            &raw mut route_id,
        );
        if route_rc == 0 {
            assert!(route_id == 1 || route_id == 2);
        }

        let norm_len = slice.len() % 80;
        let mut norm_perm = 0u64;
        let norm_rc = nona_normalize_and_obfuscate(
            slice.as_ptr(),
            norm_len,
            read_u64_le(slice, 0) | 1,
            read_u64_le(slice, 8),
            &raw mut arena.sanitized,
            &raw mut norm_perm,
        );
        if norm_len == 0 || norm_len > 64 {
            assert!(norm_rc < 0);
        }
    }
}

#[inline(never)]
fn fuzz_c_abi_peripherals(arena: &mut AlignedArena, slice: &[u8]) {
    let n_elements = (usize::from(slice[0]) % 16).max(1);
    let byte_len = n_elements * 32;
    let fuzz_in_len = read_usize_le(slice, 1) % 4200;
    let fuzz_out_len = read_usize_le(slice, 9) % 4200;
    let fuzz_count = read_usize_le(slice, 17) % 140;

    arena.psi_state.base_value.limbs = [
        read_u64_le(slice, 0),
        read_u64_le(slice, 8),
        read_u64_le(slice, 16),
        read_u64_le(slice, 24),
    ];
    arena.psi_state.exponent.limbs = [
        read_u64_le(slice, 32),
        read_u64_le(slice, 40),
        read_u64_le(slice, 48),
        read_u64_le(slice, 56),
    ];

    unsafe {
        let _ = nona_ingest_stream(arena.in_a.as_ptr(), fuzz_in_len);
        let _ = nona_gatekeeper_validate(
            arena.in_a.as_ptr(),
            fuzz_in_len,
            fuzz_count,
            arena.key.as_ptr(),
        );
        let _ = nona_validate_ffi_bounds(
            arena.in_a.as_ptr(),
            fuzz_in_len,
            fuzz_count,
            arena.key.as_ptr(),
            32,
            arena.out_a.as_mut_ptr(),
            fuzz_out_len,
            byte_len,
        );
        assert_eq!(nona_core_process(&raw mut arena.psi_state), 0);
        let _ = nona_process_exception_step(
            &raw mut arena.ecb,
            slice[0],
            arena.out_b.as_mut_ptr(),
        );
        assert_eq!(nona_ct_zeroize(arena.out_b.as_mut_ptr(), 64), 0);
        assert!(nona_ct_zeroize(arena.out_b.as_mut_ptr(), 0) < 0);
    }
}

/// # Panics
/// Panics only if a C-ABI invariant (such as deterministic rejection of null/unaligned/aliased
/// buffers or bounded cardinality) is violated.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
    if data.is_null() || size == 0 {
        return 0;
    }
    let slice = unsafe { core::slice::from_raw_parts(data, size) };
    let arena = unsafe { &mut *ARENA.0.get() };

    let copy_len = size.min(4096);
    arena.in_a[..copy_len].copy_from_slice(&slice[..copy_len]);
    for i in 0..copy_len {
        arena.in_b[i] = slice[copy_len - 1 - i] ^ 0x5a;
    }
    for (i, dst) in arena.key[..32].iter_mut().enumerate() {
        *dst = slice.get(i).copied().unwrap_or(0);
    }
    for (i, slot) in arena.payloads_in.iter_mut().enumerate() {
        *slot = read_u64_le(slice, (i * 8) % size.max(1));
    }

    fuzz_c_abi_blinding_stages(arena, slice);
    fuzz_c_abi_intersect_stages(arena, slice);
    fuzz_c_abi_bijection_and_routing(arena, slice);
    fuzz_c_abi_peripherals(arena, slice);
    0
}

fn parse_runs_arg(default_runs: usize) -> usize {
    for arg in std::env::args().skip(1) {
        if let Some(val) = arg.strip_prefix("-runs=") {
            if let Ok(parsed) = val.parse::<usize>() {
                return parsed.max(1);
            }
        }
    }
    default_runs
}

fn main() {
    let cycles = parse_runs_arg(2_000);
    println!("[*] Launching C-ABI FFI Perimeter Fuzzing ({cycles} cycles)...");

    let mut state: u64 = 0x9e3779b97f4a7c15;
    let mut next_u64 = || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545F4914F6CDD1D)
    };

    let mut corpus = vec![0u8; 4096];
    for cycle in 1..=cycles {
        let size = (usize::try_from(next_u64()).unwrap_or(0) % corpus.len()).max(1);
        for chunk in corpus[..size].chunks_mut(8) {
            let rnd = next_u64().to_le_bytes();
            let copy_len = chunk.len().min(8);
            chunk[..copy_len].copy_from_slice(&rnd[..copy_len]);
        }

        LLVMFuzzerTestOneInput(corpus.as_ptr(), size);

        if cycle % 500 == 0 || cycle == cycles {
            println!("  [+] C-ABI FFI harness completed {cycle} / {cycles} cycles (zero panics)");
        }
    }
    println!("[*] C-ABI FFI continuous fuzzing PASSED ({cycles}/{cycles} iterations).");
}
