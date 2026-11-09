// ============================================================================
// NONA CONFIDENTIAL ENCLAVE INTEGRATION TEST: C-ABI BOUNDARY HARNESS
// Deployment Profile: Pure #![no_std] Freestanding Binary (harness = false)
// ============================================================================

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

#[cfg(all(not(feature = "std"), target_os = "macos"))]
#[link(name = "System")]
extern "C" {}

#[cfg(all(not(feature = "std"), target_os = "linux"))]
#[link(name = "c")]
extern "C" {}


use core::ptr;
use nona_core::{
    nona_adaptive_psi_route, nona_gatekeeper_validate, nona_ingest_stream,
    nona_normalize_and_obfuscate, nona_phase1_blind, nona_phase2_intersect, nona_phase2_reblind,
    normalization::SanitizedCode, NONA_ERR_INVALID_CURVE_POINT, NONA_SUCCESS,
};

fn test_c_abi_null_pointer_containment() {
    #[repr(align(64))]
    struct AlignedU64(u64);

    #[repr(align(64))]
    struct AlignedBuffer([u8; 64]);

    let mut out_cardinality = AlignedU64(0);
    let mut dummy_buf = AlignedBuffer([0u8; 64]);

    unsafe {
        // 1. Verify null input buffers return -1 (NONA_ERR_NULL_POINTER)
        assert_eq!(
            nona_phase1_blind(
                ptr::null(),
                64,
                2,
                dummy_buf.0.as_ptr(),
                dummy_buf.0.as_mut_ptr(),
                64
            ),
            -1
        );
        assert_eq!(
            nona_phase2_intersect(
                ptr::null(),
                64,
                dummy_buf.0.as_ptr(),
                64,
                2,
                dummy_buf.0.as_mut_ptr(),
                64,
                0,
                &raw mut out_cardinality.0
            ),
            -1
        );
        assert_eq!(nona_ingest_stream(ptr::null(), 128), -1);
        assert_eq!(
            nona_gatekeeper_validate(ptr::null(), 32, 1, ptr::null()),
            -1
        );

        // 2. Verify null cardinality out pointer returns -1 (NONA_ERR_NULL_POINTER)
        assert_eq!(
            nona_phase2_intersect(
                dummy_buf.0.as_ptr(),
                64,
                dummy_buf.0.as_ptr(),
                64,
                2,
                dummy_buf.0.as_mut_ptr(),
                64,
                0,
                ptr::null_mut()
            ),
            -1
        );

        let mut out_code = SanitizedCode { data: [0u8; 64] };
        let mut out_idx = 0u64;
        assert_eq!(
            nona_normalize_and_obfuscate(
                ptr::null(),
                64,
                3,
                7,
                &raw mut out_code,
                &raw mut out_idx
            ),
            -1
        );
    }
}

fn test_c_abi_ingest_stream_framing() {
    #[repr(C, align(64))]
    struct AlignedBuffer([u8; 128]);

    let dummy_data = AlignedBuffer([0xAAu8; 128]);
    unsafe {
        // Valid 128-byte aligned chunk stream
        assert_eq!(nona_ingest_stream(dummy_data.0.as_ptr(), 128), 0);

        // Misaligned chunk size (len % 128 != 0) must return -3
        assert_eq!(nona_ingest_stream(dummy_data.0.as_ptr(), 64), -3);

        // Over-capacity stream length (> 4096 bytes) must return -3
        assert_eq!(nona_ingest_stream(dummy_data.0.as_ptr(), 4096 + 128), -3);
    }
}

fn test_c_abi_monomorphic_normalization_flow() {
    #[repr(C, align(64))]
    struct AlignedInput([u8; 64]);

    let mut raw_input = AlignedInput([0u8; 64]);
    let sample_bytes = b"987654321\r\n";
    raw_input.0[..sample_bytes.len()].copy_from_slice(sample_bytes);

    let mut out_code = SanitizedCode { data: [0u8; 64] };
    let mut out_idx = 0u64;

    unsafe {
        let rc = nona_normalize_and_obfuscate(
            raw_input.0.as_ptr(),
            64,
            1103515245,
            12345,
            &raw mut out_code,
            &raw mut out_idx,
        );
        assert_eq!(rc, 0);

        // Monomorphic CR/LF stripping check
        assert_eq!(out_code.data[9], 0x00);
        assert_eq!(out_code.data[10], 0x00);
        assert_ne!(out_idx, 0);
    }
}

fn test_c_abi_adaptive_route_selection() {
    let mut route_id = 0u32;
    unsafe {
        // N * 128 >= M -> Expect DH-PSI (Route 1)
        assert_eq!(nona_adaptive_psi_route(10, 100, &raw mut route_id), 0);
        assert_eq!(route_id, 1);

        // N * 128 < M -> Expect VOLE-PSI (Route 2)
        assert_eq!(nona_adaptive_psi_route(1, 200, &raw mut route_id), 0);
        assert_eq!(route_id, 2);
    }
}

fn test_c_abi_memory_fault_injection_and_wraparound() {
    #[repr(align(64))]
    struct AlignedBuffer<const N: usize>([u8; N]);

    let in_buf = AlignedBuffer([0u8; 64]);
    let key_buf = AlignedBuffer([0u8; 64]);
    let mut out_buf = AlignedBuffer([0u8; 64]);

    unsafe {
        // 1. Pointer wraparound: address space ceiling pointer (!63usize)
        let wrap_ptr = (!63usize) as *const u8;
        let rc_wrap = nona_phase1_blind(
            wrap_ptr,
            64,
            2,
            key_buf.0.as_ptr(),
            out_buf.0.as_mut_ptr(),
            64,
        );
        assert_eq!(rc_wrap, -7, "Expected NONA_ERR_POINTER_WRAPAROUND (-7)");

        // 2. Buffer overflow ceiling: length > 4096 bytes (4224 bytes)
        let rc_len = nona_phase1_blind(
            in_buf.0.as_ptr(),
            4224,
            2,
            key_buf.0.as_ptr(),
            out_buf.0.as_mut_ptr(),
            4224,
        );
        assert_eq!(rc_len, -3, "Expected NONA_ERR_LENGTH_BOUND_VIOLATION (-3)");

        // 3. Buffer aliasing: input buffer overlaps output buffer
        let rc_alias = nona_phase1_blind(
            out_buf.0.as_mut_ptr(),
            64,
            2,
            key_buf.0.as_ptr(),
            out_buf.0.as_mut_ptr(),
            64,
        );
        assert_eq!(rc_alias, -5, "Expected NONA_ERR_BUFFER_ALIASING (-5)");
    }
}

fn test_c_abi_phase2_reblind_invalid_curve_point_rejection() {
    #[repr(align(64))]
    struct AlignedBuffer([u8; 64]);

    let mut dummy_key = AlignedBuffer([0u8; 64]);
    dummy_key.0[0] = 0x42;
    let mut dummy_in = AlignedBuffer([0u8; 64]);
    let mut dummy_out = AlignedBuffer([0u8; 64]);

    unsafe {
        // Point x = 0: 0^3 + 7 = 7 mod p is a quadratic non-residue
        let rc = nona_phase2_reblind(
            dummy_in.0.as_ptr(),
            64,
            2,
            dummy_key.0.as_ptr(),
            dummy_out.0.as_mut_ptr(),
            64,
        );
        assert_eq!(rc, NONA_ERR_INVALID_CURVE_POINT);

        // Valid round: Phase 1 SWU outputs valid curve points that Phase 2 accepts
        let rc1 = nona_phase1_blind(
            dummy_in.0.as_ptr(),
            64,
            2,
            dummy_key.0.as_ptr(),
            dummy_out.0.as_mut_ptr(),
            64,
        );
        assert_eq!(rc1, NONA_SUCCESS);

        let rc2 = nona_phase2_reblind(
            dummy_out.0.as_ptr(),
            64,
            2,
            dummy_key.0.as_ptr(),
            dummy_in.0.as_mut_ptr(),
            64,
        );
        assert_eq!(rc2, NONA_SUCCESS);
    }
}

fn run_all_c_abi_tests() {
    test_c_abi_null_pointer_containment();
    test_c_abi_ingest_stream_framing();
    test_c_abi_monomorphic_normalization_flow();
    test_c_abi_adaptive_route_selection();
    test_c_abi_memory_fault_injection_and_wraparound();
    test_c_abi_phase2_reblind_invalid_curve_point_rejection();
}

#[cfg(all(not(feature = "std"), not(target_os = "none")))]
#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8) -> i32 {
    run_all_c_abi_tests();
    0
}

#[cfg(all(not(feature = "std"), target_os = "none"))]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    run_all_c_abi_tests();
    // Deterministic bare-metal completion loop or exit trap
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(feature = "std")]
fn main() {
    run_all_c_abi_tests();
}
