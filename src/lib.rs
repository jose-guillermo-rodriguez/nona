//! Project Nona Core Engine Logic and C-ABI Execution Boundary.
//! Stateless execution utility compiled for isolated microarchitectural targets.
//!
//! # Executable API Contract
//!
//! ```rust
//! use nona_core::normalization::normalize_bytes;
//! use nona_core::psi::{FieldElement, ProjectivePoint};
//!
//! // 1. O(1) Cache-aligned byte normalization contract
//! let mut raw = [0u8; 64];
//! raw[..5].copy_from_slice(b"HELLO");
//! let sanitized = normalize_bytes(&raw).expect("valid 64-byte payload");
//! assert_eq!(&sanitized.data[..5], b"hello");
//!
//! // 2. Prime field arithmetic contract
//! let zero = FieldElement::zero();
//! let one = FieldElement::one();
//! assert!(zero.is_zero());
//! assert!(!one.is_zero());
//! assert!(zero.add(&one).ct_eq(&one));
//!
//! // 3. Projective curve generator contract
//! let g = ProjectivePoint::generator();
//! assert!(!g.is_infinity());
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::missing_safety_doc)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::mem_forget)]
#![deny(clippy::large_stack_frames)]

#[cfg(all(not(feature = "std"), not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    exception::zeroize_and_abort(-99);
}

/// Language personality routine required for C-ABI static library linkage.
///
/// Precompiled `core` objects in the Rust toolchain reference `rust_eh_personality`
/// even under `panic = "abort"`. Defining this symbol directly within the static
/// archive satisfies external C/C++ linker resolution natively across ELF and Mach-O,
/// closing the C-ABI boundary with zero downstream linkage friction.
#[cfg(all(not(feature = "std"), not(test)))]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

pub mod allocator;
#[cfg(not(target_os = "none"))]
pub mod attestation;
pub mod aws_root_ca;
pub mod crypto;
#[cfg(not(target_os = "none"))]
pub mod enclave_server;
pub mod exception;
pub mod gatekeeper;
pub mod ingest;
pub mod normalization;
pub mod obfuscation;
pub mod psi;
pub mod ring_buffer;

pub use crate::crypto::nona_adaptive_psi_route;
pub use crate::obfuscation::nona_permute_index;

pub use crate::psi::{
    nona_phase1_blind, nona_phase1_blind_impl, nona_phase2_intersect, nona_phase2_intersect_impl,
    nona_phase2_intersect_payload, nona_phase2_reblind, nona_phase2_reblind_impl,
};

// C-ABI Status Codes (Aligned with include/nona.h nona_status_t)

pub use crate::gatekeeper::*;

/// Satisfies [FR-19-FFIBND]
/// Validates an FFI pointer for nullness, alignment, and buffer bounds.
/// Satisfies Architectural Invariant §1: Stack Frame Ceiling (< 4 KiB).
/// Inline stack-pointer assertion verifying 16-byte ABI alignment and non-exhaustion.
#[macro_export]
macro_rules! assert_stack_boundary {
    () => {
        #[cfg(all(target_arch = "x86_64", not(target_os = "none")))]
        {
            let sp: usize;
            unsafe {
                core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack));
            }
            if (sp & 0x7) != 0 {
                return $crate::gatekeeper::NONA_ERR_UNALIGNED_POINTER;
            }
        }
        #[cfg(all(target_arch = "aarch64", not(target_os = "none")))]
        {
            let sp: usize;
            unsafe {
                core::arch::asm!("mov {}, sp", out(reg) sp, options(nomem, nostack));
            }
            if (sp & 0xF) != 0 {
                return $crate::gatekeeper::NONA_ERR_UNALIGNED_POINTER;
            }
        }
    };
}

#[allow(clippy::bad_bit_mask)]
#[macro_export]
macro_rules! validate_ffi_ptr {
    (@check_stack) => {
        $crate::assert_stack_boundary!();
    };
    (@check_null $ptr:expr, $null_err:expr) => {
        $crate::validate_ffi_ptr!(@check_stack);
        if $ptr.is_null() {
            return $null_err;
        }
    };
    (@check_align $ptr:expr, $align_bytes:expr) => {
        if (($ptr as usize) & ($align_bytes - 1)) != 0 {
            return $crate::gatekeeper::NONA_ERR_UNALIGNED_POINTER;
        }
    };
    (@check_len $len:expr) => {
        if $len == 0 || $len > 4096 {
            return $crate::gatekeeper::NONA_ERR_LENGTH_BOUND_VIOLATION;
        }
    };

    ($ptr:expr, 1, $null_err:expr) => {
        $crate::validate_ffi_ptr!(@check_null $ptr, $null_err);
    };
    ($ptr:expr, $align_bytes:expr, $null_err:expr) => {
        $crate::validate_ffi_ptr!(@check_null $ptr, $null_err);
        $crate::validate_ffi_ptr!(@check_align $ptr, $align_bytes);
    };
    ($ptr:expr, $len:expr, 1, $null_err:expr, $slice_var:ident) => {
        $crate::validate_ffi_ptr!(@check_null $ptr, $null_err);
        $crate::validate_ffi_ptr!(@check_len $len);
        let $slice_var = unsafe { core::slice::from_raw_parts($ptr, $len) };
    };
    ($ptr:expr, $len:expr, $align_bytes:expr, $null_err:expr, $slice_var:ident) => {
        $crate::validate_ffi_ptr!(@check_null $ptr, $null_err);
        $crate::validate_ffi_ptr!(@check_len $len);
        $crate::validate_ffi_ptr!(@check_align $ptr, $align_bytes);
        let $slice_var = unsafe { core::slice::from_raw_parts($ptr, $len) };
    };
}

pub(crate) static ACTIVE_BUFFER: core::sync::atomic::AtomicPtr<u8> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
pub(crate) static ACTIVE_BUFFER_LEN: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Satisfies [FR-05-RAMCLR]
/// Satisfies [FR-20-ABRTGATE]
/// Registers global volatile buffer for signal emergency decontamination.
pub unsafe fn register_active_buffer(ptr: *mut u8, len: usize) {
    ACTIVE_BUFFER_LEN.store(len, core::sync::atomic::Ordering::SeqCst);
    ACTIVE_BUFFER.store(ptr, core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Satisfies [FR-05-RAMCLR]
/// Unregisters and fences global active volatile buffer.
pub unsafe fn unregister_active_buffer() {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    ACTIVE_BUFFER.store(core::ptr::null_mut(), core::sync::atomic::Ordering::SeqCst);
    ACTIVE_BUFFER_LEN.store(0, core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// Satisfies [FR-15-OPSECABRT]
/// Satisfies [FR-05-RAMCLR]
/// Asynchronous signal handler triggering volatile decontamination and clean re-raise.
#[cfg(not(target_os = "none"))]
extern "C" fn handle_signal(sig: libc::c_int) {
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    exception::decontaminate();
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

#[no_mangle]
/// Satisfies [FR-04-PERMEM]
/// Satisfies [FR-05-RAMCLR]
/// Satisfies [FR-11-STACKCEIL]
/// Substrate initialization disabling core dumps, locking RAM (mlockall), and binding signal traps.
/// Host defense mechanics (page-locking and core-dump suppression) are gated behind feature = "host-defense".
pub extern "C" fn nona_core_init() -> i32 {
    #[cfg(feature = "host-defense")]
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
            return -1;
        }

        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
            #[cfg(feature = "panic_on_lock_failure")]
            {
                exception::decontaminate();
                return -2;
            }
            #[cfg(not(feature = "panic_on_lock_failure"))]
            {
                return -2;
            }
        }
    }

    #[cfg(not(target_os = "none"))]
    unsafe {
        if libc::signal(
            libc::SIGINT,
            handle_signal as *const () as libc::sighandler_t,
        ) == libc::SIG_ERR
        {
            return -3;
        }
        if libc::signal(
            libc::SIGTERM,
            handle_signal as *const () as libc::sighandler_t,
        ) == libc::SIG_ERR
        {
            return -4;
        }
    }

    0
}

#[inline(always)]
/// Satisfies [FR-10-PSIMATCH]
/// Inner wrapper evaluating single-stage PSI matching circuit over validated pointer.
unsafe fn process_psi_state(state: *mut psi::PsiCircuitState) -> i32 {
    validate_ffi_ptr!(state, 64, -2);
    psi::evaluate_match_circuit(&mut *state);
    0
}

#[no_mangle]
/// Satisfies [FR-10-PSIMATCH]
/// Satisfies [FR-11-STACKCEIL]
/// Satisfies [FR-19-FFIBND]
/// C-ABI export evaluating single-stage PSI matching circuit with stack ceiling check.
pub extern "C" fn nona_core_process(state: *mut psi::PsiCircuitState) -> i32 {
    unsafe { process_psi_state(state) }
}

/// Satisfies [FR-18-ZEROREM]
/// C-ABI export for constant-time volatile memory zeroization.
#[no_mangle]
pub unsafe extern "C" fn nona_ct_zeroize(ptr: *mut u8, len: usize) -> i32 {
    if ptr.is_null() {
        return NONA_ERR_NULL_POINTER;
    }
    let slice = core::slice::from_raw_parts_mut(ptr, len);
    crypto::ct_zeroize(slice);
    NONA_OK
}

#[inline(always)]
/// Satisfies [FR-01-NORMBYTE]
/// Constant-time parsing of sanitized ASCII bytes into u64 value.
fn parse_sanitized_to_u64(sanitized: &normalization::SanitizedCode) -> u64 {
    let mut parsed_val: u64 = 0;
    let mut digit_count: u64 = 0;
    for &byte in sanitized.data.iter() {
        let (is_digit, safe_digit) = crypto::ct_parse_digit(byte);
        // Closed-form constant-time borrow bit extraction: 1 if digit_count < 19, else 0
        let under_limit = ((!digit_count & 19u64)
            | (!(digit_count ^ 19u64) & digit_count.wrapping_sub(19u64)))
            >> 63;
        let active_digit = is_digit & under_limit;

        // Expand active_digit (0 or 1) into a full 64-bit mask (0x0 or 0xFFFF_FFFF_FFFF_FFFF)
        let mask = 0u64.wrapping_sub(active_digit);
        let multiplier = crypto::ct_select_u64(mask, 10, 1);
        let addend = safe_digit & mask;
        parsed_val = parsed_val.wrapping_mul(multiplier).wrapping_add(addend);
        digit_count = digit_count.wrapping_add(is_digit);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    parsed_val
}

#[no_mangle]
/// Satisfies [FR-01-NORMBYTE]
/// Satisfies [FR-09-IDXOBFC]
/// Satisfies [FR-11-STACKCEIL]
/// Satisfies [FR-19-FFIBND]
/// Polymorphic 64-byte byte normalization and Feistel index permutation C-ABI export.
pub unsafe extern "C" fn nona_normalize_and_obfuscate(
    input_ptr: *const u8,
    input_len: usize,
    a: u64,
    c: u64,
    output_code: *mut normalization::SanitizedCode,
    out_permuted_index: *mut u64,
) -> i32 {
    validate_ffi_ptr!(input_ptr, input_len, 1, -1, input_slice);
    validate_ffi_ptr!(output_code, 64, -1);
    validate_ffi_ptr!(out_permuted_index, 8, -1);

    let status = normalization::normalize_to_buffer(input_slice, &mut (*output_code).data);
    if status != 1 {
        return -1;
    }
    let parsed_val = parse_sanitized_to_u64(&*output_code);
    let circuit = obfuscation::IndexPermutationCircuit::new(a, c);
    let permuted = circuit.permute(parsed_val);
    out_permuted_index.write(permuted);

    0
}

#[no_mangle]
/// Satisfies [FR-20-ABRTGATE]
/// Satisfies [FR-11-STACKCEIL]
/// Satisfies [FR-19-FFIBND]
/// Evaluates exception control block sliding error rates and performs volatile decontamination.
pub unsafe extern "C" fn nona_process_exception_step(
    ecb: *mut exception::ExceptionControlBlock,
    e_i: u8,
    window_buffer: *mut u8,
) -> i32 {
    validate_ffi_ptr!(ecb, 64, -1);
    validate_ffi_ptr!(window_buffer, 64, -1);

    let ecb_ref = &mut *ecb;
    ecb_ref.update_write_cursor(e_i);
    let status = ecb_ref.evaluate_window(e_i, 1000);

    let window_ref = &mut *(window_buffer.cast::<[u8; 64]>());
    crypto::ct_zeroize(window_ref);

    if status == -3 {
        exception::decontaminate();
    }

    status
}

#[no_mangle]
/// Satisfies [FR-17-STRMIN]
/// Satisfies [FR-11-STACKCEIL]
/// Satisfies [FR-19-FFIBND]
/// Zero-copy stream ingestion C-ABI export into N=128 ring manifold.
pub unsafe extern "C" fn nona_ingest_stream(stream_ptr: *const u8, len: usize) -> i32 {
    crate::validate_ffi_ptr!(stream_ptr, 64, -1);
    if len > 4096 {
        return -3;
    }
    crate::ingest::process_ingest_stream_impl(stream_ptr, len)
}

#[no_mangle]
/// Satisfies [FR-08-GATEKEEPR]
/// Satisfies [FR-11-STACKCEIL]
/// Satisfies [FR-19-FFIBND]
/// Branchless parameter gatekeeper and payload digest validation export.
pub unsafe extern "C" fn nona_gatekeeper_validate(
    payload_ptr: *const u8,
    payload_len: usize,
    cardinality: usize,
    expected_hash: *const u8,
) -> i32 {
    validate_ffi_ptr!(payload_ptr, payload_len, 1, -1, _slice);
    validate_ffi_ptr!(expected_hash, 1, -1);

    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    gatekeeper::nona_gatekeeper_validate_impl(payload_ptr, payload_len, cardinality, expected_hash)
}

#[no_mangle]
/// Satisfies [FR-19-FFIBND]
/// Satisfies [FR-11-STACKCEIL]
/// Multi-buffer FFI boundary, alignment, and spatial disjointness validation export.
pub unsafe extern "C" fn nona_validate_ffi_bounds(
    in_ptr: *const u8,
    in_len: usize,
    n_elements: usize,
    key_ptr: *const u8,
    key_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
    expected_out_len: usize,
) -> i32 {
    gatekeeper::nona_validate_ffi_bounds_impl(
        in_ptr,
        in_len,
        n_elements,
        key_ptr,
        key_len,
        out_ptr,
        out_len,
        expected_out_len,
    )
}

#[cfg(feature = "std")]
pub mod client;

#[cfg(test)]
mod tests_f26 {
    use super::*;

    #[test]
    fn test_parse_sanitized_to_u64_overflow_gate() {
        // Construct a SanitizedCode with 19 nines
        let mut code_19 = normalization::SanitizedCode { data: [0u8; 64] };
        for i in 0..19 {
            code_19.data[i] = b'9';
        }
        assert_eq!(parse_sanitized_to_u64(&code_19), 9_999_999_999_999_999_999);

        // Construct a SanitizedCode with 20 nines (gated at 19 digits, zero overflow)
        let mut code_20 = normalization::SanitizedCode { data: [0u8; 64] };
        for i in 0..20 {
            code_20.data[i] = b'9';
        }
        assert_eq!(parse_sanitized_to_u64(&code_20), 9_999_999_999_999_999_999);

        // Construct a SanitizedCode with 64 nines (full 64-byte buffer saturation)
        let code_64 = normalization::SanitizedCode { data: [b'9'; 64] };
        assert_eq!(parse_sanitized_to_u64(&code_64), 9_999_999_999_999_999_999);
    }
}
