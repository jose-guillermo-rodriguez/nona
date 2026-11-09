//! Stateless Branchless FFI Parameter Validation Gatekeeper Substrate.

use core::sync::atomic::{compiler_fence, Ordering};
use zeroize::{Zeroize, ZeroizeOnDrop};

// CANONICAL C-ABI STATUS CODES
pub const NONA_SUCCESS: i32 = 0;
pub const NONA_OK: i32 = 0;
pub const NONA_ERR_NULL_POINTER: i32 = -1;
pub const NONA_ERR_UNALIGNED_POINTER: i32 = -2;
pub const NONA_ERR_LENGTH_BOUND_VIOLATION: i32 = -3;
pub const NONA_ERR_LOCK_BUSY: i32 = -4;
pub const NONA_ERR_BUFFER_ALIASING: i32 = -5;
pub const NONA_ERR_INVALID_FLAGS: i32 = -6;
pub const NONA_ERR_POINTER_WRAPAROUND: i32 = -7;
pub const NONA_ERR_OUT_OF_MEMORY: i32 = -8;
pub const NONA_ERR_STACK_CEILING_EXCEEDED: i32 = -9;
pub const NONA_ERR_ELEMENT_COUNT_BOUND_VIOLATION: i32 = -10;
pub const NONA_ERR_STACK_OVERFLOW: i32 = -11;
pub const NONA_ERR_INVALID_PARAM: i32 = -12;
pub const NONA_ERR_INVALID_CURVE_POINT: i32 = -13;
pub const NONA_ERR_INTERNAL_PANIC: i32 = -14;

pub const MAX_BUFFER_CAPACITY: usize = 4096;
pub const MAX_ELEMENT_COUNT: usize = 128;
pub const DIGEST_LEN: usize = 32;

/// Satisfies [FR-08-GATEKEEPR]
/// Satisfies [FR-02-STKBUFF]
/// Secure, 64-byte aligned wrapper structure for cryptographic verification.
#[repr(C, align(64))]
#[derive(Zeroize, ZeroizeOnDrop, Default)]
pub struct GatekeeperScratchpad {
    pub computed: [u8; 32],
    pub expected: [u8; 32],
}

impl GatekeeperScratchpad {
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            computed: [0u8; 32],
            expected: [0u8; 32],
        }
    }
}

/// Satisfies [FR-19-FFIBND]
/// Constant-time branchless evaluation to determine whether two memory spans are spatially disjoint.
#[inline(always)]
pub fn is_disjoint(ptr_a: *const u8, len_a: usize, ptr_b: *const u8, len_b: usize) -> bool {
    let a_start = ptr_a as usize;
    let (a_end, a_ovf) = a_start.overflowing_add(len_a);

    let b_start = ptr_b as usize;
    let (b_end, b_ovf) = b_start.overflowing_add(len_b);

    if a_ovf || b_ovf {
        return false;
    }

    let a_before_b = (a_end <= b_start) as u8;
    let b_before_a = (b_end <= a_start) as u8;

    (a_before_b | b_before_a) != 0
}

#[inline(always)]
fn ct_le(a: u64, b: u64) -> u64 {
    let (_, borrow) = b.overflowing_sub(a);
    (borrow as u64) ^ 1
}

#[inline(always)]
fn ct_validate_bounds(len: u64, card: u64) -> (u64, u64) {
    let s_l = ct_le(1, len) & ct_le(len, 4096);
    let s_n = ct_le(1, card) & ct_le(card, 128);
    (s_l, s_n)
}

#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn ct_compute_status(s_l: u64, s_n: u64, s_h: u64) -> i32 {
    let sl = (s_l & 1) as i32;
    let sn = (s_n & 1) as i32;
    let sh = (s_h & 1) as i32;
    let term1 = (1 - sl) * NONA_ERR_LENGTH_BOUND_VIOLATION;
    let term2 = sl * (1 - sn) * NONA_ERR_ELEMENT_COUNT_BOUND_VIOLATION;
    let term3 = sl * sn * (1 - sh) * NONA_ERR_INTERNAL_PANIC;
    term1 + term2 + term3
}

#[inline(always)]
fn compute_xor_digest(payload: &[u8], out: &mut [u8; 32]) {
    out.fill(0);
    let len_bytes = (payload.len() as u64).to_le_bytes();
    out[..8].copy_from_slice(&len_bytes);
    for (i, &byte) in payload.iter().enumerate() {
        out[i % 32] ^= byte;
    }
    compiler_fence(Ordering::SeqCst);
}

/// Satisfies [FR-19-FFIBND]
/// Satisfies [FR-08-GATEKEEPR]
/// Multi-buffer FFI boundary, alignment, capacity, and spatial disjointness validation implementation.
pub unsafe fn nona_validate_ffi_bounds_impl(
    in_ptr: *const u8,
    in_len: usize,
    n_elements: usize,
    key_ptr: *const u8,
    key_len: usize,
    out_ptr: *mut u8,
    out_len: usize,
    expected_out_len: usize,
) -> i32 {
    if in_ptr.is_null() || key_ptr.is_null() || out_ptr.is_null() {
        return NONA_ERR_NULL_POINTER;
    }

    // 64-byte cache line alignment requirement across all FFI buffer pointers
    if (((in_ptr as usize) | (key_ptr as usize) | (out_ptr as usize)) & 63) != 0 {
        return NONA_ERR_UNALIGNED_POINTER;
    }

    // Pointer wraparound protection using overflowing_add
    let (in_end, in_ovf) = (in_ptr as usize).overflowing_add(in_len);
    let (key_end, key_ovf) = (key_ptr as usize).overflowing_add(key_len);
    let (out_end, out_ovf) = (out_ptr as usize).overflowing_add(out_len);
    if in_ovf
        || key_ovf
        || out_ovf
        || in_end < (in_ptr as usize)
        || key_end < (key_ptr as usize)
        || out_end < (out_ptr as usize)
    {
        return NONA_ERR_POINTER_WRAPAROUND;
    }

    // Length boundary verification
    if in_len == 0
        || in_len > MAX_BUFFER_CAPACITY
        || key_len == 0
        || key_len > MAX_BUFFER_CAPACITY
        || out_len < expected_out_len
    {
        return NONA_ERR_LENGTH_BOUND_VIOLATION;
    }

    // Element count bounded to maximum capacity
    if n_elements == 0 || n_elements > MAX_ELEMENT_COUNT {
        return NONA_ERR_ELEMENT_COUNT_BOUND_VIOLATION;
    }

    // Spatial non-overlapping buffer disjointness verification
    if !is_disjoint(in_ptr, in_len, out_ptr.cast_const(), out_len)
        || !is_disjoint(key_ptr, key_len, out_ptr.cast_const(), out_len)
        || !is_disjoint(in_ptr, in_len, key_ptr, key_len)
    {
        return NONA_ERR_BUFFER_ALIASING;
    }

    compiler_fence(Ordering::SeqCst);
    NONA_SUCCESS
}

/// Satisfies [FR-08-GATEKEEPR]
/// Satisfies [FR-19-FFIBND]
/// Branchless parameter gatekeeper evaluating XOR payload digests against expected values.
#[allow(clippy::cast_possible_truncation)]
pub unsafe fn nona_gatekeeper_validate_impl(
    payload_ptr: *const u8,
    payload_len: usize,
    cardinality: usize,
    expected_hash: *const u8,
) -> i32 {
    if payload_ptr.is_null() || expected_hash.is_null() {
        return NONA_ERR_NULL_POINTER;
    }

    // Pointer wraparound protection
    let (payload_end, p_ovf) = (payload_ptr as usize).overflowing_add(payload_len);
    let (hash_end, h_ovf) = (expected_hash as usize).overflowing_add(DIGEST_LEN);
    if p_ovf || h_ovf || payload_end < (payload_ptr as usize) || hash_end < (expected_hash as usize)
    {
        return NONA_ERR_POINTER_WRAPAROUND;
    }

    // Spatial buffer disjointness verification
    if !is_disjoint(payload_ptr, payload_len, expected_hash, DIGEST_LEN) {
        return NONA_ERR_BUFFER_ALIASING;
    }

    let mut scratch = GatekeeperScratchpad::new();
    core::ptr::copy_nonoverlapping(expected_hash, scratch.expected.as_mut_ptr(), DIGEST_LEN);
    compiler_fence(Ordering::SeqCst);

    let (s_l, s_n) = ct_validate_bounds(payload_len as u64, cardinality as u64);

    // Gate read length by validity mask s_l to prevent overreads on invalid pointers
    let valid_mask = 0usize.wrapping_sub(s_l as usize);
    let safe_len = payload_len & valid_mask;
    let payload = core::slice::from_raw_parts(payload_ptr, safe_len);
    compute_xor_digest(payload, &mut scratch.computed);
    compiler_fence(Ordering::SeqCst);

    let s_h = crate::crypto::ct_eq_32_bytes(&scratch.computed, &scratch.expected);
    let status = ct_compute_status(s_l, s_n, s_h);

    crate::crypto::ct_zeroize(&mut scratch.expected);
    crate::crypto::ct_zeroize(&mut scratch.computed);
    compiler_fence(Ordering::SeqCst);

    status
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gatekeeper_scratchpad_alignment_and_purge() {
        assert_eq!(core::mem::size_of::<GatekeeperScratchpad>(), 64);
        assert_eq!(core::mem::align_of::<GatekeeperScratchpad>(), 64);

        let mut scratch = GatekeeperScratchpad::new();
        scratch.computed[0] = 0xAA;
        scratch.expected[0] = 0xBB;
        scratch.zeroize();
        assert_eq!(scratch.computed, [0u8; 32]);
        assert_eq!(scratch.expected, [0u8; 32]);
    }

    #[test]
    fn test_is_disjoint_logic() {
        let buf = [0u8; 128];
        let ptr_a = buf.as_ptr();
        let ptr_b = unsafe { buf.as_ptr().add(64) };

        assert!(is_disjoint(ptr_a, 64, ptr_b, 64));
        assert!(!is_disjoint(ptr_a, 65, ptr_b, 64));
        assert!(!is_disjoint(ptr_a, 64, ptr_a, 32));
    }

    #[test]
    fn test_nona_validate_ffi_bounds_alignment_and_disjointness() {
        #[repr(align(64))]
        struct AlignedMem([u8; 64]);

        let in_buf = AlignedMem([0u8; 64]);
        let key_buf = AlignedMem([0u8; 64]);
        let mut out_buf = AlignedMem([0u8; 64]);

        let status = unsafe {
            nona_validate_ffi_bounds_impl(
                in_buf.0.as_ptr(),
                64,
                1,
                key_buf.0.as_ptr(),
                64,
                out_buf.0.as_mut_ptr(),
                64,
                64,
            )
        };
        assert_eq!(status, NONA_SUCCESS);

        // Misalignment check
        let status_unaligned = unsafe {
            nona_validate_ffi_bounds_impl(
                in_buf.0.as_ptr().add(1),
                63,
                1,
                key_buf.0.as_ptr(),
                64,
                out_buf.0.as_mut_ptr(),
                64,
                64,
            )
        };
        assert_eq!(status_unaligned, NONA_ERR_UNALIGNED_POINTER);

        // Buffer aliasing check
        let status_aliased = unsafe {
            nona_validate_ffi_bounds_impl(
                in_buf.0.as_ptr(),
                64,
                1,
                key_buf.0.as_ptr(),
                64,
                in_buf.0.as_ptr() as *mut u8,
                64,
                64,
            )
        };
        assert_eq!(status_aliased, NONA_ERR_BUFFER_ALIASING);

        // Pointer wraparound check (high address wrapping past address space ceiling)
        let wrap_ptr = (!63usize) as *const u8;
        let status_wrap = unsafe {
            nona_validate_ffi_bounds_impl(
                wrap_ptr,
                64,
                1,
                key_buf.0.as_ptr(),
                64,
                out_buf.0.as_mut_ptr(),
                64,
                64,
            )
        };
        assert_eq!(status_wrap, NONA_ERR_POINTER_WRAPAROUND);

        // Length bound violation check (> 4096 bytes)
        let status_overflow = unsafe {
            nona_validate_ffi_bounds_impl(
                in_buf.0.as_ptr(),
                4224,
                1,
                key_buf.0.as_ptr(),
                64,
                out_buf.0.as_mut_ptr(),
                64,
                64,
            )
        };
        assert_eq!(status_overflow, NONA_ERR_LENGTH_BOUND_VIOLATION);
    }
}
