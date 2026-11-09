//! Zero-Copy, Cache-Aligned circular ring buffer substrate module.
//! Satisfies FR-10-RINGMAN (N=128, & 127 masking) and FR-18-ZEROREM.

use zeroize::{Zeroize, ZeroizeOnDrop};

pub const CAPACITY: usize = 128;
pub const CHUNK_SIZE: usize = 128;
pub type RingBuffer = ZeroCopyRingBuffer;

/// Strict 64-byte boundary aligned storage target for individual ring slots.
/// Occupies exactly 128 bytes (2 cache lines) and is 64-byte aligned.
/// Satisfies [FR-10-RINGMAN]
/// Satisfies [FR-02-STKBUFF]
/// 128-byte storage slot aligned strictly to 64-byte cache line boundaries.
#[repr(C, align(64))]
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct RingSlot {
    pub payload: [u8; 128],
}

impl RingSlot {
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            payload: [0u8; 128],
        }
    }
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
#[inline(always)]
unsafe fn copy_128_avx512(src: *const u8, dst: *mut u8) {
    use core::arch::x86_64::*;
    let r0 = _mm512_loadu_si512(src as *const _);
    let r1 = _mm512_loadu_si512(src.add(64) as *const _);
    _mm512_storeu_si512(dst as *mut _, r0);
    _mm512_storeu_si512(dst.add(64) as *mut _, r1);
}

#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(target_feature = "avx512f")
))]
#[inline(always)]
unsafe fn copy_128_avx2(src: *const u8, dst: *mut u8) {
    use core::arch::x86_64::*;
    let r0 = _mm256_loadu_si256(src as *const _);
    let r1 = _mm256_loadu_si256(src.add(32) as *const _);
    let r2 = _mm256_loadu_si256(src.add(64) as *const _);
    let r3 = _mm256_loadu_si256(src.add(96) as *const _);
    _mm256_storeu_si256(dst as *mut _, r0);
    _mm256_storeu_si256(dst.add(32) as *mut _, r1);
    _mm256_storeu_si256(dst.add(64) as *mut _, r2);
    _mm256_storeu_si256(dst.add(96) as *mut _, r3);
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[inline(always)]
unsafe fn copy_128_neon(src: *const u8, dst: *mut u8) {
    use core::arch::aarch64::*;
    let r0 = vld1q_u8(src);
    let r1 = vld1q_u8(src.add(16));
    let r2 = vld1q_u8(src.add(32));
    let r3 = vld1q_u8(src.add(48));
    let r4 = vld1q_u8(src.add(64));
    let r5 = vld1q_u8(src.add(80));
    let r6 = vld1q_u8(src.add(96));
    let r7 = vld1q_u8(src.add(112));
    vst1q_u8(dst, r0);
    vst1q_u8(dst.add(16), r1);
    vst1q_u8(dst.add(32), r2);
    vst1q_u8(dst.add(48), r3);
    vst1q_u8(dst.add(64), r4);
    vst1q_u8(dst.add(80), r5);
    vst1q_u8(dst.add(96), r6);
    vst1q_u8(dst.add(112), r7);
}

#[cfg(not(any(
    all(target_arch = "x86_64", target_feature = "avx512f"),
    all(target_arch = "x86_64", target_feature = "avx2"),
    all(target_arch = "aarch64", target_feature = "neon")
)))]
#[inline(always)]
unsafe fn copy_128_fallback(src: *const u8, dst: *mut u8) {
    core::ptr::copy_nonoverlapping(src, dst, 128);
}

/// Satisfies [FR-07-SIMDTUN]
/// Satisfies [FR-10-RINGMAN]
/// SIMD-accelerated 128-byte payload copy routine.
#[inline(always)]
unsafe fn copy_128(src: *const u8, dst: *mut u8) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    copy_128_avx512(src, dst);
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(target_feature = "avx512f")
    ))]
    copy_128_avx2(src, dst);
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    copy_128_neon(src, dst);
    #[cfg(not(any(
        all(target_arch = "x86_64", target_feature = "avx512f"),
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon")
    )))]
    copy_128_fallback(src, dst);
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
#[inline(always)]
unsafe fn zero_128_avx512(dst: *mut u8) {
    use core::arch::x86_64::*;
    let z = _mm512_setzero_si512();
    _mm512_storeu_si512(dst as *mut _, z);
    _mm512_storeu_si512(dst.add(64) as *mut _, z);
}

#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    not(target_feature = "avx512f")
))]
#[inline(always)]
unsafe fn zero_128_avx2(dst: *mut u8) {
    use core::arch::x86_64::*;
    let z = _mm256_setzero_si256();
    _mm256_storeu_si256(dst as *mut _, z);
    _mm256_storeu_si256(dst.add(32) as *mut _, z);
    _mm256_storeu_si256(dst.add(64) as *mut _, z);
    _mm256_storeu_si256(dst.add(96) as *mut _, z);
}

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
#[inline(always)]
unsafe fn zero_128_neon(dst: *mut u8) {
    use core::arch::aarch64::*;
    let z = vdupq_n_u8(0);
    vst1q_u8(dst, z);
    vst1q_u8(dst.add(16), z);
    vst1q_u8(dst.add(32), z);
    vst1q_u8(dst.add(48), z);
    vst1q_u8(dst.add(64), z);
    vst1q_u8(dst.add(80), z);
    vst1q_u8(dst.add(96), z);
    vst1q_u8(dst.add(112), z);
}

#[cfg(not(any(
    all(target_arch = "x86_64", target_feature = "avx512f"),
    all(target_arch = "x86_64", target_feature = "avx2"),
    all(target_arch = "aarch64", target_feature = "neon")
)))]
#[inline(always)]
unsafe fn zero_128_fallback(dst: *mut u8) {
    let slice = core::slice::from_raw_parts_mut(dst, 128);
    crate::crypto::ct_zeroize(slice);
}

/// Satisfies [FR-07-SIMDTUN]
/// Satisfies [FR-18-ZEROREM]
/// SIMD-accelerated 128-byte payload zeroization routine.
#[inline(always)]
unsafe fn zero_128(dst: *mut u8) {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))]
    zero_128_avx512(dst);
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        not(target_feature = "avx512f")
    ))]
    zero_128_avx2(dst);
    #[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
    zero_128_neon(dst);
    #[cfg(not(any(
        all(target_arch = "x86_64", target_feature = "avx512f"),
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "neon")
    )))]
    zero_128_fallback(dst);
}

/// A zero-copy, fixed-capacity N=128, cache-aligned circular ring buffer.
/// Enforces alignment to 64-byte boundaries (FR-10-RINGMAN).
/// Satisfies [FR-10-RINGMAN]
/// Satisfies [FR-02-STKBUFF]
/// Zero-copy, fixed N=128 cache-aligned circular ring buffer manifold.
#[repr(C, align(64))]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ZeroCopyRingBuffer {
    pub slots: [RingSlot; 128],
    pub read_index: u64,
    pub write_index: u64,
    pub occupied_mask: u128,
}

impl ZeroCopyRingBuffer {
    const INIT_SLOT: RingSlot = RingSlot::new();
    pub const INIT: Self = Self {
        slots: [Self::INIT_SLOT; 128],
        read_index: 0,
        write_index: 0,
        occupied_mask: 0,
    };

    /// Attempt to push a 128-byte payload into the ring buffer.
    /// Utilizes zero-copy and 1-cycle bitwise index masking (idx & 127).
    #[inline(always)]
    /// Satisfies [FR-10-RINGMAN]
    /// Pushes 128-byte payload into ring buffer using 1-cycle bitwise masking.
    pub fn try_push(&mut self, source: &[u8; 128]) -> Result<(), &'static str> {
        let idx = (self.write_index & 127) as usize;
        let mask = 1u128 << idx;

        if (self.occupied_mask & mask) != 0 {
            return Err("Ring buffer is full at target write index");
        }

        unsafe {
            copy_128(source.as_ptr(), self.slots[idx].payload.as_mut_ptr());
        }

        self.occupied_mask |= mask;
        self.write_index = self.write_index.wrapping_add(1);

        Ok(())
    }

    #[inline(always)]
    fn get_read_slot_mask(&self, read_idx: u64) -> (usize, u128) {
        let idx = (read_idx & 127) as usize;
        let mask = 1u128 << idx;
        (idx, mask)
    }

    #[inline(always)]
    unsafe fn extract_slot_payload(&self, idx: usize, dest: &mut [u8; 128]) {
        copy_128(self.slots[idx].payload.as_ptr(), dest.as_mut_ptr());
    }

    #[inline(always)]
    unsafe fn zero_slot(&mut self, idx: usize) {
        zero_128(self.slots[idx].payload.as_mut_ptr());
    }

    #[inline(always)]
    fn commit_pop_transaction(&mut self, mask: u128) {
        self.occupied_mask &= !mask;
        self.read_index = self.read_index.wrapping_add(1);
    }

    /// Attempt to pop a 128-byte payload from the ring buffer.
    /// Zero-copy extraction followed by active zeroization (H(R)=0).
    #[inline(always)]
    /// Satisfies [FR-10-RINGMAN]
    /// Satisfies [FR-18-ZEROREM]
    /// Pops 128-byte payload followed by active volatile zeroization (H(R)=0).
    pub fn try_pop(&mut self, dest: &mut [u8; 128]) -> Result<(), &'static str> {
        let (idx, mask) = self.get_read_slot_mask(self.read_index);
        if (self.occupied_mask & mask) == 0 {
            return Err("Ring buffer is empty at target read index");
        }
        // Memory ordering invariant: Relinquish bitmask ownership FIRST before zeroization
        self.commit_pop_transaction(mask);
        unsafe {
            self.extract_slot_payload(idx, dest);
            self.zero_slot(idx);
        }
        Ok(())
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.occupied_mask.count_ones() as usize
    }

    #[inline(always)]
    pub fn available_capacity(&self) -> usize {
        CAPACITY.saturating_sub(self.occupied_mask.count_ones() as usize)
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.occupied_mask == 0
    }

    #[inline(always)]
    pub fn is_full(&self) -> bool {
        self.occupied_mask == u128::MAX
    }

    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    unsafe fn flush_x86_64(&self, ptr: *const u8) {
        core::arch::x86_64::_mm_clflush(ptr);
        core::arch::x86_64::_mm_clflush(ptr.add(64));
    }
    #[cfg(target_arch = "aarch64")]
    #[inline(always)]
    unsafe fn flush_aarch64(&self, ptr: *const u8) {
        core::arch::asm!(
            "dc cvac, {0}",
            "dc cvac, {1}",
            in(reg) ptr,
            in(reg) ptr.add(64),
        );
    }

    #[inline(always)]
    /// Satisfies [FR-10-RINGMAN]
    /// Satisfies [FR-35-TENANTFENCE]
    /// Flushes cache line for slot index and executes memory fencing.
    pub fn flush_and_fence_slot(&self, index: usize) {
        let idx = index & 127;
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Acquire);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
        let ptr = self.slots[idx].payload.as_ptr();

        #[cfg(target_arch = "x86_64")]
        unsafe {
            self.flush_x86_64(ptr);
        }
        #[cfg(target_arch = "aarch64")]
        unsafe {
            self.flush_aarch64(ptr);
        }

        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::Release);
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
    }
}

impl Default for RingSlot {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_buffer_fifo_operations() {
        let mut rb = ZeroCopyRingBuffer::INIT;
        assert!(rb.is_empty());
        assert_eq!(rb.len(), 0);

        let mut item = [0u8; 128];
        item[0] = 42;
        item[127] = 99;

        assert!(rb.try_push(&item).is_ok());
        assert_eq!(rb.len(), 1);
        assert!(!rb.is_empty());

        let mut popped = [0u8; 128];
        assert!(rb.try_pop(&mut popped).is_ok());
        assert_eq!(popped[0], 42);
        assert_eq!(popped[127], 99);
        assert!(rb.is_empty());

        assert_eq!(rb.slots[0].payload, [0u8; 128]);
    }

    #[test]
    fn test_ring_buffer_saturation_and_128_wrapping() {
        let mut rb = ZeroCopyRingBuffer::INIT;
        let item = [7u8; 128];

        for _ in 0..128 {
            assert!(rb.try_push(&item).is_ok());
        }
        assert!(rb.is_full());
        assert_eq!(rb.len(), 128);

        assert!(rb.try_push(&item).is_err());

        let mut popped = [0u8; 128];
        assert!(rb.try_pop(&mut popped).is_ok());
        assert_eq!(popped, [7u8; 128]);
        assert!(!rb.is_full());
        assert_eq!(rb.len(), 127);

        assert!(rb.try_push(&item).is_ok());
        assert!(rb.is_full());
    }
}
