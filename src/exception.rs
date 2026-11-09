//! Exception Containment Engine.
//! Handles sliding window trackers and volatile decontamination in constant-time,
//! branchless, zero-allocation primitives.

use core::sync::atomic::Ordering;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const EVALUATION_WINDOW_BOUNDARY: u64 = 1000;

/// Satisfies [FR-20-ABRTGATE]
/// Satisfies [FR-02-STKBUFF]
/// 64-byte L1 cache-aligned Exception Control Block governing sliding error rates.
#[repr(C, align(64))]
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ExceptionControlBlock {
    /// Global total monotonic count
    pub g_total: u64,
    /// Global exception monotonic count
    pub g_err: u64,
    /// Sliding window total tracker
    pub w_total: u64,
    /// Sliding window exception tracker
    pub w_err: u64,
    /// Ring buffer write cursor index
    pub c_write: u64,
    /// Ring buffer read cursor index
    pub c_read: u64,
    /// Cache line alignment reservation padding (64 - 48 = 16 bytes)
    pub _padding: [u8; 16],
}

impl ExceptionControlBlock {
    /// Create a new zero-initialized ExceptionControlBlock.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            g_total: 0,
            g_err: 0,
            w_total: 0,
            w_err: 0,
            c_write: 0,
            c_read: 0,
            _padding: [0u8; 16],
        }
    }

    /// Advance `c_write` by 1 if `e_i == 0`; advance by 0 if `e_i == 1`
    /// using wrapping branchless bitwise operations without conditional jumps.
    #[inline(always)]
    /// Satisfies [FR-20-ABRTGATE]
    /// Advance write cursor using wrapping branchless bitwise operations.
    pub fn update_write_cursor(&mut self, e_i: u8) {
        // Delta = ((e_i - 1) >> 63) & 1
        let delta = (((e_i as u64).wrapping_sub(1)) >> 63) & 1;
        self.c_write = self.c_write.wrapping_add(delta);
    }

    /// Satisfies [FR-20-ABRTGATE]
    /// Evaluate sliding window over a 1,000-iteration boundary.
    #[inline(always)]
    pub fn evaluate_window(&mut self, e_i: u8, theta: u64) -> i32 {
        let w_total_next = self.w_total.wrapping_add(1);
        let e_bit = (e_i != 0) as u64;
        let w_err_next = self.w_err.wrapping_add(e_bit);

        // Determine if we have reached the 1,000-iteration boundary
        let diff = w_total_next.wrapping_sub(EVALUATION_WINDOW_BOUNDARY);
        let nz = ((diff | diff.wrapping_neg()) >> 63) & 1;
        let comp = nz ^ 1;

        // Reset mask: m_keep = comp - 1
        // If comp is 1 (reached 1000), m_keep is 0x0 (all zeros)
        // If comp is 0 (not reached), m_keep is 0xFFFFFFFF_FFFFFFFF (all ones)
        let m_keep = comp.wrapping_sub(1);

        // Apply reset mask
        self.w_total = w_total_next & m_keep;
        self.w_err = w_err_next & m_keep;

        // Update global counters continuously without masking
        self.g_total = self.g_total.wrapping_add(1);
        self.g_err = self.g_err.wrapping_add(e_i as u64);

        // Check threshold failure: F = 1 if w_err_next >= theta, 0 otherwise
        let f = ((theta.wrapping_sub(w_err_next.wrapping_add(1))) >> 63) & 1;

        // Compute Status: S = comp * (1 - 4 * F)
        let comp_i32 = (comp & 0x7FFF_FFFF) as i32;
        comp_i32.wrapping_mul(1 - 4 * (f as i32))
    }
}

impl Default for ExceptionControlBlock {
    fn default() -> Self {
        Self::new()
    }
}

/// Satisfies [FR-05-RAMCLR]
/// Satisfies [FR-20-ABRTGATE]
/// Constant-time volatile decontamination of registered active memory buffer.
#[inline]
pub fn decontaminate() {
    let ptr = crate::ACTIVE_BUFFER.load(Ordering::SeqCst);
    let len = crate::ACTIVE_BUFFER_LEN.load(Ordering::SeqCst);
    if !ptr.is_null() && len > 0 {
        // SAFETY: Pointer and length are validated during buffer registration.
        unsafe {
            let slice = core::slice::from_raw_parts_mut(ptr, len);
            crate::crypto::ct_zeroize(slice);
        }
    }
}

/// Satisfies [FR-05-RAMCLR]
/// Safe diverging fallback for panic handlers: zeroizes memory without firing CPU traps (ud2/brk).
#[cold]
pub fn zeroize_and_abort(_code: i32) -> ! {
    decontaminate();
    core::sync::atomic::compiler_fence(Ordering::SeqCst);
    #[cfg(feature = "host-defense")]
    unsafe {
        libc::raise(libc::SIGABRT);
    }
    #[cfg(not(target_os = "none"))]
    unsafe {
        libc::_exit(if _code != 0 { _code as libc::c_int } else { 1 });
    }
    #[cfg(target_os = "none")]
    {
        // Safe for unprivileged enclaves (CPL=3 / EL0): non-trapping spin loop
        loop {
            core::hint::spin_loop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_write_cursor() {
        let mut ecb = ExceptionControlBlock::new();
        assert_eq!(ecb.c_write, 0);

        ecb.update_write_cursor(0);
        assert_eq!(ecb.c_write, 1);

        ecb.update_write_cursor(1);
        assert_eq!(ecb.c_write, 1);
    }

    #[test]
    fn test_decontaminate_zeroizes_buffer() {
        use core::sync::atomic::Ordering;

        let mut buffer = [0xA5u8; 128];
        assert!(
            buffer.iter().any(|&b| b != 0),
            "Canary buffer must initially be non-zero"
        );

        // Register canary buffer as active memory region
        crate::ACTIVE_BUFFER.store(buffer.as_mut_ptr(), Ordering::SeqCst);
        crate::ACTIVE_BUFFER_LEN.store(buffer.len(), Ordering::SeqCst);

        // Execute volatile memory wipe
        decontaminate();

        // Deregister active buffer
        crate::ACTIVE_BUFFER.store(core::ptr::null_mut(), Ordering::SeqCst);
        crate::ACTIVE_BUFFER_LEN.store(0, Ordering::SeqCst);

        // Assert 100% of canary bytes collapsed to 0x00
        assert!(
            buffer.iter().all(|&b| b == 0),
            "Memory remanence detected: decontaminate() failed to zeroize active buffer"
        );
    }
}
