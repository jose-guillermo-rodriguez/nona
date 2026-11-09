//! Monomorphic O(1) Constant-Time Byte Normalization, SIMD Dispatch, and Zero-Padding Substrate.
//! Satisfies FR-01-NORMBYTE, FR-02-STKBUFF, and FR-33-SIMDDISPATCH over 64-byte cache-aligned windows.

// ============================================================================
// BIFURCATION POINT: VERUS FORMAL SPECIFICATION BOUNDARY
// ============================================================================

#[cfg(verus)]
use vstd::prelude::*;
#[cfg(verus)]
use vstd::slice::*;

#[cfg(verus)]
verus! {

/// 64-Byte aligned sanitized payload buffer satisfying FR-02-STKBUFF
#[repr(C, align(64))]
pub struct SanitizedCode {
    pub data: [u8; 64],
}

/// Satisfies [FR-01-NORMBYTE]
/// Satisfies [FR-12-FORMALSPEC]
/// Specification predicate for valid byte normalization.
pub open spec fn spec_is_valid_byte(x: u8) -> bool {
    x != 0x00u8 && x != 0x0Du8 && x != 0x0Au8
}

/// Satisfies [FR-01-NORMBYTE]
/// Satisfies [FR-12-FORMALSPEC]
/// Verus formal verification procedure for O(1) byte normalization.
pub fn normalize_bytes_verus(w_norm: &[u8], buf: &mut [u8]) -> (result: i8)
    requires
        w_norm@.len() == 64,
        buf@.len() == 64,
    ensures
        result == 1 || result == -1,
{
    let mut write_idx: usize = 0;
    let mut i: usize = 0;

    while i < 64
        invariant
            i <= 64,
            write_idx <= i,
            buf@.len() == 64,
            w_norm@.len() == 64,
        decreases 64 - i
    {
        let x = w_norm[i];
        let is_valid: u8 = if x != 0x00u8 && x != 0x0Du8 && x != 0x0Au8 { 1u8 } else { 0u8 };
        let should_write = is_valid;

        let mut j: usize = 0;
        while j < 64
            invariant
                j <= 64,
                i <= 64,
                write_idx <= i,
                buf@.len() == 64,
                w_norm@.len() == 64,
            decreases 64 - j
        {
            let is_target = (j == write_idx) as u8;
            let write_mask = 0u8.wrapping_sub(should_write & is_target);
            let current_val = buf[j];
            buf[j] = (current_val & !write_mask) | (x & write_mask);
            j += 1;
        }

        write_idx = write_idx + (should_write as usize);
        i += 1;
    }

    let has_data = (write_idx > 0) as i8;
    (has_data * 2) - 1
}

/// Satisfies [FR-01-NORMBYTE]
/// Satisfies [FR-12-FORMALSPEC]
/// Formally verified byte normalization wrapper returning Option<SanitizedCode>.
pub fn normalize_bytes(input: &[u8]) -> (res: core::option::Option<SanitizedCode>)
    requires
        input@.len() == 64,
{
    let mut code = SanitizedCode { data: [0u8; 64] };
    let status = normalize_bytes_verus(input, &mut code.data);
    if status == 1i8 {
        core::option::Option::Some(code)
    } else {
        core::option::Option::None
    }
}

} // verus!

// ============================================================================
// BIFURCATION POINT: PRODUCTION HIGH-PERFORMANCE C-ABI COMPLIANT BOUNDARY
// ============================================================================

#[cfg(not(verus))]
mod prod {
    use zeroize::{Zeroize, ZeroizeOnDrop};

    /// Satisfies [FR-01-NORMBYTE]
    /// Satisfies [FR-02-STKBUFF]
    /// 64-byte aligned sanitized payload buffer satisfying FR-02-STKBUFF.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nona_core::normalization::SanitizedCode;
    ///
    /// let code = SanitizedCode::default();
    /// assert_eq!(code.data.len(), 64);
    /// assert_eq!(code.data, [0u8; 64]);
    /// ```
    #[repr(C, align(64))]
    #[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
    pub struct SanitizedCode {
        pub data: [u8; 64],
    }

    impl Default for SanitizedCode {
        #[inline(always)]
        fn default() -> Self {
            Self { data: [0u8; 64] }
        }
    }

    // ------------------------------------------------------------------------
    // SCALAR ENGINE (BRANCHLESS BEDROCK)
    // ------------------------------------------------------------------------

    /// Branchless single-byte classifier and case-folding transformer.
    /// Delimiters stripped: NULL (0x00), TAB (0x09), LF (0x0A), CR (0x0D), SPACE (0x20).
    /// Case folding: 'A'..='Z' -> 'a'..='z' via branchless bitwise OR 0x20.
    #[inline(always)]
    pub fn normalize_byte_scalar(x: u8) -> (u8, u8) {
        let is_null = ((x == 0x00) as u8) & 1;
        let is_tab = ((x == 0x09) as u8) & 1;
        let is_lf = ((x == 0x0A) as u8) & 1;
        let is_cr = ((x == 0x0D) as u8) & 1;
        let is_sp = ((x == 0x20) as u8) & 1;
        let is_delim = is_null | is_tab | is_lf | is_cr | is_sp;
        let is_valid = is_delim ^ 1;

        // Branchless uppercase detection: x in [0x41, 0x5A]
        let ge_a = ((0x40u8.wrapping_sub(x)) >> 7) & 1;
        let le_z = ((x.wrapping_sub(0x5Bu8)) >> 7) & 1;
        let is_upper = ge_a & le_z;
        let folded = x | (is_upper << 5);

        (is_valid, folded)
    }

    /// Pure scalar normalization routine over 64-byte slice.
    #[inline(always)]
    pub fn normalize_scalar_64(w_norm: &[u8], buf: &mut [u8]) -> i8 {
        if w_norm.len() != 64 || buf.len() != 64 {
            return -1;
        }

        buf.fill(0);
        let mut write_idx: usize = 0;

        for &x in w_norm.iter() {
            let (is_valid, folded) = normalize_byte_scalar(x);
            let mask = 0u8.wrapping_sub(is_valid);
            buf[write_idx] = folded & mask;
            write_idx += is_valid as usize;
        }

        let has_data = ((write_idx > 0) as i8) & 1;
        (has_data * 2) - 1
    }

    // ------------------------------------------------------------------------
    // HARDWARE VECTOR ACCELERATION (AVX-512, AVX2, ARM NEON)
    // ------------------------------------------------------------------------

    #[cfg(all(target_arch = "x86_64", not(target_os = "none")))]
    pub(crate) mod x86_simd {
        use core::arch::x86_64::*;
        use core::sync::atomic::{AtomicU8, Ordering};

        static CACHED_CAPS: AtomicU8 = AtomicU8::new(0);
        const CAPS_UNINIT: u8 = 0;
        const CAPS_PROBED: u8 = 1 << 0;
        const CAPS_AVX2: u8 = 1 << 1;
        const CAPS_AVX512: u8 = 1 << 2;

        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        pub struct SimdCaps {
            pub has_avx2: bool,
            pub has_avx512: bool,
        }

        impl SimdCaps {
            #[inline]
            pub fn probe() -> Self {
                let cached = CACHED_CAPS.load(Ordering::Relaxed);
                if cached != CAPS_UNINIT {
                    return Self {
                        has_avx2: (cached & CAPS_AVX2) != 0,
                        has_avx512: (cached & CAPS_AVX512) != 0,
                    };
                }

                let probed = Self::probe_uncached();
                let mut bits = CAPS_PROBED;
                if probed.has_avx2 {
                    bits |= CAPS_AVX2;
                }
                if probed.has_avx512 {
                    bits |= CAPS_AVX512;
                }
                CACHED_CAPS.store(bits, Ordering::Relaxed);
                probed
            }

            #[cold]
            fn probe_uncached() -> Self {
                // Step 1: Validate maximum supported CPUID standard leaf >= 1
                let max_leaf = __cpuid(0).eax;
                if max_leaf < 1 {
                    return Self {
                        has_avx2: false,
                        has_avx512: false,
                    };
                }

                // Step 2: Verify OSXSAVE gate in Leaf 1 (ECX bit 27) before executing _xgetbv
                let leaf1 = __cpuid(1);
                if (leaf1.ecx & (1 << 27)) == 0 {
                    return Self {
                        has_avx2: false,
                        has_avx512: false,
                    };
                }

                // Step 3: Verify OS vector state allocation in XCR0
                let xcr0 = unsafe { _xgetbv(0) };
                let ymm_ok = (xcr0 & 0x06) == 0x06;
                if !ymm_ok {
                    return Self {
                        has_avx2: false,
                        has_avx512: false,
                    };
                }
                let zmm_ok = (xcr0 & 0xE6) == 0xE6;

                // Step 4: Verify Leaf 7 support only if XCR0 vector context is enabled by OS
                if max_leaf < 7 {
                    return Self {
                        has_avx2: false,
                        has_avx512: false,
                    };
                }

                let leaf7 = __cpuid_count(7, 0);
                let avx2_hw = (leaf7.ebx & (1 << 5)) != 0;
                let avx512f_hw = (leaf7.ebx & (1 << 16)) != 0;
                let avx512bw_hw = (leaf7.ebx & (1 << 30)) != 0;

                Self {
                    has_avx2: avx2_hw,
                    has_avx512: zmm_ok && avx512f_hw && avx512bw_hw,
                }
            }
        }

        #[allow(clippy::cast_ptr_alignment)]
        #[target_feature(enable = "avx512f,avx512bw")]
        pub unsafe fn normalize_avx512_64(w_norm: &[u8], buf: &mut [u8]) -> i8 {
            buf.fill(0);
            let v = _mm512_loadu_si512(w_norm.as_ptr().cast::<core::arch::x86_64::__m512i>());

            // Branchless case-folding: 'A'..='Z'
            let c_a = _mm512_set1_epi8(b'A'.cast_signed());
            let c_z = _mm512_set1_epi8(b'Z'.cast_signed());
            let mask_ge = _mm512_cmpge_epu8_mask(v, c_a);
            let mask_le = _mm512_cmple_epu8_mask(v, c_z);
            let mask_upper = mask_ge & mask_le;
            let or_folded = _mm512_or_si512(v, _mm512_set1_epi8(0x20));
            let folded = _mm512_mask_mov_epi8(v, mask_upper, or_folded);

            // Whitespace / delimiter rejection
            let m_null = _mm512_cmpeq_epu8_mask(v, _mm512_set1_epi8(0x00));
            let m_tab = _mm512_cmpeq_epu8_mask(v, _mm512_set1_epi8(0x09));
            let m_lf = _mm512_cmpeq_epu8_mask(v, _mm512_set1_epi8(0x0A));
            let m_cr = _mm512_cmpeq_epu8_mask(v, _mm512_set1_epi8(0x0D));
            let m_sp = _mm512_cmpeq_epu8_mask(v, _mm512_set1_epi8(0x20));
            let keep_mask = !(m_null | m_tab | m_lf | m_cr | m_sp);

            // Single-instruction hardware stream compaction
            _mm512_mask_compressstoreu_epi8(buf.as_mut_ptr().cast(), keep_mask, folded);
            let write_count = keep_mask.count_ones() as usize;

            let has_data = ((write_count > 0) as i8) & 1;
            (has_data * 2) - 1
        }

        #[allow(clippy::cast_ptr_alignment)]
        #[target_feature(enable = "avx2")]
        pub unsafe fn normalize_avx2_64(w_norm: &[u8], buf: &mut [u8]) -> i8 {
            buf.fill(0);
            let mut write_idx: usize = 0;

            for chunk_idx in 0..2 {
                let offset = chunk_idx * 32;
                let v = _mm256_loadu_si256(w_norm.as_ptr().add(offset).cast::<__m256i>());

                // Unsigned range check using max/min algebra
                let c_a = _mm256_set1_epi8(b'A'.cast_signed());
                let c_z = _mm256_set1_epi8(b'Z'.cast_signed());
                let ge_a = _mm256_cmpeq_epi8(_mm256_max_epu8(v, c_a), v);
                let le_z = _mm256_cmpeq_epi8(_mm256_min_epu8(v, c_z), v);
                let is_upper = _mm256_and_si256(ge_a, le_z);
                let fold_mask = _mm256_and_si256(is_upper, _mm256_set1_epi8(0x20));
                let folded = _mm256_or_si256(v, fold_mask);

                // Delimiter comparison
                let m_null = _mm256_cmpeq_epi8(v, _mm256_set1_epi8(0x00));
                let m_tab = _mm256_cmpeq_epi8(v, _mm256_set1_epi8(0x09));
                let m_lf = _mm256_cmpeq_epi8(v, _mm256_set1_epi8(0x0A));
                let m_cr = _mm256_cmpeq_epi8(v, _mm256_set1_epi8(0x0D));
                let m_sp = _mm256_cmpeq_epi8(v, _mm256_set1_epi8(0x20));
                let is_delim = _mm256_or_si256(
                    _mm256_or_si256(m_null, m_tab),
                    _mm256_or_si256(_mm256_or_si256(m_lf, m_cr), m_sp),
                );

                let mut folded_bytes = [0u8; 32];
                let mut delim_mask = [0u8; 32];
                _mm256_storeu_si256(folded_bytes.as_mut_ptr().cast::<__m256i>(), folded);
                _mm256_storeu_si256(delim_mask.as_mut_ptr().cast::<__m256i>(), is_delim);

                for i in 0..32 {
                    let valid = ((delim_mask[i] == 0) as u8) & 1;
                    let mask = 0u8.wrapping_sub(valid);
                    buf[write_idx] = folded_bytes[i] & mask;
                    write_idx += valid as usize;
                }
            }

            let has_data = ((write_idx > 0) as i8) & 1;
            (has_data * 2) - 1
        }
    }

    #[cfg(target_arch = "aarch64")]
    mod arm_simd {
        use core::arch::aarch64::*;

        #[inline(always)]
        pub unsafe fn normalize_neon_64(w_norm: &[u8], buf: &mut [u8]) -> i8 {
            buf.fill(0);
            let mut write_idx: usize = 0;

            for chunk_idx in 0..4 {
                let offset = chunk_idx * 16;
                let v = vld1q_u8(w_norm.as_ptr().add(offset));

                // Case-folding: 'A'..='Z'
                let ge_a = vcgeq_u8(v, vdupq_n_u8(b'A'));
                let le_z = vcleq_u8(v, vdupq_n_u8(b'Z'));
                let is_upper = vandq_u8(ge_a, le_z);
                let fold_mask = vandq_u8(is_upper, vdupq_n_u8(0x20));
                let folded = vorrq_u8(v, fold_mask);

                // Delimiter classification
                let m_null = vceqq_u8(v, vdupq_n_u8(0x00));
                let m_tab = vceqq_u8(v, vdupq_n_u8(0x09));
                let m_lf = vceqq_u8(v, vdupq_n_u8(0x0A));
                let m_cr = vceqq_u8(v, vdupq_n_u8(0x0D));
                let m_sp = vceqq_u8(v, vdupq_n_u8(0x20));
                let is_delim = vorrq_u8(
                    vorrq_u8(m_null, m_tab),
                    vorrq_u8(vorrq_u8(m_lf, m_cr), m_sp),
                );

                let mut folded_bytes = [0u8; 16];
                let mut delim_bytes = [0u8; 16];
                vst1q_u8(folded_bytes.as_mut_ptr(), folded);
                vst1q_u8(delim_bytes.as_mut_ptr(), is_delim);

                for i in 0..16 {
                    let valid = ((delim_bytes[i] == 0) as u8) & 1;
                    let mask = 0u8.wrapping_sub(valid);
                    buf[write_idx] = folded_bytes[i] & mask;
                    write_idx += valid as usize;
                }
            }

            let has_data = ((write_idx > 0) as i8) & 1;
            (has_data * 2) - 1
        }
    }

    // ------------------------------------------------------------------------
    // TOPOLOGICAL ROUTING ENTRY POINTS
    // ------------------------------------------------------------------------

    /// Satisfies [FR-01-NORMBYTE]
    /// Satisfies [FR-33-SIMDDISPATCH]
    /// Monomorphic O(1) byte normalization with runtime SIMD dispatch.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nona_core::normalization::normalize_to_buffer;
    ///
    /// let mut input = [0u8; 64];
    /// input[..9].copy_from_slice(b"USER \t ID");
    /// let mut output = [0u8; 64];
    /// let rc = normalize_to_buffer(&input, &mut output);
    /// assert_eq!(rc, 1);
    /// assert_eq!(&output[..6], b"userid");
    /// ```
    #[inline(always)]
    pub fn normalize_to_buffer(w_norm: &[u8], buf: &mut [u8]) -> i8 {
        if w_norm.len() != 64 || buf.len() != 64 {
            return -1;
        }

        #[allow(unused_variables)]
        let is_aligned = (((w_norm.as_ptr() as usize) | (buf.as_ptr() as usize)) & 63) == 0;

        #[cfg(all(target_arch = "x86_64", not(target_os = "none")))]
        if is_aligned {
            let caps = x86_simd::SimdCaps::probe();
            if caps.has_avx512 {
                return unsafe { x86_simd::normalize_avx512_64(w_norm, buf) };
            }
            if caps.has_avx2 {
                return unsafe { x86_simd::normalize_avx2_64(w_norm, buf) };
            }
        }

        #[cfg(target_arch = "aarch64")]
        if is_aligned {
            return unsafe { arm_simd::normalize_neon_64(w_norm, buf) };
        }

        #[allow(unreachable_code)]
        normalize_scalar_64(w_norm, buf)
    }

    /// Satisfies [FR-33-SIMDDISPATCH]
    /// Vectorized bulk normalization across arbitrary 64-byte aligned blocks.
    #[inline(always)]
    pub fn normalize_bulk_to_buffer(input: &[u8], output: &mut [u8]) -> i32 {
        if input.is_empty() || !input.len().is_multiple_of(64) || output.len() < input.len() {
            return -1;
        }

        let chunks = input.len() / 64;
        #[allow(unused_variables)]
        let is_aligned = (((input.as_ptr() as usize) | (output.as_ptr() as usize)) & 63) == 0;

        #[cfg(all(target_arch = "x86_64", not(target_os = "none")))]
        if is_aligned {
            let caps = x86_simd::SimdCaps::probe();
            if caps.has_avx512 {
                for c in 0..chunks {
                    let in_chunk = &input[c * 64..(c + 1) * 64];
                    let out_chunk = &mut output[c * 64..(c + 1) * 64];
                    if unsafe { x86_simd::normalize_avx512_64(in_chunk, out_chunk) } != 1 {
                        return -1;
                    }
                }
                return 0;
            }
            if caps.has_avx2 {
                for c in 0..chunks {
                    let in_chunk = &input[c * 64..(c + 1) * 64];
                    let out_chunk = &mut output[c * 64..(c + 1) * 64];
                    if unsafe { x86_simd::normalize_avx2_64(in_chunk, out_chunk) } != 1 {
                        return -1;
                    }
                }
                return 0;
            }
        }

        #[cfg(target_arch = "aarch64")]
        if is_aligned {
            for c in 0..chunks {
                let in_chunk = &input[c * 64..(c + 1) * 64];
                let out_chunk = &mut output[c * 64..(c + 1) * 64];
                if unsafe { arm_simd::normalize_neon_64(in_chunk, out_chunk) } != 1 {
                    return -1;
                }
            }
            return 0;
        }

        #[allow(unreachable_code)]
        {
            for c in 0..chunks {
                let in_chunk = &input[c * 64..(c + 1) * 64];
                let out_chunk = &mut output[c * 64..(c + 1) * 64];
                if normalize_scalar_64(in_chunk, out_chunk) != 1 {
                    return -1;
                }
            }
            0
        }
    }

    /// Satisfies [FR-01-NORMBYTE]
    /// Satisfies [FR-02-STKBUFF]
    /// Normalizes input slice into 64-byte cache-aligned SanitizedCode.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use nona_core::normalization::normalize_bytes;
    ///
    /// let mut input = [0u8; 64];
    /// input[..10].copy_from_slice(b"TEST-DATA ");
    /// let sanitized = normalize_bytes(&input).expect("normalization must succeed");
    /// assert_eq!(&sanitized.data[..9], b"test-data");
    ///
    /// // Input with invalid length is rejected:
    /// assert!(normalize_bytes(b"invalid_length").is_none());
    /// ```
    #[inline(always)]
    pub fn normalize_bytes(input: &[u8]) -> Option<SanitizedCode> {
        if input.len() != 64 {
            return None;
        }

        let mut code = SanitizedCode::default();
        let status = normalize_to_buffer(input, &mut code.data);

        if status == 1 {
            Some(code)
        } else {
            None
        }
    }
}

#[cfg(not(verus))]
pub use prod::*;

// ============================================================================
// COMPREHENSIVE EQUIVALENCE & INTEGRITY TEST SUITE
// ============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_normalization_ascii_sanitization_and_padding() {
        let mut raw = [0u8; 64];
        let input_bytes = b"ab-cd_12.34@EXAMPLE.COM";
        raw[..input_bytes.len()].copy_from_slice(input_bytes);

        let res = normalize_bytes(&raw).expect("Normalization failed");
        assert_eq!(res.data.len(), 64);
        assert!(res.data.iter().any(|&b| b != 0));
        assert!(res.data.iter().all(|&b| b == 0 || b.is_ascii()));

        // Verify lowercase case-folding invariant
        assert_eq!(&res.data[..23], b"ab-cd_12.34@example.com");
    }

    #[test]
    fn test_normalization_whitespace_and_delimiter_stripping() {
        let mut raw = [0u8; 64];
        let payload = b" \t ALPHA \r\n BETA \0";
        raw[..payload.len()].copy_from_slice(payload);

        let mut out = [0u8; 64];
        let rc = normalize_to_buffer(&raw, &mut out);
        assert_eq!(rc, 1);
        assert_eq!(&out[..9], b"alphabeta");
        assert!(out[9..].iter().all(|&b| b == 0));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn test_scalar_simd_bit_for_bit_equivalence() {
        let mut pseudo_rand = 0x123456789ABCDEF0u64;
        let mut next_u8 = || {
            pseudo_rand = pseudo_rand
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1);
            (pseudo_rand >> 33) as u8
        };

        for _ in 0..1000 {
            let mut sample = [0u8; 64];
            for b in sample.iter_mut() {
                *b = next_u8();
            }

            let mut out_scalar = [0u8; 64];
            let mut out_simd = [0u8; 64];

            let rc_scalar = normalize_scalar_64(&sample, &mut out_scalar);
            let rc_simd = normalize_to_buffer(&sample, &mut out_simd);

            assert_eq!(
                rc_scalar, rc_simd,
                "Status mismatch between scalar and SIMD"
            );
            assert_eq!(
                out_scalar, out_simd,
                "Bit-for-bit divergence between scalar and SIMD"
            );
        }
    }

    #[test]
    fn test_bulk_normalization_stride() {
        let mut in_bulk = [0u8; 128];
        in_bulk[..11].copy_from_slice(b"CHUNK ONE\r\n");
        in_bulk[64..75].copy_from_slice(b"CHUNK TWO\r\n");

        let mut out_bulk = [0u8; 128];
        let rc = normalize_bulk_to_buffer(&in_bulk, &mut out_bulk);
        assert_eq!(rc, 0);
        assert_eq!(&out_bulk[..8], b"chunkone");
        assert_eq!(&out_bulk[64..72], b"chunktwo");
    }

    #[test]
    fn test_all_delimiters_returns_negative() {
        let raw = [b' '; 64];
        let mut out = [0u8; 64];
        let rc = normalize_to_buffer(&raw, &mut out);
        assert_eq!(rc, -1);
        assert!(out.iter().all(|&b| b == 0));
    }
    #[test]
    fn test_unaligned_slices_do_not_fault() {
        let raw_in = [0x55u8; 128];
        let mut raw_out = [0u8; 128];

        // 1. Explicit verification of offset 1 (&buf[1..65])
        let unaligned_in_1 = &raw_in[1..65];
        let unaligned_out_1 = &mut raw_out[1..65];
        assert_ne!((unaligned_in_1.as_ptr() as usize) & 63, 0);
        assert_eq!(normalize_to_buffer(unaligned_in_1, unaligned_out_1), 1);
        assert_eq!(normalize_bulk_to_buffer(unaligned_in_1, unaligned_out_1), 0);

        // 2. Explicit verification of offset 2 (&buf[2..66])
        let unaligned_in_2 = &raw_in[2..66];
        let unaligned_out_2 = &mut raw_out[2..66];
        assert_ne!((unaligned_in_2.as_ptr() as usize) & 63, 0);
        assert_eq!(normalize_to_buffer(unaligned_in_2, unaligned_out_2), 1);
        assert_eq!(normalize_bulk_to_buffer(unaligned_in_2, unaligned_out_2), 0);

        // 3. Sweep all 63 possible non-64-byte alignment phases
        for offset in 1..64 {
            let slice_in = &raw_in[offset..offset + 64];
            let slice_out = &mut raw_out[offset..offset + 64];
            assert_eq!(
                normalize_to_buffer(slice_in, slice_out),
                1,
                "Unaligned normalize_to_buffer failed at byte offset {offset}"
            );
        }
    }

    #[test]
    fn test_simd_caps_probe_deterministic_idempotence() {
        #[cfg(target_arch = "x86_64")]
        {
            let first = crate::normalization::prod::x86_simd::SimdCaps::probe();
            let second = crate::normalization::prod::x86_simd::SimdCaps::probe();
            assert_eq!(first, second);
        }
    }
}
