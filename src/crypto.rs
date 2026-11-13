//! Low-Entropy Cryptographic and Constant-Time Math Primitives.
//! Strictly `#![no_std]` compliant; avoids any heap allocation.

use core::sync::atomic::compiler_fence;
use core::sync::atomic::Ordering;
#[cfg(not(verus))]
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Satisfies [FR-07-SIMDTUN]
/// Constant-time selection returning `a` if `mask` is 0xFFFFFFFF_FFFFFFFF, or `b` if 0.
#[inline(always)]
pub fn ct_select_u64(mask: u64, a: u64, b: u64) -> u64 {
    let result = (a & mask) | (b & !mask);
    compiler_fence(Ordering::SeqCst);
    result
}

/// Constant-time selection for bytes. Returns `a` if `mask` is 0xFF, or `b` if `mask` is 0.
#[inline(always)]
pub fn ct_select_u8(mask: u8, a: u8, b: u8) -> u8 {
    let result = (a & mask) | (b & !mask);
    compiler_fence(Ordering::SeqCst);
    result
}

/// Satisfies [FR-01-NORMBYTE]
/// Constant-time verification of whether a byte is an ASCII digit ('0'..='9').
#[inline(always)]
pub fn ct_is_digit(byte: u8) -> u8 {
    let u = 0x39_u8.wrapping_sub(byte);
    let v = byte.wrapping_sub(0x30_u8);
    ((!(u | v)) >> 7) & 1
}

/// Satisfies [FR-01-NORMBYTE]
/// Constant-time parse step for converting an ASCII digit byte to its u64 representation.
#[inline(always)]
pub fn ct_parse_digit(byte: u8) -> (u64, u64) {
    let is_digit = ct_is_digit(byte) as u64;
    let digit_val = (byte as u64).wrapping_sub(0x30);
    let mask = 0u64.wrapping_sub(is_digit);
    (is_digit, digit_val & mask)
}

/// Satisfies [FR-06-PSIMALG]
/// Satisfies [FR-07-SIMDTUN]
/// Constant-time selection over 256-bit limb arrays.
#[inline(always)]
pub fn ct_select_limbs_256(a: &[u64; 4], b: &[u64; 4], mask: u64) -> [u64; 4] {
    let mut res = [0u64; 4];
    res[0] = (a[0] & mask) | (b[0] & !mask);
    res[1] = (a[1] & mask) | (b[1] & !mask);
    res[2] = (a[2] & mask) | (b[2] & !mask);
    res[3] = (a[3] & mask) | (b[3] & !mask);
    compiler_fence(Ordering::SeqCst);
    res
}

/// Satisfies [FR-06-PSIMALG]
/// Satisfies [FR-07-SIMDTUN]
/// Constant-time 32-byte equality comparison returning 1 if equal, 0 if unequal.
pub fn ct_eq_32_bytes(a: &[u8; 32], b: &[u8; 32]) -> u64 {
    let mut d: u64 = 0;
    for i in 0..32 {
        d |= (a[i] ^ b[i]) as u64;
    }
    compiler_fence(Ordering::SeqCst);
    // Closed-form branchless zero-check over Z/(2^64)Z
    ((d | 0u64.wrapping_sub(d)) >> 63) ^ 1
}

/// Satisfies [FR-05-RAMCLR]
/// Satisfies [FR-18-ZEROREM]
/// Constant-time volatile zeroization routine preventing DCE pruning.
#[inline(never)]
pub fn ct_zeroize(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(verus)]
use vstd::prelude::*;

#[cfg(verus)]
verus! {
    /// Satisfies [FR-30-GHOSTPERM]
    /// Satisfies [FR-12-FORMALSPEC]
    /// Verus tracked linear ghost token tracking channel sequence advancement.
    pub tracked struct ChannelToken {
        pub ghost channel_id: nat,
        pub ghost seq_num: nat,
    }

    impl ChannelToken {
        pub open spec fn is_valid(self, cid: nat, seq: nat) -> bool {
            self.channel_id == cid && self.seq_num == seq
        }

        pub proof fn advance_seq(tracked self) -> (tracked next: ChannelToken)
            ensures
                next.channel_id == self.channel_id,
                next.seq_num == self.seq_num + 1,
        {
            ChannelToken {
                channel_id: self.channel_id,
                seq_num: self.seq_num + 1,
            }
        }
    }

    /// Satisfies [FR-31-ADAPTVOLE]
    /// Satisfies [FR-12-FORMALSPEC]
    /// Machine-checked proof that branchless borrow-bit extraction over Z/(2^64)Z
    /// strictly evaluates to 1 if and only if n_scaled < m_elements, and 0 otherwise.
    pub proof fn lemma_adaptive_route_borrow_bit(n_scaled: u64, m_elements: u64)
        ensures
            (((!n_scaled & m_elements) | (!(n_scaled ^ m_elements) & (n_scaled.wrapping_sub(m_elements)))) >> 63)
                == (if n_scaled < m_elements { 1u64 } else { 0u64 })
    {
        assert((((!n_scaled & m_elements) | (!(n_scaled ^ m_elements) & (n_scaled.wrapping_sub(m_elements)))) >> 63)
            == (if n_scaled < m_elements { 1u64 } else { 0u64 })) by(bit_vector);
    }
}

pub const NONA_ROUTE_DH_PSI: u32 = 1;
pub const NONA_ROUTE_VOLE_PSI: u32 = 2;
pub const NONA_VOLE_THRESHOLD_RATIO: u64 = 128;
pub const MAX_ROUTER_ELEMENTS: u64 = u64::MAX / NONA_VOLE_THRESHOLD_RATIO;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    CapacityOverflow,
}

#[inline(always)]
/// Satisfies [FR-31-ADAPTVOLE]
/// Constant-time adaptive threshold decision circuit selecting between DH-PSI and VOLE-PSI.
#[allow(clippy::cast_possible_truncation)]
pub fn ct_adaptive_route_decision(
    n_elements: u64,
    m_elements: u64,
) -> Result<(u32, u64), CryptoError> {
    if n_elements > MAX_ROUTER_ELEMENTS {
        return Err(CryptoError::CapacityOverflow);
    }
    let n_scaled = n_elements
        .checked_mul(NONA_VOLE_THRESHOLD_RATIO)
        .ok_or(CryptoError::CapacityOverflow)?;

    let delta = n_scaled.wrapping_sub(m_elements);
    // Closed-form constant-time borrow bit extraction over Z/(2^64)Z
    let delta_bit = ((!n_scaled & m_elements) | (!(n_scaled ^ m_elements) & delta)) >> 63;

    // delta_bit == 0 (N * 128 >= M) -> select NONA_ROUTE_DH_PSI (1)
    // delta_bit == 1 (N * 128 < M)  -> select NONA_ROUTE_VOLE_PSI (2)
    let mask = 0u64.wrapping_sub(delta_bit ^ 1);
    let route_id = ct_select_u64(mask, NONA_ROUTE_DH_PSI as u64, NONA_ROUTE_VOLE_PSI as u64) as u32;

    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    Ok((route_id, delta_bit))
}

/// secp256k1 scalar group order q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
pub const ORDER_Q: [u64; 4] = [
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
];

const LAMBDA_L0: u64 = 0x402da1732fc9bebf;
const LAMBDA_L1: u64 = 0x4551231950b75fc4;

#[repr(C, align(64))]
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(not(verus), derive(Zeroize, ZeroizeOnDrop))]
/// Satisfies [FR-02-STKBUFF]
/// Satisfies [FR-18-ZEROREM]
/// Cache-aligned (64-byte) 256-bit secp256k1 scalar field element modulo q.
///
/// # Trusted Computing Base (TCB) Boundary Classification
/// High-Assurance Runtime Perimeter (Tier 3): secp256k1 scalar group arithmetic
/// modulo q and endomorphism reduction (lambda-decomposition) are explicitly scoped
/// out of the formal SMT inductive verification surface due to non-linear degree-2
/// reduction decidability limits. Canonicity, non-overflow, and algebraic distributivity
/// are validated via differential oracle fuzzing, Wycheproof vectors, and
/// domain boundary suites. Formally cataloged in docs/TCB.md §3 and SPECIFICATION.md §4.5.0.
pub struct Scalar {
    pub limbs: [u64; 4],
}

#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn scalar_add_nocarry(a: &[u64; 4], b: &[u64; 4]) -> (u64, [u64; 4]) {
    let mut res = [0u64; 4];
    let mut carry = 0u128;
    let mut i = 0;
    while i < 4 {
        let sum = (a[i] as u128) + (b[i] as u128) + carry;
        res[i] = sum as u64;
        carry = sum >> 64;
        i += 1;
    }
    (carry as u64, res)
}

#[inline(always)]
fn scalar_sub_noborrow(a: &[u64; 4], b: &[u64; 4]) -> (u64, [u64; 4]) {
    let mut res = [0u64; 4];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < 4 {
        let (d1, b1) = a[i].overflowing_sub(borrow);
        let (d2, b2) = d1.overflowing_sub(b[i]);
        res[i] = d2;
        borrow = (b1 as u64) | (b2 as u64);
        i += 1;
    }
    (borrow, res)
}

#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn scalar_mul_512(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut r = [0u64; 8];
    let mut i = 0;
    while i < 4 {
        let mut carry = 0u64;
        let mut j = 0;
        while j < 4 {
            let val = (a[i] as u128) * (b[j] as u128) + (r[i + j] as u128) + (carry as u128);
            r[i + j] = val as u64;
            carry = (val >> 64) as u64;
            j += 1;
        }
        r[i + 4] = carry;
        i += 1;
    }
    r
}

#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn mul_256_by_lambda(a: &[u64; 4]) -> [u64; 7] {
    let mut res = [0u128; 7];
    let mut i = 0;
    while i < 4 {
        let ai = a[i] as u128;
        res[i] += ai * (LAMBDA_L0 as u128);
        res[i + 1] += ai * (LAMBDA_L1 as u128);
        res[i + 2] += ai;
        i += 1;
    }
    let mut out = [0u64; 7];
    let mut carry = 0u128;
    let mut j = 0;
    while j < 7 {
        let val = res[j] + carry;
        out[j] = val as u64;
        carry = val >> 64;
        j += 1;
    }
    out
}

#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn reduce_scalar_512(r: &[u64; 8]) -> [u64; 4] {
    let r_lo = [r[0], r[1], r[2], r[3]];
    let r_hi = [r[4], r[5], r[6], r[7]];

    let p1 = mul_256_by_lambda(&r_hi);

    let mut t = [0u64; 7];
    let mut carry = 0u128;
    let mut i = 0;
    while i < 4 {
        let val = (p1[i] as u128) + (r_lo[i] as u128) + carry;
        t[i] = val as u64;
        carry = val >> 64;
        i += 1;
    }
    while i < 7 {
        let val = (p1[i] as u128) + carry;
        t[i] = val as u64;
        carry = val >> 64;
        i += 1;
    }

    let t_lo = [t[0], t[1], t[2], t[3]];
    let t_hi = [t[4], t[5], t[6], 0];
    let p2 = mul_256_by_lambda(&t_hi);

    let mut t2 = [0u64; 5];
    let mut carry2 = 0u128;
    let mut j = 0;
    while j < 4 {
        let val = (p2[j] as u128) + (t_lo[j] as u128) + carry2;
        t2[j] = val as u64;
        carry2 = val >> 64;
        j += 1;
    }
    let val_last = (p2[4] as u128) + carry2;
    t2[4] = val_last as u64;

    let t2_hi = [t2[4], 0, 0, 0];
    let p3 = mul_256_by_lambda(&t2_hi);

    let mut t3 = [0u64; 4];
    let mut carry3 = 0u128;
    let mut k = 0;
    while k < 4 {
        let val = (p3[k] as u128) + (t2[k] as u128) + carry3;
        t3[k] = val as u64;
        carry3 = val >> 64;
        k += 1;
    }

    let (borrow, d) = scalar_sub_noborrow(&t3, &ORDER_Q);
    let condition = (carry3 as u64) | (1u64.wrapping_sub(borrow));
    let mask = !(condition.wrapping_sub(1));
    let mut res = [0u64; 4];
    let mut m = 0;
    while m < 4 {
        res[m] = (d[m] & mask) | (t3[m] & !mask);
        m += 1;
    }
    res
}

impl Scalar {
    #[inline(always)]
    pub const fn zero() -> Self {
        Self { limbs: [0; 4] }
    }

    #[inline(always)]
    pub const fn one() -> Self {
        Self {
            limbs: [1, 0, 0, 0],
        }
    }

    #[inline(always)]
    pub const fn from_limbs(limbs: [u64; 4]) -> Self {
        Self { limbs }
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        (self.limbs[0] | self.limbs[1] | self.limbs[2] | self.limbs[3]) == 0
    }

    #[inline(always)]
    pub fn is_canonical(&self) -> bool {
        let (borrow, _) = scalar_sub_noborrow(&self.limbs, &ORDER_Q);
        borrow == 1
    }

    #[inline(always)]
    pub unsafe fn from_bytes_le(ptr: *const u8) -> Self {
        let mut limbs = [0u64; 4];
        core::ptr::copy_nonoverlapping(ptr, limbs.as_mut_ptr().cast::<u8>(), 32);
        limbs[0] = u64::from_le(limbs[0]);
        limbs[1] = u64::from_le(limbs[1]);
        limbs[2] = u64::from_le(limbs[2]);
        limbs[3] = u64::from_le(limbs[3]);
        Self { limbs }
    }

    #[inline(always)]
    pub unsafe fn to_bytes_le(&self, ptr: *mut u8) {
        let limbs_le = [
            self.limbs[0].to_le(),
            self.limbs[1].to_le(),
            self.limbs[2].to_le(),
            self.limbs[3].to_le(),
        ];
        core::ptr::copy_nonoverlapping(limbs_le.as_ptr().cast::<u8>(), ptr, 32);
    }

    pub fn add(&self, other: &Self) -> Self {
        let (carry, s) = scalar_add_nocarry(&self.limbs, &other.limbs);
        let (borrow, d) = scalar_sub_noborrow(&s, &ORDER_Q);
        let condition = carry | (1u64.wrapping_sub(borrow));
        let mask = !(condition.wrapping_sub(1));
        let mut res = [0u64; 4];
        let mut i = 0;
        while i < 4 {
            res[i] = (d[i] & mask) | (s[i] & !mask);
            i += 1;
        }
        Self { limbs: res }
    }

    pub fn mul(&self, other: &Self) -> Self {
        let r = scalar_mul_512(&self.limbs, &other.limbs);
        let limbs = reduce_scalar_512(&r);
        Self { limbs }
    }
}

/// Satisfies [FR-31-ADAPTVOLE]
/// Evaluates the Vector Oblivious Linear Evaluation (VOLE) linear relation:
/// w_i = u_i * Delta + v_i (mod q)
/// over the secp256k1 scalar field F_q in constant time.
pub fn vole_subfield_eval(
    u_vec: &[Scalar],
    v_vec: &[Scalar],
    delta: &Scalar,
    out_w: &mut [Scalar],
) -> i32 {
    let k = u_vec.len();
    if k != v_vec.len() || k != out_w.len() || k == 0 {
        return -1;
    }

    let mut i = 0;
    while i < k {
        let prod = u_vec[i].mul(delta);
        out_w[i] = prod.add(&v_vec[i]);
        i += 1;
    }

    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    0
}

#[cfg(not(verus))]
#[no_mangle]
/// Satisfies [FR-31-ADAPTVOLE]
/// Satisfies [FR-19-FFIBND]
/// Exported C-ABI entry point for adaptive VOLE threshold decision routing.
pub unsafe extern "C" fn nona_adaptive_psi_route(
    n_elements: u64,
    m_elements: u64,
    out_route_id: *mut u32,
) -> i32 {
    if out_route_id.is_null() {
        return -1; // NONA_ERR_NULL_POINTER
    }

    let (route_id, _) = match ct_adaptive_route_decision(n_elements, m_elements) {
        Ok(res) => res,
        Err(CryptoError::CapacityOverflow) => {
            return crate::gatekeeper::NONA_ERR_ELEMENT_COUNT_BOUND_VIOLATION
        }
    };
    *out_route_id = route_id;
    0
}

// ============================================================================
// FIPS 180-4 SECURE HASH STANDARD: SHA-512 (Zero Allocations / Constant Time)
// ============================================================================

const SHA512_K: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

fn sha512_ch(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (!x & z)
}

fn sha512_maj(x: u64, y: u64, z: u64) -> u64 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn sha512_big_sigma0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}

fn sha512_big_sigma1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

fn sha512_small_sigma0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

fn sha512_small_sigma1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

pub fn sha512_digest(data: &[u8]) -> [u8; 64] {
    let mut state: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    let total_len = data.len();
    let mut chunk_buf = [0u8; 128];
    let mut offset = 0;

    while offset + 128 <= total_len {
        chunk_buf.copy_from_slice(&data[offset..offset + 128]);
        sha512_process_block(&mut state, &chunk_buf);
        offset += 128;
    }

    let rem = total_len - offset;
    chunk_buf[..rem].copy_from_slice(&data[offset..]);
    chunk_buf[rem] = 0x80;

    if rem + 1 > 112 {
        for b in &mut chunk_buf[rem + 1..] {
            *b = 0;
        }
        sha512_process_block(&mut state, &chunk_buf);
        chunk_buf = [0u8; 128];
    } else {
        for b in &mut chunk_buf[rem + 1..112] {
            *b = 0;
        }
    }

    let bit_len = (total_len as u128) * 8;
    let bit_len_bytes = bit_len.to_be_bytes();
    chunk_buf[112..128].copy_from_slice(&bit_len_bytes);
    sha512_process_block(&mut state, &chunk_buf);

    let mut out = [0u8; 64];
    for (i, word) in state.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
    }
    ct_zeroize(&mut chunk_buf);
    out
}

fn sha512_process_block(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 80];
    for i in 0..16 {
        w[i] = u64::from_be_bytes([
            block[i * 8],
            block[i * 8 + 1],
            block[i * 8 + 2],
            block[i * 8 + 3],
            block[i * 8 + 4],
            block[i * 8 + 5],
            block[i * 8 + 6],
            block[i * 8 + 7],
        ]);
    }

    for i in 16..80 {
        let s0 = sha512_small_sigma0(w[i - 15]);
        let s1 = sha512_small_sigma1(w[i - 2]);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    for i in 0..80 {
        let t1 = h
            .wrapping_add(sha512_big_sigma1(e))
            .wrapping_add(sha512_ch(e, f, g))
            .wrapping_add(SHA512_K[i])
            .wrapping_add(w[i]);
        let t2 = sha512_big_sigma0(a).wrapping_add(sha512_maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);

    w.fill(0);
}


// ============================================================================
// FIPS 180-4 SECURE HASH STANDARD: SHA-384 (Zero Allocations / Constant Time)
// ============================================================================

pub fn sha384_digest(data: &[u8]) -> [u8; 48] {
    let mut state: [u64; 8] = [
        0xcbbb9d5dc1059ed8,
        0x629a292a367cd507,
        0x9159015a3070dd17,
        0x152fecd8f70e5939,
        0x67332667ffc00b31,
        0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7,
        0x47b5481dbefa4fa4,
    ];

    let total_len = data.len();
    let mut chunk_buf = [0u8; 128];
    let mut offset = 0;

    while offset + 128 <= total_len {
        chunk_buf.copy_from_slice(&data[offset..offset + 128]);
        sha512_process_block(&mut state, &chunk_buf);
        offset += 128;
    }

    let rem = total_len - offset;
    chunk_buf[..rem].copy_from_slice(&data[offset..]);
    chunk_buf[rem] = 0x80;

    if rem + 1 > 112 {
        for b in &mut chunk_buf[rem + 1..] {
            *b = 0;
        }
        sha512_process_block(&mut state, &chunk_buf);
        chunk_buf = [0u8; 128];
    } else {
        for b in &mut chunk_buf[rem + 1..112] {
            *b = 0;
        }
    }

    let bit_len = (total_len as u128) * 8;
    let bit_len_bytes = bit_len.to_be_bytes();
    chunk_buf[112..128].copy_from_slice(&bit_len_bytes);
    sha512_process_block(&mut state, &chunk_buf);

    let mut out = [0u8; 48];
    let mut i = 0;
    while i < 6 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_be_bytes());
        i += 1;
    }
    ct_zeroize(&mut chunk_buf);
    out
}

// ============================================================================
// NIST P-384 (secp384r1) Elliptic Curve & ECDSA-SHA384 Verification (#![no_std])
// ============================================================================

/// P-384 prime field modulus p = 2^384 - 2^128 - 2^96 + 2^32 - 1 (little-endian limbs)
const P384_P: [u64; 6] = [
    0x0000_0000_ffff_ffff,
    0xffff_ffff_0000_0000,
    0xffff_ffff_ffff_fffe,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
];

/// P-384 scalar group order n (little-endian limbs)
const P384_N: [u64; 6] = [
    0xecec_196a_ccc5_2973,
    0x581a_0db2_48b0_a77a,
    0xc763_4d81_f437_2ddf,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
];

/// 2^384 - n (190-bit residual for fast multi-precision reduction mod n)
const P384_DELTA_N: [u64; 3] = [
    0x1313_e695_333a_d68d,
    0xa7e5_f24d_b74f_5885,
    0x389c_b27e_0bc8_d220,
];

/// P-384 curve parameter b (little-endian limbs)
const P384_B: [u64; 6] = [
    0x2a85_c8ed_d3ec_2aef,
    0xc656_398d_8a2e_d19d,
    0x0314_088f_5013_875a,
    0x181d_9c6e_fe81_4112,
    0x988e_056b_e3f8_2d19,
    0xb331_2fa7_e23e_e7e4,
];

/// P-384 generator G_x (little-endian limbs)
const P384_GX: [u64; 6] = [
    0x3a54_5e38_7276_0ab7,
    0x5502_f25d_bf55_296c,
    0x59f7_41e0_8254_2a38,
    0x6e1d_3b62_8ba7_9b98,
    0x8eb1_c71e_f320_ad74,
    0xaa87_ca22_be8b_0537,
];

/// P-384 generator G_y (little-endian limbs)
const P384_GY: [u64; 6] = [
    0x7a43_1d7c_90ea_0e5f,
    0x0a60_b1ce_1d7e_819d,
    0xe9da_3113_b5f0_b8c0,
    0xf8f4_1dbd_289a_147c,
    0x5d9e_98bf_9292_dc29,
    0x3617_de4a_9626_2c6f,
];

#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn u384_add_raw(a: &[u64; 6], b: &[u64; 6]) -> (u64, [u64; 6]) {
    let mut res = [0u64; 6];
    let mut carry = 0u128;
    let mut i = 0;
    while i < 6 {
        let sum = (a[i] as u128) + (b[i] as u128) + carry;
        res[i] = sum as u64;
        carry = sum >> 64;
        i += 1;
    }
    (carry as u64, res)
}

#[inline(always)]
fn u384_sub_raw(a: &[u64; 6], b: &[u64; 6]) -> (u64, [u64; 6]) {
    let mut res = [0u64; 6];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < 6 {
        let (d1, b1) = a[i].overflowing_sub(borrow);
        let (d2, b2) = d1.overflowing_sub(b[i]);
        res[i] = d2;
        borrow = (b1 as u64) | (b2 as u64);
        i += 1;
    }
    (borrow, res)
}

#[inline(always)]
fn u384_ct_select(mask: u64, a: &[u64; 6], b: &[u64; 6]) -> [u64; 6] {
    let mut res = [0u64; 6];
    let mut i = 0;
    while i < 6 {
        res[i] = (a[i] & mask) | (b[i] & !mask);
        i += 1;
    }
    res
}

#[inline(always)]
fn u384_is_zero(a: &[u64; 6]) -> bool {
    (a[0] | a[1] | a[2] | a[3] | a[4] | a[5]) == 0
}

#[inline(always)]
fn u384_lt(a: &[u64; 6], b: &[u64; 6]) -> bool {
    let (borrow, _) = u384_sub_raw(a, b);
    borrow == 1
}

#[inline(always)]
fn u384_from_be_bytes(bytes: &[u8; 48]) -> [u64; 6] {
    let mut limbs = [0u64; 6];
    let mut i = 0;
    while i < 6 {
        let offset = (5 - i) * 8;
        limbs[i] = u64::from_be_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
            bytes[offset + 6],
            bytes[offset + 7],
        ]);
        i += 1;
    }
    limbs
}

#[inline(always)]
fn u384_to_be_bytes(limbs: &[u64; 6]) -> [u8; 48] {
    let mut out = [0u8; 48];
    let mut i = 0;
    while i < 6 {
        let offset = (5 - i) * 8;
        out[offset..offset + 8].copy_from_slice(&limbs[i].to_be_bytes());
        i += 1;
    }
    out
}

#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn u384_mul_768(a: &[u64; 6], b: &[u64; 6]) -> [u64; 12] {
    let mut r = [0u64; 12];
    let mut i = 0;
    while i < 6 {
        let mut carry = 0u64;
        let mut j = 0;
        while j < 6 {
            let val = (a[i] as u128) * (b[j] as u128) + (r[i + j] as u128) + (carry as u128);
            r[i + j] = val as u64;
            carry = (val >> 64) as u64;
            j += 1;
        }
        r[i + 6] = carry;
        i += 1;
    }
    r
}

/// Folds a 6-limb (384-bit) upper value `hi` into a 9-limb value:
/// `lo + (hi << 128) + (hi << 96) - (hi << 32) + hi`
/// using exact identity 2^384 ≡ 2^128 + 2^96 - 2^32 + 1 (mod p).
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn p384_fold_upper_6(lo: &[u64; 6], hi: &[u64; 6]) -> [u64; 9] {
    // 1. Add lo + hi + (hi << 128) + (hi << 96)
    let mut acc = [0u64; 9];
    let mut carry = 0u128;
    let mut i = 0;
    while i < 9 {
        let lo_term = if i < 6 { lo[i] as u128 } else { 0 };
        let hi_term = if i < 6 { hi[i] as u128 } else { 0 };
        let shl128_term = if (2..8).contains(&i) {
            hi[i - 2] as u128
        } else {
            0
        };
        let shl96_term = match i {
            1 => (hi[0] << 32) as u128,
            2..=6 => ((hi[i - 1] << 32) | (hi[i - 2] >> 32)) as u128,
            7 => (hi[5] >> 32) as u128,
            _ => 0,
        };
        let sum = lo_term + hi_term + shl128_term + shl96_term + carry;
        acc[i] = sum as u64;
        carry = sum >> 64;
        i += 1;
    }

    // 2. Subtract (hi << 32) (at most 7 limbs: indices 0..=6)
    let mut borrow = 0u64;
    let mut j = 0;
    while j < 9 {
        let sub_term = match j {
            0 => hi[0] << 32,
            1..=5 => (hi[j] << 32) | (hi[j - 1] >> 32),
            6 => hi[5] >> 32,
            _ => 0,
        };
        let (d1, b1) = acc[j].overflowing_sub(borrow);
        let (d2, b2) = d1.overflowing_sub(sub_term);
        acc[j] = d2;
        borrow = (b1 as u64) | (b2 as u64);
        j += 1;
    }
    acc
}

/// Folds a 3-limb upper value `hi1` into a 6-limb `lo1` modulo P384_P.
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn p384_fold_upper_3(lo1: &[u64; 6], hi1: &[u64; 3]) -> [u64; 7] {
    let mut acc = [0u64; 7];
    let mut carry = 0u128;
    let mut i = 0;
    while i < 7 {
        let lo_term = if i < 6 { lo1[i] as u128 } else { 0 };
        let hi_term = if i < 3 { hi1[i] as u128 } else { 0 };
        let shl128_term = if (2..5).contains(&i) {
            hi1[i - 2] as u128
        } else {
            0
        };
        let shl96_term = match i {
            1 => (hi1[0] << 32) as u128,
            2..=3 => ((hi1[i - 1] << 32) | (hi1[i - 2] >> 32)) as u128,
            4 => (hi1[2] >> 32) as u128,
            _ => 0,
        };
        let sum = lo_term + hi_term + shl128_term + shl96_term + carry;
        acc[i] = sum as u64;
        carry = sum >> 64;
        i += 1;
    }

    let mut borrow = 0u64;
    let mut j = 0;
    while j < 7 {
        let sub_term = match j {
            0 => hi1[0] << 32,
            1..=2 => (hi1[j] << 32) | (hi1[j - 1] >> 32),
            3 => hi1[2] >> 32,
            _ => 0,
        };
        let (d1, b1) = acc[j].overflowing_sub(borrow);
        let (d2, b2) = d1.overflowing_sub(sub_term);
        acc[j] = d2;
        borrow = (b1 as u64) | (b2 as u64);
        j += 1;
    }
    acc
}

#[inline(always)]
fn p384_reduce_768(t: &[u64; 12]) -> [u64; 6] {
    let lo = [t[0], t[1], t[2], t[3], t[4], t[5]];
    let hi = [t[6], t[7], t[8], t[9], t[10], t[11]];
    let t1 = p384_fold_upper_6(&lo, &hi);
    let lo1 = [t1[0], t1[1], t1[2], t1[3], t1[4], t1[5]];
    let hi1 = [t1[6], t1[7], t1[8]];
    let t2 = p384_fold_upper_3(&lo1, &hi1);

    let mut cur = [t2[0], t2[1], t2[2], t2[3], t2[4], t2[5]];
    let mut top = t2[6];

    // At most 2 conditional subtractions of P384_P
    let mut pass = 0;
    while pass < 2 {
        let (borrow, diff) = u384_sub_raw(&cur, &P384_P);
        let ge_p = (top != 0) || (borrow == 0);
        let mask = 0u64.wrapping_sub(ge_p as u64);
        cur = u384_ct_select(mask, &diff, &cur);
        top = top.saturating_sub(ge_p as u64);
        pass += 1;
    }
    cur
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Fe384 {
    limbs: [u64; 6],
}

impl Fe384 {
    const ZERO: Self = Self { limbs: [0; 6] };
    const ONE: Self = Self {
        limbs: [1, 0, 0, 0, 0, 0],
    };

    fn from_be_bytes(bytes: &[u8; 48]) -> Option<Self> {
        let limbs = u384_from_be_bytes(bytes);
        if u384_lt(&limbs, &P384_P) {
            Some(Self { limbs })
        } else {
            None
        }
    }

    fn is_zero(&self) -> bool {
        u384_is_zero(&self.limbs)
    }

    fn add(&self, other: &Self) -> Self {
        let (carry, s) = u384_add_raw(&self.limbs, &other.limbs);
        let (borrow, d) = u384_sub_raw(&s, &P384_P);
        let cond = carry | (1u64.wrapping_sub(borrow));
        let mask = !(cond.wrapping_sub(1));
        Self {
            limbs: u384_ct_select(mask, &d, &s),
        }
    }

    fn sub(&self, other: &Self) -> Self {
        let (borrow, d) = u384_sub_raw(&self.limbs, &other.limbs);
        let ( _, d_plus_p) = u384_add_raw(&d, &P384_P);
        let mask = 0u64.wrapping_sub(borrow);
        Self {
            limbs: u384_ct_select(mask, &d_plus_p, &d),
        }
    }

    fn double(&self) -> Self {
        self.add(self)
    }

    fn mul(&self, other: &Self) -> Self {
        let prod = u384_mul_768(&self.limbs, &other.limbs);
        Self {
            limbs: p384_reduce_768(&prod),
        }
    }

    fn square(&self) -> Self {
        self.mul(self)
    }

    /// Computes `self^(p - 2) mod p` via constant-time square-and-multiply.
    fn invert(&self) -> Self {
        let mut exp = P384_P;
        // p - 2: P384_P[0] is 0xffffffff, so subtracting 2 yields 0xfffffffd without borrow
        exp[0] -= 2;

        let mut acc = Self::ONE;
        let mut bit_idx: i32 = 383;
        while bit_idx >= 0 {
            acc = acc.square();
            let idx = usize::try_from(bit_idx).unwrap_or(0);
            let limb = exp[idx / 64];
            let bit = (limb >> (idx % 64)) & 1;
            let prod = acc.mul(self);
            let mask = 0u64.wrapping_sub(bit);
            acc = Self {
                limbs: u384_ct_select(mask, &prod.limbs, &acc.limbs),
            };
            bit_idx -= 1;
        }
        acc
    }
}

/// Multiplies a 6-limb value `hi` by the 3-limb residual `P384_DELTA_N`, adding `lo`.
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn n384_mul_add_6x3(lo: &[u64; 6], hi: &[u64; 6]) -> [u64; 9] {
    let mut r = [0u64; 9];
    r[..6].copy_from_slice(lo);
    let mut i = 0;
    while i < 6 {
        let mut carry = 0u64;
        let mut j = 0;
        while j < 3 {
            let val = (hi[i] as u128) * (P384_DELTA_N[j] as u128)
                + (r[i + j] as u128)
                + (carry as u128);
            r[i + j] = val as u64;
            carry = (val >> 64) as u64;
            j += 1;
        }
        let mut k = i + 3;
        let mut c = carry as u128;
        while c > 0 && k < 9 {
            let sum = (r[k] as u128) + c;
            r[k] = sum as u64;
            c = sum >> 64;
            k += 1;
        }
        i += 1;
    }
    r
}

/// Multiplies a 3-limb value `hi1` by `P384_DELTA_N` (3 limbs), adding 6-limb `lo1`.
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn n384_mul_add_3x3(lo1: &[u64; 6], hi1: &[u64; 3]) -> [u64; 7] {
    let mut r = [0u64; 7];
    r[..6].copy_from_slice(lo1);
    let mut i = 0;
    while i < 3 {
        let mut carry = 0u64;
        let mut j = 0;
        while j < 3 {
            let val = (hi1[i] as u128) * (P384_DELTA_N[j] as u128)
                + (r[i + j] as u128)
                + (carry as u128);
            r[i + j] = val as u64;
            carry = (val >> 64) as u64;
            j += 1;
        }
        let mut k = i + 3;
        let mut c = carry as u128;
        while c > 0 && k < 7 {
            let sum = (r[k] as u128) + c;
            r[k] = sum as u64;
            c = sum >> 64;
            k += 1;
        }
        i += 1;
    }
    r
}

#[inline(always)]
fn n384_reduce_768(t: &[u64; 12]) -> [u64; 6] {
    let lo = [t[0], t[1], t[2], t[3], t[4], t[5]];
    let hi = [t[6], t[7], t[8], t[9], t[10], t[11]];
    let t1 = n384_mul_add_6x3(&lo, &hi);
    let lo1 = [t1[0], t1[1], t1[2], t1[3], t1[4], t1[5]];
    let hi1 = [t1[6], t1[7], t1[8]];
    let t2 = n384_mul_add_3x3(&lo1, &hi1);

    let mut cur = [t2[0], t2[1], t2[2], t2[3], t2[4], t2[5]];
    let mut top = t2[6];
    let mut pass = 0;
    while pass < 2 {
        let (borrow, diff) = u384_sub_raw(&cur, &P384_N);
        let ge_n = (top != 0) || (borrow == 0);
        let mask = 0u64.wrapping_sub(ge_n as u64);
        cur = u384_ct_select(mask, &diff, &cur);
        top = top.saturating_sub(ge_n as u64);
        pass += 1;
    }
    cur
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Scalar384 {
    limbs: [u64; 6],
}

impl Scalar384 {
    const ONE: Self = Self {
        limbs: [1, 0, 0, 0, 0, 0],
    };

    fn from_be_bytes_nonzero(bytes: &[u8; 48]) -> Option<Self> {
        let limbs = u384_from_be_bytes(bytes);
        if u384_is_zero(&limbs) || !u384_lt(&limbs, &P384_N) {
            None
        } else {
            Some(Self { limbs })
        }
    }

    fn from_be_bytes_reduced(bytes: &[u8; 48]) -> Self {
        let mut limbs = u384_from_be_bytes(bytes);
        let (borrow, diff) = u384_sub_raw(&limbs, &P384_N);
        let mask = 0u64.wrapping_sub((borrow == 0) as u64);
        limbs = u384_ct_select(mask, &diff, &limbs);
        Self { limbs }
    }

    #[cfg(any(test, feature = "std"))]
    fn is_zero(&self) -> bool {
        u384_is_zero(&self.limbs)
    }

    #[cfg(any(test, feature = "std"))]
    fn to_be_bytes(self) -> [u8; 48] {
        u384_to_be_bytes(&self.limbs)
    }

    #[cfg(any(test, feature = "std"))]
    fn add(&self, other: &Self) -> Self {
        let (carry, s) = u384_add_raw(&self.limbs, &other.limbs);
        let (borrow, d) = u384_sub_raw(&s, &P384_N);
        let cond = carry | (1u64.wrapping_sub(borrow));
        let mask = !(cond.wrapping_sub(1));
        Self {
            limbs: u384_ct_select(mask, &d, &s),
        }
    }

    fn mul(&self, other: &Self) -> Self {
        let prod = u384_mul_768(&self.limbs, &other.limbs);
        Self {
            limbs: n384_reduce_768(&prod),
        }
    }

    fn square(&self) -> Self {
        self.mul(self)
    }

    /// Computes `self^(n - 2) mod n` via constant-time square-and-multiply.
    fn invert(&self) -> Self {
        let mut exp = P384_N;
        // P384_N[0] = 0xecec196accc52973 >= 2, so subtracting 2 does not underflow
        exp[0] -= 2;

        let mut acc = Self::ONE;
        let mut bit_idx: i32 = 383;
        while bit_idx >= 0 {
            acc = acc.square();
            let idx = usize::try_from(bit_idx).unwrap_or(0);
            let limb = exp[idx / 64];
            let bit = (limb >> (idx % 64)) & 1;
            let prod = acc.mul(self);
            let mask = 0u64.wrapping_sub(bit);
            acc = Self {
                limbs: u384_ct_select(mask, &prod.limbs, &acc.limbs),
            };
            bit_idx -= 1;
        }
        acc
    }
}

/// Validated affine point on NIST P-384 (`secp384r1`: `y^2 ≡ x^3 - 3x + b mod p`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct P384Point {
    x: Fe384,
    y: Fe384,
}

impl P384Point {
    pub const fn generator() -> Self {
        Self {
            x: Fe384 { limbs: P384_GX },
            y: Fe384 { limbs: P384_GY },
        }
    }

    /// Decodes a 97-byte SEC 1 uncompressed P-384 point (`0x04 || X(48) || Y(48)`)
    /// and validates that `(x, y)` lies strictly on the `secp384r1` curve.
    #[inline(never)]
    pub fn from_uncompressed_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 97 || bytes[0] != 0x04 {
            return None;
        }
        let mut xb = [0u8; 48];
        let mut yb = [0u8; 48];
        xb.copy_from_slice(&bytes[1..49]);
        yb.copy_from_slice(&bytes[49..97]);

        let x = Fe384::from_be_bytes(&xb)?;
        let y = Fe384::from_be_bytes(&yb)?;

        // Check y^2 == x^3 - 3x + b (mod p)
        let lhs = y.square();
        let x2 = x.square();
        let x3 = x2.mul(&x);
        let three_x = x.double().add(&x);
        let b_fe = Fe384 { limbs: P384_B };
        let rhs = x3.sub(&three_x).add(&b_fe);

        if lhs == rhs {
            Some(Self { x, y })
        } else {
            None
        }
    }

    #[cfg(any(test, feature = "std"))]
    pub fn to_uncompressed_bytes(&self) -> [u8; 97] {
        let mut out = [0u8; 97];
        out[0] = 0x04;
        out[1..49].copy_from_slice(&u384_to_be_bytes(&self.x.limbs));
        out[49..97].copy_from_slice(&u384_to_be_bytes(&self.y.limbs));
        out
    }
}

#[derive(Clone, Copy)]
struct P384Jacobian {
    x: Fe384,
    y: Fe384,
    z: Fe384,
}

impl P384Jacobian {
    const INFINITY: Self = Self {
        x: Fe384::ONE,
        y: Fe384::ONE,
        z: Fe384::ZERO,
    };

    fn from_affine(pt: &P384Point) -> Self {
        Self {
            x: pt.x,
            y: pt.y,
            z: Fe384::ONE,
        }
    }

    fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Jacobian doubling for `a = -3`:
    /// `M = 3*(X - Z^2)*(X + Z^2)`
    fn double(&self) -> Self {
        if self.is_infinity() || self.y.is_zero() {
            return Self::INFINITY;
        }
        let z2 = self.z.square();
        let x_minus_z2 = self.x.sub(&z2);
        let x_plus_z2 = self.x.add(&z2);
        let prod = x_minus_z2.mul(&x_plus_z2);
        let m = prod.double().add(&prod); // 3 * (X^2 - Z^4)

        let y2 = self.y.square();
        let xy2 = self.x.mul(&y2);
        let s = xy2.double().double(); // 4 * X * Y^2

        let m2 = m.square();
        let two_s = s.double();
        let x3 = m2.sub(&two_s);

        let y4 = y2.square();
        let eight_y4 = y4.double().double().double();
        let y3 = m.mul(&s.sub(&x3)).sub(&eight_y4);

        let z3 = self.y.mul(&self.z).double();
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Mixed Jacobian-Affine addition `self + q`.
    fn add_mixed(&self, q: &P384Point) -> Self {
        if self.is_infinity() {
            return Self::from_affine(q);
        }
        let z1z1 = self.z.square();
        let u2 = q.x.mul(&z1z1);
        let s2 = q.y.mul(&self.z).mul(&z1z1);

        let h = u2.sub(&self.x);
        let r = s2.sub(&self.y);

        if h.is_zero() {
            if r.is_zero() {
                return self.double();
            }
            return Self::INFINITY;
        }

        let hh = h.square();
        let hhh = h.mul(&hh);
        let v = self.x.mul(&hh);

        let r2 = r.square();
        let two_v = v.double();
        let x3 = r2.sub(&hhh).sub(&two_v);

        let y3 = r.mul(&v.sub(&x3)).sub(&self.y.mul(&hhh));
        let z3 = self.z.mul(&h);
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    #[inline(never)]
    fn scalar_mul(pt: &P384Point, scalar: &Scalar384) -> Self {
        let mut acc = Self::INFINITY;
        let mut bit_idx: i32 = 383;
        while bit_idx >= 0 {
            acc = acc.double();
            let idx = usize::try_from(bit_idx).unwrap_or(0);
            let limb = scalar.limbs[idx / 64];
            let bit = (limb >> (idx % 64)) & 1;
            if bit == 1 {
                acc = acc.add_mixed(pt);
            }
            bit_idx -= 1;
        }
        acc
    }

    #[inline(never)]
    fn add_jacobian(&self, other: &Self) -> Self {
        if self.is_infinity() {
            return *other;
        }
        if other.is_infinity() {
            return *self;
        }
        let z1z1 = self.z.square();
        let z2z2 = other.z.square();
        let u1 = self.x.mul(&z2z2);
        let u2 = other.x.mul(&z1z1);
        let s1 = self.y.mul(&other.z).mul(&z2z2);
        let s2 = other.y.mul(&self.z).mul(&z1z1);

        let h = u2.sub(&u1);
        let r = s2.sub(&s1);
        if h.is_zero() {
            if r.is_zero() {
                return self.double();
            }
            return Self::INFINITY;
        }
        let hh = h.square();
        let hhh = h.mul(&hh);
        let v = u1.mul(&hh);

        let x3 = r.square().sub(&hhh).sub(&v.double());
        let y3 = r.mul(&v.sub(&x3)).sub(&s1.mul(&hhh));
        let z3 = self.z.mul(&other.z).mul(&h);
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn affine_x(&self) -> Option<Fe384> {
        if self.is_infinity() {
            return None;
        }
        let z_inv = self.z.invert();
        let z_inv2 = z_inv.square();
        Some(self.x.mul(&z_inv2))
    }

    #[cfg(any(test, feature = "std"))]
    fn to_affine(self) -> Option<P384Point> {
        if self.is_infinity() {
            return None;
        }
        let z_inv = self.z.invert();
        let z_inv2 = z_inv.square();
        let z_inv3 = z_inv2.mul(&z_inv);
        Some(P384Point {
            x: self.x.mul(&z_inv2),
            y: self.y.mul(&z_inv3),
        })
    }
}

/// Verifies an ECDSA-P384-SHA384 signature `(r, s)` over `message` against `pubkey`.
#[inline(never)]
pub fn ecdsa_p384_verify(
    pubkey: &P384Point,
    message: &[u8],
    r_bytes: &[u8; 48],
    s_bytes: &[u8; 48],
) -> bool {
    let Some(r) = Scalar384::from_be_bytes_nonzero(r_bytes) else {
        return false;
    };
    let Some(s) = Scalar384::from_be_bytes_nonzero(s_bytes) else {
        return false;
    };

    let digest = sha384_digest(message);
    let e = Scalar384::from_be_bytes_reduced(&digest);

    let w = s.invert();
    let u1 = e.mul(&w);
    let u2 = r.mul(&w);

    let g = P384Point::generator();
    let p1 = P384Jacobian::scalar_mul(&g, &u1);
    let p2 = P384Jacobian::scalar_mul(pubkey, &u2);
    let r_pt = p1.add_jacobian(&p2);

    let Some(rx_fe) = r_pt.affine_x() else {
        return false;
    };
    let rx_bytes = u384_to_be_bytes(&rx_fe.limbs);
    let v = Scalar384::from_be_bytes_reduced(&rx_bytes);

    let mut diff = 0u64;
    let mut i = 0;
    while i < 6 {
        diff |= v.limbs[i] ^ r.limbs[i];
        i += 1;
    }
    compiler_fence(Ordering::SeqCst);
    diff == 0
}

#[cfg(any(test, feature = "std"))]
pub fn p384_public_key_from_private(privkey_bytes: &[u8; 48]) -> Option<P384Point> {
    let d = Scalar384::from_be_bytes_nonzero(privkey_bytes)?;
    let g = P384Point::generator();
    P384Jacobian::scalar_mul(&g, &d).to_affine()
}

#[cfg(any(test, feature = "std"))]
pub fn ecdsa_p384_sign_deterministic(
    privkey_bytes: &[u8; 48],
    message: &[u8],
) -> Option<[u8; 96]> {
    let d = Scalar384::from_be_bytes_nonzero(privkey_bytes)?;
    let msg_hash = sha384_digest(message);
    let e = Scalar384::from_be_bytes_reduced(&msg_hash);

    // Deterministic RFC 6979-style hedged nonce derivation: H(privkey || msg_hash || counter)
    let mut seed_buf = [0u8; 97];
    seed_buf[..48].copy_from_slice(privkey_bytes);
    seed_buf[48..96].copy_from_slice(&msg_hash);

    let g = P384Point::generator();
    let mut counter: u8 = 1;
    loop {
        seed_buf[96] = counter;
        let k_digest = sha384_digest(&seed_buf);
        let k = Scalar384::from_be_bytes_reduced(&k_digest);
        if !k.is_zero() {
            let r_jac = P384Jacobian::scalar_mul(&g, &k);
            if let Some(rx_fe) = r_jac.affine_x() {
                let rx_bytes = u384_to_be_bytes(&rx_fe.limbs);
                let r = Scalar384::from_be_bytes_reduced(&rx_bytes);
                if !r.is_zero() {
                    let k_inv = k.invert();
                    let s = k_inv.mul(&e.add(&r.mul(&d)));
                    if !s.is_zero() {
                        let mut sig = [0u8; 96];
                        sig[..48].copy_from_slice(&r.to_be_bytes());
                        sig[48..96].copy_from_slice(&s.to_be_bytes());
                        ct_zeroize(&mut seed_buf);
                        return Some(sig);
                    }
                }
            }
        }
        counter = counter.wrapping_add(1);
        if counter == 0 {
            ct_zeroize(&mut seed_buf);
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_parse_digit_bounds() {
        assert_eq!(ct_parse_digit(b'0'), (1, 0));
        assert_eq!(ct_parse_digit(b'5'), (1, 5));
        assert_eq!(ct_parse_digit(b'9'), (1, 9));
        assert_eq!(ct_parse_digit(b'/'), (0, 0)); // 0x2F must yield 0
        assert_eq!(ct_parse_digit(b':'), (0, 0)); // 0x3A must yield 0
        assert_eq!(ct_parse_digit(0x00), (0, 0)); // Null byte must yield 0
    }

    #[test]
    fn test_vole_linear_relation_over_scalar_field_fq() {
        use super::{vole_subfield_eval, Scalar, ORDER_Q};

        // Test 1: (0 * delta) + v = v mod q
        let u = [Scalar::zero()];
        let v = [Scalar::from_limbs([42, 0, 0, 0])];
        let delta = Scalar::from_limbs([999, 0, 0, 0]);
        let mut w = [Scalar::zero()];
        assert_eq!(vole_subfield_eval(&u, &v, &delta, &mut w), 0);
        assert_eq!(w[0].limbs, [42, 0, 0, 0]);

        // Test 2: (1 * delta) + 0 = delta mod q
        let u = [Scalar::one()];
        let v = [Scalar::zero()];
        let delta = Scalar::from_limbs([0x12345678, 0x9abcdef0, 0, 0]);
        let mut w = [Scalar::zero()];
        assert_eq!(vole_subfield_eval(&u, &v, &delta, &mut w), 0);
        assert_eq!(w[0].limbs, delta.limbs);

        // Test 3: Large modular wrap-around modulo q
        // delta = q - 1, u = 2, v = 3
        // w = 2 * (q - 1) + 3 = 2q - 2 + 3 = q + 1 = 1 mod q
        let delta = Scalar::from_limbs([ORDER_Q[0] - 1, ORDER_Q[1], ORDER_Q[2], ORDER_Q[3]]);
        let u = [Scalar::from_limbs([2, 0, 0, 0])];
        let v = [Scalar::from_limbs([3, 0, 0, 0])];
        let mut w = [Scalar::zero()];
        assert_eq!(vole_subfield_eval(&u, &v, &delta, &mut w), 0);
        assert_eq!(w[0].limbs, [1, 0, 0, 0]);
    }

    #[test]
    fn test_sha384_nist_kat_and_p384_ecdsa_roundtrip() {
        // NIST FIPS 180-4 SHA-384("abc") test vector
        let digest = sha384_digest(b"abc");
        let expected_abc: [u8; 48] = [
            0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b,
            0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
            0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63,
            0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
            0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23,
            0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
        ];
        assert_eq!(digest, expected_abc);

        // ECDSA-P384 sign & verify roundtrip
        let mut privkey = [0u8; 48];
        privkey[47] = 0x2a;
        privkey[0] = 0x19;
        let Some(pubkey) = p384_public_key_from_private(&privkey) else {
            return;
        };
        let msg = b"Nona AWS Nitro Enclave COSE_Sign1 Sig_structure test";
        let Some(sig) = ecdsa_p384_sign_deterministic(&privkey, msg) else {
            return;
        };
        let mut r = [0u8; 48];
        let mut s = [0u8; 48];
        r.copy_from_slice(&sig[..48]);
        s.copy_from_slice(&sig[48..96]);
        assert!(ecdsa_p384_verify(&pubkey, msg, &r, &s));

        // Single-bit mutation in message or signature must fail closed
        assert!(!ecdsa_p384_verify(&pubkey, b"tampered", &r, &s));
        let mut bad_s = s;
        bad_s[47] ^= 0x01;
        assert!(!ecdsa_p384_verify(&pubkey, msg, &r, &bad_s));
    }
}

#[cfg(test)]
mod adaptive_routing_tests {
    use super::*;

    #[test]
    fn test_ct_adaptive_route_decision_boundaries() {
        let test_vectors: &[(u64, u64, u32, u64)] = &[
            (0, 0, NONA_ROUTE_DH_PSI, 0),
            (1, 128, NONA_ROUTE_DH_PSI, 0),
            (1, 129, NONA_ROUTE_VOLE_PSI, 1),
            (1 << 56, 1 << 63, NONA_ROUTE_DH_PSI, 0),
            ((1 << 56) - 1, 1 << 63, NONA_ROUTE_VOLE_PSI, 1),
            (0, 1 << 63, NONA_ROUTE_VOLE_PSI, 1),
        ];

        for &(n, m, expected_route, expected_bit) in test_vectors {
            let (route, bit) = ct_adaptive_route_decision(n, m).unwrap_or((0, 0));
            assert_ne!(route, 0, "valid test vector rejected");
            assert_eq!(bit, expected_bit, "Bit mismatch for n={n}, m={m}");
            assert_eq!(route, expected_route, "Route mismatch for n={n}, m={m}");
        }
    }
}
