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
/// # Trusted Computing Base (TCB) Boundary Classification [VERIF-03]
/// High-Assurance Runtime Perimeter (Tier 3): secp256k1 scalar group arithmetic
/// modulo q and endomorphism reduction (lambda-decomposition) are explicitly scoped
/// out of the formal SMT inductive verification surface due to non-linear degree-2
/// reduction decidability limits. Canonicity, non-overflow, and algebraic distributivity
/// are validated via differential oracle fuzzing (TEST-02), Wycheproof vectors, and
/// domain boundary suites (TEST-08). Formally cataloged in docs/TCB.md §3 and SPECIFICATION.md §4.5.0.
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
}

#[cfg(test)]
mod tests_f25 {
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
