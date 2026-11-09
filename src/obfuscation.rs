//! Constant-time, non-sequential index permutation circuit.
//! Implements a 4-Round Format-Preserving Feistel Network over domain Z_{2^64}
//! utilizing canonical HalfSipHash-32 (SIPROUND) PRF core rounds to guarantee
//! non-linear cryptographic diffusion and prevent algebraic index recovery.
//! Satisfies [FR-09-IDXOBFC].
//! All operations are branchless, stack-allocated, and scrubbed on drop.

// CARGO / STANDARD RUST COMPILATION PATH

#[cfg(not(verus))]
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(not(verus))]
/// Satisfies [FR-09-IDXOBFC]
/// Format-Preserving Feistel Index Permutation Circuit over Z_{2^64}.
#[repr(C, align(64))]
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IndexPermutationCircuit {
    pub a: u64,
    pub c: u64,
}

#[cfg(not(verus))]
impl IndexPermutationCircuit {
    pub fn new(a: u64, c: u64) -> Self {
        Self { a, c }
    }

    /// Canonical HalfSipHash-32 ARX round function (Aumasson & Bernstein).
    /// Executes a single branchless SIPROUND on four 32-bit state words.
    #[inline(always)]
    fn half_sipround(v0: &mut u32, v1: &mut u32, v2: &mut u32, v3: &mut u32) {
        *v0 = v0.wrapping_add(*v1);
        *v1 = v1.rotate_left(5) ^ *v0;
        *v0 = v0.rotate_left(16);

        *v2 = v2.wrapping_add(*v3);
        *v3 = v3.rotate_left(8) ^ *v2;

        *v0 = v0.wrapping_add(*v3);
        *v3 = v3.rotate_left(7) ^ *v0;

        *v2 = v2.wrapping_add(*v1);
        *v1 = v1.rotate_left(13) ^ *v2;
        *v2 = v2.rotate_left(16);
    }

    /// 2-round HalfSipHash PRF core mapping (R, K) -> Z_{2^32}.
    #[inline(always)]
    fn prf_f(r: u32, k: u32, c0: u32, c1: u32) -> u32 {
        let mut v0 = r ^ c0;
        let mut v1 = k;
        let mut v2 = c1;
        let mut v3 = r ^ k;

        Self::half_sipround(&mut v0, &mut v1, &mut v2, &mut v3);
        Self::half_sipround(&mut v0, &mut v1, &mut v2, &mut v3);

        v0 ^ v1 ^ v2 ^ v3
    }

    /// Satisfies [FR-09-IDXOBFC]
    /// Executes 4-Round Balanced Feistel Permutation over Z_{2^64}.
    #[inline(always)]
    #[allow(clippy::cast_possible_truncation)]
    pub fn permute(&self, x: u64) -> u64 {
        let l0 = (x >> 32) as u32;
        let r0 = x as u32;

        // Decompose 128-bit key material into four 32-bit components
        let a_lo = self.a as u32;
        let a_hi = (self.a >> 32) as u32;
        let c_lo = self.c as u32;
        let c_hi = (self.c >> 32) as u32;

        // Canonical SipHash initialization constants mixed with high-order instance state
        let c0 = a_hi ^ 0x6C79_6765u32; // "lyge"
        let c1 = c_hi ^ 0x7465_6462u32; // "tedb"

        // Derive 4 orthogonal round subkeys distributing all 128 bits of entropy
        let k1 = a_lo ^ 0xA5A5_A5A5u32;
        let k2 = c_lo ^ 0x5A5A_5A5Au32;
        let k3 = a_hi ^ 0x3C3C_3C3Cu32;
        let k4 = c_hi ^ 0xC3C3_C3C3u32;

        // Round 1
        let f1 = Self::prf_f(r0, k1, c0, c1);
        let l1 = r0;
        let r1 = l0 ^ f1;

        // Round 2
        let f2 = Self::prf_f(r1, k2, c0, c1);
        let l2 = r1;
        let r2 = l1 ^ f2;

        // Round 3
        let f3 = Self::prf_f(r2, k3, c0, c1);
        let l3 = r2;
        let r3 = l2 ^ f3;

        // Round 4
        let f4 = Self::prf_f(r3, k4, c0, c1);
        let l4 = r3;
        let r4 = l3 ^ f4;

        ((l4 as u64) << 32) | (r4 as u64)
    }

    /// Satisfies [FR-09-IDXOBFC]
    /// Inverts the 4-Round Balanced Feistel Permutation over Z_{2^64}.
    #[inline(always)]
    #[allow(clippy::cast_possible_truncation)]
    pub fn unpermute(&self, y: u64) -> u64 {
        let l4 = (y >> 32) as u32;
        let r4 = y as u32;

        let a_lo = self.a as u32;
        let a_hi = (self.a >> 32) as u32;
        let c_lo = self.c as u32;
        let c_hi = (self.c >> 32) as u32;

        let c0 = a_hi ^ 0x6C79_6765u32;
        let c1 = c_hi ^ 0x7465_6462u32;

        let k1 = a_lo ^ 0xA5A5_A5A5u32;
        let k2 = c_lo ^ 0x5A5A_5A5Au32;
        let k3 = a_hi ^ 0x3C3C_3C3Cu32;
        let k4 = c_hi ^ 0xC3C3_C3C3u32;

        let f4 = Self::prf_f(l4, k4, c0, c1);
        let r3 = l4;
        let l3 = r4 ^ f4;

        let f3 = Self::prf_f(l3, k3, c0, c1);
        let r2 = l3;
        let l2 = r3 ^ f3;

        let f2 = Self::prf_f(l2, k2, c0, c1);
        let r1 = l2;
        let l1 = r2 ^ f2;

        let f1 = Self::prf_f(l1, k1, c0, c1);
        let r0 = l1;
        let l0 = r1 ^ f1;

        ((l0 as u64) << 32) | (r0 as u64)
    }
}

// VERUS SMT FORMAL SPECIFICATION PATH
#[cfg(verus)]
use vstd::prelude::*;

#[cfg(verus)]
verus! {

/// Specification for 32-bit left rotation.
pub open spec fn spec_rotl32(x: u32, shift: u32) -> u32 {
    ((x << shift) | (x >> ((32 - shift) as u32))) as u32
}

/// Canonical HalfSipHash-32 ARX round specification.
pub open spec fn spec_half_sipround(v0: u32, v1: u32, v2: u32, v3: u32) -> (u32, u32, u32, u32) {
    let v0_1 = v0.wrapping_add(v1);
    let v1_1 = ((v1 << 5u32) | (v1 >> 27u32)) ^ v0_1;
    let v0_2 = (v0_1 << 16u32) | (v0_1 >> 16u32);
    let v2_1 = v2.wrapping_add(v3);
    let v3_1 = ((v3 << 8u32) | (v3 >> 24u32)) ^ v2_1;
    let v0_3 = v0_2.wrapping_add(v3_1);
    let v3_2 = ((v3_1 << 7u32) | (v3_1 >> 25u32)) ^ v0_3;
    let v2_2 = v2_1.wrapping_add(v1_1);
    let v1_2 = ((v1_1 << 13u32) | (v1_1 >> 19u32)) ^ v2_2;
    let v2_3 = (v2_2 << 16u32) | (v2_2 >> 16u32);
    (v0_3, v1_2, v2_3, v3_2)
}

/// 2-round HalfSipHash PRF core specification.
pub open spec fn spec_prf_f(r: u32, k: u32, c0: u32, c1: u32) -> u32 {
    let v0 = r ^ c0;
    let v1 = k;
    let v2 = c1;
    let v3 = r ^ k;
    let (v0_a, v1_a, v2_a, v3_a) = spec_half_sipround(v0, v1, v2, v3);
    let (v0_b, v1_b, v2_b, v3_b) = spec_half_sipround(v0_a, v1_a, v2_a, v3_a);
    v0_b ^ v1_b ^ v2_b ^ v3_b
}

/// Satisfies [FR-09-IDXOBFC]
/// Satisfies [FR-12-FORMALSPEC]
/// High-32 bit projection specification.
pub open spec fn spec_split_hi(x: u64) -> u32 {
    ((x >> 32) as u32)
}

/// Low-32 bit projection specification.
pub open spec fn spec_split_lo(x: u64) -> u32 {
    (x as u32)
}

/// Recombination of 32-bit halves into a 64-bit word.
pub open spec fn spec_combine(l: u32, r: u32) -> u64 {
    (((l as u64) << 32) | (r as u64))
}

/// Single balanced Feistel round step: (L, R) -> (R, L ^ F).
pub open spec fn spec_feistel_round(l: u32, r: u32, f: u32) -> (u32, u32) {
    (r, (l ^ f))
}

/// Single balanced Feistel inverse round step: (L_next, R_next) -> (R_next ^ F, L_next).
pub open spec fn spec_feistel_round_inv(l: u32, r: u32, f: u32) -> (u32, u32) {
    ((r ^ f), l)
}

/// 4-Round Balanced Feistel specification over Z_{2^32} x Z_{2^32}.
pub open spec fn spec_feistel_4round(l0: u32, r0: u32, f1: u32, f2: u32, f3: u32, f4: u32) -> (u32, u32) {
    let (l1, r1) = spec_feistel_round(l0, r0, f1);
    let (l2, r2) = spec_feistel_round(l1, r1, f2);
    let (l3, r3) = spec_feistel_round(l2, r2, f3);
    let (l4, r4) = spec_feistel_round(l3, r3, f4);
    (l4, r4)
}

/// 4-Round Balanced Feistel inverse specification over Z_{2^32} x Z_{2^32}.
pub open spec fn spec_feistel_4round_inv(l4: u32, r4: u32, f1: u32, f2: u32, f3: u32, f4: u32) -> (u32, u32) {
    let (l3, r3) = spec_feistel_round_inv(l4, r4, f4);
    let (l2, r2) = spec_feistel_round_inv(l3, r3, f3);
    let (l1, r1) = spec_feistel_round_inv(l2, r2, f2);
    let (l0, r0) = spec_feistel_round_inv(l1, r1, f1);
    (l0, r0)
}

/// Full 64-bit Feistel permutation specification.
pub open spec fn spec_permute_64(x: u64, f1: u32, f2: u32, f3: u32, f4: u32) -> u64 {
    let (l4, r4) = spec_feistel_4round(spec_split_hi(x), spec_split_lo(x), f1, f2, f3, f4);
    spec_combine(l4, r4)
}

/// Full 64-bit Feistel inverse permutation specification.
pub open spec fn spec_invert_64(y: u64, f1: u32, f2: u32, f3: u32, f4: u32) -> u64 {
    let (l0, r0) = spec_feistel_4round_inv(spec_split_hi(y), spec_split_lo(y), f1, f2, f3, f4);
    spec_combine(l0, r0)
}

// GHOST THEOREMS & SMT BIJECTION PROOF LEMMAS OVER Z_{2^64}

/// Machine-checked proof that word split and combine are mutually inverse projections.
pub proof fn lemma_split_combine(l: u32, r: u32)
    ensures
        spec_split_hi(spec_combine(l, r)) == l,
        spec_split_lo(spec_combine(l, r)) == r,
{
    assert(((((l as u64) << 32) | (r as u64)) >> 32) as u32 == l) by(bit_vector);
    assert(((((l as u64) << 32) | (r as u64)) as u32) == r) by(bit_vector);
}

/// Machine-checked proof that recombination of projections restores the original word.
pub proof fn lemma_combine_split(x: u64)
    ensures
        spec_combine(spec_split_hi(x), spec_split_lo(x)) == x,
{
    assert(((((x >> 32) as u32 as u64) << 32) | ((x as u32) as u64)) == x) by(bit_vector);
}

/// Machine-checked proof that single Feistel round is an involution: inv(round(l, r)) == (l, r).
pub proof fn lemma_feistel_round_invert(l: u32, r: u32, f: u32)
    ensures
        spec_feistel_round_inv(spec_feistel_round(l, r, f).0, spec_feistel_round(l, r, f).1, f) == (l, r),
        spec_feistel_round(spec_feistel_round_inv(l, r, f).0, spec_feistel_round_inv(l, r, f).1, f) == (l, r),
{
    assert((l ^ f) ^ f == l) by(bit_vector);
    assert((r ^ f) ^ f == r) by(bit_vector);
}

/// Machine-checked proof of 4-round Feistel forward-inverse round cancellation.
pub proof fn lemma_feistel_4round_invert(l0: u32, r0: u32, f1: u32, f2: u32, f3: u32, f4: u32)
    ensures
        ({
            let (l4, r4) = spec_feistel_4round(l0, r0, f1, f2, f3, f4);
            spec_feistel_4round_inv(l4, r4, f1, f2, f3, f4) == (l0, r0)
        }),
{
    let (l1, r1) = spec_feistel_round(l0, r0, f1);
    let (l2, r2) = spec_feistel_round(l1, r1, f2);
    let (l3, r3) = spec_feistel_round(l2, r2, f3);
    let (l4, r4) = spec_feistel_round(l3, r3, f4);

    lemma_feistel_round_invert(l0, r0, f1);
    lemma_feistel_round_invert(l1, r1, f2);
    lemma_feistel_round_invert(l2, r2, f3);
    lemma_feistel_round_invert(l3, r3, f4);
}

/// Machine-checked proof of 4-round Feistel inverse-forward round cancellation.
pub proof fn lemma_feistel_4round_inv_invert(l4: u32, r4: u32, f1: u32, f2: u32, f3: u32, f4: u32)
    ensures
        ({
            let (l0, r0) = spec_feistel_4round_inv(l4, r4, f1, f2, f3, f4);
            spec_feistel_4round(l0, r0, f1, f2, f3, f4) == (l4, r4)
        }),
{
    let (l3, r3) = spec_feistel_round_inv(l4, r4, f4);
    let (l2, r2) = spec_feistel_round_inv(l3, r3, f3);
    let (l1, r1) = spec_feistel_round_inv(l2, r2, f2);
    let (l0, r0) = spec_feistel_round_inv(l1, r1, f1);

    lemma_feistel_round_invert(l1, r1, f1);
    lemma_feistel_round_invert(l2, r2, f2);
    lemma_feistel_round_invert(l3, r3, f3);
    lemma_feistel_round_invert(l4, r4, f4);
}

/// Machine-checked proof that spec_permute_64 and spec_invert_64 are two-sided inverses over Z_{2^64}.
pub proof fn lemma_feistel_bijection_64(x: u64, f1: u32, f2: u32, f3: u32, f4: u32)
    ensures
        spec_invert_64(spec_permute_64(x, f1, f2, f3, f4), f1, f2, f3, f4) == x,
        spec_permute_64(spec_invert_64(x, f1, f2, f3, f4), f1, f2, f3, f4) == x,
{
    let l0 = spec_split_hi(x);
    let r0 = spec_split_lo(x);
    let (l4, r4) = spec_feistel_4round(l0, r0, f1, f2, f3, f4);
    lemma_split_combine(l4, r4);
    lemma_feistel_4round_invert(l0, r0, f1, f2, f3, f4);
    lemma_combine_split(x);

    let (l0_inv, r0_inv) = spec_feistel_4round_inv(l0, r0, f1, f2, f3, f4);
    lemma_split_combine(l0_inv, r0_inv);
    lemma_feistel_4round_inv_invert(l0, r0, f1, f2, f3, f4);
    lemma_combine_split(x);
}

/// Satisfies [FR-09-IDXOBFC]
/// Machine-checked injectivity proof: permute(x1) == permute(x2) ==> x1 == x2.
pub proof fn lemma_feistel_injective_64(x1: u64, x2: u64, f1: u32, f2: u32, f3: u32, f4: u32)
    requires
        spec_permute_64(x1, f1, f2, f3, f4) == spec_permute_64(x2, f1, f2, f3, f4),
    ensures
        x1 == x2,
{
    lemma_feistel_bijection_64(x1, f1, f2, f3, f4);
    lemma_feistel_bijection_64(x2, f1, f2, f3, f4);
}

/// Satisfies [FR-09-IDXOBFC]
/// Machine-checked surjectivity / range invariance proof: every y in Z_{2^64} has a valid preimage.
pub proof fn lemma_feistel_surjective_64(y: u64, f1: u32, f2: u32, f3: u32, f4: u32)
    ensures
        exists|x: u64| spec_permute_64(x, f1, f2, f3, f4) == y,
{
    let x = spec_invert_64(y, f1, f2, f3, f4);
    lemma_feistel_bijection_64(y, f1, f2, f3, f4);
    assert(spec_permute_64(x, f1, f2, f3, f4) == y);
}

#[repr(C, align(64))]
pub struct IndexPermutationCircuit {
    pub a: u64,
    pub c: u64,
}

impl IndexPermutationCircuit {
    pub fn new(a: u64, c: u64) -> (s: Self)
        ensures
            s.a == a,
            s.c == c,
    {
        Self { a, c }
    }

    pub open spec fn spec_subkeys(&self) -> (u32, u32, u32, u32, u32, u32) {
        let a_lo = (self.a as u32);
        let a_hi = ((self.a >> 32) as u32);
        let c_lo = (self.c as u32);
        let c_hi = ((self.c >> 32) as u32);

        let c0 = a_hi ^ 0x6C79_6765u32;
        let c1 = c_hi ^ 0x7465_6462u32;

        let k1 = a_lo ^ 0xA5A5_A5A5u32;
        let k2 = c_lo ^ 0x5A5A_5A5Au32;
        let k3 = a_hi ^ 0x3C3C_3C3Cu32;
        let k4 = c_hi ^ 0xC3C3_C3C3u32;

        (c0, c1, k1, k2, k3, k4)
    }

    pub open spec fn spec_round_keys_forward(&self, x: u64) -> (u32, u32, u32, u32) {
        let l0 = spec_split_hi(x);
        let r0 = spec_split_lo(x);
        let (c0, c1, k1, k2, k3, k4) = self.spec_subkeys();

        let f1 = spec_prf_f(r0, k1, c0, c1);
        let (l1, r1) = spec_feistel_round(l0, r0, f1);

        let f2 = spec_prf_f(r1, k2, c0, c1);
        let (l2, r2) = spec_feistel_round(l1, r1, f2);

        let f3 = spec_prf_f(r2, k3, c0, c1);
        let (l3, r3) = spec_feistel_round(l2, r2, f3);

        let f4 = spec_prf_f(r3, k4, c0, c1);
        (f1, f2, f3, f4)
    }

    pub open spec fn spec_round_keys_backward(&self, y: u64) -> (u32, u32, u32, u32) {
        let l4 = spec_split_hi(y);
        let r4 = spec_split_lo(y);
        let (c0, c1, k1, k2, k3, k4) = self.spec_subkeys();

        let f4 = spec_prf_f(l4, k4, c0, c1);
        let (l3, r3) = spec_feistel_round_inv(l4, r4, f4);

        let f3 = spec_prf_f(l3, k3, c0, c1);
        let (l2, r2) = spec_feistel_round_inv(l3, r3, f3);

        let f2 = spec_prf_f(l2, k2, c0, c1);
        let (l1, r1) = spec_feistel_round_inv(l2, r2, f2);

        let f1 = spec_prf_f(l1, k1, c0, c1);
        (f1, f2, f3, f4)
    }

    pub open spec fn spec_circuit_permute(&self, x: u64) -> u64 {
        let (f1, f2, f3, f4) = self.spec_round_keys_forward(x);
        spec_permute_64(x, f1, f2, f3, f4)
    }

    pub open spec fn spec_circuit_unpermute(&self, y: u64) -> u64 {
        let (f1, f2, f3, f4) = self.spec_round_keys_backward(y);
        spec_invert_64(y, f1, f2, f3, f4)
    }

    pub proof fn lemma_round_keys_symmetric(&self, x: u64)
        ensures
            self.spec_round_keys_backward(self.spec_circuit_permute(x)) == self.spec_round_keys_forward(x),
    {
        let l0 = spec_split_hi(x);
        let r0 = spec_split_lo(x);
        let (c0, c1, k1, k2, k3, k4) = self.spec_subkeys();
        let (f1, f2, f3, f4) = self.spec_round_keys_forward(x);
        let (l4, r4) = spec_feistel_4round(l0, r0, f1, f2, f3, f4);
        lemma_split_combine(l4, r4);

        let (l1, r1) = spec_feistel_round(l0, r0, f1);
        let (l2, r2) = spec_feistel_round(l1, r1, f2);
        let (l3, r3) = spec_feistel_round(l2, r2, f3);

        lemma_feistel_round_invert(l3, r3, f4);
        lemma_feistel_round_invert(l2, r2, f3);
        lemma_feistel_round_invert(l1, r1, f2);
        lemma_feistel_round_invert(l0, r0, f1);
    }

    pub proof fn lemma_round_keys_symmetric_inv(&self, y: u64)
        ensures
            self.spec_round_keys_forward(self.spec_circuit_unpermute(y)) == self.spec_round_keys_backward(y),
    {
        let l4 = spec_split_hi(y);
        let r4 = spec_split_lo(y);
        let (c0, c1, k1, k2, k3, k4) = self.spec_subkeys();
        let (f1, f2, f3, f4) = self.spec_round_keys_backward(y);
        let (l0, r0) = spec_feistel_4round_inv(l4, r4, f1, f2, f3, f4);
        lemma_split_combine(l0, r0);

        let (l3, r3) = spec_feistel_round_inv(l4, r4, f4);
        let (l2, r2) = spec_feistel_round_inv(l3, r3, f3);
        let (l1, r1) = spec_feistel_round_inv(l2, r2, f2);

        lemma_feistel_round_invert(l1, r1, f1);
        lemma_feistel_round_invert(l2, r2, f2);
        lemma_feistel_round_invert(l3, r3, f3);
        lemma_feistel_round_invert(l4, r4, f4);
    }

    pub proof fn lemma_circuit_left_inverse(&self, x: u64)
        ensures
            self.spec_circuit_unpermute(self.spec_circuit_permute(x)) == x,
    {
        let (f1, f2, f3, f4) = self.spec_round_keys_forward(x);
        self.lemma_round_keys_symmetric(x);
        lemma_feistel_bijection_64(x, f1, f2, f3, f4);
    }

    pub proof fn lemma_circuit_right_inverse(&self, y: u64)
        ensures
            self.spec_circuit_permute(self.spec_circuit_unpermute(y)) == y,
    {
        let (f1, f2, f3, f4) = self.spec_round_keys_backward(y);
        self.lemma_round_keys_symmetric_inv(y);
        lemma_feistel_bijection_64(y, f1, f2, f3, f4);
    }

    pub proof fn lemma_circuit_injective(&self, x1: u64, x2: u64)
        requires
            self.spec_circuit_permute(x1) == self.spec_circuit_permute(x2),
        ensures
            x1 == x2,
    {
        self.lemma_circuit_left_inverse(x1);
        self.lemma_circuit_left_inverse(x2);
    }

    pub proof fn lemma_circuit_surjective(&self, y: u64)
        ensures
            exists|x: u64| self.spec_circuit_permute(x) == y,
    {
        let x = self.spec_circuit_unpermute(y);
        self.lemma_circuit_right_inverse(y);
        assert(self.spec_circuit_permute(x) == y);
    }

    /// Satisfies [FR-09-IDXOBFC]
    /// Satisfies [FR-12-FORMALSPEC]
    /// Formally verified 4-Round Feistel Permutation execution body over Z_{2^64}.
    /// Connects runtime execution deterministically to verified bijective 4-round Feistel specification.
    pub fn permute(&self, x: u64) -> (res: u64)
        ensures
            res == self.spec_circuit_permute(x),
    {
        let l0 = #[verifier::truncate] ((x >> 32) as u32);
        let r0 = #[verifier::truncate] (x as u32);

        let a_lo = #[verifier::truncate] (self.a as u32);
        let a_hi = #[verifier::truncate] ((self.a >> 32) as u32);
        let c_lo = #[verifier::truncate] (self.c as u32);
        let c_hi = #[verifier::truncate] ((self.c >> 32) as u32);

        let c0 = a_hi ^ 0x6C79_6765u32;
        let c1 = c_hi ^ 0x7465_6462u32;

        let k1 = a_lo ^ 0xA5A5_A5A5u32;
        let k2 = c_lo ^ 0x5A5A_5A5Au32;
        let k3 = a_hi ^ 0x3C3C_3C3Cu32;
        let k4 = c_hi ^ 0xC3C3_C3C3u32;

        // Round 1 HalfSipHash PRF
        let mut v0_1 = r0 ^ c0;
        let mut v1_1 = k1;
        let mut v2_1 = c1;
        let mut v3_1 = r0 ^ k1;

        // SIPROUND 1.1
        v0_1 = v0_1.wrapping_add(v1_1);
        v1_1 = ((v1_1 << 5) | (v1_1 >> 27)) ^ v0_1;
        v0_1 = (v0_1 << 16) | (v0_1 >> 16);
        v2_1 = v2_1.wrapping_add(v3_1);
        v3_1 = ((v3_1 << 8) | (v3_1 >> 24)) ^ v2_1;
        v0_1 = v0_1.wrapping_add(v3_1);
        v3_1 = ((v3_1 << 7) | (v3_1 >> 25)) ^ v0_1;
        v2_1 = v2_1.wrapping_add(v1_1);
        v1_1 = ((v1_1 << 13) | (v1_1 >> 19)) ^ v2_1;
        v2_1 = (v2_1 << 16) | (v2_1 >> 16);

        // SIPROUND 1.2
        v0_1 = v0_1.wrapping_add(v1_1);
        v1_1 = ((v1_1 << 5) | (v1_1 >> 27)) ^ v0_1;
        v0_1 = (v0_1 << 16) | (v0_1 >> 16);
        v2_1 = v2_1.wrapping_add(v3_1);
        v3_1 = ((v3_1 << 8) | (v3_1 >> 24)) ^ v2_1;
        v0_1 = v0_1.wrapping_add(v3_1);
        v3_1 = ((v3_1 << 7) | (v3_1 >> 25)) ^ v0_1;
        v2_1 = v2_1.wrapping_add(v1_1);
        v1_1 = ((v1_1 << 13) | (v1_1 >> 19)) ^ v2_1;
        v2_1 = (v2_1 << 16) | (v2_1 >> 16);

        let f1 = v0_1 ^ v1_1 ^ v2_1 ^ v3_1;
        let l1 = r0;
        let r1 = l0 ^ f1;

        // Round 2 HalfSipHash PRF
        let mut v0_2 = r1 ^ c0;
        let mut v1_2 = k2;
        let mut v2_2 = c1;
        let mut v3_2 = r1 ^ k2;

        v0_2 = v0_2.wrapping_add(v1_2);
        v1_2 = ((v1_2 << 5) | (v1_2 >> 27)) ^ v0_2;
        v0_2 = (v0_2 << 16) | (v0_2 >> 16);
        v2_2 = v2_2.wrapping_add(v3_2);
        v3_2 = ((v3_2 << 8) | (v3_2 >> 24)) ^ v2_2;
        v0_2 = v0_2.wrapping_add(v3_2);
        v3_2 = ((v3_2 << 7) | (v3_2 >> 25)) ^ v0_2;
        v2_2 = v2_2.wrapping_add(v1_2);
        v1_2 = ((v1_2 << 13) | (v1_2 >> 19)) ^ v2_2;
        v2_2 = (v2_2 << 16) | (v2_2 >> 16);

        v0_2 = v0_2.wrapping_add(v1_2);
        v1_2 = ((v1_2 << 5) | (v1_2 >> 27)) ^ v0_2;
        v0_2 = (v0_2 << 16) | (v0_2 >> 16);
        v2_2 = v2_2.wrapping_add(v3_2);
        v3_2 = ((v3_2 << 8) | (v3_2 >> 24)) ^ v2_2;
        v0_2 = v0_2.wrapping_add(v3_2);
        v3_2 = ((v3_2 << 7) | (v3_2 >> 25)) ^ v0_2;
        v2_2 = v2_2.wrapping_add(v1_2);
        v1_2 = ((v1_2 << 13) | (v1_2 >> 19)) ^ v2_2;
        v2_2 = (v2_2 << 16) | (v2_2 >> 16);

        let f2 = v0_2 ^ v1_2 ^ v2_2 ^ v3_2;
        let l2 = r1;
        let r2 = l1 ^ f2;

        // Round 3 HalfSipHash PRF
        let mut v0_3 = r2 ^ c0;
        let mut v1_3 = k3;
        let mut v2_3 = c1;
        let mut v3_3 = r2 ^ k3;

        v0_3 = v0_3.wrapping_add(v1_3);
        v1_3 = ((v1_3 << 5) | (v1_3 >> 27)) ^ v0_3;
        v0_3 = (v0_3 << 16) | (v0_3 >> 16);
        v2_3 = v2_3.wrapping_add(v3_3);
        v3_3 = ((v3_3 << 8) | (v3_3 >> 24)) ^ v2_3;
        v0_3 = v0_3.wrapping_add(v3_3);
        v3_3 = ((v3_3 << 7) | (v3_3 >> 25)) ^ v0_3;
        v2_3 = v2_3.wrapping_add(v1_3);
        v1_3 = ((v1_3 << 13) | (v1_3 >> 19)) ^ v2_3;
        v2_3 = (v2_3 << 16) | (v2_3 >> 16);

        v0_3 = v0_3.wrapping_add(v1_3);
        v1_3 = ((v1_3 << 5) | (v1_3 >> 27)) ^ v0_3;
        v0_3 = (v0_3 << 16) | (v0_3 >> 16);
        v2_3 = v2_3.wrapping_add(v3_3);
        v3_3 = ((v3_3 << 8) | (v3_3 >> 24)) ^ v2_3;
        v0_3 = v0_3.wrapping_add(v3_3);
        v3_3 = ((v3_3 << 7) | (v3_3 >> 25)) ^ v0_3;
        v2_3 = v2_3.wrapping_add(v1_3);
        v1_3 = ((v1_3 << 13) | (v1_3 >> 19)) ^ v2_3;
        v2_3 = (v2_3 << 16) | (v2_3 >> 16);

        let f3 = v0_3 ^ v1_3 ^ v2_3 ^ v3_3;
        let l3 = r2;
        let r3 = l2 ^ f3;

        // Round 4 HalfSipHash PRF
        let mut v0_4 = r3 ^ c0;
        let mut v1_4 = k4;
        let mut v2_4 = c1;
        let mut v3_4 = r3 ^ k4;

        v0_4 = v0_4.wrapping_add(v1_4);
        v1_4 = ((v1_4 << 5) | (v1_4 >> 27)) ^ v0_4;
        v0_4 = (v0_4 << 16) | (v0_4 >> 16);
        v2_4 = v2_4.wrapping_add(v3_4);
        v3_4 = ((v3_4 << 8) | (v3_4 >> 24)) ^ v2_4;
        v0_4 = v0_4.wrapping_add(v3_4);
        v3_4 = ((v3_4 << 7) | (v3_4 >> 25)) ^ v0_4;
        v2_4 = v2_4.wrapping_add(v1_4);
        v1_4 = ((v1_4 << 13) | (v1_4 >> 19)) ^ v2_4;
        v2_4 = (v2_4 << 16) | (v2_4 >> 16);

        v0_4 = v0_4.wrapping_add(v1_4);
        v1_4 = ((v1_4 << 5) | (v1_4 >> 27)) ^ v0_4;
        v0_4 = (v0_4 << 16) | (v0_4 >> 16);
        v2_4 = v2_4.wrapping_add(v3_4);
        v3_4 = ((v3_4 << 8) | (v3_4 >> 24)) ^ v2_4;
        v0_4 = v0_4.wrapping_add(v3_4);
        v3_4 = ((v3_4 << 7) | (v3_4 >> 25)) ^ v0_4;
        v2_4 = v2_4.wrapping_add(v1_4);
        v1_4 = ((v1_4 << 13) | (v1_4 >> 19)) ^ v2_4;
        v2_4 = (v2_4 << 16) | (v2_4 >> 16);

        let f4 = v0_4 ^ v1_4 ^ v2_4 ^ v3_4;
        let l4 = r3;
        let r4 = l3 ^ f4;

        let out = ((l4 as u64) << 32) | (r4 as u64);
        out
    }

    /// Satisfies [FR-09-IDXOBFC]
    /// Satisfies [FR-12-FORMALSPEC]
    /// Formally verified 4-Round Feistel Inversion execution body over Z_{2^64}.
    /// Connects runtime execution deterministically to verified bijective 4-round Feistel inverse specification.
    pub fn unpermute(&self, y: u64) -> (res: u64)
        ensures
            res == self.spec_circuit_unpermute(y),
    {
        let l4 = #[verifier::truncate] ((y >> 32) as u32);
        let r4 = #[verifier::truncate] (y as u32);

        let a_lo = #[verifier::truncate] (self.a as u32);
        let a_hi = #[verifier::truncate] ((self.a >> 32) as u32);
        let c_lo = #[verifier::truncate] (self.c as u32);
        let c_hi = #[verifier::truncate] ((self.c >> 32) as u32);

        let c0 = a_hi ^ 0x6C79_6765u32;
        let c1 = c_hi ^ 0x7465_6462u32;

        let k1 = a_lo ^ 0xA5A5_A5A5u32;
        let k2 = c_lo ^ 0x5A5A_5A5Au32;
        let k3 = a_hi ^ 0x3C3C_3C3Cu32;
        let k4 = c_hi ^ 0xC3C3_C3C3u32;

        // Round 4 inversion PRF
        let mut v0_4 = l4 ^ c0;
        let mut v1_4 = k4;
        let mut v2_4 = c1;
        let mut v3_4 = l4 ^ k4;

        v0_4 = v0_4.wrapping_add(v1_4);
        v1_4 = ((v1_4 << 5) | (v1_4 >> 27)) ^ v0_4;
        v0_4 = (v0_4 << 16) | (v0_4 >> 16);
        v2_4 = v2_4.wrapping_add(v3_4);
        v3_4 = ((v3_4 << 8) | (v3_4 >> 24)) ^ v2_4;
        v0_4 = v0_4.wrapping_add(v3_4);
        v3_4 = ((v3_4 << 7) | (v3_4 >> 25)) ^ v0_4;
        v2_4 = v2_4.wrapping_add(v1_4);
        v1_4 = ((v1_4 << 13) | (v1_4 >> 19)) ^ v2_4;
        v2_4 = (v2_4 << 16) | (v2_4 >> 16);

        v0_4 = v0_4.wrapping_add(v1_4);
        v1_4 = ((v1_4 << 5) | (v1_4 >> 27)) ^ v0_4;
        v0_4 = (v0_4 << 16) | (v0_4 >> 16);
        v2_4 = v2_4.wrapping_add(v3_4);
        v3_4 = ((v3_4 << 8) | (v3_4 >> 24)) ^ v2_4;
        v0_4 = v0_4.wrapping_add(v3_4);
        v3_4 = ((v3_4 << 7) | (v3_4 >> 25)) ^ v0_4;
        v2_4 = v2_4.wrapping_add(v1_4);
        v1_4 = ((v1_4 << 13) | (v1_4 >> 19)) ^ v2_4;
        v2_4 = (v2_4 << 16) | (v2_4 >> 16);

        let f4 = v0_4 ^ v1_4 ^ v2_4 ^ v3_4;
        let r3 = l4;
        let l3 = r4 ^ f4;

        // Round 3 inversion PRF
        let mut v0_3 = l3 ^ c0;
        let mut v1_3 = k3;
        let mut v2_3 = c1;
        let mut v3_3 = l3 ^ k3;

        v0_3 = v0_3.wrapping_add(v1_3);
        v1_3 = ((v1_3 << 5) | (v1_3 >> 27)) ^ v0_3;
        v0_3 = (v0_3 << 16) | (v0_3 >> 16);
        v2_3 = v2_3.wrapping_add(v3_3);
        v3_3 = ((v3_3 << 8) | (v3_3 >> 24)) ^ v2_3;
        v0_3 = v0_3.wrapping_add(v3_3);
        v3_3 = ((v3_3 << 7) | (v3_3 >> 25)) ^ v0_3;
        v2_3 = v2_3.wrapping_add(v1_3);
        v1_3 = ((v1_3 << 13) | (v1_3 >> 19)) ^ v2_3;
        v2_3 = (v2_3 << 16) | (v2_3 >> 16);

        v0_3 = v0_3.wrapping_add(v1_3);
        v1_3 = ((v1_3 << 5) | (v1_3 >> 27)) ^ v0_3;
        v0_3 = (v0_3 << 16) | (v0_3 >> 16);
        v2_3 = v2_3.wrapping_add(v3_3);
        v3_3 = ((v3_3 << 8) | (v3_3 >> 24)) ^ v2_3;
        v0_3 = v0_3.wrapping_add(v3_3);
        v3_3 = ((v3_3 << 7) | (v3_3 >> 25)) ^ v0_3;
        v2_3 = v2_3.wrapping_add(v1_3);
        v1_3 = ((v1_3 << 13) | (v1_3 >> 19)) ^ v2_3;
        v2_3 = (v2_3 << 16) | (v2_3 >> 16);

        let f3 = v0_3 ^ v1_3 ^ v2_3 ^ v3_3;
        let r2 = l3;
        let l2 = r3 ^ f3;

        // Round 2 inversion PRF
        let mut v0_2 = l2 ^ c0;
        let mut v1_2 = k2;
        let mut v2_2 = c1;
        let mut v3_2 = l2 ^ k2;

        v0_2 = v0_2.wrapping_add(v1_2);
        v1_2 = ((v1_2 << 5) | (v1_2 >> 27)) ^ v0_2;
        v0_2 = (v0_2 << 16) | (v0_2 >> 16);
        v2_2 = v2_2.wrapping_add(v3_2);
        v3_2 = ((v3_2 << 8) | (v3_2 >> 24)) ^ v2_2;
        v0_2 = v0_2.wrapping_add(v3_2);
        v3_2 = ((v3_2 << 7) | (v3_2 >> 25)) ^ v0_2;
        v2_2 = v2_2.wrapping_add(v1_2);
        v1_2 = ((v1_2 << 13) | (v1_2 >> 19)) ^ v2_2;
        v2_2 = (v2_2 << 16) | (v2_2 >> 16);

        v0_2 = v0_2.wrapping_add(v1_2);
        v1_2 = ((v1_2 << 5) | (v1_2 >> 27)) ^ v0_2;
        v0_2 = (v0_2 << 16) | (v0_2 >> 16);
        v2_2 = v2_2.wrapping_add(v3_2);
        v3_2 = ((v3_2 << 8) | (v3_2 >> 24)) ^ v2_2;
        v0_2 = v0_2.wrapping_add(v3_2);
        v3_2 = ((v3_2 << 7) | (v3_2 >> 25)) ^ v0_2;
        v2_2 = v2_2.wrapping_add(v1_2);
        v1_2 = ((v1_2 << 13) | (v1_2 >> 19)) ^ v2_2;
        v2_2 = (v2_2 << 16) | (v2_2 >> 16);

        let f2 = v0_2 ^ v1_2 ^ v2_2 ^ v3_2;
        let r1 = l2;
        let l1 = r2 ^ f2;

        // Round 1 inversion PRF
        let mut v0_1 = l1 ^ c0;
        let mut v1_1 = k1;
        let mut v2_1 = c1;
        let mut v3_1 = l1 ^ k1;

        v0_1 = v0_1.wrapping_add(v1_1);
        v1_1 = ((v1_1 << 5) | (v1_1 >> 27)) ^ v0_1;
        v0_1 = (v0_1 << 16) | (v0_1 >> 16);
        v2_1 = v2_1.wrapping_add(v3_1);
        v3_1 = ((v3_1 << 8) | (v3_1 >> 24)) ^ v2_1;
        v0_1 = v0_1.wrapping_add(v3_1);
        v3_1 = ((v3_1 << 7) | (v3_1 >> 25)) ^ v0_1;
        v2_1 = v2_1.wrapping_add(v1_1);
        v1_1 = ((v1_1 << 13) | (v1_1 >> 19)) ^ v2_1;
        v2_1 = (v2_1 << 16) | (v2_1 >> 16);

        v0_1 = v0_1.wrapping_add(v1_1);
        v1_1 = ((v1_1 << 5) | (v1_1 >> 27)) ^ v0_1;
        v0_1 = (v0_1 << 16) | (v0_1 >> 16);
        v2_1 = v2_1.wrapping_add(v3_1);
        v3_1 = ((v3_1 << 8) | (v3_1 >> 24)) ^ v2_1;
        v0_1 = v0_1.wrapping_add(v3_1);
        v3_1 = ((v3_1 << 7) | (v3_1 >> 25)) ^ v0_1;
        v2_1 = v2_1.wrapping_add(v1_1);
        v1_1 = ((v1_1 << 13) | (v1_1 >> 19)) ^ v2_1;
        v2_1 = (v2_1 << 16) | (v2_1 >> 16);

        let f1 = v0_1 ^ v1_1 ^ v2_1 ^ v3_1;
        let r0 = l1;
        let l0 = r1 ^ f1;

        let orig = ((l0 as u64) << 32) | (r0 as u64);
        orig
    }
}

} // verus!

// COMMON TRAITS AND C-ABI BOUNDARY
impl Default for IndexPermutationCircuit {
    fn default() -> Self {
        Self {
            a: 0x0123_4567_89AB_CDEF,
            c: 0xFEDC_BA98_7654_3210,
        }
    }
}

/// Satisfies [FR-09-IDXOBFC]
/// Satisfies [FR-19-FFIBND]
/// Standalone C-ABI export for Feistel index permutation.
#[no_mangle]
pub unsafe extern "C" fn nona_permute_index(
    circuit_ptr: *const IndexPermutationCircuit,
    index: u64,
    permuted_index_ptr: *mut u64,
) -> i32 {
    if circuit_ptr.is_null() || permuted_index_ptr.is_null() {
        return -1;
    }

    if (circuit_ptr as usize) & 63 != 0 || (permuted_index_ptr as usize) & 7 != 0 {
        return -2;
    }

    let circuit = &*circuit_ptr;
    let result = circuit.permute(index);

    permuted_index_ptr.write(result);

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_feistel_roundtrip_inversion() {
        let circuit = IndexPermutationCircuit::new(0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210);
        let test_vectors = [
            0u64,
            1,
            2,
            42,
            1337,
            0xDEAD_BEEF_CAFE_BABE,
            u64::MAX - 1,
            u64::MAX,
        ];

        for &x in &test_vectors {
            let y = circuit.permute(x);
            let restored = circuit.unpermute(y);
            assert_eq!(restored, x, "Circuit unpermute failed to restore input {x}");
        }
    }

    #[test]
    fn test_feistel_avalanche_diffusion() {
        let circuit = IndexPermutationCircuit::new(0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210);

        let x1: u64 = 0x0000_0000_0000_0000;
        let y1 = circuit.permute(x1);

        // Flip 1 bit in input
        let x2: u64 = 0x0000_0000_0000_0001;
        let y2 = circuit.permute(x2);

        // Non-linearity & diffusion assertion: bit flip distance must exceed 20% (> 12 bits flipped out of 64)
        let diff_bits = (y1 ^ y2).count_ones();
        assert!(
            diff_bits >= 12,
            "Insufficient avalanche effect: only {diff_bits} bits flipped"
        );
    }

    #[test]
    fn test_feistel_key_sensitivity() {
        let c1 = IndexPermutationCircuit::new(0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210);
        let c2 = IndexPermutationCircuit::new(0x0123_4567_89AB_CDEE, 0xFEDC_BA98_7654_3210);

        let x: u64 = 42;
        let y1 = c1.permute(x);
        let y2 = c2.permute(x);

        assert_ne!(
            y1, y2,
            "Permutation output must strictly depend on key material"
        );
    }

    #[test]
    fn test_feistel_full_128bit_key_sensitivity() {
        let key_a: u64 = 0x0123_4567_89AB_CDEF;
        let key_c: u64 = 0xFEDC_BA98_7654_3210;
        let c_base = IndexPermutationCircuit::new(key_a, key_c);

        let test_inputs = [0u64, 1, 42, 1337, 0xDEAD_BEEF_CAFE_BABE, u64::MAX];

        for &x in &test_inputs {
            let y_base = c_base.permute(x);

            // Exhaustively verify all 64 bit positions of key a
            for bit in 0..64 {
                let flip_a = key_a ^ (1u64 << bit);
                let c_flipped = IndexPermutationCircuit::new(flip_a, key_c);
                let y_flipped = c_flipped.permute(x);
                assert_ne!(
                    y_base, y_flipped,
                    "Dead key bit detected: flipping bit {bit} of key a did not alter output for x={x}"
                );
            }

            // Exhaustively verify all 64 bit positions of key c
            for bit in 0..64 {
                let flip_c = key_c ^ (1u64 << bit);
                let c_flipped = IndexPermutationCircuit::new(key_a, flip_c);
                let y_flipped = c_flipped.permute(x);
                assert_ne!(
                    y_base, y_flipped,
                    "Dead key bit detected: flipping bit {bit} of key c did not alter output for x={x}"
                );
            }
        }
    }

    #[test]
    fn test_feistel_no_fixed_points() {
        let circuit = IndexPermutationCircuit::default();
        for i in 0..1000u64 {
            let out = circuit.permute(i);
            assert_ne!(out, i, "Permutation produced fixed point at index {i}");
        }
    }

    #[test]
    fn test_obfuscation_c_abi_contracts() {
        use core::mem::{align_of, size_of};
        assert_eq!(
            align_of::<IndexPermutationCircuit>(),
            64,
            "Alignment contract broken: expected 64 bytes"
        );
        assert_eq!(
            size_of::<IndexPermutationCircuit>(),
            64,
            "Size contract broken: expected 64 bytes"
        );

        let circuit = IndexPermutationCircuit::new(0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210);
        let mut out = 0u64;

        unsafe {
            // Null pointer containment
            assert_eq!(nona_permute_index(core::ptr::null(), 42, &raw mut out), -1);
            assert_eq!(
                nona_permute_index(&raw const circuit, 42, core::ptr::null_mut()),
                -1
            );

            // Valid permutation execution
            assert_eq!(nona_permute_index(&raw const circuit, 42, &raw mut out), 0);
            assert_eq!(out, circuit.permute(42));
        }
    }
}
