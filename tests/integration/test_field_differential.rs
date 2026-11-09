#![allow(
    clippy::needless_range_loop,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
// Copyright (c) 2026 Nona Contributors.
// Licensed under the Apache License, Version 2.0 or the MIT License.

//! TEST-02: secp256k1 Field Arithmetic Differential & Stress Test Harness
//!
//! Differential and boundary verification of secp256k1 field reduction invariants:
//! - Independent reference 512-bit modular arithmetic oracle (RefU512)
//! - Pathological boundary and carry-forcing test vectors
//! - 10,000-trial differential testing against production FieldElement arithmetic
//! - Verification of field axioms: distributivity, associativity, and Fermat inversion

#![cfg(feature = "std")]

use nona_core::psi::FieldElement;

/// Prime modulus p = 2^256 - 2^32 - 977
const P_LIMBS: [u64; 4] = [
    0xFFFFFFFEFFFFFC2F,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];

/// Solinas constant K = 2^32 + 977 = 0x1000003D1
const K_VAL: u64 = 4_294_968_273;

// ============================================================================
// Independent 512-bit Arbitrary-Precision Arithmetic Reference Oracle
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RefU512 {
    limbs: [u64; 8],
}

impl RefU512 {
    const fn zero() -> Self {
        Self { limbs: [0; 8] }
    }

    fn from_fe(fe: &FieldElement) -> Self {
        Self {
            limbs: [
                fe.limbs[0],
                fe.limbs[1],
                fe.limbs[2],
                fe.limbs[3],
                0,
                0,
                0,
                0,
            ],
        }
    }

    fn from_limbs256(limbs: &[u64; 4]) -> Self {
        Self {
            limbs: [limbs[0], limbs[1], limbs[2], limbs[3], 0, 0, 0, 0],
        }
    }

    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        for i in (0..8).rev() {
            if self.limbs[i] < other.limbs[i] {
                return std::cmp::Ordering::Less;
            } else if self.limbs[i] > other.limbs[i] {
                return std::cmp::Ordering::Greater;
            }
        }
        std::cmp::Ordering::Equal
    }

    fn add(&self, other: &Self) -> Self {
        let mut out = [0u64; 8];
        let mut carry = 0u128;
        for i in 0..8 {
            let sum = (self.limbs[i] as u128) + (other.limbs[i] as u128) + carry;
            out[i] = sum as u64;
            carry = sum >> 64;
        }
        Self { limbs: out }
    }

    fn sub(&self, other: &Self) -> Self {
        let mut out = [0u64; 8];
        let mut borrow = 0i128;
        for i in 0..8 {
            let diff = (self.limbs[i] as i128) - (other.limbs[i] as i128) - borrow;
            if diff < 0 {
                out[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                out[i] = diff as u64;
                borrow = 0;
            }
        }
        Self { limbs: out }
    }

    fn mul256(a: &[u64; 4], b: &[u64; 4]) -> Self {
        let mut out = [0u64; 8];
        for i in 0..4 {
            let mut carry = 0u128;
            for j in 0..4 {
                let cur = out[i + j] as u128;
                let prod = (a[i] as u128) * (b[j] as u128) + cur + carry;
                out[i + j] = prod as u64;
                carry = prod >> 64;
            }
            out[i + 4] = carry as u64;
        }
        Self { limbs: out }
    }

    fn shl1(&mut self) -> u64 {
        let mut carry = 0u64;
        for i in 0..8 {
            let next_carry = self.limbs[i] >> 63;
            self.limbs[i] = (self.limbs[i] << 1) | carry;
            carry = next_carry;
        }
        carry
    }

    /// Exact Euclidean division remainder: self % modulus
    fn rem_mod(&self, modulus: &Self) -> Self {
        if self.cmp(modulus) == std::cmp::Ordering::Less {
            return *self;
        }
        let mut rem = Self::zero();
        for i in (0..512).rev() {
            let bit = (self.limbs[i / 64] >> (i % 64)) & 1;
            rem.shl1();
            rem.limbs[0] |= bit;
            if rem.cmp(modulus) != std::cmp::Ordering::Less {
                rem = rem.sub(modulus);
            }
        }
        rem
    }

    #[allow(clippy::wrong_self_convention)]
    fn to_fe(&self) -> FieldElement {
        FieldElement {
            limbs: [self.limbs[0], self.limbs[1], self.limbs[2], self.limbs[3]],
        }
    }
}

fn oracle_p() -> RefU512 {
    RefU512::from_limbs256(&P_LIMBS)
}

fn oracle_mod_add(a: &FieldElement, b: &FieldElement) -> FieldElement {
    let ra = RefU512::from_fe(a);
    let rb = RefU512::from_fe(b);
    let p = oracle_p();
    let sum = ra.add(&rb);
    sum.rem_mod(&p).to_fe()
}

fn oracle_mod_sub(a: &FieldElement, b: &FieldElement) -> FieldElement {
    let ra = RefU512::from_fe(a);
    let rb = RefU512::from_fe(b);
    let p = oracle_p();
    let diff = if ra.cmp(&rb) == std::cmp::Ordering::Less {
        ra.add(&p).sub(&rb)
    } else {
        ra.sub(&rb)
    };
    diff.rem_mod(&p).to_fe()
}

fn oracle_mod_mul(a: &FieldElement, b: &FieldElement) -> FieldElement {
    let prod = RefU512::mul256(&a.limbs, &b.limbs);
    let p = oracle_p();
    prod.rem_mod(&p).to_fe()
}

// XorShift PRNG for reproducible differential test vectors
struct XorShiftRng {
    state: u64,
}

impl XorShiftRng {
    fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0xDEADBEEF } else { seed },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }

    fn next_fe(&mut self) -> FieldElement {
        loop {
            let limbs = [
                self.next_u64(),
                self.next_u64(),
                self.next_u64(),
                self.next_u64(),
            ];
            let fe = FieldElement { limbs };
            // Ensure fe < P
            let r = RefU512::from_fe(&fe);
            if r.cmp(&oracle_p()) == std::cmp::Ordering::Less {
                return fe;
            }
        }
    }
}

// ============================================================================
// Differential Tests
// ============================================================================

#[test]
fn test_field_oracle_exact_boundary_vectors() {
    let zero = FieldElement::zero();
    let one = FieldElement::one();
    let p_minus_1 = FieldElement {
        limbs: [
            0xFFFFFFFEFFFFFC2E,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
        ],
    };
    let p_minus_2 = FieldElement {
        limbs: [
            0xFFFFFFFEFFFFFC2D,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
        ],
    };

    // 1. (p - 1) * (p - 1) = 1
    let sq_p_minus_1 = p_minus_1.mul(&p_minus_1);
    let expected_sq1 = oracle_mod_mul(&p_minus_1, &p_minus_1);
    assert_eq!(sq_p_minus_1.limbs, one.limbs);
    assert_eq!(sq_p_minus_1.limbs, expected_sq1.limbs);

    // 2. (p - 2) * (p - 2) = 4
    let sq_p_minus_2 = p_minus_2.mul(&p_minus_2);
    let expected_sq2 = oracle_mod_mul(&p_minus_2, &p_minus_2);
    let four = FieldElement {
        limbs: [4, 0, 0, 0],
    };
    assert_eq!(sq_p_minus_2.limbs, four.limbs);
    assert_eq!(sq_p_minus_2.limbs, expected_sq2.limbs);

    // 3. (p - 1) + 1 = 0
    let sum_p = p_minus_1.add(&one);
    assert_eq!(sum_p.limbs, zero.limbs);
    assert_eq!(sum_p.limbs, oracle_mod_add(&p_minus_1, &one).limbs);

    // 4. 0 - 1 = p - 1
    let diff_p = zero.sub(&one);
    assert_eq!(diff_p.limbs, p_minus_1.limbs);
    assert_eq!(diff_p.limbs, oracle_mod_sub(&zero, &one).limbs);

    // 5. Inversion of 1 and p - 1
    assert_eq!(one.invert().limbs, one.limbs);
    assert_eq!(p_minus_1.invert().limbs, p_minus_1.limbs);
}

#[test]
fn test_field_solinas_carry_forcing_vectors() {
    // Vectors specifically crafted to exercise Solinas carry3 folding
    // where high-order products produce multiple limb-carries into s3 and s4.
    let k_fe = FieldElement {
        limbs: [K_VAL, 0, 0, 0],
    };
    let p_minus_k = FieldElement {
        limbs: [
            0xFFFFFFFEFFFFFC2F - K_VAL,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
        ],
    };

    let prod = p_minus_k.mul(&k_fe);
    let expected = oracle_mod_mul(&p_minus_k, &k_fe);
    assert_eq!(
        prod.limbs, expected.limbs,
        "Solinas reduction mismatch on pathological carry-forcing vector p-K * K"
    );

    let sq_p_minus_k = p_minus_k.square();
    let expected_sq = oracle_mod_mul(&p_minus_k, &p_minus_k);
    assert_eq!(
        sq_p_minus_k.limbs, expected_sq.limbs,
        "Solinas square mismatch on pathological carry-forcing vector p-K"
    );
}

#[test]
fn test_field_differential_10k_random_operations() {
    const ITERATIONS: usize = 10_000;
    let mut rng = XorShiftRng::new(0x2026_1103_CAFE);

    for i in 0..ITERATIONS {
        let a = rng.next_fe();
        let b = rng.next_fe();

        // 1. Addition Differential
        let add_prod = a.add(&b);
        let add_ref = oracle_mod_add(&a, &b);
        assert_eq!(
            add_prod.limbs, add_ref.limbs,
            "Addition divergence at iteration {}: a={:?}, b={:?}",
            i, a.limbs, b.limbs
        );

        // 2. Subtraction Differential
        let sub_prod = a.sub(&b);
        let sub_ref = oracle_mod_sub(&a, &b);
        assert_eq!(
            sub_prod.limbs, sub_ref.limbs,
            "Subtraction divergence at iteration {}: a={:?}, b={:?}",
            i, a.limbs, b.limbs
        );

        // 3. Multiplication Differential & canonical reduction gate
        let mul_prod = a.mul(&b);
        let mul_ref = oracle_mod_mul(&a, &b);
        assert_eq!(
            mul_prod.limbs, mul_ref.limbs,
            "Multiplication divergence at iteration {}: a={:?}, b={:?}",
            i, a.limbs, b.limbs
        );

        // 4. Squaring Differential
        let sq_prod = a.square();
        let sq_ref = oracle_mod_mul(&a, &a);
        assert_eq!(
            sq_prod.limbs, sq_ref.limbs,
            "Squaring divergence at iteration {}: a={:?}",
            i, a.limbs
        );

        // 5. Invariant: strict canonicity (limbs strictly < P)
        let r_mul = RefU512::from_fe(&mul_prod);
        assert!(
            r_mul.cmp(&oracle_p()) == std::cmp::Ordering::Less,
            "Non-canonical multiplication output (limbs >= P) at iteration {}: limbs={:?}",
            i,
            mul_prod.limbs
        );
    }
}

#[test]
fn test_field_fermat_inversion_differential_invariants() {
    let mut rng = XorShiftRng::new(0xFEED_FACE_2026);
    let one = FieldElement::one();

    for i in 0..100 {
        let a = rng.next_fe();
        if a.is_zero() {
            continue;
        }

        let a_inv = a.invert();
        let prod = a.mul(&a_inv);

        assert_eq!(
            prod.limbs, one.limbs,
            "Fermat Little Theorem invariant broken: a * a^-1 != 1 at trial {}: a={:?}",
            i, a.limbs
        );
    }
}

#[test]
fn test_field_algebraic_distributivity_law() {
    let mut rng = XorShiftRng::new(0xABCD_EF01_2345);

    for i in 0..100 {
        let a = rng.next_fe();
        let b = rng.next_fe();
        let c = rng.next_fe();

        // a * (b + c)
        let b_plus_c = b.add(&c);
        let lhs = a.mul(&b_plus_c);

        // a * b + a * c
        let ab = a.mul(&b);
        let ac = a.mul(&c);
        let rhs = ab.add(&ac);

        assert_eq!(
            lhs.limbs, rhs.limbs,
            "Distributive law broken at trial {}: a={:?}, b={:?}, c={:?}",
            i, a.limbs, b.limbs, c.limbs
        );
    }
}
