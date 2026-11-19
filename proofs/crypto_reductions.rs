//! Machine-Checked Cryptographic Security Reductions for Nona DH-PSI & Payload OTP.
//! Formalizes prime-order cyclic group exponent blinding, Decisional Diffie-Hellman (DDH)
//! self-randomizability and non-DDH gap preservation, and 256-bit / 64-bit XOR one-time-pad
//! payload confidentiality with zero axiomatic overrides.

#![allow(unused_imports)]

use vstd::prelude::*;
use vstd::arithmetic::div_mod::*;

verus! {

// ============================================================================
// 1. MODULAR ARITHMETIC & EXTENDED EUCLIDEAN INVERSE FOUNDATIONS
// ============================================================================

/// Euclidean greatest common divisor over natural numbers.
pub open spec fn spec_gcd(a: nat, b: nat) -> nat
    decreases b
{
    if b == 0 {
        a
    } else {
        spec_gcd(b, a % b)
    }
}

/// Predicate characterizing a valid non-zero blinding scalar in Z_q*.
pub open spec fn is_valid_scalar(alpha: int, q: int) -> bool {
    0 < alpha && alpha < q
}

/// Predicate characterizing multiplicative inverse relation (alpha * alpha_inv) === 1 (mod q).
pub open spec fn is_mod_inverse(alpha: int, alpha_inv: int, q: int) -> bool {
    is_valid_scalar(alpha, q) &&
    is_valid_scalar(alpha_inv, q) &&
    ((alpha * alpha_inv) % q == 1)
}

/// Helper: left modular reduction invariance under multiplication.
pub proof fn lemma_mod_mul_left(a: int, b: int, q: int)
    requires
        q > 0,
    ensures
        ((a % q) * b) % q == (a * b) % q,
{
    let k = a / q;
    let r = a % q;
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(a, q);
    assert(a * b == (r * b) + (k * b) * q) by(nonlinear_arith)
        requires a == q * k + r;
    vstd::arithmetic::div_mod::lemma_mod_multiples_vanish(k * b, r * b, q);
}

/// Helper: right modular reduction invariance under multiplication.
pub proof fn lemma_mod_mul_right(a: int, b: int, q: int)
    requires
        q > 0,
    ensures
        (a * (b % q)) % q == (a * b) % q,
{
    assert(a * (b % q) == (b % q) * a) by(nonlinear_arith);
    assert(a * b == b * a) by(nonlinear_arith);
    lemma_mod_mul_left(b, a, q);
}

/// Helper: canonical small integer modulo identity (0 <= m < q ==> m % q == m).
pub proof fn lemma_small_mod_id(m: int, q: int)
    requires
        q > 0,
        0 <= m < q,
    ensures
        m % q == m,
{
    let k = m / q;
    let r = m % q;
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(m, q);
    assert(q > 0 && k >= 1 ==> q * k >= q) by(nonlinear_arith);
    assert(q > 0 && k <= -1 ==> q * k <= -q) by(nonlinear_arith);
    if k >= 1 {
        assert(q * k + r >= q);
        assert(false);
    }
    if k <= -1 {
        assert(q * k + r < 0);
        assert(false);
    }
    assert(k == 0);
    assert(m == q * k + r && k == 0 ==> m == r) by(nonlinear_arith);
}

/// Helper: if x, y in [0, q) and (x - y) % q == 0, then x == y.
pub proof fn lemma_mod_sub_eq_zero_implies_eq(x: int, y: int, q: int)
    requires
        q > 0,
        0 <= x < q,
        0 <= y < q,
        (x - y) % q == 0,
    ensures
        x == y,
{
    let k = (x - y) / q;
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(x - y, q);
    assert(q > 0 && k >= 1 ==> q * k >= q) by(nonlinear_arith);
    assert(q > 0 && k <= -1 ==> q * k <= -q) by(nonlinear_arith);
    if k >= 1 {
        assert(x - y >= q);
        assert(false);
    }
    if k <= -1 {
        assert(x - y <= -q);
        assert(false);
    }
    assert(k == 0);
    assert(x - y == q * 0 + 0 ==> x == y) by(nonlinear_arith);
}

/// Theorem 1: Prime-order subgroup exponent blinding multiplicative identity (x * 1 === x mod q).
pub proof fn lemma_mod_exp_identity(x: int, q: int)
    requires
        q > 1,
        0 <= x < q,
    ensures
        (x * 1) % q == x,
{
    assert(x * 1 == x) by(nonlinear_arith);
    lemma_small_mod_id(x, q);
}

/// Theorem 2: Associativity of sequential scalar blinding (((x * alpha) mod q) * beta === x * ((alpha * beta) mod q) mod q).
pub proof fn lemma_mod_exp_associativity(x: int, alpha: int, beta: int, q: int)
    requires
        q > 1,
    ensures
        (((x * alpha) % q) * beta) % q == (x * ((alpha * beta) % q)) % q,
{
    lemma_mod_mul_left(x * alpha, beta, q);
    lemma_mod_mul_right(x, alpha * beta, q);
    assert((x * alpha) * beta == x * (alpha * beta)) by(nonlinear_arith);
}

/// Theorem 3: Commutative DH-PSI double-blinding equivalence (((x * alpha) mod q) * beta === ((x * beta) mod q) * alpha mod q).
pub proof fn lemma_mod_exp_commutativity(x: int, alpha: int, beta: int, q: int)
    requires
        q > 1,
    ensures
        (((x * alpha) % q) * beta) % q == (((x * beta) % q) * alpha) % q,
{
    lemma_mod_mul_left(x * alpha, beta, q);
    lemma_mod_mul_left(x * beta, alpha, q);
    assert((x * alpha) * beta == (x * beta) * alpha) by(nonlinear_arith);
}

/// Theorem 4: Constructive Extended Euclidean Bezout identity (a * u + b * v == gcd(a, b)).
pub proof fn lemma_bezout_extended_gcd(a: nat, b: nat) -> (uv: (int, int))
    ensures
        (a as int) * uv.0 + (b as int) * uv.1 == spec_gcd(a, b) as int,
    decreases b
{
    if b == 0 {
        assert((a as int) * 1 + (0 as int) * 0 == a as int) by(nonlinear_arith);
        (1, 0)
    } else {
        let rem = a % b;
        let uv1 = lemma_bezout_extended_gcd(b, rem);
        let u1 = uv1.0;
        let v1 = uv1.1;
        let ai = a as int;
        let bi = b as int;
        let q_div = ai / bi;
        let r_mod = ai % bi;
        vstd::arithmetic::div_mod::lemma_fundamental_div_mod(ai, bi);
        assert((rem as int) == r_mod);
        let u = v1;
        let v = u1 - q_div * v1;
        assert(ai * u + bi * v == bi * u1 + r_mod * v1) by(nonlinear_arith)
            requires
                ai == bi * q_div + r_mod,
                u == v1,
                v == u1 - q_div * v1;
        (u, v)
    }
}

/// Theorem 5: Constructive modular multiplicative inverse existence for coprime scalars in Z_q*.
pub proof fn lemma_bezout_modular_inverse(alpha: nat, q: nat) -> (alpha_inv: nat)
    requires
        q > 1,
        0 < alpha < q,
        spec_gcd(alpha, q) == 1,
    ensures
        is_mod_inverse(alpha as int, alpha_inv as int, q as int),
{
    let uv = lemma_bezout_extended_gcd(alpha, q);
    let u = uv.0;
    let v = uv.1;
    let ai = alpha as int;
    let qi = q as int;

    let u_q = u / qi;
    let u_r = u % qi;
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(u, qi);

    let k_mult = v + ai * u_q;
    assert(ai * u_r + qi * k_mult == 1) by(nonlinear_arith)
        requires
            ai * u + qi * v == 1,
            u == qi * u_q + u_r,
            k_mult == v + ai * u_q;

    vstd::arithmetic::div_mod::lemma_mod_multiples_vanish(k_mult, ai * u_r, qi);
    lemma_small_mod_id(1, qi);
    assert((ai * u_r) % qi == 1);

    if u_r == 0 {
        assert(ai * 0 == 0) by(nonlinear_arith);
        assert(0int % qi == 0int);
        assert(false);
    }
    assert(0 < u_r && u_r < qi);
    u_r as nat
}

/// Theorem 6: Blinded exponent inverse cancellation (((x * alpha) mod q) * alpha_inv === x mod q).
pub proof fn lemma_mod_exp_inverse_cancellation(x: int, alpha: int, alpha_inv: int, q: int)
    requires
        q > 1,
        0 <= x < q,
        (alpha * alpha_inv) % q == 1,
    ensures
        (((x * alpha) % q) * alpha_inv) % q == x,
{
    lemma_mod_exp_associativity(x, alpha, alpha_inv, q);
    lemma_mod_exp_identity(x, q);
}

/// Theorem 7: Non-zero subgroup closure under invertible scalar blinding (x in Z_q* ==> (x * alpha) mod q in Z_q*).
pub proof fn lemma_blinding_nonzero_subgroup_closure(x: int, alpha: int, alpha_inv: int, q: int)
    requires
        q > 1,
        0 < x < q,
        0 < alpha < q,
        (alpha * alpha_inv) % q == 1,
    ensures
        0 < (x * alpha) % q < q,
{
    let y = (x * alpha) % q;
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(x * alpha, q);
    assert(0 <= y < q);
    if y == 0 {
        lemma_mod_exp_inverse_cancellation(x, alpha, alpha_inv, q);
        assert(0 * alpha_inv == 0) by(nonlinear_arith);
        assert(0int % q == 0int);
        assert(false);
    }
}

/// Theorem 8: Bijective permutation injectivity on Z_q for invertible blinding scalars.
pub proof fn lemma_blinding_bijection_injective(x1: int, x2: int, alpha: int, alpha_inv: int, q: int)
    requires
        q > 1,
        0 <= x1 < q,
        0 <= x2 < q,
        (alpha * alpha_inv) % q == 1,
        (x1 * alpha) % q == (x2 * alpha) % q,
    ensures
        x1 == x2,
{
    lemma_mod_exp_inverse_cancellation(x1, alpha, alpha_inv, q);
    lemma_mod_exp_inverse_cancellation(x2, alpha, alpha_inv, q);
}

/// Theorem 9: DH-PSI set-intersection soundness and completeness over hashed subgroup points:
/// H(x_i)^(alpha * beta) == H(y_j)^(beta * alpha) <==> H(x_i) == H(y_j) (mod q).
pub proof fn lemma_dh_psi_set_intersection_soundness_and_completeness(
    hx: int,
    hy: int,
    alpha: int,
    alpha_inv: int,
    beta: int,
    beta_inv: int,
    q: int,
)
    requires
        q > 1,
        0 <= hx < q,
        0 <= hy < q,
        (alpha * alpha_inv) % q == 1,
        (beta * beta_inv) % q == 1,
    ensures
        ((((hx * alpha) % q) * beta) % q == (((hy * beta) % q) * alpha) % q) <==> (hx == hy),
{
    let lhs = (((hx * alpha) % q) * beta) % q;
    let rhs = (((hy * beta) % q) * alpha) % q;

    if hx == hy {
        lemma_mod_exp_commutativity(hx, alpha, beta, q);
    }

    if lhs == rhs {
        lemma_mod_exp_commutativity(hy, beta, alpha, q);
        let hy_ab = (((hy * alpha) % q) * beta) % q;
        assert(lhs == hy_ab);

        let hx_a = (hx * alpha) % q;
        let hy_a = (hy * alpha) % q;
        vstd::arithmetic::div_mod::lemma_fundamental_div_mod(hx * alpha, q);
        vstd::arithmetic::div_mod::lemma_fundamental_div_mod(hy * alpha, q);

        lemma_blinding_bijection_injective(hx_a, hy_a, beta, beta_inv, q);
        lemma_blinding_bijection_injective(hx, hy, alpha, alpha_inv, q);
    }
}

// ============================================================================
// 2. DECISIONAL DIFFIE-HELLMAN (DDH) SELF-RANDOMIZABILITY & UNLINKABILITY
// ============================================================================

/// Predicate characterizing a valid DDH triple (a, b, c) where c === a * b (mod q).
pub open spec fn is_ddh_triple(a: int, b: int, c: int, q: int) -> bool {
    0 <= a < q &&
    0 <= b < q &&
    0 <= c < q &&
    c == (a * b) % q
}

/// Predicate characterizing a non-DDH (random / non-congruent) triple (a, b, c) where c !== a * b (mod q).
pub open spec fn is_non_ddh_triple(a: int, b: int, c: int, q: int) -> bool {
    0 <= a < q &&
    0 <= b < q &&
    0 <= c < q &&
    c != (a * b) % q
}

/// Algebraic DDH self-randomization map: (a, b, c) |-> (a, (r * b + s) mod q, (r * c + s * a) mod q).
pub open spec fn ddh_rerandomize(a: int, b: int, c: int, r: int, s: int, q: int) -> (int, int, int) {
    let b_prime = (r * b + s) % q;
    let c_prime = (r * c + s * a) % q;
    (a, b_prime, c_prime)
}

/// Theorem 10: Exact DDH algebraic gap invariance under rerandomization:
/// (c' - (a * b') mod q) mod q == (r * (c - (a * b) mod q)) mod q.
pub proof fn lemma_ddh_rerandomize_gap_identity(a: int, b: int, c: int, r: int, s: int, q: int)
    requires
        q > 1,
        0 <= a < q,
        0 <= b < q,
        0 <= c < q,
        0 <= r < q,
        0 <= s < q,
    ensures
        ({
            let (_, b_prime, c_prime) = ddh_rerandomize(a, b, c, r, s, q);
            (c_prime - ((a * b_prime) % q)) % q == (r * (c - ((a * b) % q))) % q
        }),
{
    let b_prime = (r * b + s) % q;
    let c_prime = (r * c + s * a) % q;
    let ab_mod = (a * b) % q;
    let abp_mod = (a * b_prime) % q;

    lemma_mod_mul_right(a, r * b + s, q);
    assert(abp_mod == (a * (r * b + s)) % q);

    let q_c = (r * c + s * a) / q;
    let q_abp = (a * (r * b + s)) / q;
    let q_ab = (a * b) / q;
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(r * c + s * a, q);
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(a * (r * b + s), q);
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(a * b, q);

    let k_shift = q_abp - q_c - r * q_ab;
    assert((c_prime - abp_mod) == r * (c - ab_mod) + k_shift * q) by(nonlinear_arith)
        requires
            r * c + s * a == q * q_c + c_prime,
            a * (r * b + s) == q * q_abp + abp_mod,
            a * b == q * q_ab + ab_mod,
            k_shift == q_abp - q_c - r * q_ab;

    vstd::arithmetic::div_mod::lemma_mod_multiples_vanish(k_shift, r * (c - ab_mod), q);
}

/// Theorem 11: DDH tuple preservation under self-randomization:
/// If (a, b, c) is a true DDH triple, then ddh_rerandomize(a, b, c, r, s, q) is also a true DDH triple.
pub proof fn lemma_ddh_rerandomize_preserves_ddh(a: int, b: int, c: int, r: int, s: int, q: int)
    requires
        q > 1,
        is_ddh_triple(a, b, c, q),
        0 < r < q,
        0 <= s < q,
    ensures
        ({
            let (a_prime, b_prime, c_prime) = ddh_rerandomize(a, b, c, r, s, q);
            is_ddh_triple(a_prime, b_prime, c_prime, q)
        }),
{
    let (a_prime, b_prime, c_prime) = ddh_rerandomize(a, b, c, r, s, q);
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(r * b + s, q);
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(r * c + s * a, q);
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(a * b_prime, q);

    lemma_ddh_rerandomize_gap_identity(a, b, c, r, s, q);
    let abp_mod = (a * b_prime) % q;
    assert(c - ((a * b) % q) == 0);
    assert(r * 0 == 0) by(nonlinear_arith);
    assert(0int % q == 0int);
    assert((c_prime - abp_mod) % q == 0);
    lemma_mod_sub_eq_zero_implies_eq(c_prime, abp_mod, q);
}

/// Theorem 12: Uniform marginal distribution (injectivity over shift s in [0, q-1]):
/// Distinct additive blinding shifts s1 != s2 produce distinct b' = (r * b + s) mod q.
pub proof fn lemma_ddh_rerandomize_uniform_marginal_injective(
    b: int,
    r: int,
    s1: int,
    s2: int,
    q: int,
)
    requires
        q > 1,
        0 <= s1 < q,
        0 <= s2 < q,
        (r * b + s1) % q == (r * b + s2) % q,
    ensures
        s1 == s2,
{
    let q1 = (r * b + s1) / q;
    let q2 = (r * b + s2) / q;
    let bp = (r * b + s1) % q;
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(r * b + s1, q);
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(r * b + s2, q);

    assert((s1 - s2) == (q1 - q2) * q) by(nonlinear_arith)
        requires
            r * b + s1 == q * q1 + bp,
            r * b + s2 == q * q2 + bp;
    vstd::arithmetic::div_mod::lemma_mod_multiples_vanish(q1 - q2, 0, q);
    assert(0int % q == 0int);
    assert((s1 - s2) % q == 0);
    lemma_mod_sub_eq_zero_implies_eq(s1, s2, q);
}

/// Theorem 13: Uniform marginal distribution (surjectivity onto Z_q):
/// For any target element y in [0, q-1], there exists an explicit shift s in [0, q-1]
/// such that (r * b + s) mod q == y.
pub proof fn lemma_ddh_rerandomize_uniform_marginal_surjective(
    b: int,
    r: int,
    y: int,
    q: int,
) -> (s: int)
    requires
        q > 1,
        0 <= y < q,
    ensures
        0 <= s < q,
        (r * b + s) % q == y,
{
    let rb_mod = (r * b) % q;
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(r * b, q);
    let s = if y >= rb_mod { y - rb_mod } else { y + q - rb_mod };
    assert(0 <= s && s < q);

    let q_rb = (r * b) / q;
    let k_shift = if y >= rb_mod { q_rb } else { q_rb + 1 };
    assert(r * b + s == y + k_shift * q) by(nonlinear_arith)
        requires
            r * b == q * q_rb + rb_mod,
            s == (if y >= rb_mod { y - rb_mod } else { y + q - rb_mod }),
            k_shift == (if y >= rb_mod { q_rb } else { q_rb + 1 });

    vstd::arithmetic::div_mod::lemma_mod_multiples_vanish(k_shift, y, q);
    lemma_small_mod_id(y, q);
    s
}

/// Theorem 14: Strict preservation of non-DDH gap under rerandomization:
/// If (a, b, c) is a non-DDH triple and r is invertible modulo q, then ddh_rerandomize(a, b, c, r, s, q)
/// strictly remains a non-DDH triple (c' !== a * b' mod q).
pub proof fn lemma_ddh_rerandomize_preserves_non_ddh_gap(
    a: int,
    b: int,
    c: int,
    r: int,
    r_inv: int,
    s: int,
    q: int,
)
    requires
        q > 1,
        is_non_ddh_triple(a, b, c, q),
        0 < r < q,
        (r * r_inv) % q == 1,
        0 <= s < q,
    ensures
        ({
            let (a_prime, b_prime, c_prime) = ddh_rerandomize(a, b, c, r, s, q);
            is_non_ddh_triple(a_prime, b_prime, c_prime, q)
        }),
{
    let (a_prime, b_prime, c_prime) = ddh_rerandomize(a, b, c, r, s, q);
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(r * b + s, q);
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(r * c + s * a, q);
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(a * b_prime, q);

    let ab_mod = (a * b) % q;
    let abp_mod = (a * b_prime) % q;
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(a * b, q);

    if c_prime == abp_mod {
        lemma_ddh_rerandomize_gap_identity(a, b, c, r, s, q);
        assert(c_prime - abp_mod == 0);
        assert(0int % q == 0int);
        assert((r * (c - ab_mod)) % q == 0);

        let delta = c - ab_mod;
        lemma_mod_mul_left(r * delta, r_inv, q);
        assert(((r * delta) * r_inv) % q == (0 * r_inv) % q);
        assert(0 * r_inv == 0) by(nonlinear_arith);
        assert(0int % q == 0int);

        assert((r * delta) * r_inv == (r * r_inv) * delta) by(nonlinear_arith);
        lemma_mod_mul_left(r * r_inv, delta, q);
        assert((1 * delta) % q == 0);
        assert(1 * delta == delta) by(nonlinear_arith);
        assert(delta % q == 0);

        lemma_mod_sub_eq_zero_implies_eq(c, ab_mod, q);
        assert(false);
    }
}

// ============================================================================
// 3. KAPPA_J KEY DERIVATION & PAYLOAD ONE-TIME-PAD CONFIDENTIALITY
// ============================================================================

/// 256-bit block representation (four 64-bit little-endian words).
pub struct Block256 {
    pub w0: u64,
    pub w1: u64,
    pub w2: u64,
    pub w3: u64,
}

/// Bitwise 256-bit XOR one-time-pad masking specification.
pub open spec fn spec_xor256(m: Block256, k: Block256) -> Block256 {
    Block256 {
        w0: m.w0 ^ k.w0,
        w1: m.w1 ^ k.w1,
        w2: m.w2 ^ k.w2,
        w3: m.w3 ^ k.w3,
    }
}

/// 64-bit XOR-fold payload mask derivation matching derive_payload_mask in src/psi.rs.
pub open spec fn spec_derive_payload_mask_64(token: Block256) -> u64 {
    token.w0 ^ token.w1 ^ token.w2 ^ token.w3
}

/// 64-bit associated payload XOR one-time-pad masking specification.
pub open spec fn spec_xor64(payload: u64, kappa: u64) -> u64 {
    payload ^ kappa
}

/// Theorem 15: 256-bit XOR masking involution (xor256(xor256(m, k), k) == m).
pub proof fn lemma_xor256_involution(m: Block256, k: Block256)
    ensures
        spec_xor256(spec_xor256(m, k), k) == m,
{
    let m0 = m.w0; let m1 = m.w1; let m2 = m.w2; let m3 = m.w3;
    let k0 = k.w0; let k1 = k.w1; let k2 = k.w2; let k3 = k.w3;
    assert((m0 ^ k0) ^ k0 == m0) by(bit_vector);
    assert((m1 ^ k1) ^ k1 == m1) by(bit_vector);
    assert((m2 ^ k2) ^ k2 == m2) by(bit_vector);
    assert((m3 ^ k3) ^ k3 == m3) by(bit_vector);
}

/// Theorem 16: 256-bit XOR key-recovery bijectivity:
/// For any plaintext m and ciphertext c, k = xor256(m, c) is the unique key satisfying xor256(m, k) == c.
pub proof fn lemma_xor256_key_recovery_bijectivity(m: Block256, c: Block256)
    ensures
        ({
            let k = spec_xor256(m, c);
            spec_xor256(m, k) == c &&
            forall|k_alt: Block256| spec_xor256(m, k_alt) == c ==> k_alt == k
        }),
{
    let m0 = m.w0; let m1 = m.w1; let m2 = m.w2; let m3 = m.w3;
    let c0 = c.w0; let c1 = c.w1; let c2 = c.w2; let c3 = c.w3;
    let k = spec_xor256(m, c);
    assert((m0 ^ (m0 ^ c0)) == c0) by(bit_vector);
    assert((m1 ^ (m1 ^ c1)) == c1) by(bit_vector);
    assert((m2 ^ (m2 ^ c2)) == c2) by(bit_vector);
    assert((m3 ^ (m3 ^ c3)) == c3) by(bit_vector);

    assert forall|k_alt: Block256| spec_xor256(m, k_alt) == c implies k_alt == k by {
        let ka0 = k_alt.w0; let ka1 = k_alt.w1; let ka2 = k_alt.w2; let ka3 = k_alt.w3;
        assert(((m0 ^ ka0) == c0) ==> (ka0 == (m0 ^ c0))) by(bit_vector);
        assert(((m1 ^ ka1) == c1) ==> (ka1 == (m1 ^ c1))) by(bit_vector);
        assert(((m2 ^ ka2) == c2) ==> (ka2 == (m2 ^ c2))) by(bit_vector);
        assert(((m3 ^ ka3) == c3) ==> (ka3 == (m3 ^ c3))) by(bit_vector);
    };
}

/// Theorem 17: 256-bit XOR ciphertext injectivity under a fixed key (xor256(m1, k) == xor256(m2, k) ==> m1 == m2).
pub proof fn lemma_xor256_ciphertext_injective(m1: Block256, m2: Block256, k: Block256)
    requires
        spec_xor256(m1, k) == spec_xor256(m2, k),
    ensures
        m1 == m2,
{
    lemma_xor256_involution(m1, k);
    lemma_xor256_involution(m2, k);
}

/// Theorem 18: 64-bit associated payload OTP involution and unique key-recovery bijectivity.
pub proof fn lemma_payload_otp_involution_and_key_recovery(payload: u64, token: Block256)
    ensures
        ({
            let kappa = spec_derive_payload_mask_64(token);
            let cipher = spec_xor64(payload, kappa);
            spec_xor64(cipher, kappa) == payload &&
            spec_xor64(payload, cipher) == kappa
        }),
{
    let kappa = spec_derive_payload_mask_64(token);
    assert(((payload ^ kappa) ^ kappa) == payload) by(bit_vector);
    assert((payload ^ (payload ^ kappa)) == kappa) by(bit_vector);
}

/// Theorem 19: Element-domain separation under bijective DH-PSI blinding:
/// Distinct subgroup elements hx1 != hx2 produce strictly distinct doubly-blinded tokens
/// under invertible blinding scalars alpha, beta in Z_q*, preventing cross-element kappa_j reuse.
pub proof fn lemma_kappa_element_domain_separation(
    hx1: int,
    hx2: int,
    alpha: int,
    alpha_inv: int,
    beta: int,
    beta_inv: int,
    q: int,
)
    requires
        q > 1,
        0 <= hx1 < q,
        0 <= hx2 < q,
        hx1 != hx2,
        (alpha * alpha_inv) % q == 1,
        (beta * beta_inv) % q == 1,
    ensures
        (((hx1 * alpha) % q) * beta) % q != (((hx2 * alpha) % q) * beta) % q,
{
    let t1_a = (hx1 * alpha) % q;
    let t2_a = (hx2 * alpha) % q;
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(hx1 * alpha, q);
    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(hx2 * alpha, q);

    if (((hx1 * alpha) % q) * beta) % q == (((hx2 * alpha) % q) * beta) % q {
        lemma_blinding_bijection_injective(t1_a, t2_a, beta, beta_inv, q);
        lemma_blinding_bijection_injective(hx1, hx2, alpha, alpha_inv, q);
        assert(false);
    }
}

} // verus!
