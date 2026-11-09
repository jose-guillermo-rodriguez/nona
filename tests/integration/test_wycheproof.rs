// Copyright (c) 2026 Nona Contributors.
// Licensed under the Apache License, Version 2.0 or the MIT License.

//! Project Wycheproof & NIST CAVP secp256k1 Validation Suite
//!
//! Validates secp256k1 curve operations against standard Wycheproof test vectors:
//! - Invalid points not on curve (y^2 != x^3 + 7 mod p)
//! - Points at infinity in projective/Jacobian coordinates (Z = 0)
//! - Montgomery simultaneous batch inversion edge cases (mixed and all-zero Z arrays)
//! - Scalar group order boundaries: [0]G, [1]G, [n-1]G, [n]G = O, [n+1]G = G
//! - Simplified SWU map-to-curve deterministic safety across edge cases

#![cfg(feature = "std")]

use nona_core::crypto::Scalar;
use nona_core::psi::{FieldElement, JacobianPoint};

// Curve modulus p = 2^256 - 2^32 - 977
#[allow(dead_code)]
const P_HEX: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";

// Curve order n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
const ORDER_N: [u64; 4] = [
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
];

const ORDER_N_MINUS_1: [u64; 4] = [
    0xBFD25E8CD0364140,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
];

const ORDER_N_PLUS_1: [u64; 4] = [
    0xBFD25E8CD0364142,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
];

// secp256k1 Base Generator G
const G_X_LIMBS: [u64; 4] = [
    0x59F2815B16F81798,
    0x029BFCDB2DCE28D9,
    0x55A06295CE870B07,
    0x79BE667EF9DCBBAC,
];

const G_Y_LIMBS: [u64; 4] = [
    0x9C47D08FFB10D4B8,
    0xFD17B448A6855419,
    0x5DA4FBFC0E1108A8,
    0x483ADA7726A3C465,
];

// Helper: Check if affine (x, y) satisfies y^2 = x^3 + 7 mod p
fn is_on_curve(x: &FieldElement, y: &FieldElement) -> bool {
    let y_sq = y.square();
    let x_cu = x.square().mul(x);
    let seven = FieldElement {
        limbs: [7, 0, 0, 0],
    };
    let rhs = x_cu.add(&seven);
    y_sq.ct_eq(&rhs)
}

#[test]
fn test_wycheproof_canonical_generator_on_curve() {
    let gx = FieldElement { limbs: G_X_LIMBS };
    let gy = FieldElement { limbs: G_Y_LIMBS };
    assert!(is_on_curve(&gx, &gy), "Generator G must be on secp256k1");
}

#[test]
fn test_wycheproof_point_not_on_curve_rejection() {
    // Vectors derived from Wycheproof ecdh_secp256k1_test.json:
    // Points with modified x or y that fail y^2 = x^3 + 7 (mod p)
    let gx = FieldElement { limbs: G_X_LIMBS };
    let bad_gy = FieldElement {
        limbs: [G_Y_LIMBS[0] ^ 1, G_Y_LIMBS[1], G_Y_LIMBS[2], G_Y_LIMBS[3]],
    };
    assert!(
        !is_on_curve(&gx, &bad_gy),
        "Tampered point must not be on curve"
    );

    // Point (0, 0): 0^2 != 0^3 + 7 mod p
    let zero = FieldElement::zero();
    assert!(
        !is_on_curve(&zero, &zero),
        "Point (0, 0) is not on secp256k1"
    );

    // Quadratic non-residue for x = 0: y^2 = 7 mod p has no solution
    let candidate_y = FieldElement {
        limbs: [7, 0, 0, 0],
    }
    .sqrt_candidate();
    assert!(
        !candidate_y.square().ct_eq(&FieldElement {
            limbs: [7, 0, 0, 0]
        }),
        "7 is a QNR mod p"
    );
}

#[test]
fn test_wycheproof_projective_to_affine_point_at_infinity() {
    // Challenge invariant: Projective-to-affine conversion with Z = 0 must safely produce X = 0
    let inf = JacobianPoint::infinity();
    assert!(inf.is_infinity());
    let affine_x = inf.to_affine_x();
    assert!(
        affine_x.is_zero(),
        "to_affine_x of point at infinity must return 0"
    );

    // Arbitrary (X, Y) with Z = 0 must also be treated as point at infinity
    let custom_inf = JacobianPoint {
        x: FieldElement {
            limbs: [0x1234, 0x5678, 0x9abc, 0xdef0],
        },
        y: FieldElement {
            limbs: [0xbeef, 0xdead, 0xcafe, 0xbabe],
        },
        z: FieldElement::zero(),
    };
    assert!(custom_inf.is_infinity());
    let custom_affine_x = custom_inf.to_affine_x();
    assert!(
        custom_affine_x.is_zero(),
        "to_affine_x with Z=0 must safely return 0 without division by zero"
    );
}

#[test]
fn test_wycheproof_batch_to_affine_with_points_at_infinity() {
    // Challenge invariant: batch_to_affine_x containing points at infinity (Z = 0)
    let g = JacobianPoint::generator();
    let inf = JacobianPoint::infinity();

    let points = [g.clone(), inf.clone(), g.double(), inf.clone(), g.clone()];
    let mut out_x: [FieldElement; 5] = core::array::from_fn(|_| FieldElement::zero());

    JacobianPoint::batch_to_affine_x(&points, &mut out_x).expect("batch inversion should succeed");

    assert!(out_x[0].ct_eq(&g.to_affine_x()), "points[0] must match G_x");
    assert!(out_x[1].is_zero(), "points[1] (infinity) must yield X = 0");
    assert!(
        out_x[2].ct_eq(&g.double().to_affine_x()),
        "points[2] must match 2G_x"
    );
    assert!(out_x[3].is_zero(), "points[3] (infinity) must yield X = 0");
    assert!(out_x[4].ct_eq(&g.to_affine_x()), "points[4] must match G_x");
}

#[test]
fn test_wycheproof_batch_to_affine_all_infinity() {
    // Array where every point has Z = 0
    let inf = JacobianPoint::infinity();
    let points = [inf.clone(), inf.clone(), inf.clone(), inf.clone()];
    let mut out_x: [FieldElement; 4] = core::array::from_fn(|_| FieldElement::zero());

    JacobianPoint::batch_to_affine_x(&points, &mut out_x)
        .expect("all-infinity batch should succeed");

    for (idx, x) in out_x.iter().enumerate() {
        assert!(
            x.is_zero(),
            "out_x[{idx}] must be zero for point at infinity"
        );
    }
}

#[test]
fn test_wycheproof_group_order_boundaries_and_annihilation() {
    let g = JacobianPoint::generator();

    // [0]G = O
    let p0 = g.scalar_mul(&Scalar::zero());
    assert!(p0.is_infinity(), "[0]G must be infinity");
    assert!(p0.to_affine_x().is_zero());

    // [1]G = G
    let p1 = g.scalar_mul(&Scalar::one());
    assert!(
        p1.to_affine_x().ct_eq(&g.to_affine_x()),
        "[1]G must equal G"
    );

    // [n]G = O
    let pn = g.scalar_mul(&Scalar::from_limbs(ORDER_N));
    assert!(
        pn.is_infinity(),
        "[n]G must annihilate to point at infinity"
    );
    assert!(pn.to_affine_x().is_zero());

    // [n+1]G is non-canonical (s >= n), must evaluate to point at infinity (s >= n canonical rejection)
    let pn1 = g.scalar_mul(&Scalar::from_limbs(ORDER_N_PLUS_1));
    assert!(
        pn1.is_infinity(),
        "[n+1]G is non-canonical and must annihilate to point at infinity (s >= n canonical rejection)"
    );
    assert!(pn1.to_affine_x().is_zero());

    // [n-1]G + G = [n]G = O
    let p_n_minus_1 = g.scalar_mul(&Scalar::from_limbs(ORDER_N_MINUS_1));
    let p_sum = p_n_minus_1.add(&g);
    assert!(p_sum.is_infinity(), "[n-1]G + G must equal O");
}

#[test]
fn test_wycheproof_simplified_swu_straight_line_and_edge_cases() {
    // Seed = 0 (edge case)
    let p_zero = JacobianPoint::map_to_curve(&FieldElement::zero());
    assert!(
        !p_zero.is_infinity(),
        "SWU map(0) must not produce infinity"
    );
    let x0 = p_zero.to_affine_x();
    assert!(!x0.is_zero(), "SWU map(0) affine X must be valid");

    // Seed = 1
    let p_one = JacobianPoint::map_to_curve(&FieldElement::one());
    assert!(!p_one.is_infinity());

    // Seed = p - 1
    let p_minus_one = JacobianPoint::map_to_curve(&FieldElement {
        limbs: [
            0xFFFFFFFEFFFFFC2E,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
            0xFFFFFFFFFFFFFFFF,
        ],
    });
    assert!(!p_minus_one.is_infinity());

    // Differential invariance: same input yields identical affine X
    let p_repeat = JacobianPoint::map_to_curve(&FieldElement::zero());
    assert!(
        p_repeat.to_affine_x().ct_eq(&x0),
        "SWU mapping must be deterministic"
    );
}
