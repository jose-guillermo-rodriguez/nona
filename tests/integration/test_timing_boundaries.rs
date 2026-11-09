#![allow(clippy::cast_precision_loss)]
#![cfg(feature = "std")]

use nona_core::crypto::Scalar;
use nona_core::psi::{FieldElement, JacobianPoint};
use std::time::Instant;

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

#[test]
fn test_scalar_mul_boundary_invariance() {
    let g = JacobianPoint {
        x: FieldElement { limbs: G_X_LIMBS },
        y: FieldElement { limbs: G_Y_LIMBS },
        z: FieldElement::one(),
    };

    let uniform_scalar = Scalar::from_limbs([
        0xAAAAAAAAAAAAAAAA,
        0x5555555555555555,
        0xA5A5A5A5A5A5A5A5,
        0x5A5A5A5A5A5A5A5A,
    ]);

    let leading_zero_scalar = Scalar::from_limbs([0x0000000000000001, 0, 0, 0]);

    let zero_scalar = Scalar::zero();

    // Warm up CPU frequency governor and instruction caches across all inputs
    for _ in 0..100 {
        let _ = core::hint::black_box(g.scalar_mul(core::hint::black_box(&uniform_scalar)));
        let _ = core::hint::black_box(g.scalar_mul(core::hint::black_box(&leading_zero_scalar)));
        let _ = core::hint::black_box(g.scalar_mul(core::hint::black_box(&zero_scalar)));
    }

    let n = if cfg!(debug_assertions) { 200 } else { 2_000 };
    let mut t_uniform = Vec::with_capacity(n);
    let mut t_zeros = Vec::with_capacity(n);
    let mut t_zero_scalar = Vec::with_capacity(n);

    // Interleaved cyclic round-robin sampling to eliminate environmental drift
    for i in 0..n {
        match i % 3 {
            0 => {
                let start = Instant::now();
                let _ = core::hint::black_box(g.scalar_mul(core::hint::black_box(&uniform_scalar)));
                t_uniform.push(start.elapsed().as_nanos());

                let start = Instant::now();
                let _ = core::hint::black_box(
                    g.scalar_mul(core::hint::black_box(&leading_zero_scalar)),
                );
                t_zeros.push(start.elapsed().as_nanos());

                let start = Instant::now();
                let _ = core::hint::black_box(g.scalar_mul(core::hint::black_box(&zero_scalar)));
                t_zero_scalar.push(start.elapsed().as_nanos());
            }
            1 => {
                let start = Instant::now();
                let _ = core::hint::black_box(
                    g.scalar_mul(core::hint::black_box(&leading_zero_scalar)),
                );
                t_zeros.push(start.elapsed().as_nanos());

                let start = Instant::now();
                let _ = core::hint::black_box(g.scalar_mul(core::hint::black_box(&zero_scalar)));
                t_zero_scalar.push(start.elapsed().as_nanos());

                let start = Instant::now();
                let _ = core::hint::black_box(g.scalar_mul(core::hint::black_box(&uniform_scalar)));
                t_uniform.push(start.elapsed().as_nanos());
            }
            _ => {
                let start = Instant::now();
                let _ = core::hint::black_box(g.scalar_mul(core::hint::black_box(&zero_scalar)));
                t_zero_scalar.push(start.elapsed().as_nanos());

                let start = Instant::now();
                let _ = core::hint::black_box(g.scalar_mul(core::hint::black_box(&uniform_scalar)));
                t_uniform.push(start.elapsed().as_nanos());

                let start = Instant::now();
                let _ = core::hint::black_box(
                    g.scalar_mul(core::hint::black_box(&leading_zero_scalar)),
                );
                t_zeros.push(start.elapsed().as_nanos());
            }
        }
    }

    let mean_u: f64 = t_uniform.iter().sum::<u128>() as f64 / n as f64;
    let mean_z: f64 = t_zeros.iter().sum::<u128>() as f64 / n as f64;
    let mean_null: f64 = t_zero_scalar.iter().sum::<u128>() as f64 / n as f64;

    let delta_ratio_z = (mean_u - mean_z).abs() / mean_u;
    let delta_ratio_null = (mean_u - mean_null).abs() / mean_u;

    println!(
        "[GATE 5] Timing delta ratio (leading zeros): {:.4}%",
        delta_ratio_z * 100.0
    );
    println!(
        "[GATE 5] Timing delta ratio (zero scalar):    {:.4}%",
        delta_ratio_null * 100.0
    );

    let threshold = if cfg!(debug_assertions) { 0.12 } else { 0.05 };
    assert!(
        delta_ratio_z < threshold,
        "Timing side-channel detected: leading zero branches executed with variable timing!"
    );
    assert!(
        delta_ratio_null < threshold,
        "Timing side-channel detected: zero scalar executed with variable timing!"
    );
}
