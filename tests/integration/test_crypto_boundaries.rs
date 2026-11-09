//! TEST-08: Router Arithmetic Boundary & Integer Overflow Test Harness
//! Validates safe capacity calculation across domain boundaries [2^56, 2^64 - 1].

use nona_core::crypto::{
    ct_adaptive_route_decision, CryptoError, MAX_ROUTER_ELEMENTS, NONA_ROUTE_DH_PSI,
    NONA_ROUTE_VOLE_PSI,
};

#[test]
fn test_crypto_router_zero_and_small_elements() {
    assert_eq!(ct_adaptive_route_decision(0, 0), Ok((NONA_ROUTE_DH_PSI, 0)));
    assert_eq!(
        ct_adaptive_route_decision(1, 128),
        Ok((NONA_ROUTE_DH_PSI, 0))
    );
    assert_eq!(
        ct_adaptive_route_decision(1, 129),
        Ok((NONA_ROUTE_VOLE_PSI, 1))
    );
}

#[test]
fn test_crypto_router_boundary_2_pow_56() {
    // 2^56 = 72_057_594_037_927_936
    // 2^56 * 128 = 2^63 (valid, fits in u64)
    let n = 1u64 << 56;
    let m = 1u64 << 63;
    assert_eq!(ct_adaptive_route_decision(n, m), Ok((NONA_ROUTE_DH_PSI, 0)));
}

#[test]
fn test_crypto_router_boundary_max_valid_elements() {
    // MAX_ROUTER_ELEMENTS = 2^57 - 1 = 144_115_188_075_855_871
    // (2^57 - 1) * 128 = u64::MAX - 127
    let n = MAX_ROUTER_ELEMENTS;
    let res = ct_adaptive_route_decision(n, 0);
    assert!(res.is_ok());
    assert_eq!(res.unwrap().0, NONA_ROUTE_DH_PSI);
}

#[test]
fn test_crypto_router_boundary_overflow_2_pow_57() {
    // 2^57 = 144_115_188_075_855_872
    // 2^57 * 128 = 2^64 (overflows u64)
    let n = 1u64 << 57;
    assert_eq!(
        ct_adaptive_route_decision(n, 0),
        Err(CryptoError::CapacityOverflow)
    );
}

#[test]
fn test_crypto_router_boundary_overflow_u64_max() {
    // u64::MAX: wrapping_mul would wrap to u64::MAX - 127
    assert_eq!(
        ct_adaptive_route_decision(u64::MAX, 0),
        Err(CryptoError::CapacityOverflow)
    );
}

#[test]
fn test_crypto_router_boundary_domain_sweep() {
    let threshold = 1u64 << 57;

    assert!(ct_adaptive_route_decision(threshold - 2, 0).is_ok());
    assert!(ct_adaptive_route_decision(threshold - 1, 0).is_ok());
    assert_eq!(
        ct_adaptive_route_decision(threshold, 0),
        Err(CryptoError::CapacityOverflow)
    );
    assert_eq!(
        ct_adaptive_route_decision(threshold + 1, 0),
        Err(CryptoError::CapacityOverflow)
    );
}
