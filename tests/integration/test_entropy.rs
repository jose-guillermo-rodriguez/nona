// Copyright (c) 2026 Nona Contributors.
// Licensed under the Apache License, Version 2.0 or the MIT License.

//! TEST-01: Enclave Ephemeral Session Key Freshness and Entropy Harness
//!
//! Verification of enclave ephemeral session key entropy and non-degeneracy invariants:
//! - Simulates 1,000 distinct enclave lifecycle boot/reset transitions.
//! - Extracts ephemeral session keypairs across each reset cycle.
//! - Asserts zero collisions across all 1,000 iterations (|Set| == 1,000).
//! - Strictly rejects degenerate all-zero keys and stale deterministic test vectors.
//! - Verifies secp256k1 compressed public key encoding invariants.

#![cfg(feature = "std")]

use nona_core::enclave_server::{get_or_create_session_key, reset_session_key};
use std::collections::BTreeSet;

#[test]
fn test_enclave_session_key_freshness() {
    const TOTAL_CYCLES: usize = 1_000;

    let mut privkey_set = BTreeSet::new();
    let mut pubkey_set = BTreeSet::new();

    // Construct the discarded deterministic formula: ((i * 7) + 0x42) | 1
    let mut stale_formula = [0u8; 32];
    for (i, byte) in stale_formula.iter_mut().enumerate() {
        *byte = (u8::try_from(i).unwrap_or(0).wrapping_mul(7)).wrapping_add(0x42);
    }
    stale_formula[0] |= 1;

    for cycle in 0..TOTAL_CYCLES {
        // Enforce enclave cold-reboot cycle
        reset_session_key();

        let (privkey, pubkey) = get_or_create_session_key();

        // 1. Degenerate zero check
        assert_ne!(
            privkey, [0u8; 32],
            "Cycle {cycle}: Private key returned all zeroes"
        );

        // 2. Stale test-vector regression check
        assert_ne!(
            privkey, stale_formula,
            "Cycle {cycle}: Private key matched discarded static formula; entropy source non-functional"
        );

        // 3. secp256k1 public key header verification
        assert!(
            pubkey[0] == 0x02 || pubkey[0] == 0x03,
            "Cycle {}: Public key header must be 0x02 or 0x03, got 0x{:02x}",
            cycle,
            pubkey[0]
        );

        // 4. Verify public key payload is non-zero
        assert_ne!(
            &pubkey[1..33],
            &[0u8; 32],
            "Cycle {cycle}: Public key coordinate X is all zeroes"
        );

        // Collect keys into sets to track collision-freedom
        let priv_inserted = privkey_set.insert(privkey);
        assert!(
            priv_inserted,
            "Catastrophic RNG collision: duplicate private key generated at cycle {cycle}"
        );

        let pub_inserted = pubkey_set.insert(pubkey);
        assert!(
            pub_inserted,
            "Catastrophic RNG collision: duplicate public key generated at cycle {cycle}"
        );
    }

    // Assert exact cardinality: 1,000 distinct session keys generated with zero collisions
    assert_eq!(
        privkey_set.len(),
        TOTAL_CYCLES,
        "Private key set cardinality mismatch: expected {}, got {}",
        TOTAL_CYCLES,
        privkey_set.len()
    );

    assert_eq!(
        pubkey_set.len(),
        TOTAL_CYCLES,
        "Public key set cardinality mismatch: expected {}, got {}",
        TOTAL_CYCLES,
        pubkey_set.len()
    );
}
