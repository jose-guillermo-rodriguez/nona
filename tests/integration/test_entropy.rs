// Copyright (c) 2026 Nona Contributors.
// Licensed under the Apache License, Version 2.0 or the MIT License.

//! TEST-01: Enclave Hardware NSM Entropy and Fail-Closed Invariant Harness
//!
//! Verification of hardware `/dev/nsm` RNG seeding and fail-stop invariants:
//! - Verifies canonical CBOR `GetRandom` request encoding and response parsing.
//! - Rejects malformed, truncated, or zero-length NSM `GetRandom` CBOR payloads.
//! - When `/dev/nsm` is absent, verifies that session key initialization and DP noise
//!   injection immediately trigger an unrecoverable fail-closed process abort (`zeroize_and_abort`)
//!   with zero fallback to OS syscalls, CPU RNG instructions, or system clocks.
//! - When `/dev/nsm` hardware is present, verifies 1,000 distinct enclave boot/reset
//!   keypair cycles with zero collisions (`|Set| == 1,000`).

#![cfg(feature = "std")]

use nona_core::attestation::{
    encode_nsm_get_random_request, parse_nsm_get_random_response, NONA_ERR_NSM_IOCTL_FAILED,
};
use nona_core::enclave_server::{
    get_or_create_session_pubkey, load_session_privkey_into, reset_session_key, AlignedKeyBuffer,
};
use nona_core::psi::inject_differential_privacy_noise;
use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

#[test]
fn test_nsm_get_random_cbor_framing_and_rejection() {
    let mut req_buf = [0u8; 16];
    let req_len = encode_nsm_get_random_request(&mut req_buf).expect("encode GetRandom");
    assert_eq!(req_len, 10);
    assert_eq!(&req_buf[..req_len], b"\x69GetRandom");

    // Canonical CBOR {"GetRandom": {"random": h'1122334455667788'}}
    let mut resp = [0u8; 29];
    resp[0] = 0xa1;
    resp[1] = 0x69;
    resp[2..11].copy_from_slice(b"GetRandom");
    resp[11] = 0xa1;
    resp[12] = 0x66;
    resp[13..19].copy_from_slice(b"random");
    resp[19] = 0x58;
    resp[20] = 8;
    resp[21..29].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

    assert_eq!(
        parse_nsm_get_random_response(&resp),
        Ok(&[0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88][..])
    );

    // Empty byte string must be rejected
    let mut empty_bstr = resp;
    empty_bstr[19] = 0x40;
    assert_eq!(
        parse_nsm_get_random_response(&empty_bstr[..20]),
        Err(NONA_ERR_NSM_IOCTL_FAILED)
    );

    // Trailing garbage bytes must be rejected
    let mut trailing = [0u8; 30];
    trailing[..29].copy_from_slice(&resp);
    trailing[29] = 0xff;
    assert_eq!(
        parse_nsm_get_random_response(&trailing),
        Err(NONA_ERR_NSM_IOCTL_FAILED)
    );
}

#[test]
fn test_enclave_session_key_freshness_or_fail_closed_abort() {
    if std::env::var("NONA_CHILD_PROBE_SESSION_KEY").is_ok() {
        reset_session_key();
        let _ = get_or_create_session_pubkey();
        return;
    }
    if std::env::var("NONA_CHILD_PROBE_DP_NOISE").is_ok() {
        let _ = inject_differential_privacy_noise(3, 10);
        return;
    }

    if !Path::new("/dev/nsm").exists() {
        let exe = std::env::current_exe().expect("current_exe");

        let session_probe = Command::new(&exe)
            .env("NONA_CHILD_PROBE_SESSION_KEY", "1")
            .args([
                "--exact",
                "test_enclave_session_key_freshness_or_fail_closed_abort",
                "--nocapture",
            ])
            .output()
            .expect("spawn session key fail-closed probe");
        assert!(
            !session_probe.status.success(),
            "Session key seeding MUST fail closed and abort when /dev/nsm is absent"
        );

        let dp_probe = Command::new(&exe)
            .env("NONA_CHILD_PROBE_DP_NOISE", "1")
            .args([
                "--exact",
                "test_enclave_session_key_freshness_or_fail_closed_abort",
                "--nocapture",
            ])
            .output()
            .expect("spawn DP noise fail-closed probe");
        assert!(
            !dp_probe.status.success(),
            "PSI-CA noise seeding MUST fail closed and abort when /dev/nsm is absent"
        );
        return;
    }

    const TOTAL_CYCLES: usize = 1_000;

    let mut privkey_set = BTreeSet::new();
    let mut pubkey_set = BTreeSet::new();

    let mut stale_formula = [0u8; 32];
    for (i, byte) in stale_formula.iter_mut().enumerate() {
        *byte = (u8::try_from(i).unwrap_or(0).wrapping_mul(7)).wrapping_add(0x42);
    }
    stale_formula[0] |= 1;

    for cycle in 0..TOTAL_CYCLES {
        reset_session_key();

        let pubkey = get_or_create_session_pubkey();
        let mut priv_buf = AlignedKeyBuffer { data: [0u8; 32] };
        load_session_privkey_into(&mut priv_buf);
        let privkey = priv_buf.data;

        assert_ne!(
            privkey, [0u8; 32],
            "Cycle {cycle}: Private key returned all zeroes"
        );
        assert_ne!(
            privkey, stale_formula,
            "Cycle {cycle}: Private key matched discarded static formula"
        );
        assert!(
            pubkey[0] == 0x02 || pubkey[0] == 0x03,
            "Cycle {cycle}: Invalid compressed pubkey prefix 0x{:02x}",
            pubkey[0]
        );
        assert_ne!(
            &pubkey[1..33],
            &[0u8; 32],
            "Cycle {cycle}: Public key X coordinate is all zeroes"
        );

        assert!(
            privkey_set.insert(privkey),
            "Duplicate private key generated at cycle {cycle}"
        );
        assert!(
            pubkey_set.insert(pubkey),
            "Duplicate public key generated at cycle {cycle}"
        );
    }

    assert_eq!(privkey_set.len(), TOTAL_CYCLES);
    assert_eq!(pubkey_set.len(), TOTAL_CYCLES);
}
