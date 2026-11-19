// Copyright (c) 2026 Nona Contributors.
// Licensed under the Apache License, Version 2.0 or the MIT License.

//! libFuzzer and Standalone Continuous Fuzzing Harness: Attested KMS Envelope & Curve Unwrapping
//!
//! Fuzzes AttestedKeyEnvelope wire parsing, SEC 1 compressed secp256k1 & P-384 point
//! validation, ECDH recipient envelope unwrapping, PCR/nonce/tag binding checks,
//! vsock CMD_KMS_RECIPIENT_UNWRAP state transitions, and fail-closed zeroization.

use core::cell::UnsafeCell;
use nona_core::attestation::derive_compressed_public_key;
use nona_core::crypto::{
    unwrap_attested_recipient_envelope, AttestedEnvelopeError, AttestedKeyEnvelope, P384Point,
    ATTESTED_ENVELOPE_WIRE_SIZE,
};
use nona_core::enclave_server::{
    configure_expected_pcr_policy, inspect_ephemeral_recipient_privkey_is_zeroized,
    provision_ephemeral_recipient_from_seed, reset_nonce_replay_cache, reset_session_key,
    EnclaveConnectionSlot, EnclaveRequestHeader, SessionPhase, VsockSessionState, CMD_ATTEST,
    CMD_KMS_RECIPIENT_UNWRAP, NONA_VSOCK_MAGIC, NONA_VSOCK_VERSION, NONA_WIRE_ERR_OPAQUE,
};
use nona_core::psi::ProjectivePoint;

struct StaticSlot(UnsafeCell<EnclaveConnectionSlot>);
unsafe impl Sync for StaticSlot {}

static SESSION_SLOT: StaticSlot = StaticSlot(UnsafeCell::new(EnclaveConnectionSlot::INIT));

fn fill_from_fuzz<const N: usize>(slice: &[u8], offset: usize, seed: u8) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, dst) in out.iter_mut().enumerate() {
        let b = slice.get((offset + i) % slice.len()).copied().unwrap_or(0);
        *dst = b ^ seed.wrapping_add(u8::try_from(i & 0xff).unwrap_or(0));
    }
    out
}

fn make_canonical_scalar_seed(slice: &[u8], offset: usize, fallback_lsb: u8) -> [u8; 32] {
    let mut scalar = fill_from_fuzz::<32>(slice, offset, 0x13);
    scalar[30] &= 0x0f;
    scalar[31] = 0x00;
    if scalar.iter().all(|&b| b == 0) {
        scalar[0] = fallback_lsb.max(1);
    }
    scalar
}

#[inline(never)]
fn fuzz_kms_wire_and_curve_decoders(slice: &[u8]) {
    match AttestedKeyEnvelope::from_wire_bytes(slice) {
        Ok(env) => {
            assert_eq!(slice.len(), ATTESTED_ENVELOPE_WIRE_SIZE);
            assert_eq!(env.key_len, 32);
            assert_eq!(&env.to_wire_bytes()[..], slice);
        }
        Err(err) => {
            assert_eq!(err, AttestedEnvelopeError::InvalidLength);
        }
    }

    let sec1_candidate = fill_from_fuzz::<33>(slice, 0, 0x00);
    if let Some(pt) = ProjectivePoint::from_compressed_sec1(&sec1_candidate) {
        assert!(!pt.is_infinity());
    }
    let p384_len = slice.len().min(128);
    let _ = P384Point::from_uncompressed_bytes(&slice[..p384_len]);
}

#[inline(never)]
fn fuzz_kms_malformed_envelope_unwrap(
    slice: &[u8],
    eph_priv: &[u8; 32],
    recipient_pub: &[u8; 33],
) {
    let expected_nonce = fill_from_fuzz::<32>(slice, 33, 0x41);
    let expected_pcr0 = fill_from_fuzz::<48>(slice, 65, 0x51);
    let expected_pcr1 = fill_from_fuzz::<48>(slice, 113, 0x61);
    let expected_pcr2 = fill_from_fuzz::<48>(slice, 161, 0x71);

    let mut wire_buf = fill_from_fuzz::<ATTESTED_ENVELOPE_WIRE_SIZE>(slice, 0, 0x00);
    wire_buf[257] = 32;
    let Ok(malformed_env) = AttestedKeyEnvelope::from_wire_bytes(&wire_buf) else {
        return;
    };

    let mut out_secret = [0xFFu8; 32];
    let mut eph_copy = *eph_priv;
    let res = unwrap_attested_recipient_envelope(
        &mut eph_copy,
        recipient_pub,
        &expected_nonce,
        &expected_pcr0,
        &expected_pcr1,
        &expected_pcr2,
        &malformed_env,
        &mut out_secret,
    );
    assert_eq!(eph_copy, [0u8; 32]);
    if res.is_err() {
        assert_eq!(out_secret, [0u8; 32]);
    }
}

#[inline(never)]
fn fuzz_kms_authentic_wrap_and_mutation(
    slice: &[u8],
    eph_priv: &[u8; 32],
    recipient_pub: &[u8; 33],
    mutated_wire_out: &mut [u8; ATTESTED_ENVELOPE_WIRE_SIZE],
) -> bool {
    let expected_nonce = fill_from_fuzz::<32>(slice, 33, 0x41);
    let expected_pcr0 = fill_from_fuzz::<48>(slice, 65, 0x51);
    let expected_pcr1 = fill_from_fuzz::<48>(slice, 113, 0x61);
    let expected_pcr2 = fill_from_fuzz::<48>(slice, 161, 0x71);
    let kms_priv = make_canonical_scalar_seed(slice, 7, 0x3d);
    let plaintext_secret = make_canonical_scalar_seed(slice, 19, 0x57);

    let Ok(valid_env) = AttestedKeyEnvelope::wrap_for_recipient(
        &kms_priv,
        recipient_pub,
        &expected_nonce,
        &expected_pcr0,
        &expected_pcr1,
        &expected_pcr2,
        &plaintext_secret,
    ) else {
        return false;
    };

    let mut eph_valid = *eph_priv;
    let mut unwrapped = [0u8; 32];
    let ok_res = unwrap_attested_recipient_envelope(
        &mut eph_valid,
        recipient_pub,
        &expected_nonce,
        &expected_pcr0,
        &expected_pcr1,
        &expected_pcr2,
        &valid_env,
        &mut unwrapped,
    );
    assert_eq!(ok_res, Ok(()));
    assert_eq!(unwrapped, plaintext_secret);
    assert_eq!(eph_valid, [0u8; 32]);

    *mutated_wire_out = valid_env.to_wire_bytes();
    let mut_idx = usize::from(slice[0]) % (ATTESTED_ENVELOPE_WIRE_SIZE - 1);
    let mut_mask = slice.get(1).copied().unwrap_or(0x80).max(1);
    mutated_wire_out[mut_idx] ^= mut_mask;
    true
}

#[inline(never)]
fn fuzz_kms_verify_mutated_rejection(
    slice: &[u8],
    eph_priv: &[u8; 32],
    recipient_pub: &[u8; 33],
    mutated_wire: &[u8; ATTESTED_ENVELOPE_WIRE_SIZE],
) {
    let expected_nonce = fill_from_fuzz::<32>(slice, 33, 0x41);
    let expected_pcr0 = fill_from_fuzz::<48>(slice, 65, 0x51);
    let expected_pcr1 = fill_from_fuzz::<48>(slice, 113, 0x61);
    let expected_pcr2 = fill_from_fuzz::<48>(slice, 161, 0x71);

    if let Ok(mutated_env) = AttestedKeyEnvelope::from_wire_bytes(mutated_wire) {
        let mut eph_mut = *eph_priv;
        let mut out_mut = [0xAAu8; 32];
        let mut_res = unwrap_attested_recipient_envelope(
            &mut eph_mut,
            recipient_pub,
            &expected_nonce,
            &expected_pcr0,
            &expected_pcr1,
            &expected_pcr2,
            &mutated_env,
            &mut out_mut,
        );
        assert!(mut_res.is_err());
        assert_eq!(eph_mut, [0u8; 32]);
        assert_eq!(out_mut, [0u8; 32]);
    }
}

#[inline(never)]
fn fuzz_kms_vsock_unwrap_session(
    slice: &[u8],
    eph_priv: &[u8; 32],
    mutated_wire: &[u8; ATTESTED_ENVELOPE_WIRE_SIZE],
) {
    let expected_nonce = fill_from_fuzz::<32>(slice, 33, 0x41);
    let expected_pcr0 = fill_from_fuzz::<48>(slice, 65, 0x51);
    let expected_pcr1 = fill_from_fuzz::<48>(slice, 113, 0x61);
    let expected_pcr2 = fill_from_fuzz::<48>(slice, 161, 0x71);

    reset_session_key();
    reset_nonce_replay_cache();
    configure_expected_pcr_policy(&expected_pcr0, &expected_pcr1, &expected_pcr2);
    if provision_ephemeral_recipient_from_seed(eph_priv).is_ok() {
        let slot = unsafe { &mut *SESSION_SLOT.0.get() };
        let mut session = VsockSessionState::new();
        let attest_hdr = EnclaveRequestHeader {
            magic: NONA_VSOCK_MAGIC,
            version: NONA_VSOCK_VERSION,
            command: CMD_ATTEST,
            payload_len: 32,
            flags: 0,
            reserved: [0u8; 16],
        };
        let _ = session.dispatch_frame(&attest_hdr, &expected_nonce, slot);

        let unwrap_hdr = EnclaveRequestHeader {
            magic: NONA_VSOCK_MAGIC,
            version: NONA_VSOCK_VERSION,
            command: CMD_KMS_RECIPIENT_UNWRAP,
            payload_len: u32::try_from(ATTESTED_ENVELOPE_WIRE_SIZE).unwrap_or(258),
            flags: 0,
            reserved: [0u8; 16],
        };
        let (wire_st, _) = session.dispatch_frame(&unwrap_hdr, mutated_wire, slot);
        assert_eq!(wire_st, NONA_WIRE_ERR_OPAQUE);
        assert_eq!(session.phase(), SessionPhase::ClosedZeroized);
        assert!(inspect_ephemeral_recipient_privkey_is_zeroized());
    }
    reset_session_key();
    reset_nonce_replay_cache();
}

/// # Panics
/// Panics only if an envelope authentication, fail-closed rejection, or volatile zeroization
/// invariant is violated.
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
    if data.is_null() || size == 0 {
        return 0;
    }
    let slice = unsafe { core::slice::from_raw_parts(data, size) };

    fuzz_kms_wire_and_curve_decoders(slice);

    let mut eph_priv = make_canonical_scalar_seed(slice, 1, 0x2b);
    let mut recipient_pub = [0u8; 33];
    if derive_compressed_public_key(&eph_priv, &mut recipient_pub) != 0 {
        eph_priv.fill(0);
        return 0;
    }

    fuzz_kms_malformed_envelope_unwrap(slice, &eph_priv, &recipient_pub);

    let mut mutated_wire = [0u8; ATTESTED_ENVELOPE_WIRE_SIZE];
    if fuzz_kms_authentic_wrap_and_mutation(slice, &eph_priv, &recipient_pub, &mut mutated_wire) {
        fuzz_kms_verify_mutated_rejection(slice, &eph_priv, &recipient_pub, &mutated_wire);
        fuzz_kms_vsock_unwrap_session(slice, &eph_priv, &mutated_wire);
    }

    eph_priv.fill(0);
    0
}

fn parse_runs_arg(default_runs: usize) -> usize {
    for arg in std::env::args().skip(1) {
        if let Some(val) = arg.strip_prefix("-runs=") {
            if let Ok(parsed) = val.parse::<usize>() {
                return parsed.max(1);
            }
        }
    }
    default_runs
}

fn main() {
    let cycles = parse_runs_arg(2_000);
    println!("[*] Launching Attested KMS Recipient Envelope Fuzzing ({cycles} cycles)...");

    let mut state: u64 = 0xcbf29ce484222325;
    let mut next_u64 = || {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        state.wrapping_mul(0x2545F4914F6CDD1D)
    };

    let mut corpus = vec![0u8; 512];
    for cycle in 1..=cycles {
        let size = if cycle % 4 == 0 {
            ATTESTED_ENVELOPE_WIRE_SIZE
        } else {
            (usize::try_from(next_u64()).unwrap_or(0) % corpus.len()).max(1)
        };
        for chunk in corpus[..size].chunks_mut(8) {
            let rnd = next_u64().to_le_bytes();
            let copy_len = chunk.len().min(8);
            chunk[..copy_len].copy_from_slice(&rnd[..copy_len]);
        }

        LLVMFuzzerTestOneInput(corpus.as_ptr(), size);

        if cycle % 500 == 0 || cycle == cycles {
            println!("  [+] KMS envelope harness completed {cycle} / {cycles} cycles (zero panics)");
        }
    }
    println!("[*] Attested KMS Recipient continuous fuzzing PASSED ({cycles}/{cycles} iterations).");
}
