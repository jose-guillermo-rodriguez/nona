//! Adversarial AWS KMS Attested Recipient Key-Release & Session Binding Suite.

#[cfg(feature = "std")]
mod kms_recipient_binding_tests {
    use nona_core::attestation::derive_compressed_public_key;
    use nona_core::client::synthesize_signed_cose_sign1_attestation;
    use nona_core::client::NonaClient;
    use nona_core::crypto::{
        sha512_digest, unwrap_attested_recipient_envelope, AttestedEnvelopeError,
        AttestedKeyEnvelope, ATTESTED_ENVELOPE_WIRE_SIZE,
    };
    use nona_core::enclave_server::{
        configure_expected_pcr_policy, inspect_ephemeral_recipient_privkey_is_zeroized,
        provision_ephemeral_recipient_from_seed, reset_nonce_replay_cache, reset_session_key,
        EnclaveConnectionSlot, EnclaveRequestHeader, SessionPhase, VsockSessionState,
        CMD_ATTEST, CMD_BLIND_PHASE1, CMD_KMS_RECIPIENT_UNWRAP, CMD_PHASE2_INTERSECT,
        CMD_PHASE2_REBLIND, FLAG_USE_SESSION_KEY, NONA_VSOCK_MAGIC, NONA_VSOCK_VERSION,
        NONA_WIRE_ERR_OPAQUE,
    };
    use std::sync::Mutex;

    static ENCLAVE_STATE_LOCK: Mutex<()> = Mutex::new(());

    fn make_hdr(cmd: u16, plen: usize, flags: u32) -> EnclaveRequestHeader {
        EnclaveRequestHeader {
            magic: NONA_VSOCK_MAGIC,
            version: NONA_VSOCK_VERSION,
            command: cmd,
            payload_len: u32::try_from(plen).unwrap_or(0),
            flags,
            reserved: [0u8; 16],
        }
    }

    fn test_pcrs() -> ([u8; 48], [u8; 48], [u8; 48]) {
        ([0x11u8; 48], [0x22u8; 48], [0x33u8; 48])
    }

    #[test]
    fn test_kms_recipient_happy_path_end_to_end_psi() {
        let _guard = ENCLAVE_STATE_LOCK.lock().expect("lock enclave state");
        reset_session_key();
        reset_nonce_replay_cache();

        let (pcr0, pcr1, pcr2) = test_pcrs();
        configure_expected_pcr_policy(&pcr0, &pcr1, &pcr2);

        // 1. Provision enclave ephemeral recipient keypair and bind into signed COSE_Sign1 attestation
        let mut eph_priv_seed = [0u8; 32];
        eph_priv_seed[0] = 0x4b;
        eph_priv_seed[31] = 0x19;
        let recipient_pubkey =
            provision_ephemeral_recipient_from_seed(&eph_priv_seed).expect("provision recipient");
        assert!(
            !inspect_ephemeral_recipient_privkey_is_zeroized(),
            "Ephemeral recipient key must be active prior to envelope unwrap"
        );

        let challenge_nonce = [0x9au8; 32];
        let user_data_digest = sha512_digest(&recipient_pubkey);
        let now_secs: u64 = 1_785_000_000;
        let (cose_doc, root_der) = synthesize_signed_cose_sign1_attestation(
            &user_data_digest,
            Some(&challenge_nonce),
            now_secs * 1000,
            &pcr0,
            &pcr1,
            &pcr2,
        );

        // 2. Verify attestation document binds recipient public key, challenge nonce, and PCR0..2
        assert!(
            NonaClient::parse_and_verify_cose_attestation_full(
                &cose_doc,
                &user_data_digest,
                Some(&challenge_nonce),
                "",
                &root_der,
                now_secs,
            )
            .is_ok(),
            "Attestation document binding ephemeral recipient key must verify cleanly"
        );

        // 3. Simulated AWS KMS wraps session blinding scalar r to recipient_pubkey
        let mut kms_eph_priv = [0u8; 32];
        kms_eph_priv[0] = 0x77;
        kms_eph_priv[31] = 0x05;

        let mut session_blinding_secret = [0u8; 32];
        session_blinding_secret[0] = 0x3d;
        session_blinding_secret[15] = 0x88;
        session_blinding_secret[31] = 0x12;

        let envelope = AttestedKeyEnvelope::wrap_for_recipient(
            &kms_eph_priv,
            &recipient_pubkey,
            &challenge_nonce,
            &pcr0,
            &pcr1,
            &pcr2,
            &session_blinding_secret,
        )
        .expect("wrap KMS recipient envelope");
        let wire_envelope = envelope.to_wire_bytes();
        assert_eq!(wire_envelope.len(), ATTESTED_ENVELOPE_WIRE_SIZE);

        // 4. Drive vsock session handshake: CMD_ATTEST -> CMD_KMS_RECIPIENT_UNWRAP -> Phase 1 -> Phase 2
        let mut slot = EnclaveConnectionSlot::INIT;
        let mut session = VsockSessionState::new();

        let attest_hdr = make_hdr(CMD_ATTEST, challenge_nonce.len(), 0);
        let _ = session.dispatch_frame(&attest_hdr, &challenge_nonce, &mut slot);
        assert_eq!(session.phase(), SessionPhase::AttestedBound);

        let unwrap_hdr = make_hdr(CMD_KMS_RECIPIENT_UNWRAP, wire_envelope.len(), 0);
        let (unwrap_st, unwrap_len) =
            session.dispatch_frame(&unwrap_hdr, &wire_envelope, &mut slot);
        assert_eq!(unwrap_st, 0, "Valid KMS recipient envelope must unwrap cleanly");
        assert_eq!(unwrap_len, 0);
        assert_eq!(session.phase(), SessionPhase::AttestedBound);

        // 5. Ephemeral private key MUST be zeroized immediately after unwrapping
        assert!(
            inspect_ephemeral_recipient_privkey_is_zeroized(),
            "Ephemeral recipient private key must be destroyed immediately after unwrapping"
        );

        // 6. Execute Phase 1 blinding and Phase 2 reblinding/intersection using unwrapped session secret
        let elem = [0x21u8; 32];
        let p1_hdr = make_hdr(CMD_BLIND_PHASE1, 32, FLAG_USE_SESSION_KEY);
        let (p1_st, p1_len) = session.dispatch_frame(&p1_hdr, &elem, &mut slot);
        assert_eq!(p1_st, 0);
        assert_eq!(p1_len, 32);
        assert_eq!(session.phase(), SessionPhase::Phase1Blinded);

        let mut blinded_a = [0u8; 32];
        blinded_a.copy_from_slice(&slot.out_buffer.data[..32]);
        assert_ne!(blinded_a, [0u8; 32]);
        assert_ne!(blinded_a, elem);

        let p2_rb_hdr = make_hdr(CMD_PHASE2_REBLIND, 32, FLAG_USE_SESSION_KEY);
        let (rb_st, rb_len) = session.dispatch_frame(&p2_rb_hdr, &blinded_a, &mut slot);
        assert_eq!(rb_st, 0);
        assert_eq!(rb_len, 32);
        assert_eq!(session.phase(), SessionPhase::Phase2Reblinded);

        let mut double_blinded = [0u8; 32];
        double_blinded.copy_from_slice(&slot.out_buffer.data[..32]);

        let mut intersect_payload = [0u8; 80];
        intersect_payload[4..8].copy_from_slice(&1u32.to_le_bytes());
        intersect_payload[8..12].copy_from_slice(&1u32.to_le_bytes());
        intersect_payload[16..48].copy_from_slice(&double_blinded);
        intersect_payload[48..80].copy_from_slice(&double_blinded);
        let int_hdr = make_hdr(CMD_PHASE2_INTERSECT, intersect_payload.len(), 0);
        let (int_st, int_len) =
            session.dispatch_frame(&int_hdr, &intersect_payload, &mut slot);
        assert_eq!(int_st, 0);
        assert_eq!(int_len, 68);
        assert_eq!(session.phase(), SessionPhase::Phase2Intersected);

        reset_session_key();
        reset_nonce_replay_cache();
    }

    #[test]
    fn test_kms_recipient_rejects_wrong_recipient_key_and_tampered_tag() {
        let _guard = ENCLAVE_STATE_LOCK.lock().expect("lock enclave state");
        reset_session_key();
        reset_nonce_replay_cache();

        let (pcr0, pcr1, pcr2) = test_pcrs();
        configure_expected_pcr_policy(&pcr0, &pcr1, &pcr2);

        let mut eph_priv = [0u8; 32];
        eph_priv[0] = 0x51;
        let recipient_pubkey =
            provision_ephemeral_recipient_from_seed(&eph_priv).expect("provision recipient");

        let mut wrong_priv = [0u8; 32];
        wrong_priv[0] = 0x52;
        let mut wrong_recipient_pubkey = [0u8; 33];
        assert_eq!(
            derive_compressed_public_key(&wrong_priv, &mut wrong_recipient_pubkey),
            0
        );

        let mut kms_priv = [0u8; 32];
        kms_priv[0] = 0x63;
        let nonce = [0x44u8; 32];
        let mut secret = [0u8; 32];
        secret[0] = 0x17;

        // 1. Envelope wrapped for wrong recipient public key must fail authentication and zeroize key
        let wrong_recipient_env = AttestedKeyEnvelope::wrap_for_recipient(
            &kms_priv,
            &wrong_recipient_pubkey,
            &nonce,
            &pcr0,
            &pcr1,
            &pcr2,
            &secret,
        )
        .expect("wrap for wrong recipient");

        let mut slot = EnclaveConnectionSlot::INIT;
        let mut session = VsockSessionState::new();
        let _ = session.dispatch_frame(&make_hdr(CMD_ATTEST, 32, 0), &nonce, &mut slot);

        let (st1, _) = session.dispatch_frame(
            &make_hdr(CMD_KMS_RECIPIENT_UNWRAP, ATTESTED_ENVELOPE_WIRE_SIZE, 0),
            &wrong_recipient_env.to_wire_bytes(),
            &mut slot,
        );
        assert_eq!(st1, NONA_WIRE_ERR_OPAQUE);
        assert_eq!(session.phase(), SessionPhase::ClosedZeroized);
        assert!(inspect_ephemeral_recipient_privkey_is_zeroized());

        // 2. Single-bit flip in auth_tag or wrapped_key must fail closed and zeroize ephemeral key
        reset_session_key();
        reset_nonce_replay_cache();
        let _ = provision_ephemeral_recipient_from_seed(&eph_priv).expect("re-provision");
        let valid_env = AttestedKeyEnvelope::wrap_for_recipient(
            &kms_priv,
            &recipient_pubkey,
            &nonce,
            &pcr0,
            &pcr1,
            &pcr2,
            &secret,
        )
        .expect("wrap valid");
        let mut tampered_wire = valid_env.to_wire_bytes();
        tampered_wire[245] ^= 0x80;

        let mut session2 = VsockSessionState::new();
        let _ = session2.dispatch_frame(&make_hdr(CMD_ATTEST, 32, 0), &nonce, &mut slot);
        let (st2, _) = session2.dispatch_frame(
            &make_hdr(CMD_KMS_RECIPIENT_UNWRAP, ATTESTED_ENVELOPE_WIRE_SIZE, 0),
            &tampered_wire,
            &mut slot,
        );
        assert_eq!(st2, NONA_WIRE_ERR_OPAQUE);
        assert_eq!(session2.phase(), SessionPhase::ClosedZeroized);
        assert!(inspect_ephemeral_recipient_privkey_is_zeroized());

        reset_session_key();
        reset_nonce_replay_cache();
    }

    #[test]
    fn test_kms_recipient_rejects_mismatched_and_replayed_challenge_nonces() {
        let _guard = ENCLAVE_STATE_LOCK.lock().expect("lock enclave state");
        reset_session_key();
        reset_nonce_replay_cache();

        let (pcr0, pcr1, pcr2) = test_pcrs();
        configure_expected_pcr_policy(&pcr0, &pcr1, &pcr2);

        let mut eph_priv = [0u8; 32];
        eph_priv[0] = 0x31;
        let recipient_pubkey =
            provision_ephemeral_recipient_from_seed(&eph_priv).expect("provision");

        let mut kms_priv = [0u8; 32];
        kms_priv[0] = 0x32;
        let nonce_a = [0xa1u8; 32];
        let nonce_b = [0xb2u8; 32];
        let mut secret = [0u8; 32];
        secret[0] = 0x29;

        // 1. Envelope bound to nonce_b sent into session bound to nonce_a must fail closed
        let env_b = AttestedKeyEnvelope::wrap_for_recipient(
            &kms_priv,
            &recipient_pubkey,
            &nonce_b,
            &pcr0,
            &pcr1,
            &pcr2,
            &secret,
        )
        .expect("wrap env_b");

        let mut slot = EnclaveConnectionSlot::INIT;
        let mut session = VsockSessionState::new();
        let _ = session.dispatch_frame(&make_hdr(CMD_ATTEST, 32, 0), &nonce_a, &mut slot);
        let (st_mismatch, _) = session.dispatch_frame(
            &make_hdr(CMD_KMS_RECIPIENT_UNWRAP, ATTESTED_ENVELOPE_WIRE_SIZE, 0),
            &env_b.to_wire_bytes(),
            &mut slot,
        );
        assert_eq!(st_mismatch, NONA_WIRE_ERR_OPAQUE);
        assert_eq!(session.phase(), SessionPhase::ClosedZeroized);
        assert!(inspect_ephemeral_recipient_privkey_is_zeroized());

        // 2. Valid envelope accepted once, then replayed in a second session -> rejected
        reset_session_key();
        reset_nonce_replay_cache();
        let recipient_pubkey2 =
            provision_ephemeral_recipient_from_seed(&eph_priv).expect("provision 2");
        let env_a = AttestedKeyEnvelope::wrap_for_recipient(
            &kms_priv,
            &recipient_pubkey2,
            &nonce_a,
            &pcr0,
            &pcr1,
            &pcr2,
            &secret,
        )
        .expect("wrap env_a");
        let wire_a = env_a.to_wire_bytes();

        let mut session_ok = VsockSessionState::new();
        let _ = session_ok.dispatch_frame(&make_hdr(CMD_ATTEST, 32, 0), &nonce_a, &mut slot);
        let (st_ok, _) = session_ok.dispatch_frame(
            &make_hdr(CMD_KMS_RECIPIENT_UNWRAP, ATTESTED_ENVELOPE_WIRE_SIZE, 0),
            &wire_a,
            &mut slot,
        );
        assert_eq!(st_ok, 0);

        // Replay exact same nonce_a envelope on a new session
        let _ = provision_ephemeral_recipient_from_seed(&eph_priv).expect("provision replay");
        let mut session_replay = VsockSessionState::new();
        let _ = session_replay.dispatch_frame(&make_hdr(CMD_ATTEST, 32, 0), &nonce_a, &mut slot);
        let (st_replay, _) = session_replay.dispatch_frame(
            &make_hdr(CMD_KMS_RECIPIENT_UNWRAP, ATTESTED_ENVELOPE_WIRE_SIZE, 0),
            &wire_a,
            &mut slot,
        );
        assert_eq!(st_replay, NONA_WIRE_ERR_OPAQUE);
        assert_eq!(session_replay.phase(), SessionPhase::ClosedZeroized);
        assert!(inspect_ephemeral_recipient_privkey_is_zeroized());

        reset_session_key();
        reset_nonce_replay_cache();
    }

    #[test]
    fn test_kms_recipient_rejects_pcr0_and_pcr2_mismatch() {
        let _guard = ENCLAVE_STATE_LOCK.lock().expect("lock enclave state");
        reset_session_key();
        reset_nonce_replay_cache();

        let (pcr0, pcr1, pcr2) = test_pcrs();
        configure_expected_pcr_policy(&pcr0, &pcr1, &pcr2);

        let mut eph_priv = [0u8; 32];
        eph_priv[0] = 0x71;
        let recipient_pubkey =
            provision_ephemeral_recipient_from_seed(&eph_priv).expect("provision");

        let mut kms_priv = [0u8; 32];
        kms_priv[0] = 0x72;
        let nonce = [0x55u8; 32];
        let mut secret = [0u8; 32];
        secret[0] = 0x41;

        // 1. Single-bit flip in PCR0 fails closed
        let mut bad_pcr0 = pcr0;
        bad_pcr0[47] ^= 0x01;
        let env_bad_pcr0 = AttestedKeyEnvelope::wrap_for_recipient(
            &kms_priv,
            &recipient_pubkey,
            &nonce,
            &bad_pcr0,
            &pcr1,
            &pcr2,
            &secret,
        )
        .expect("wrap bad_pcr0");

        let mut slot = EnclaveConnectionSlot::INIT;
        let mut session1 = VsockSessionState::new();
        let _ = session1.dispatch_frame(&make_hdr(CMD_ATTEST, 32, 0), &nonce, &mut slot);
        let (st_pcr0, _) = session1.dispatch_frame(
            &make_hdr(CMD_KMS_RECIPIENT_UNWRAP, ATTESTED_ENVELOPE_WIRE_SIZE, 0),
            &env_bad_pcr0.to_wire_bytes(),
            &mut slot,
        );
        assert_eq!(st_pcr0, NONA_WIRE_ERR_OPAQUE);
        assert_eq!(session1.phase(), SessionPhase::ClosedZeroized);
        assert!(inspect_ephemeral_recipient_privkey_is_zeroized());

        // 2. Single-bit flip in PCR2 fails closed
        reset_session_key();
        reset_nonce_replay_cache();
        let _ = provision_ephemeral_recipient_from_seed(&eph_priv).expect("re-provision");
        let mut bad_pcr2 = pcr2;
        bad_pcr2[0] ^= 0x01;
        let env_bad_pcr2 = AttestedKeyEnvelope::wrap_for_recipient(
            &kms_priv,
            &recipient_pubkey,
            &nonce,
            &pcr0,
            &pcr1,
            &bad_pcr2,
            &secret,
        )
        .expect("wrap bad_pcr2");

        let mut session2 = VsockSessionState::new();
        let _ = session2.dispatch_frame(&make_hdr(CMD_ATTEST, 32, 0), &nonce, &mut slot);
        let (st_pcr2, _) = session2.dispatch_frame(
            &make_hdr(CMD_KMS_RECIPIENT_UNWRAP, ATTESTED_ENVELOPE_WIRE_SIZE, 0),
            &env_bad_pcr2.to_wire_bytes(),
            &mut slot,
        );
        assert_eq!(st_pcr2, NONA_WIRE_ERR_OPAQUE);
        assert_eq!(session2.phase(), SessionPhase::ClosedZeroized);
        assert!(inspect_ephemeral_recipient_privkey_is_zeroized());

        reset_session_key();
        reset_nonce_replay_cache();
    }

    #[test]
    fn test_kms_recipient_ephemeral_privkey_zeroized_directly_on_unwrap() {
        let (pcr0, pcr1, pcr2) = test_pcrs();
        let mut eph_priv = [0u8; 32];
        eph_priv[0] = 0x89;
        eph_priv[16] = 0x42;
        let mut recipient_pubkey = [0u8; 33];
        assert_eq!(
            derive_compressed_public_key(&eph_priv, &mut recipient_pubkey),
            0
        );

        let mut kms_priv = [0u8; 32];
        kms_priv[0] = 0x91;
        let nonce = [0x33u8; 32];
        let mut secret = [0u8; 32];
        secret[0] = 0x57;
        secret[31] = 0x03;

        let env = AttestedKeyEnvelope::wrap_for_recipient(
            &kms_priv,
            &recipient_pubkey,
            &nonce,
            &pcr0,
            &pcr1,
            &pcr2,
            &secret,
        )
        .expect("wrap");

        let mut unwrapped = [0u8; 32];
        let res = unwrap_attested_recipient_envelope(
            &mut eph_priv,
            &recipient_pubkey,
            &nonce,
            &pcr0,
            &pcr1,
            &pcr2,
            &env,
            &mut unwrapped,
        );
        assert_eq!(res, Ok(()));
        assert_eq!(unwrapped, secret);
        assert_eq!(
            eph_priv, [0u8; 32],
            "Ephemeral private key buffer must be zeroized immediately after unwrapping"
        );

        // Error path also zeroizes ephemeral private key and output buffer
        let mut eph_priv_err = [0xAAu8; 32];
        let mut out_err = [0xBBu8; 32];
        let err_res = unwrap_attested_recipient_envelope(
            &mut eph_priv_err,
            &recipient_pubkey,
            &[0xFFu8; 32],
            &pcr0,
            &pcr1,
            &pcr2,
            &env,
            &mut out_err,
        );
        assert_eq!(err_res, Err(AttestedEnvelopeError::NonceMismatch));
        assert_eq!(eph_priv_err, [0u8; 32]);
        assert_eq!(out_err, [0u8; 32]);
    }
}
