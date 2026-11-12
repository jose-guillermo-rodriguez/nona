// Copyright (c) 2026 Nona Contributors.
// Licensed under the Apache License, Version 2.0 or the MIT License.

//! HIGH-ASSURANCE GATE: Negative Attestation & Manifest Policy Falsification Suite
//!
//! Validates that the verifier fails closed against:
//! 1. Dummy/unverified COSE Sign1 ECDSA signatures (prevents signature bypass).
//! 2. Manifest substring injection attacks (prevents policy bypass via JSON comments/unverified keys).
//! 3. Simulation manifest key-shadowing attacks (enforces strict AST schema with deny_unknown_fields).

#[cfg(feature = "std")]
mod negative_attestation_tests {
    use nona_core::client::{hex, synthesize_mock_cose_sign1_document, NonaClient};
    use nona_core::crypto::sha512_digest;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    struct ScopedTempFile {
        path: PathBuf,
    }

    impl ScopedTempFile {
        fn create(prefix: &str, content: &str) -> Self {
            let count = COUNTER.fetch_add(1, Ordering::SeqCst);
            let pid = std::process::id();
            let thread_id = format!("{:?}", std::thread::current().id())
                .replace("ThreadId(", "")
                .replace(')', "");
            let filename = format!("nona_{prefix}_{pid}_{thread_id}_{count}.json");
            let path = std::env::temp_dir().join(filename);

            let mut f = std::fs::File::create(&path).expect("Failed to create temporary manifest");
            f.write_all(content.as_bytes())
                .expect("Failed to write temporary manifest content");
            f.sync_all().expect("Failed to sync manifest file to disk");

            Self { path }
        }

        fn path_str(&self) -> &str {
            self.path.to_str().expect("Valid UTF-8 path expected")
        }
    }

    impl Drop for ScopedTempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn test_gate_reject_dummy_signature_in_attestation() {
        let pcr0 = [0x11u8; 48];
        let pcr1 = [0x22u8; 48];
        let pcr2 = [0x33u8; 48];

        let pcr0_hex = hex::encode(&pcr0);
        let pcr1_hex = hex::encode(&pcr1);
        let pcr2_hex = hex::encode(&pcr2);

        let manifest_content = format!(
            r#"{{
  "schema_version": "2.0.0",
  "measurements": {{
    "PCR0": "{pcr0_hex}",
    "PCR1": "{pcr1_hex}",
    "PCR2": "{pcr2_hex}"
  }}
}}"#
        );

        let manifest = ScopedTempFile::create("gate_test_manifest", &manifest_content);

        let pubkey = [0x02u8; 33];
        let expected_digest = sha512_digest(&pubkey);

        let mock_doc = synthesize_mock_cose_sign1_document(
            &expected_digest,
            &pcr0,
            &pcr1,
            &pcr2,
            true,
        );

        let verify_result = NonaClient::parse_and_verify_cose_attestation(
            &mock_doc,
            &expected_digest,
            manifest.path_str(),
        );

        assert!(
            verify_result.is_err(),
            "[HIGH-ASSURANCE VIOLATION] Verifier accepted attestation document with a dummy signature! ECDSA-P384 verification is missing."
        );
    }

    #[test]
    fn test_gate_reject_manifest_substring_injection() {
        let runtime_pcr0 = [0xAAu8; 48];
        let runtime_pcr1 = [0xBBu8; 48];
        let runtime_pcr2 = [0xCCu8; 48];

        let pcr0_hex = hex::encode(&runtime_pcr0);
        let pcr1_hex = hex::encode(&runtime_pcr1);
        let pcr2_hex = hex::encode(&runtime_pcr2);

        let deceptive_manifest_content = format!(
            r#"{{
  "schema_version": "2.0.0",
  "_comment_audit_log": "Previous authorized hash: {pcr0_hex}",
  "measurements": {{
    "PCR0": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "PCR1": "{pcr1_hex}",
    "PCR2": "{pcr2_hex}"
  }}
}}"#
        );

        let deceptive_manifest = ScopedTempFile::create("deceptive_manifest", &deceptive_manifest_content);

        let verify_res = NonaClient::verify_manifest_pcrs(
            deceptive_manifest.path_str(),
            &runtime_pcr0,
            &runtime_pcr1,
            &runtime_pcr2,
        );

        assert!(
            verify_res.is_err(),
            "[HIGH-ASSURANCE VIOLATION] Verifier accepted deceptive manifest via raw substring search! AST key parsing is missing."
        );
    }

    #[test]
    fn test_gate_reject_simulation_manifest_key_shadowing() {
        let valid_pcr0 = hex::encode(&[0x11u8; 48]);
        let valid_pcr1 = hex::encode(&[0x22u8; 48]);
        let valid_pcr2 = hex::encode(&[0x33u8; 48]);

        let shadowed_manifest_content = format!(
            r#"{{
  "schema_version": "2.0.0",
  "untrusted_audit_history": {{
    "PCR0": "{valid_pcr0}",
    "PCR1": "{valid_pcr1}",
    "PCR2": "{valid_pcr2}"
  }},
  "measurements": {{
    "PCR0": "invalid_short_pcr",
    "PCR1": "invalid_short_pcr",
    "PCR2": "invalid_short_pcr"
  }}
}}"#
        );

        let shadowed_manifest = ScopedTempFile::create("shadowed_sim_manifest", &shadowed_manifest_content);

        let verify_res = NonaClient::verify_simulation_manifest(shadowed_manifest.path_str());

        assert!(
            verify_res.is_err(),
            "[HIGH-ASSURANCE VIOLATION] Simulation manifest verifier accepted shadowed keys via substring find()! Strict AST schema is missing."
        );
    }

    #[test]
    fn test_gate_reject_pcr_wildcard_prefix_and_regex_policies() {
        let pcr0 = [0x11u8; 48];
        let pcr1 = [0x22u8; 48];
        let pcr2 = [0x33u8; 48];

        let pcr0_hex = hex::encode(&pcr0);
        let pcr1_hex = hex::encode(&pcr1);
        let pcr2_hex = hex::encode(&pcr2);

        let invalid_policies = [
            // Wildcard on PCR2 application measurement
            format!(
                r#"{{"measurements": {{"PCR0": "{pcr0_hex}", "PCR1": "{pcr1_hex}", "PCR2": "*"}}}}"#
            ),
            // Prefix wildcard on PCR2 application measurement
            format!(
                r#"{{"measurements": {{"PCR0": "{pcr0_hex}", "PCR1": "{pcr1_hex}", "PCR2": "{}*"}}}}"#,
                &pcr2_hex[..32]
            ),
            // Regex pattern on PCR2 application measurement
            format!(
                r#"{{"measurements": {{"PCR0": "{pcr0_hex}", "PCR1": "{pcr1_hex}", "PCR2": "^[0-9a-f]{{96}}$"}}}}"#
            ),
            // Truncated prefix without wildcard
            format!(
                r#"{{"measurements": {{"PCR0": "{pcr0_hex}", "PCR1": "{pcr1_hex}", "PCR2": "{}"}}}}"#,
                &pcr2_hex[..64]
            ),
            // 0x-prefixed digest
            format!(
                r#"{{"measurements": {{"PCR0": "0x{pcr0_hex}", "PCR1": "{pcr1_hex}", "PCR2": "{pcr2_hex}"}}}}"#
            ),
        ];

        for (idx, policy_json) in invalid_policies.iter().enumerate() {
            let manifest = ScopedTempFile::create(&format!("wildcard_policy_{idx}"), policy_json);
            let res = NonaClient::verify_manifest_pcrs(manifest.path_str(), &pcr0, &pcr1, &pcr2);
            assert!(
                res.is_err(),
                "Verifier must reject non-exact/wildcard/regex PCR policy variant {idx}"
            );
        }
    }

    #[test]
    fn test_gate_reject_duplicate_json_keys_and_non_48_byte_pcrs() {
        let pcr0 = [0x11u8; 48];
        let pcr1 = [0x22u8; 48];
        let pcr2 = [0x33u8; 48];

        let pcr0_hex = hex::encode(&pcr0);
        let pcr1_hex = hex::encode(&pcr1);
        let pcr2_hex = hex::encode(&pcr2);

        // Duplicate PCR2 key shadowing attack
        let dup_key_manifest = format!(
            r#"{{
  "measurements": {{
    "PCR0": "{pcr0_hex}",
    "PCR1": "{pcr1_hex}",
    "PCR2": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "PCR2": "{pcr2_hex}"
  }}
}}"#
        );
        let dup_file = ScopedTempFile::create("dup_key_manifest", &dup_key_manifest);
        assert!(
            NonaClient::verify_manifest_pcrs(dup_file.path_str(), &pcr0, &pcr1, &pcr2).is_err(),
            "Verifier must reject duplicate JSON keys in manifest"
        );

        // Valid manifest rejected against empty/non-48-byte runtime PCR slices
        let valid_manifest = format!(
            r#"{{"measurements": {{"PCR0": "{pcr0_hex}", "PCR1": "{pcr1_hex}", "PCR2": "{pcr2_hex}"}}}}"#
        );
        let valid_file = ScopedTempFile::create("valid_pin_manifest", &valid_manifest);
        assert!(
            NonaClient::verify_manifest_pcrs(valid_file.path_str(), &[], &pcr1, &pcr2).is_err(),
            "Verifier must reject empty runtime PCR slice"
        );
        assert!(
            NonaClient::verify_manifest_pcrs(valid_file.path_str(), &pcr0[..32], &pcr1, &pcr2)
                .is_err(),
            "Verifier must reject non-48-byte runtime PCR slice"
        );

        // Exact bit-for-bit match succeeds; single-bit flip in PCR2 fails closed
        assert!(
            NonaClient::verify_manifest_pcrs(valid_file.path_str(), &pcr0, &pcr1, &pcr2).is_ok(),
            "Exact bit-for-bit PCR0/PCR1/PCR2 match must succeed"
        );
        let mut flipped_pcr2 = pcr2;
        flipped_pcr2[47] ^= 0x01;
        assert!(
            NonaClient::verify_manifest_pcrs(valid_file.path_str(), &pcr0, &pcr1, &flipped_pcr2)
                .is_err(),
            "Single-bit mutation in PCR2 must fail closed"
        );
    }

    #[test]
    fn test_gate_reject_missing_manifest_path_fail_closed() {
        let pcr0 = [0x11u8; 48];
        let pcr1 = [0x22u8; 48];
        let pcr2 = [0x33u8; 48];
        let pubkey = [0x02u8; 33];
        let expected_digest = sha512_digest(&pubkey);
        let doc = synthesize_mock_cose_sign1_document(&expected_digest, &pcr0, &pcr1, &pcr2, true);

        let res = NonaClient::parse_and_verify_cose_attestation(
            &doc,
            &expected_digest,
            "/nonexistent/path/to/enclave_manifest.json",
        );
        assert!(
            res.is_err(),
            "Non-empty missing manifest path must fail closed instead of skipping PCR check"
        );
    }

    #[test]
    fn test_gate_reject_empty_manifest_on_attest_and_bind_and_pcr_collisions() {
        let pcr0 = [0x11u8; 48];
        let pcr1 = [0x22u8; 48];
        let pcr0_hex = hex::encode(&pcr0);
        let pcr1_hex = hex::encode(&pcr1);

        // Degenerate PCR0 == PCR2 collision must fail closed
        let collision_manifest = format!(
            r#"{{"measurements": {{"PCR0": "{pcr0_hex}", "PCR1": "{pcr1_hex}", "PCR2": "{pcr0_hex}"}}}}"#
        );
        let collision_file = ScopedTempFile::create("pcr_collision_manifest", &collision_manifest);
        assert!(
            NonaClient::verify_manifest_pcrs(collision_file.path_str(), &pcr0, &pcr1, &pcr0)
                .is_err(),
            "Verifier must reject degenerate PCR0 == PCR2 register collision"
        );

        // Empty or whitespace-only manifest path on attest_and_bind must fail closed immediately
        let listener = std::os::unix::net::UnixListener::bind(
            std::env::temp_dir().join(format!("nona_empty_manifest_gate_{}.sock", std::process::id())),
        )
        .expect("Failed to bind temporary unix socket");
        let sock_path = listener.local_addr().unwrap().as_pathname().unwrap().to_path_buf();
        let mut client = NonaClient::connect_unix(sock_path.to_str().unwrap())
            .expect("Failed to connect unix client");

        assert!(
            client.attest_and_bind("").is_err(),
            "attest_and_bind must reject empty manifest path"
        );
        assert!(
            client.attest_and_bind("   ").is_err(),
            "attest_and_bind must reject whitespace manifest path"
        );
        drop(client);
        drop(listener);
        let _ = std::fs::remove_file(sock_path);
    }
}
