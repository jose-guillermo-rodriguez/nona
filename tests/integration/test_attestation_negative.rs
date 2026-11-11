// Copyright (c) 2026 Nona Contributors.
// Licensed under the Apache License, Version 2.0 or the MIT License.

//! HIGH-ASSURANCE GATE: Negative Attestation & Manifest Policy Falsification Suite
//!
//! Validates that the verifier fails closed against:
//! 1. Dummy/unverified COSE Sign1 ECDSA signatures (prevents signature bypass).
//! 2. Manifest substring injection attacks (prevents policy bypass via JSON comments/unverified keys).

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
}
