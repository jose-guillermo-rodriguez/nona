// ============================================================================
// ============================================================================

use nona_core::enclave_server::{
    dispatch_frame, EnclaveFrameBuffer, EnclaveRequestHeader, CMD_ATTEST, CMD_BLIND_PHASE1,
    CMD_INGEST, CMD_PING, NONA_VSOCK_MAGIC, NONA_VSOCK_VERSION,
};

#[test]
fn test_enclave_protocol_header_magic_and_version_rejection() {
    let mut resp_buf = EnclaveFrameBuffer::INIT;

    // 1. Invalid Magic
    let bad_magic_hdr = EnclaveRequestHeader {
        magic: 0xDEADBEEF,
        version: NONA_VSOCK_VERSION,
        command: CMD_PING,
        payload_len: 4,
        flags: 0,
        reserved: [0u8; 16],
    };
    let (status, len) = dispatch_frame(&bad_magic_hdr, b"test", &mut resp_buf.data);
    assert_eq!(status, -100); // NONA_ERR_INVALID_MAGIC
    assert_eq!(len, 0);

    // 2. Invalid Protocol Version
    let bad_ver_hdr = EnclaveRequestHeader {
        magic: NONA_VSOCK_MAGIC,
        version: 999,
        command: CMD_PING,
        payload_len: 4,
        flags: 0,
        reserved: [0u8; 16],
    };
    let (status, len) = dispatch_frame(&bad_ver_hdr, b"test", &mut resp_buf.data);
    assert_eq!(status, -101); // NONA_ERR_INVALID_VERSION
    assert_eq!(len, 0);
}

#[test]
fn test_enclave_cmd_ping_roundtrip() {
    let mut in_buf = EnclaveFrameBuffer::INIT;
    let mut resp_buf = EnclaveFrameBuffer::INIT;

    let ping_payload = b"NONA_ENCLAVE_HEARTBEAT_2026";
    in_buf.data[..ping_payload.len()].copy_from_slice(ping_payload);

    let req_hdr = EnclaveRequestHeader {
        magic: NONA_VSOCK_MAGIC,
        version: NONA_VSOCK_VERSION,
        command: CMD_PING,
        payload_len: u32::try_from(ping_payload.len()).unwrap_or(0),
        flags: 0,
        reserved: [0u8; 16],
    };

    let (status, resp_len) = dispatch_frame(
        &req_hdr,
        &in_buf.data[..ping_payload.len()],
        &mut resp_buf.data,
    );

    assert_eq!(status, 0);
    assert_eq!(resp_len as usize, ping_payload.len());
    assert_eq!(&resp_buf.data[..resp_len as usize], ping_payload);

    // Verify sanitization
    in_buf.purge();
    resp_buf.purge();
    assert_eq!(in_buf.data[0], 0);
    assert_eq!(resp_buf.data[0], 0);
}

#[test]
fn test_enclave_cmd_ingest_framing_and_rejection() {
    let mut in_buf = EnclaveFrameBuffer::INIT;
    let mut resp_buf = EnclaveFrameBuffer::INIT;

    // 1. Unaligned stream chunk (not a multiple of 128 bytes)
    let bad_len_hdr = EnclaveRequestHeader {
        magic: NONA_VSOCK_MAGIC,
        version: NONA_VSOCK_VERSION,
        command: CMD_INGEST,
        payload_len: 64, // Not multiple of 128
        flags: 0,
        reserved: [0u8; 16],
    };
    in_buf.data[0..64].fill(0x55);
    let (status, _) = dispatch_frame(&bad_len_hdr, &in_buf.data[..64], &mut resp_buf.data);
    assert_eq!(status, -3); // Length bound violation

    // 2. Canonical 128-byte aligned ingestion frame
    let good_len_hdr = EnclaveRequestHeader {
        magic: NONA_VSOCK_MAGIC,
        version: NONA_VSOCK_VERSION,
        command: CMD_INGEST,
        payload_len: 128,
        flags: 0,
        reserved: [0u8; 16],
    };
    in_buf.data[0..128].fill(0xAA);
    let (status, out_len) = dispatch_frame(&good_len_hdr, &in_buf.data[..128], &mut resp_buf.data);
    assert_eq!(status, 0); // NONA_SUCCESS
    assert_eq!(out_len, 0);

    in_buf.purge();
    resp_buf.purge();
}

#[test]
fn test_enclave_cmd_blind_phase1_cryptographic_pipeline() {
    let mut in_buf = EnclaveFrameBuffer::INIT;
    let mut resp_buf = EnclaveFrameBuffer::INIT;

    // Construct Phase 1 frame: [32-byte secret scalar key] + [2 * 32-byte raw elements]
    let key = [0x42u8; 32];
    let elem1 = [0x11u8; 32];
    let elem2 = [0x22u8; 32];

    in_buf.data[0..32].copy_from_slice(&key);
    in_buf.data[32..64].copy_from_slice(&elem1);
    in_buf.data[64..96].copy_from_slice(&elem2);

    let req_hdr = EnclaveRequestHeader {
        magic: NONA_VSOCK_MAGIC,
        version: NONA_VSOCK_VERSION,
        command: CMD_BLIND_PHASE1,
        payload_len: 96,
        flags: 0,
        reserved: [0u8; 16],
    };

    let (status, resp_len) = dispatch_frame(&req_hdr, &in_buf.data[..96], &mut resp_buf.data);

    assert_eq!(status, 0); // NONA_SUCCESS
    assert_eq!(resp_len, 64); // 2 blinded elements of 32 bytes each

    // Blinded elements must not be zero and must not match raw inputs
    assert_ne!(&resp_buf.data[0..32], &[0u8; 32]);
    assert_ne!(&resp_buf.data[0..32], &elem1);
    assert_ne!(&resp_buf.data[32..64], &elem2);

    // Verify deterministic blinded output
    let mut resp_buf2 = EnclaveFrameBuffer::INIT;
    let (status2, resp_len2) = dispatch_frame(&req_hdr, &in_buf.data[..96], &mut resp_buf2.data);
    assert_eq!(status2, 0);
    assert_eq!(resp_len2, 64);
    assert_eq!(&resp_buf.data[..64], &resp_buf2.data[..64]);

    in_buf.purge();
    resp_buf.purge();
    resp_buf2.purge();
}

#[test]
fn test_enclave_cmd_attest_hardware_fallback() {
    let mut resp_buf = EnclaveFrameBuffer::INIT;
    let dummy_key = [0x07u8; 32];

    let req_hdr = EnclaveRequestHeader {
        magic: NONA_VSOCK_MAGIC,
        version: NONA_VSOCK_VERSION,
        command: CMD_ATTEST,
        payload_len: 32,
        flags: 0,
        reserved: [0u8; 16],
    };

    let (status, resp_len) = dispatch_frame(&req_hdr, &dummy_key, &mut resp_buf.data);

    // Outside AWS Nitro Enclave hypervisor, NSM driver returns -110 cleanly without fault
    assert_eq!(status, -110);
    assert_eq!(resp_len, 0);

    resp_buf.purge();
}

#[cfg(feature = "std")]
#[test]
fn test_real_dual_transport_client_and_tail_padding() {
    use nona_core::client::{NonaClient, DEFAULT_UNIX_SOCKET_PATH};
    use nona_core::enclave_server::{run_unix_server, DEFAULT_UNIX_SOCKET};
    use std::thread;
    use std::time::Duration;

    let _ = std::fs::remove_file(DEFAULT_UNIX_SOCKET_PATH);

    // Spawn server daemon listening on real Unix domain socket
    thread::spawn(|| unsafe {
        run_unix_server(DEFAULT_UNIX_SOCKET);
    });

    thread::sleep(Duration::from_millis(100));

    let mut client = NonaClient::connect_unix(DEFAULT_UNIX_SOCKET_PATH)
        .expect("Failed to connect to real enclave wire server");
    client.allow_simulation_fallback = true;
    client.allow_simulation_fallback = true;

    // 1. Ping roundtrip
    let echo = client.ping(b"RADICAL_EFFICACY_2026").expect("Ping failed");
    assert_eq!(&echo, b"RADICAL_EFFICACY_2026");

    // 2. Attestation handshake & fallback containment
    let attest_res = client.attest_and_bind("manifests/enclave_manifest.json");
    assert!(attest_res.is_ok());

    // 3. Chunked streaming with asymmetric tail padding (3 elements = 96 bytes, not multiple of 128 elements)
    let stream_input = vec![0x33u8; 96];
    let blinded_out = client
        .blind_stream_chunked(&stream_input)
        .expect("Streaming blinded chunk failed");
    assert_eq!(blinded_out.len(), 96);
    assert_ne!(blinded_out, stream_input);

    let _ = std::fs::remove_file(DEFAULT_UNIX_SOCKET_PATH);
}

#[cfg(feature = "std")]
#[test]
fn test_cose_cbor_attestation_and_pcr_verification() {
    use nona_core::client::{hex, NonaClient};
    use nona_core::crypto::sha512_digest;

    let manifest_path = "/tmp/nona_test_enclave_manifest.json";
    let manifest_content = r#"{
  "schema_version": "2.0.0",
  "measurements": {
    "PCR0": "86426715c1053b6ac07d5e8e1dec2c10f9a993876b4c7d816cf05fd3f09b026c1b4ee2edae93d70093c68a835c892822",
    "PCR1": "343af2ecdea0d901101e5594193c9b4dfb921e04963abce196a1698d8badcad862e89fe5b4f6b6cf14fe43d8bee94fae",
    "PCR2": "3102ff423a6f7763a997fdd7885378b4e5606b5e65d79da14ad45143f2cf076ea9259cd714b06b06c87bc4e4fd0a767e"
  }
}"#;
    std::fs::write(manifest_path, manifest_content).expect("Failed to write mock manifest");

    // 1. Validate PCR0, PCR1, PCR2 from manifest
    let pcr0 = hex::decode("86426715c1053b6ac07d5e8e1dec2c10f9a993876b4c7d816cf05fd3f09b026c1b4ee2edae93d70093c68a835c892822").unwrap();
    let pcr1 = hex::decode("343af2ecdea0d901101e5594193c9b4dfb921e04963abce196a1698d8badcad862e89fe5b4f6b6cf14fe43d8bee94fae").unwrap();
    let pcr2 = hex::decode("3102ff423a6f7763a997fdd7885378b4e5606b5e65d79da14ad45143f2cf076ea9259cd714b06b06c87bc4e4fd0a767e").unwrap();

    let pcr_verify = NonaClient::verify_manifest_pcrs(manifest_path, &pcr0, &pcr1, &pcr2);
    assert!(pcr_verify.is_ok());

    // 2. Tampered PCR detection
    let mut bad_pcr0 = pcr0.clone();
    bad_pcr0[0] ^= 0xFF;
    let bad_pcr_verify = NonaClient::verify_manifest_pcrs(manifest_path, &bad_pcr0, &pcr1, &pcr2);
    assert!(bad_pcr_verify.is_err());

    // 3. Test Canonical COSE/CBOR User Data Binding and AWS Root CA Validation
    let dummy_pubkey = [0x02u8; 33];
    let expected_digest = sha512_digest(&dummy_pubkey);

    let valid_mock_doc = nona_core::client::synthesize_mock_cose_sign1_document(
        &expected_digest,
        &pcr0,
        &pcr1,
        &pcr2,
        true,
    );

    let doc_res = NonaClient::parse_and_verify_cose_attestation(
        &valid_mock_doc,
        &expected_digest,
        manifest_path,
    );
    assert!(
        doc_res.is_ok(),
        "Failed valid COSE attestation: {doc_res:?}"
    );

    // 4. Test Key Binding Mismatch Rejection
    let mismatched_digest = [0xEEu8; 64];
    let mismatch_res = NonaClient::parse_and_verify_cose_attestation(
        &valid_mock_doc,
        &mismatched_digest,
        manifest_path,
    );
    assert!(mismatch_res.is_err(), "Expected KeyBindingMismatch error");

    // 4b. Test Authentic AWS Nitro NSM Outer Map Wrapping: {"Attestation": {"document": <COSE_Sign1>}}
    let mut wrapped_nsm_doc = Vec::new();
    // Outer Map of 1 entry: 0xa1
    wrapped_nsm_doc.push(0xa1);
    // Key: "Attestation" -> Text(11): 0x6b
    wrapped_nsm_doc.push(0x6b);
    wrapped_nsm_doc.extend_from_slice(b"Attestation");
    // Value: Map of 1 entry: 0xa1
    wrapped_nsm_doc.push(0xa1);
    // Inner Key: "document" -> Text(8): 0x68
    wrapped_nsm_doc.push(0x68);
    wrapped_nsm_doc.extend_from_slice(b"document");
    // Inner Value: Bytes(valid_mock_doc.len())
    wrapped_nsm_doc.push(0x59);
    wrapped_nsm_doc.extend_from_slice(
        &u16::try_from(valid_mock_doc.len())
            .unwrap_or(0)
            .to_be_bytes(),
    );
    wrapped_nsm_doc.extend_from_slice(&valid_mock_doc);

    let wrapped_doc_res = NonaClient::parse_and_verify_cose_attestation(
        &wrapped_nsm_doc,
        &expected_digest,
        manifest_path,
    );
    assert!(
        wrapped_doc_res.is_ok(),
        "Failed to peel and verify authentic AWS Nitro outer NSM envelope: {wrapped_doc_res:?}"
    );

    // 5. Test Missing AWS Root CA Rejection
    let no_ca_doc = nona_core::client::synthesize_mock_cose_sign1_document(
        &expected_digest,
        &pcr0,
        &pcr1,
        &pcr2,
        false,
    );
    let no_ca_res =
        NonaClient::parse_and_verify_cose_attestation(&no_ca_doc, &expected_digest, manifest_path);
    assert!(no_ca_res.is_err(), "Expected Missing AWS Root CA error");

    // 6. Test Sham Raw Substring Bypass Rejection (F-03 remediation proof)
    let mut sham_raw_doc = Vec::new();
    sham_raw_doc.extend_from_slice(b"aws.nitro-enclaves root ca cert header");
    sham_raw_doc.extend_from_slice(&expected_digest);
    sham_raw_doc.extend_from_slice(b"signature trailer");
    let sham_res = NonaClient::parse_and_verify_cose_attestation(
        &sham_raw_doc,
        &expected_digest,
        manifest_path,
    );
    assert!(
        sham_res.is_err(),
        "Sham raw substring buffer MUST be rejected by CBOR parser"
    );

    let _ = std::fs::remove_file(manifest_path);
}

#[test]
fn test_enclave_session_key_entropy_and_validity() {
    use nona_core::enclave_server::get_or_create_session_key;

    let (privkey, pubkey) = get_or_create_session_key();

    // Verify key is non-zero
    assert_ne!(privkey, [0u8; 32], "Private key must not be all zeroes");

    // Verify key is not the old static formula: (i * 7 + 0x42)
    let mut deterministic_stale = [0u8; 32];
    for (i, byte) in deterministic_stale.iter_mut().enumerate() {
        *byte = (u8::try_from(i).unwrap_or(0).wrapping_mul(7)).wrapping_add(0x42);
    }
    deterministic_stale[0] |= 1;
    assert_ne!(
        privkey, deterministic_stale,
        "Private key matches stale deterministic formula; entropy source non-functional"
    );

    // Verify public key starts with valid compressed secp256k1 parity prefix (0x02 or 0x03)
    assert!(
        pubkey[0] == 0x02 || pubkey[0] == 0x03,
        "Public key header byte must be 0x02 or 0x03, got 0x{:02x}",
        pubkey[0]
    );

    // Verify idempotency of subsequent reads
    let (priv2, pub2) = get_or_create_session_key();
    assert_eq!(
        privkey, priv2,
        "Repeated reads of session key must return identical cached keypair"
    );
    assert_eq!(
        pubkey, pub2,
        "Repeated reads of session pubkey must return identical cached keypair"
    );
}
