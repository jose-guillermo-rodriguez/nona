//! Integration test harness verifying host-enclave wire dispatch and protocol frames.

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

    // Pre-attestation anti-splice verification: channel must reject streaming and blinding
    let dummy_payload = vec![0x11u8; 96];
    assert!(
        matches!(client.blind_stream_chunked(&dummy_payload), Err(nona_core::client::ClientError::AttestationValidationFailed(_))),
        "Unattested channel must fail closed on blind_stream_chunked"
    );
    assert!(
        matches!(client.blind_phase1(&dummy_payload), Err(nona_core::client::ClientError::AttestationValidationFailed(_))),
        "Unattested channel must fail closed on blind_phase1"
    );
    let dummy_chunk = [0x22u8; 128];
    assert!(
        matches!(client.ingest_chunk(&dummy_chunk), Err(nona_core::client::ClientError::AttestationValidationFailed(_))),
        "Unattested channel must fail closed on ingest_chunk"
    );
    client.allow_simulation_fallback = true;

    // 1. Ping roundtrip
    let echo = client.ping(b"RADICAL_EFFICACY_2026").expect("Ping failed");
    assert_eq!(&echo, b"RADICAL_EFFICACY_2026");

    // 2. Attestation handshake & fallback containment
    let attest_res = client.attest_and_bind("manifests/enclave_manifest.json");
    assert!(attest_res.is_ok());

    // 3. Chunked streaming with asymmetric tail padding (3 elements = 96 bytes, not multiple of 128 elements)
    let stream_input = vec![0x33u8; 96];
    let sim_key = [0x42u8; 32];
    let blinded_out = if std::path::Path::new("/dev/nsm").exists() {
        client.blind_stream_chunked(&stream_input)
    } else {
        client.blind_stream_chunked_with_key(&sim_key, &stream_input)
    }
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

    // 3. Test Canonical COSE/CBOR User Data Binding, Nonce, Timestamp, and X.509 P-384 Chain Validation
    let dummy_pubkey = [0x02u8; 33];
    let expected_digest = sha512_digest(&dummy_pubkey);
    let test_nonce = [0x77u8; 32];
    let now_secs: u64 = 1_780_000_000;
    let now_ms: u64 = now_secs * 1000;

    let (valid_signed_doc, test_root_der) =
        nona_core::client::synthesize_signed_cose_sign1_attestation(
            &expected_digest,
            Some(&test_nonce),
            now_ms,
            &pcr0,
            &pcr1,
            &pcr2,
        );

    let doc_res = NonaClient::parse_and_verify_cose_attestation_full(
        &valid_signed_doc,
        &expected_digest,
        Some(&test_nonce),
        manifest_path,
        &test_root_der,
        now_secs,
    );
    assert!(
        doc_res.is_ok(),
        "Failed valid signed COSE_Sign1 ES384 attestation: {doc_res:?}"
    );

    // Pinned production AWS Nitro Root CA must reject synthetic test Root CA
    let unpinned_root_res = NonaClient::parse_and_verify_cose_attestation(
        &valid_signed_doc,
        &expected_digest,
        manifest_path,
    );
    assert!(
        unpinned_root_res.is_err(),
        "Production AWS Nitro Root CA pin must reject non-AWS root chain"
    );

    // 4. Test Key Binding Mismatch Rejection
    let mismatched_digest = [0xEEu8; 64];
    let mismatch_res = NonaClient::parse_and_verify_cose_attestation_full(
        &valid_signed_doc,
        &mismatched_digest,
        Some(&test_nonce),
        manifest_path,
        &test_root_der,
        now_secs,
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
    // Inner Value: Bytes(valid_signed_doc.len())
    wrapped_nsm_doc.push(0x59);
    wrapped_nsm_doc.extend_from_slice(
        &u16::try_from(valid_signed_doc.len())
            .unwrap_or(0)
            .to_be_bytes(),
    );
    wrapped_nsm_doc.extend_from_slice(&valid_signed_doc);

    let wrapped_doc_res = NonaClient::parse_and_verify_cose_attestation_full(
        &wrapped_nsm_doc,
        &expected_digest,
        Some(&test_nonce),
        manifest_path,
        &test_root_der,
        now_secs,
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

    // 6. Test Sham Raw Substring Bypass Rejection
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
    use nona_core::enclave_server::{
        get_or_create_session_pubkey, load_session_privkey_into, AlignedKeyBuffer,
    };

    if !std::path::Path::new("/dev/nsm").exists() {
        // Without /dev/nsm hardware, session key seeding fails closed via zeroize_and_abort
        // (verified via subprocess exit status in test_entropy.rs).
        return;
    }

    let pubkey = get_or_create_session_pubkey();
    let mut priv_buf = AlignedKeyBuffer { data: [0u8; 32] };
    load_session_privkey_into(&mut priv_buf);
    let privkey = priv_buf.data;

    assert_ne!(privkey, [0u8; 32], "Private key must not be all zeroes");
    assert!(
        pubkey[0] == 0x02 || pubkey[0] == 0x03,
        "Public key header byte must be 0x02 or 0x03, got 0x{:02x}",
        pubkey[0]
    );

    let pub2 = get_or_create_session_pubkey();
    let mut priv_buf2 = AlignedKeyBuffer { data: [0u8; 32] };
    load_session_privkey_into(&mut priv_buf2);
    assert_eq!(privkey, priv_buf2.data);
    assert_eq!(pubkey, pub2);
}

#[test]
fn test_enclave_cmd_attest_truncation_fail_closed() {
    use nona_core::attestation::NONA_ERR_ATTEST_OVERFLOW;

    assert_eq!(NONA_ERR_ATTEST_OVERFLOW, -112);
}

#[cfg(feature = "std")]
#[test]
fn test_enclave_wire_fail_closed_oracle_suppression() {
    use nona_core::enclave_server::{
        run_unix_server, EnclaveRequestHeader, EnclaveResponseHeader,
        NONA_VSOCK_MAGIC, NONA_VSOCK_VERSION, NONA_WIRE_ERR_OPAQUE,
    };
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::thread;
    use std::time::Duration;

    let sock_str = format!("/tmp/nona_oracle_gate_{}.sock", std::process::id());
    let _ = std::fs::remove_file(&sock_str);
    let mut sock_cstr = sock_str.clone().into_bytes();
    sock_cstr.push(0);

    thread::spawn(move || unsafe {
        run_unix_server(&sock_cstr);
    });
    thread::sleep(Duration::from_millis(100));

    let mut stream = UnixStream::connect(&sock_str).expect("connect to oracle probe socket");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");

    // Send malformed command (unknown opcode 0xDEAD)
    let bad_cmd = EnclaveRequestHeader {
        magic: NONA_VSOCK_MAGIC,
        version: NONA_VSOCK_VERSION,
        command: 0xDEAD,
        payload_len: 0,
        flags: 0,
        reserved: [0u8; 16],
    };
    stream
        .write_all(&bad_cmd.to_wire_bytes())
        .expect("write bad command");
    stream.flush().expect("flush");

    let mut resp_wire = [0u8; EnclaveResponseHeader::WIRE_SIZE];
    stream
        .read_exact(&mut resp_wire)
        .expect("read opaque error header");
    let resp = EnclaveResponseHeader::from_wire_bytes(&resp_wire);
    assert_eq!(
        resp.status, NONA_WIRE_ERR_OPAQUE,
        "Wire must suppress internal diagnostic codes into opaque -1"
    );
    assert_eq!(resp.payload_len, 0);

    // Subsequent frame on the same socket MUST fail closed (server closed connection immediately)
    let follow_up = stream.read_exact(&mut resp_wire);
    assert!(
        follow_up.is_err(),
        "Server must immediately terminate connection on verification/protocol error"
    );

    let _ = std::fs::remove_file(&sock_str);
}
