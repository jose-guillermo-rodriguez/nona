//! Adversarial Vsock Framing, Session State Machine, and C-ABI FFI Perimeter Bounds Suite.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

#[cfg(all(not(feature = "std"), target_os = "macos"))]
#[link(name = "System")]
extern "C" {}

#[cfg(all(not(feature = "std"), target_os = "linux"))]
#[link(name = "c")]
extern "C" {}

use core::cell::UnsafeCell;
use core::ptr;
#[cfg(feature = "std")]
use nona_core::enclave_server::CMD_ATTEST;
use nona_core::enclave_server::{
    dispatch_frame, EnclaveConnectionSlot, EnclaveRequestHeader, SessionPhase,
    VsockSessionState, CMD_BLIND_PHASE1, CMD_INGEST, CMD_PHASE2_INTERSECT,
    CMD_PHASE2_REBLIND, CMD_PING, MAX_VSOCK_FRAME_BYTES, MAX_WIRE_PAYLOAD_BYTES,
    NONA_ERR_INVALID_PHASE, NONA_VSOCK_MAGIC, NONA_VSOCK_VERSION, NONA_WIRE_ERR_OPAQUE,
};
use nona_core::exception::ExceptionControlBlock;
use nona_core::gatekeeper::{
    NONA_ERR_BUFFER_ALIASING, NONA_ERR_ELEMENT_COUNT_BOUND_VIOLATION, NONA_ERR_INVALID_FLAGS,
    NONA_ERR_LENGTH_BOUND_VIOLATION, NONA_ERR_NULL_POINTER, NONA_ERR_POINTER_WRAPAROUND,
    NONA_ERR_UNALIGNED_POINTER, NONA_SUCCESS,
};
use nona_core::ingest::{
    process_ingest_stream, process_ingest_stream_impl, IngestError, MAX_INGEST_PAYLOAD_BYTES,
};
use nona_core::normalization::SanitizedCode;
use nona_core::obfuscation::IndexPermutationCircuit;
use nona_core::psi::PsiCircuitState;
use nona_core::{
    nona_adaptive_psi_route, nona_core_process, nona_ct_zeroize, nona_gatekeeper_validate,
    nona_ingest_stream, nona_normalize_and_obfuscate, nona_permute_index, nona_phase1_blind,
    nona_phase2_intersect, nona_phase2_intersect_payload, nona_phase2_reblind,
    nona_process_exception_step, nona_validate_ffi_bounds,
};

struct StaticSlot(UnsafeCell<EnclaveConnectionSlot>);
unsafe impl Sync for StaticSlot {}

static TEST_SLOT: StaticSlot = StaticSlot(UnsafeCell::new(EnclaveConnectionSlot::INIT));

#[repr(C, align(64))]
struct AlignedBuf<const N: usize>([u8; N]);

#[repr(C, align(64))]
struct AlignedU64(u64);

#[repr(C, align(64))]
struct AlignedU32(u32);

#[repr(C, align(64))]
struct AlignedU64Array<const N: usize>([u64; N]);

fn make_header(command: u16, payload_len: u32, flags: u32) -> EnclaveRequestHeader {
    EnclaveRequestHeader {
        magic: NONA_VSOCK_MAGIC,
        version: NONA_VSOCK_VERSION,
        command,
        payload_len,
        flags,
        reserved: [0u8; 16],
    }
}

#[inline(never)]
fn test_oversized_header_and_pre_payload_bounds() {
    assert_eq!(
        MAX_VSOCK_FRAME_BYTES,
        EnclaveRequestHeader::WIRE_SIZE + MAX_WIRE_PAYLOAD_BYTES
    );

    for bad_len in [
        u32::try_from(MAX_WIRE_PAYLOAD_BYTES + 1).unwrap_or(u32::MAX),
        u32::MAX,
    ] {
        let oversized_hdr = make_header(CMD_PING, bad_len, 0);
        assert_eq!(oversized_hdr.validate_pre_payload(), Err(-3));
        let wire = oversized_hdr.to_wire_bytes();
        assert!(matches!(
            EnclaveRequestHeader::parse_wire_bytes(&wire),
            Err(-3)
        ));
    }

    #[cfg(feature = "std")]
    {
        use nona_core::enclave_server::{handle_enclave_client_with_staging, EnclaveResponseHeader};
        use std::io::{Read, Write};
        use std::os::unix::io::IntoRawFd;
        use std::os::unix::net::UnixStream;
        use std::thread;
        use std::time::Duration;

        for bad_len in [
            u32::try_from(MAX_WIRE_PAYLOAD_BYTES + 1).unwrap(),
            u32::MAX,
        ] {
            let (mut client_sock, server_sock) = UnixStream::pair().expect("UnixStream::pair");
            client_sock
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set_read_timeout");
            client_sock
                .set_write_timeout(Some(Duration::from_millis(500)))
                .expect("set_write_timeout");

            let server_fd = server_sock.into_raw_fd();
            let server_handle = thread::spawn(move || unsafe {
                let slot = &mut *TEST_SLOT.0.get();
                slot.in_buffer.data.fill(0xAA);
                slot.out_buffer.data.fill(0xBB);
                slot.scratch_buffer.data.fill(0xCC);
                handle_enclave_client_with_staging(server_fd, slot);
                assert!(slot.in_buffer.data.iter().all(|&b| b == 0));
                assert!(slot.out_buffer.data.iter().all(|&b| b == 0));
                assert!(slot.scratch_buffer.data.iter().all(|&b| b == 0));
                assert!(slot.attestation_doc.data.iter().all(|&b| b == 0));
            });

            let oversized_hdr = make_header(CMD_PING, bad_len, 0);
            client_sock
                .write_all(&oversized_hdr.to_wire_bytes())
                .expect("write oversized header");
            client_sock.flush().expect("flush header");

            let mut resp_wire = [0u8; EnclaveResponseHeader::WIRE_SIZE];
            client_sock
                .read_exact(&mut resp_wire)
                .expect("read opaque error response without sending payload");
            let resp = EnclaveResponseHeader::from_wire_bytes(&resp_wire);
            assert_eq!(resp.magic, NONA_VSOCK_MAGIC);
            assert_eq!(resp.status, NONA_WIRE_ERR_OPAQUE);
            assert_eq!(resp.payload_len, 0);

            let mut extra = [0u8; 1];
            assert_eq!(client_sock.read(&mut extra).unwrap_or(0), 0);

            server_handle.join().expect("server thread join");
        }
    }
}

#[inline(never)]
fn test_truncated_headers_truncated_payloads_and_length_mismatches() {
    #[cfg(feature = "std")]
    {
        use nona_core::enclave_server::handle_enclave_client_with_staging;
        use std::io::Write;
        use std::os::unix::io::IntoRawFd;
        use std::os::unix::net::UnixStream;
        use std::thread;

        {
            let (mut client_sock, server_sock) = UnixStream::pair().expect("UnixStream::pair");
            let server_fd = server_sock.into_raw_fd();
            let server_handle = thread::spawn(move || unsafe {
                let slot = &mut *TEST_SLOT.0.get();
                slot.in_buffer.data.fill(0x5A);
                handle_enclave_client_with_staging(server_fd, slot);
                assert!(slot.in_buffer.data.iter().all(|&b| b == 0));
            });

            let full_hdr = make_header(CMD_PING, 16, 0).to_wire_bytes();
            client_sock
                .write_all(&full_hdr[..31])
                .expect("write partial header");
            drop(client_sock);
            server_handle.join().expect("server thread join");
        }

        {
            let (mut client_sock, server_sock) = UnixStream::pair().expect("UnixStream::pair");
            let server_fd = server_sock.into_raw_fd();
            let server_handle = thread::spawn(move || unsafe {
                let slot = &mut *TEST_SLOT.0.get();
                handle_enclave_client_with_staging(server_fd, slot);
                assert!(slot.in_buffer.data.iter().all(|&b| b == 0));
            });

            let hdr = make_header(CMD_PING, 256, 0).to_wire_bytes();
            client_sock.write_all(&hdr).expect("write header");
            client_sock
                .write_all(&[0x42u8; 32])
                .expect("write truncated payload");
            drop(client_sock);
            server_handle.join().expect("server thread join");
        }
    }

    let short_hdr = [0u8; 31];
    assert!(matches!(
        EnclaveRequestHeader::parse_wire_bytes(&short_hdr),
        Err(-3)
    ));

    let mut raw_hdr = make_header(CMD_PING, 4, 0).to_wire_bytes();
    raw_hdr[40] = 0xFF;
    assert!(matches!(
        EnclaveRequestHeader::parse_wire_bytes(&raw_hdr),
        Err(-104)
    ));

    for cmd in [
        CMD_INGEST,
        CMD_BLIND_PHASE1,
        CMD_PHASE2_REBLIND,
        CMD_PHASE2_INTERSECT,
    ] {
        let zero_hdr = make_header(cmd, 0, 0);
        assert_eq!(zero_hdr.validate_pre_payload(), Err(-3));
    }

    let mut resp_buf = AlignedBuf([0u8; 256]);
    let mismatch_hdr = make_header(CMD_PING, 8, 0);
    let (st_trailing, out_len) = dispatch_frame(&mismatch_hdr, &[0xAAu8; 12], &mut resp_buf.0);
    assert_eq!(st_trailing, -3);
    assert_eq!(out_len, 0);

    let unknown_hdr = make_header(0xFFFF, 0, 0);
    assert_eq!(unknown_hdr.validate_pre_payload(), Err(-102));

    let dummy_ptr = (&raw const resp_buf.0).cast::<u8>();
    let rc_impl = unsafe { process_ingest_stream_impl(dummy_ptr, MAX_INGEST_PAYLOAD_BYTES + 128) };
    assert_eq!(rc_impl, NONA_ERR_LENGTH_BOUND_VIOLATION);
    assert_eq!(
        process_ingest_stream(&resp_buf.0[..64]),
        Err(IngestError::InvalidAlignment)
    );
}

#[inline(never)]
fn test_unattested_rejections() {
    let slot = unsafe { &mut *TEST_SLOT.0.get() };
    slot.purge();

    for early_cmd in [
        CMD_INGEST,
        CMD_BLIND_PHASE1,
        CMD_PHASE2_REBLIND,
        CMD_PHASE2_INTERSECT,
    ] {
        let mut session = VsockSessionState::new();
        assert_eq!(session.phase(), SessionPhase::Unattested);

        slot.in_buffer.data.fill(0x7E);
        slot.out_buffer.data.fill(0x7E);
        slot.scratch_buffer.data.fill(0x7E);
        slot.attestation_doc.data.fill(0x7E);

        let effective_len = match early_cmd {
            CMD_INGEST => 128,
            CMD_BLIND_PHASE1 | CMD_PHASE2_REBLIND => {
                slot.in_buffer.data[0] = 0x03;
                slot.in_buffer.data[32] = 0x05;
                64
            }
            CMD_PHASE2_INTERSECT => {
                slot.in_buffer.data[4..8].copy_from_slice(&1u32.to_le_bytes());
                slot.in_buffer.data[8..12].copy_from_slice(&1u32.to_le_bytes());
                80
            }
            _ => unreachable!(),
        };
        let hdr = make_header(early_cmd, u32::try_from(effective_len).unwrap_or(0), 0);

        let (status, out_len) = session.dispatch_frame_buffers(
            &hdr,
            &slot.in_buffer.data[..effective_len],
            &mut slot.out_buffer.data,
            &mut slot.scratch_buffer,
            &mut slot.attestation_doc,
        );
        if session.phase() == SessionPhase::ClosedZeroized {
            slot.purge();
        }
        assert_eq!(status, NONA_ERR_INVALID_PHASE);
        assert_eq!(out_len, 0);
        assert_eq!(session.phase(), SessionPhase::ClosedZeroized);
        assert!(session.is_closed());
        assert!(slot.in_buffer.data.iter().all(|&b| b == 0));
        assert!(slot.out_buffer.data.iter().all(|&b| b == 0));
        assert!(slot.scratch_buffer.data.iter().all(|&b| b == 0));
        assert!(slot.attestation_doc.data.iter().all(|&b| b == 0));

        let ping_hdr = make_header(CMD_PING, 4, 0);
        let (replay_st, replay_len) = session.dispatch_frame(&ping_hdr, b"ping", slot);
        assert_eq!(replay_st, NONA_WIRE_ERR_OPAQUE);
        assert_eq!(replay_len, 0);
        assert_eq!(session.phase(), SessionPhase::ClosedZeroized);
    }
}

#[cfg(feature = "std")]
#[inline(never)]
fn test_out_of_order_and_replay_phase_rejections() {
    let slot = unsafe { &mut *TEST_SLOT.0.get() };
    slot.purge();

    let nonce = [0x33u8; 32];
    let attest_hdr = make_header(CMD_ATTEST, 32, 0);

    let mut dup_session = VsockSessionState::new();
    let _ = dup_session.dispatch_frame(&attest_hdr, &nonce, slot);
    assert_eq!(dup_session.phase(), SessionPhase::AttestedBound);
    let (dup_st, _) = dup_session.dispatch_frame(&attest_hdr, &nonce, slot);
    assert_eq!(dup_st, NONA_ERR_INVALID_PHASE);
    assert_eq!(dup_session.phase(), SessionPhase::ClosedZeroized);

    let mut p2_early_session = VsockSessionState::new();
    let _ = p2_early_session.dispatch_frame(&attest_hdr, &nonce, slot);
    let mut reblind_payload = [0u8; 64];
    reblind_payload[0] = 0x05;
    let reblind_hdr = make_header(CMD_PHASE2_REBLIND, 64, 0);
    let (early_p2_st, _) =
        p2_early_session.dispatch_frame(&reblind_hdr, &reblind_payload, slot);
    assert_eq!(early_p2_st, NONA_ERR_INVALID_PHASE);
    assert_eq!(p2_early_session.phase(), SessionPhase::ClosedZeroized);

    let mut p1_payload = [0u8; 64];
    p1_payload[0] = 0x07;
    p1_payload[32] = 0x11;
    let p1_hdr = make_header(CMD_BLIND_PHASE1, 64, 0);

    let mut skip_reblind_session = VsockSessionState::new();
    let _ = skip_reblind_session.dispatch_frame(&attest_hdr, &nonce, slot);
    let _ = skip_reblind_session.dispatch_frame(&p1_hdr, &p1_payload, slot);
    assert_eq!(skip_reblind_session.phase(), SessionPhase::Phase1Blinded);

    let mut intersect_payload = [0u8; 80];
    intersect_payload[4..8].copy_from_slice(&1u32.to_le_bytes());
    intersect_payload[8..12].copy_from_slice(&1u32.to_le_bytes());
    let intersect_hdr = make_header(CMD_PHASE2_INTERSECT, 80, 0);
    let (skip_st, _) =
        skip_reblind_session.dispatch_frame(&intersect_hdr, &intersect_payload, slot);
    assert_eq!(skip_st, NONA_ERR_INVALID_PHASE);
    assert_eq!(skip_reblind_session.phase(), SessionPhase::ClosedZeroized);
}

#[cfg(feature = "std")]
#[inline(never)]
fn test_monotonic_phase_progression() {
    test_out_of_order_and_replay_phase_rejections();

    let slot = unsafe { &mut *TEST_SLOT.0.get() };
    slot.purge();

    let mut session = VsockSessionState::new();
    let nonce = [0x33u8; 32];
    let attest_hdr = make_header(CMD_ATTEST, 32, 0);
    let _ = session.dispatch_frame(&attest_hdr, &nonce, slot);
    assert_eq!(session.phase(), SessionPhase::AttestedBound);

    let mut p1_payload = [0u8; 64];
    p1_payload[0] = 0x07;
    p1_payload[32] = 0x11;
    let p1_hdr = make_header(CMD_BLIND_PHASE1, 64, 0);
    let (p1_st, p1_out_len) = session.dispatch_frame(&p1_hdr, &p1_payload, slot);
    assert_eq!(p1_st, 0);
    assert_eq!(p1_out_len, 32);
    assert_eq!(session.phase(), SessionPhase::Phase1Blinded);

    let mut blinded_token = [0u8; 32];
    blinded_token.copy_from_slice(&slot.out_buffer.data[..32]);

    let reblind_hdr = make_header(CMD_PHASE2_REBLIND, 64, 0);
    let mut p2_reblind_payload = [0u8; 64];
    p2_reblind_payload[0] = 0x09;
    p2_reblind_payload[32..64].copy_from_slice(&blinded_token);
    let (p2_rb_st, p2_rb_len) =
        session.dispatch_frame(&reblind_hdr, &p2_reblind_payload, slot);
    assert_eq!(p2_rb_st, 0);
    assert_eq!(p2_rb_len, 32);
    assert_eq!(session.phase(), SessionPhase::Phase2Reblinded);

    let mut double_blinded = [0u8; 32];
    double_blinded.copy_from_slice(&slot.out_buffer.data[..32]);

    let intersect_hdr = make_header(CMD_PHASE2_INTERSECT, 80, 0);
    let mut valid_int_payload = [0u8; 80];
    valid_int_payload[4..8].copy_from_slice(&1u32.to_le_bytes());
    valid_int_payload[8..12].copy_from_slice(&1u32.to_le_bytes());
    valid_int_payload[16..48].copy_from_slice(&double_blinded);
    valid_int_payload[48..80].copy_from_slice(&double_blinded);
    let (int_st, int_len) = session.dispatch_frame(&intersect_hdr, &valid_int_payload, slot);
    assert_eq!(int_st, 0);
    assert_eq!(int_len, 68);
    assert_eq!(session.phase(), SessionPhase::Phase2Intersected);
    assert!(session.is_closed());

    let (post_term_st, post_term_len) =
        session.dispatch_frame(&intersect_hdr, &valid_int_payload, slot);
    assert_eq!(post_term_st, NONA_WIRE_ERR_OPAQUE);
    assert_eq!(post_term_len, 0);
    assert_eq!(session.phase(), SessionPhase::ClosedZeroized);
    assert!(slot.out_buffer.data.iter().all(|&b| b == 0));
}

#[inline(never)]
fn test_ffi_blinding_entry_points() {
    let in_buf = AlignedBuf([0x11u8; 64]);
    let key_buf = AlignedBuf([0x22u8; 64]);
    let mut out_buf = AlignedBuf([0u8; 64]);
    let mut psi_state = PsiCircuitState {
        base_value: nona_core::psi::FieldElement::one(),
        exponent: nona_core::psi::FieldElement::one(),
        accumulator: nona_core::psi::FieldElement::zero(),
    };

    unsafe {
        assert_eq!(nona_core_process(ptr::null_mut()), NONA_ERR_NULL_POINTER);
        let unaligned_psi = ((&raw mut psi_state as usize) + 8) as *mut PsiCircuitState;
        assert_eq!(nona_core_process(unaligned_psi), NONA_ERR_UNALIGNED_POINTER);
        assert_eq!(
            nona_core_process((!63usize) as *mut PsiCircuitState),
            NONA_ERR_POINTER_WRAPAROUND
        );
        assert_eq!(nona_core_process(&raw mut psi_state), NONA_SUCCESS);

        assert_eq!(
            nona_phase1_blind(ptr::null(), 64, 2, key_buf.0.as_ptr(), out_buf.0.as_mut_ptr(), 64),
            NONA_ERR_NULL_POINTER
        );
        assert_eq!(
            nona_phase1_blind(
                in_buf.0.as_ptr().add(1),
                64,
                2,
                key_buf.0.as_ptr(),
                out_buf.0.as_mut_ptr(),
                64
            ),
            NONA_ERR_UNALIGNED_POINTER
        );
        assert_eq!(
            nona_phase1_blind(
                in_buf.0.as_ptr(),
                64,
                0,
                key_buf.0.as_ptr(),
                out_buf.0.as_mut_ptr(),
                64
            ),
            NONA_ERR_ELEMENT_COUNT_BOUND_VIOLATION
        );
        assert_eq!(
            nona_phase1_blind(
                in_buf.0.as_ptr(),
                64,
                usize::MAX,
                key_buf.0.as_ptr(),
                out_buf.0.as_mut_ptr(),
                64
            ),
            NONA_ERR_ELEMENT_COUNT_BOUND_VIOLATION
        );
        assert_eq!(
            nona_phase1_blind(
                in_buf.0.as_ptr(),
                64,
                2,
                key_buf.0.as_ptr(),
                in_buf.0.as_ptr().cast_mut(),
                64
            ),
            NONA_ERR_BUFFER_ALIASING
        );

        assert_eq!(
            nona_phase2_reblind(ptr::null(), 64, 2, key_buf.0.as_ptr(), out_buf.0.as_mut_ptr(), 64),
            NONA_ERR_NULL_POINTER
        );
        assert_eq!(
            nona_phase2_reblind(
                in_buf.0.as_ptr(),
                64,
                2,
                key_buf.0.as_ptr().add(4),
                out_buf.0.as_mut_ptr(),
                64
            ),
            NONA_ERR_UNALIGNED_POINTER
        );
        assert_eq!(
            nona_phase2_reblind(
                in_buf.0.as_ptr(),
                64,
                129,
                key_buf.0.as_ptr(),
                out_buf.0.as_mut_ptr(),
                64
            ),
            NONA_ERR_ELEMENT_COUNT_BOUND_VIOLATION
        );
        assert_eq!(
            nona_phase2_reblind(
                in_buf.0.as_ptr(),
                64,
                2,
                key_buf.0.as_ptr(),
                key_buf.0.as_ptr().cast_mut(),
                64
            ),
            NONA_ERR_BUFFER_ALIASING
        );
    }
}

#[inline(never)]
fn test_ffi_intersect_entry_points() {
    let in_buf = AlignedBuf([0x11u8; 64]);
    let key_buf = AlignedBuf([0x22u8; 64]);
    let mut out_buf = AlignedBuf([0u8; 64]);
    let payloads_b = AlignedU64Array([10u64, 20u64]);
    let mut payloads_out = AlignedU64Array([0u64, 0u64]);
    let mut card_out = AlignedU64(0);
    let mut sum_out = AlignedU64(0);

    unsafe {
        assert_eq!(
            nona_phase2_intersect(
                ptr::null(),
                64,
                key_buf.0.as_ptr(),
                64,
                2,
                out_buf.0.as_mut_ptr(),
                64,
                0,
                &raw mut card_out.0
            ),
            NONA_ERR_NULL_POINTER
        );
        assert_eq!(
            nona_phase2_intersect(
                in_buf.0.as_ptr(),
                64,
                key_buf.0.as_ptr(),
                64,
                2,
                out_buf.0.as_mut_ptr(),
                64,
                0,
                ((&raw mut card_out.0 as usize) + 1) as *mut u64
            ),
            NONA_ERR_UNALIGNED_POINTER
        );
        assert_eq!(
            nona_phase2_intersect(
                in_buf.0.as_ptr(),
                64,
                key_buf.0.as_ptr(),
                64,
                0,
                out_buf.0.as_mut_ptr(),
                64,
                0,
                &raw mut card_out.0
            ),
            NONA_ERR_LENGTH_BOUND_VIOLATION
        );
        assert_eq!(
            nona_phase2_intersect(
                in_buf.0.as_ptr(),
                64,
                key_buf.0.as_ptr(),
                64,
                129,
                out_buf.0.as_mut_ptr(),
                1024,
                0,
                &raw mut card_out.0
            ),
            NONA_ERR_ELEMENT_COUNT_BOUND_VIOLATION
        );
        assert_eq!(
            nona_phase2_intersect(
                in_buf.0.as_ptr(),
                64,
                key_buf.0.as_ptr(),
                64,
                2,
                out_buf.0.as_mut_ptr(),
                64,
                0,
                (out_buf.0.as_mut_ptr() as usize) as *mut u64
            ),
            NONA_ERR_BUFFER_ALIASING
        );
        assert_eq!(
            nona_phase2_intersect(
                in_buf.0.as_ptr(),
                64,
                key_buf.0.as_ptr(),
                64,
                2,
                out_buf.0.as_mut_ptr(),
                64,
                99,
                &raw mut card_out.0
            ),
            NONA_ERR_INVALID_FLAGS
        );

        assert_eq!(
            nona_phase2_intersect_payload(
                in_buf.0.as_ptr(),
                64,
                key_buf.0.as_ptr(),
                64,
                payloads_b.0.as_ptr(),
                2,
                out_buf.0.as_mut_ptr(),
                payloads_out.0.as_mut_ptr(),
                64,
                0x06,
                &raw mut card_out.0,
                ptr::null_mut()
            ),
            NONA_ERR_NULL_POINTER
        );
        assert_eq!(
            nona_phase2_intersect_payload(
                in_buf.0.as_ptr(),
                64,
                key_buf.0.as_ptr(),
                64,
                payloads_b.0.as_ptr(),
                2,
                out_buf.0.as_mut_ptr(),
                payloads_out.0.as_mut_ptr(),
                64,
                0x06,
                &raw mut card_out.0,
                &raw mut card_out.0
            ),
            NONA_ERR_BUFFER_ALIASING
        );
        assert_eq!(
            nona_phase2_intersect_payload(
                in_buf.0.as_ptr(),
                64,
                key_buf.0.as_ptr(),
                64,
                payloads_b.0.as_ptr(),
                2,
                out_buf.0.as_mut_ptr(),
                payloads_b.0.as_ptr().cast_mut(),
                64,
                0x02,
                &raw mut card_out.0,
                &raw mut sum_out.0
            ),
            NONA_ERR_BUFFER_ALIASING
        );
    }
}

#[inline(never)]
fn test_ffi_gatekeeper_and_ingest_entry_points() {
    let in_buf = AlignedBuf([0x11u8; 64]);
    let key_buf = AlignedBuf([0x22u8; 64]);
    let mut out_buf = AlignedBuf([0u8; 64]);
    let mut route_out = AlignedU32(0);

    unsafe {
        assert_eq!(nona_ct_zeroize(ptr::null_mut(), 64), NONA_ERR_NULL_POINTER);
        assert_eq!(
            nona_ct_zeroize(out_buf.0.as_mut_ptr(), 0),
            NONA_ERR_LENGTH_BOUND_VIOLATION
        );
        assert_eq!(
            nona_ct_zeroize(out_buf.0.as_mut_ptr(), 65536),
            NONA_ERR_LENGTH_BOUND_VIOLATION
        );
        assert_eq!(
            nona_ct_zeroize((!15usize) as *mut u8, 64),
            NONA_ERR_POINTER_WRAPAROUND
        );
        out_buf.0[..16].fill(0xAA);
        assert_eq!(nona_ct_zeroize(out_buf.0.as_mut_ptr(), 16), NONA_SUCCESS);
        assert!(out_buf.0[..16].iter().all(|&b| b == 0));

        assert_eq!(
            nona_adaptive_psi_route(10, 10, ptr::null_mut()),
            NONA_ERR_NULL_POINTER
        );
        assert_eq!(
            nona_adaptive_psi_route(10, 10, ((&raw mut route_out.0 as usize) + 1) as *mut u32),
            NONA_ERR_UNALIGNED_POINTER
        );
        assert_eq!(
            nona_adaptive_psi_route(u64::MAX, 10, &raw mut route_out.0),
            NONA_ERR_ELEMENT_COUNT_BOUND_VIOLATION
        );

        assert_eq!(nona_ingest_stream(ptr::null(), 128), NONA_ERR_NULL_POINTER);
        assert_eq!(
            nona_ingest_stream(in_buf.0.as_ptr().add(1), 128),
            NONA_ERR_UNALIGNED_POINTER
        );
        assert_eq!(
            nona_ingest_stream(in_buf.0.as_ptr(), 0),
            NONA_ERR_LENGTH_BOUND_VIOLATION
        );
        assert_eq!(
            nona_ingest_stream(in_buf.0.as_ptr(), 8192),
            NONA_ERR_LENGTH_BOUND_VIOLATION
        );

        assert_eq!(
            nona_gatekeeper_validate(ptr::null(), 64, 2, key_buf.0.as_ptr()),
            NONA_ERR_NULL_POINTER
        );
        assert_eq!(
            nona_gatekeeper_validate(in_buf.0.as_ptr(), 0, 2, key_buf.0.as_ptr()),
            NONA_ERR_LENGTH_BOUND_VIOLATION
        );
        assert_eq!(
            nona_gatekeeper_validate(in_buf.0.as_ptr(), 64, 0, key_buf.0.as_ptr()),
            NONA_ERR_ELEMENT_COUNT_BOUND_VIOLATION
        );
        assert_eq!(
            nona_gatekeeper_validate(in_buf.0.as_ptr(), 64, 2, in_buf.0.as_ptr()),
            NONA_ERR_BUFFER_ALIASING
        );

        assert_eq!(
            nona_validate_ffi_bounds(
                ptr::null(),
                64,
                2,
                key_buf.0.as_ptr(),
                32,
                out_buf.0.as_mut_ptr(),
                64,
                64
            ),
            NONA_ERR_NULL_POINTER
        );
        assert_eq!(
            nona_validate_ffi_bounds(
                in_buf.0.as_ptr(),
                64,
                2,
                key_buf.0.as_ptr(),
                32,
                out_buf.0.as_mut_ptr(),
                64,
                0
            ),
            NONA_ERR_LENGTH_BOUND_VIOLATION
        );
    }
}

#[inline(never)]
fn test_ffi_gatekeeper_and_obfuscation_entry_points() {
    test_ffi_gatekeeper_and_ingest_entry_points();

    let in_buf = AlignedBuf([0x11u8; 64]);
    let mut out_buf = AlignedBuf([0u8; 64]);
    let mut perm_out = AlignedU64(0);
    let mut code_out = SanitizedCode::default();
    let circuit = IndexPermutationCircuit::default();
    let mut ecb = ExceptionControlBlock::new();

    unsafe {
        assert_eq!(
            nona_normalize_and_obfuscate(
                ptr::null(),
                64,
                1,
                2,
                &raw mut code_out,
                &raw mut perm_out.0
            ),
            NONA_ERR_NULL_POINTER
        );
        assert_eq!(
            nona_normalize_and_obfuscate(
                in_buf.0.as_ptr(),
                0,
                1,
                2,
                &raw mut code_out,
                &raw mut perm_out.0
            ),
            NONA_ERR_LENGTH_BOUND_VIOLATION
        );
        assert_eq!(
            nona_normalize_and_obfuscate(
                in_buf.0.as_ptr(),
                64,
                1,
                2,
                ((&raw mut code_out as usize) + 1) as *mut SanitizedCode,
                &raw mut perm_out.0
            ),
            NONA_ERR_UNALIGNED_POINTER
        );
        assert_eq!(
            nona_normalize_and_obfuscate(
                (&raw const code_out).cast::<u8>(),
                64,
                1,
                2,
                &raw mut code_out,
                &raw mut perm_out.0
            ),
            NONA_ERR_BUFFER_ALIASING
        );

        assert_eq!(
            nona_permute_index(ptr::null(), 7, &raw mut perm_out.0),
            NONA_ERR_NULL_POINTER
        );
        assert_eq!(
            nona_permute_index(
                ((&raw const circuit as usize) + 8) as *const IndexPermutationCircuit,
                7,
                &raw mut perm_out.0
            ),
            NONA_ERR_UNALIGNED_POINTER
        );
        assert_eq!(
            nona_permute_index(
                &raw const circuit,
                7,
                (&raw const circuit).cast::<u64>().cast_mut()
            ),
            NONA_ERR_BUFFER_ALIASING
        );

        assert_eq!(
            nona_process_exception_step(ptr::null_mut(), 0, out_buf.0.as_mut_ptr()),
            NONA_ERR_NULL_POINTER
        );
        assert_eq!(
            nona_process_exception_step(&raw mut ecb, 0, (&raw mut ecb).cast::<u8>()),
            NONA_ERR_BUFFER_ALIASING
        );
    }
}

fn run_all_perimeter_tests() {
    test_oversized_header_and_pre_payload_bounds();
    test_truncated_headers_truncated_payloads_and_length_mismatches();
    test_unattested_rejections();
    #[cfg(feature = "std")]
    test_monotonic_phase_progression();
    test_ffi_blinding_entry_points();
    test_ffi_intersect_entry_points();
    test_ffi_gatekeeper_and_obfuscation_entry_points();
}

#[cfg(all(not(feature = "std"), not(target_os = "none")))]
#[no_mangle]
pub extern "C" fn main(_argc: i32, _argv: *const *const u8) -> i32 {
    run_all_perimeter_tests();
    0
}

#[cfg(all(not(feature = "std"), target_os = "none"))]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    run_all_perimeter_tests();
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(feature = "std")]
fn main() {
    run_all_perimeter_tests();
}
